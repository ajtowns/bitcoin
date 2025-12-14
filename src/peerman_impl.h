// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_processing.h>

#include <addrman.h>
#include <arith_uint256.h>
#include <banman.h>
#include <blockencodings.h>
#include <blockfilter.h>
#include <chain.h>
#include <chainparams.h>
#include <common/bloom.h>
#include <consensus/amount.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <core_memusage.h>
#include <crypto/siphash.h>
#include <deploymentstatus.h>
#include <flatfile.h>
#include <headerssync.h>
#include <index/blockfilterindex.h>
#include <kernel/chain.h>
#include <logging.h>
#include <merkleblock.h>
#include <net.h>
#include <net_permissions.h>
#include <netaddress.h>
#include <netbase.h>
#include <netmessagemaker.h>
#include <node/blockstorage.h>
#include <node/connection_types.h>
#include <node/protocol_version.h>
#include <node/timeoffsets.h>
#include <node/txdownloadman.h>
#include <node/txorphanage.h>
#include <node/txreconciliation.h>
#include <node/warnings.h>
#include <policy/feerate.h>
#include <policy/fees/block_policy_estimator.h>
#include <policy/packages.h>
#include <policy/policy.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <random.h>
#include <scheduler.h>
#include <script/script.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <sync.h>
#include <tinyformat.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <util/thread.h>
#include <util/trace.h>
#include <validation.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <compare>
#include <cstddef>
#include <deque>
#include <exception>
#include <functional>
#include <future>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <queue>
#include <ranges>
#include <ratio>
#include <set>
#include <span>
#include <thread>
#include <typeinfo>
#include <utility>

/** Default time during which a peer must stall block download progress before being disconnected.
 * the actual timeout is increased temporarily if peers are disconnected for hitting the timeout */
static constexpr auto BLOCK_STALLING_TIMEOUT_DEFAULT{2s};
/** Maximum timeout for stalling block download. */
static constexpr auto BLOCK_STALLING_TIMEOUT_MAX{64s};

/** Blocks that are in flight, and that are in the queue to be downloaded. */
struct QueuedBlock {
    /** BlockIndex. We must have this since we only request blocks when we've already validated the header. */
    const CBlockIndex* pindex;
    /** Optional, used for CMPCTBLOCK downloads */
    std::unique_ptr<PartiallyDownloadedBlock> partialBlock;
};

/**
 * Data structure for an individual peer. This struct is not protected by
 * cs_main since it does not contain validation-critical data.
 *
 * Memory is owned by shared pointers and this object is destructed when
 * the refcount drops to zero.
 *
 * Mutexes inside this struct must not be held when locking m_peer_mutex.
 *
 * TODO: move most members from CNodeState to this structure.
 * TODO: move remaining application-layer data members from CNode to this structure.
 */
struct Peer {
    /** Same id as the CNode object for this peer */
    const NodeId m_id{0};

    /** Services we offered to this peer.
     *
     *  This is supplied by CConnman during peer initialization. It's const
     *  because there is no protocol defined for renegotiating services
     *  initially offered to a peer. The set of local services we offer should
     *  not change after initialization.
     *
     *  An interesting example of this is NODE_NETWORK and initial block
     *  download: a node which starts up from scratch doesn't have any blocks
     *  to serve, but still advertises NODE_NETWORK because it will eventually
     *  fulfill this role after IBD completes. P2P code is written in such a
     *  way that it can gracefully handle peers who don't make good on their
     *  service advertisements. */
    const ServiceFlags m_our_services;
    /** Services this peer offered to us. */
    std::atomic<ServiceFlags> m_their_services{NODE_NONE};

    //! Whether this peer is an inbound connection
    const bool m_is_inbound;

    /** Protects misbehavior data members */
    Mutex m_misbehavior_mutex;
    /** Whether this peer should be disconnected and marked as discouraged (unless it has NetPermissionFlags::NoBan permission). */
    bool m_should_discourage GUARDED_BY(m_misbehavior_mutex){false};

    /** Protects block inventory data members */
    Mutex m_block_inv_mutex;
    /** List of blocks that we'll announce via an `inv` message.
     * There is no final sorting before sending, as they are always sent
     * immediately and in the order requested. */
    std::vector<uint256> m_blocks_for_inv_relay GUARDED_BY(m_block_inv_mutex);
    /** Unfiltered list of blocks that we'd like to announce via a `headers`
     * message. If we can't announce via a `headers` message, we'll fall back to
     * announcing via `inv`. */
    std::vector<uint256> m_blocks_for_headers_relay GUARDED_BY(m_block_inv_mutex);
    /** The final block hash that we sent in an `inv` message to this peer.
     * When the peer requests this block, we send an `inv` message to trigger
     * the peer to request the next sequence of block hashes.
     * Most peers use headers-first syncing, which doesn't use this mechanism */
    uint256 m_continuation_block GUARDED_BY(m_block_inv_mutex) {};

    /** Set to true once initial VERSION message was sent (only relevant for outbound peers). */
    bool m_outbound_version_message_sent GUARDED_BY(NetEventsInterface::g_msgproc_mutex){false};

    /** This peer's reported block height when we connected */
    std::atomic<int> m_starting_height{-1};

    /** The pong reply we're expecting, or 0 if no pong expected. */
    std::atomic<uint64_t> m_ping_nonce_sent{0};
    /** When the last ping was sent, or 0 if no ping was ever sent */
    std::atomic<std::chrono::microseconds> m_ping_start{0us};
    /** Whether a ping has been requested by the user */
    std::atomic<bool> m_ping_queued{false};

    /** Whether this peer relays txs via wtxid */
    std::atomic<bool> m_wtxid_relay{false};
    /** The feerate in the most recent BIP133 `feefilter` message sent to the peer.
     *  It is *not* a p2p protocol violation for the peer to send us
     *  transactions with a lower fee rate than this. See BIP133. */
    CAmount m_fee_filter_sent GUARDED_BY(NetEventsInterface::g_msgproc_mutex){0};
    /** Timestamp after which we will send the next BIP133 `feefilter` message
      * to the peer. */
    std::chrono::microseconds m_next_send_feefilter GUARDED_BY(NetEventsInterface::g_msgproc_mutex){0};

    struct TxRelay {
        mutable RecursiveMutex m_bloom_filter_mutex;
        /** Whether we relay transactions to this peer. */
        bool m_relay_txs GUARDED_BY(m_bloom_filter_mutex){false};
        /** A bloom filter for which transactions to announce to the peer. See BIP37. */
        std::unique_ptr<CBloomFilter> m_bloom_filter PT_GUARDED_BY(m_bloom_filter_mutex) GUARDED_BY(m_bloom_filter_mutex){nullptr};

        mutable RecursiveMutex m_tx_inventory_mutex;
        /** A filter of all the (w)txids that the peer has announced to
         *  us or we have announced to the peer. We use this to avoid announcing
         *  the same (w)txid to a peer that already has the transaction. */
        CRollingBloomFilter m_tx_inventory_known_filter GUARDED_BY(m_tx_inventory_mutex){50000, 0.000001};
        /** Set of wtxids we still have to announce. For non-wtxid-relay peers,
         *  we retrieve the txid from the corresponding mempool transaction when
         *  constructing the `inv` message. We use the mempool to sort transactions
         *  in dependency order before relay, so this does not have to be sorted. */
        std::set<Wtxid> m_tx_inventory_to_send GUARDED_BY(m_tx_inventory_mutex);
        /** Whether the peer has requested us to send our complete mempool. Only
         *  permitted if the peer has NetPermissionFlags::Mempool or we advertise
         *  NODE_BLOOM. See BIP35. */
        bool m_send_mempool GUARDED_BY(m_tx_inventory_mutex){false};
        /** The next time after which we will send an `inv` message containing
         *  transaction announcements to this peer. */
        std::chrono::microseconds m_next_inv_send_time GUARDED_BY(m_tx_inventory_mutex){0};
        /** The mempool sequence num at which we sent the last `inv` message to this peer.
         *  Can relay txs with lower sequence numbers than this (see CTxMempool::info_for_relay). */
        uint64_t m_last_inv_sequence GUARDED_BY(m_tx_inventory_mutex){1};

        /** Minimum fee rate with which to filter transaction announcements to this node. See BIP133. */
        std::atomic<CAmount> m_fee_filter_received{0};
    };

    /* Initializes a TxRelay struct for this peer. Can be called at most once for a peer. */
    TxRelay* SetTxRelay() EXCLUSIVE_LOCKS_REQUIRED(!m_tx_relay_mutex)
    {
        LOCK(m_tx_relay_mutex);
        Assume(!m_tx_relay);
        m_tx_relay = std::make_unique<Peer::TxRelay>();
        return m_tx_relay.get();
    };

    TxRelay* GetTxRelay() EXCLUSIVE_LOCKS_REQUIRED(!m_tx_relay_mutex)
    {
        return WITH_LOCK(m_tx_relay_mutex, return m_tx_relay.get());
    };

    /** A vector of addresses to send to the peer, limited to MAX_ADDR_TO_SEND. */
    std::vector<CAddress> m_addrs_to_send GUARDED_BY(NetEventsInterface::g_msgproc_mutex);
    /** Probabilistic filter to track recent addr messages relayed with this
     *  peer. Used to avoid relaying redundant addresses to this peer.
     *
     *  We initialize this filter for outbound peers (other than
     *  block-relay-only connections) or when an inbound peer sends us an
     *  address related message (ADDR, ADDRV2, GETADDR).
     *
     *  Presence of this filter must correlate with m_addr_relay_enabled.
     **/
    std::unique_ptr<CRollingBloomFilter> m_addr_known GUARDED_BY(NetEventsInterface::g_msgproc_mutex);
    /** Whether we are participating in address relay with this connection.
     *
     *  We set this bool to true for outbound peers (other than
     *  block-relay-only connections), or when an inbound peer sends us an
     *  address related message (ADDR, ADDRV2, GETADDR).
     *
     *  We use this bool to decide whether a peer is eligible for gossiping
     *  addr messages. This avoids relaying to peers that are unlikely to
     *  forward them, effectively blackholing self announcements. Reasons
     *  peers might support addr relay on the link include that they connected
     *  to us as a block-relay-only peer or they are a light client.
     *
     *  This field must correlate with whether m_addr_known has been
     *  initialized.*/
    std::atomic_bool m_addr_relay_enabled{false};
    /** Whether a getaddr request to this peer is outstanding. */
    bool m_getaddr_sent GUARDED_BY(NetEventsInterface::g_msgproc_mutex){false};
    /** Guards address sending timers. */
    mutable Mutex m_addr_send_times_mutex;
    /** Time point to send the next ADDR message to this peer. */
    std::chrono::microseconds m_next_addr_send GUARDED_BY(m_addr_send_times_mutex){0};
    /** Time point to possibly re-announce our local address to this peer. */
    std::chrono::microseconds m_next_local_addr_send GUARDED_BY(m_addr_send_times_mutex){0};
    /** Whether the peer has signaled support for receiving ADDRv2 (BIP155)
     *  messages, indicating a preference to receive ADDRv2 instead of ADDR ones. */
    std::atomic_bool m_wants_addrv2{false};
    /** Whether this peer has already sent us a getaddr message. */
    bool m_getaddr_recvd GUARDED_BY(NetEventsInterface::g_msgproc_mutex){false};
    /** Number of addresses that can be processed from this peer. Start at 1 to
     *  permit self-announcement. */
    double m_addr_token_bucket GUARDED_BY(NetEventsInterface::g_msgproc_mutex){1.0};
    /** When m_addr_token_bucket was last updated */
    std::chrono::microseconds m_addr_token_timestamp GUARDED_BY(NetEventsInterface::g_msgproc_mutex){GetTime<std::chrono::microseconds>()};
    /** Total number of addresses that were dropped due to rate limiting. */
    std::atomic<uint64_t> m_addr_rate_limited{0};
    /** Total number of addresses that were processed (excludes rate-limited ones). */
    std::atomic<uint64_t> m_addr_processed{0};

    /** Whether we've sent this peer a getheaders in response to an inv prior to initial-headers-sync completing */
    bool m_inv_triggered_getheaders_before_sync GUARDED_BY(NetEventsInterface::g_msgproc_mutex){false};

    /** Protects m_getdata_requests **/
    Mutex m_getdata_requests_mutex;
    /** Work queue of items requested by this peer **/
    std::deque<CInv> m_getdata_requests GUARDED_BY(m_getdata_requests_mutex);

    /** Time of the last getheaders message to this peer */
    NodeClock::time_point m_last_getheaders_timestamp GUARDED_BY(NetEventsInterface::g_msgproc_mutex){};

    /** Protects m_headers_sync **/
    Mutex m_headers_sync_mutex;
    /** Headers-sync state for this peer (eg for initial sync, or syncing large
     * reorgs) **/
    std::unique_ptr<HeadersSyncState> m_headers_sync PT_GUARDED_BY(m_headers_sync_mutex) GUARDED_BY(m_headers_sync_mutex) {};

    /** Whether we've sent our peer a sendheaders message. **/
    std::atomic<bool> m_sent_sendheaders{false};

    /** When to potentially disconnect peer for stalling headers download */
    std::chrono::microseconds m_headers_sync_timeout GUARDED_BY(NetEventsInterface::g_msgproc_mutex){0us};

    /** Whether this peer wants invs or headers (when possible) for block announcements */
    bool m_prefers_headers GUARDED_BY(NetEventsInterface::g_msgproc_mutex){false};

    /** Time offset computed during the version handshake based on the
     * timestamp the peer sent in the version message. */
    std::atomic<std::chrono::seconds> m_time_offset{0s};

    explicit Peer(NodeId id, ServiceFlags our_services, bool is_inbound)
        : m_id{id}
        , m_our_services{our_services}
        , m_is_inbound{is_inbound}
    {}

private:
    mutable Mutex m_tx_relay_mutex;

    /** Transaction relay data. May be a nullptr. */
    std::unique_ptr<TxRelay> m_tx_relay GUARDED_BY(m_tx_relay_mutex);
};

using PeerRef = std::shared_ptr<Peer>;

/**
 * Maintain validation-specific state about nodes, protected by cs_main, instead
 * by CNode's own locks. This simplifies asynchronous operation, where
 * processing of incoming data is done after the ProcessMessage call returns,
 * and we're no longer holding the node's locks.
 */
struct CNodeState {
    //! The best known block we know this peer has announced.
    const CBlockIndex* pindexBestKnownBlock{nullptr};
    //! The hash of the last unknown block this peer has announced.
    uint256 hashLastUnknownBlock{};
    //! The last full block we both have.
    const CBlockIndex* pindexLastCommonBlock{nullptr};
    //! The best header we have sent our peer.
    const CBlockIndex* pindexBestHeaderSent{nullptr};
    //! Whether we've started headers synchronization with this peer.
    bool fSyncStarted{false};
    //! Since when we're stalling block download progress (in microseconds), or 0.
    std::chrono::microseconds m_stalling_since{0us};
    std::list<QueuedBlock> vBlocksInFlight;
    //! When the first entry in vBlocksInFlight started downloading. Don't care when vBlocksInFlight is empty.
    std::chrono::microseconds m_downloading_since{0us};
    //! Whether we consider this a preferred download peer.
    bool fPreferredDownload{false};
    /** Whether this peer wants invs or cmpctblocks (when possible) for block announcements. */
    bool m_requested_hb_cmpctblocks{false};
    /** Whether this peer will send us cmpctblocks if we request them. */
    bool m_provides_cmpctblocks{false};

    /** State used to enforce CHAIN_SYNC_TIMEOUT and EXTRA_PEER_CHECK_INTERVAL logic.
      *
      * Both are only in effect for outbound, non-manual, non-protected connections.
      * Any peer protected (m_protect = true) is not chosen for eviction. A peer is
      * marked as protected if all of these are true:
      *   - its connection type is IsBlockOnlyConn() == false
      *   - it gave us a valid connecting header
      *   - we haven't reached MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT yet
      *   - its chain tip has at least as much work as ours
      *
      * CHAIN_SYNC_TIMEOUT: if a peer's best known block has less work than our tip,
      * set a timeout CHAIN_SYNC_TIMEOUT in the future:
      *   - If at timeout their best known block now has more work than our tip
      *     when the timeout was set, then either reset the timeout or clear it
      *     (after comparing against our current tip's work)
      *   - If at timeout their best known block still has less work than our
      *     tip did when the timeout was set, then send a getheaders message,
      *     and set a shorter timeout, HEADERS_RESPONSE_TIME seconds in future.
      *     If their best known block is still behind when that new timeout is
      *     reached, disconnect.
      *
      * EXTRA_PEER_CHECK_INTERVAL: after each interval, if we have too many outbound peers,
      * drop the outbound one that least recently announced us a new block.
      */
    struct ChainSyncTimeoutState {
        //! A timeout used for checking whether our peer has sufficiently synced
        std::chrono::seconds m_timeout{0s};
        //! A header with the work we require on our peer's chain
        const CBlockIndex* m_work_header{nullptr};
        //! After timeout is reached, set to true after sending getheaders
        bool m_sent_getheaders{false};
        //! Whether this peer is protected from disconnection due to a bad/slow chain
        bool m_protect{false};
    };

    ChainSyncTimeoutState m_chain_sync;

    //! Time of last new block announcement
    int64_t m_last_block_announcement{0};
};

class PeerManagerImpl final : public PeerManager
{
public:
    PeerManagerImpl(CConnman& connman, AddrMan& addrman,
                    BanMan* banman, ChainstateManager& chainman,
                    CTxMemPool& pool, node::Warnings& warnings, Options opts);

    virtual ~PeerManagerImpl();

    /** Overridden from CValidationInterface. */
    void ActiveTipChange(const CBlockIndex& new_tip, bool) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex);
    void BlockConnected(ChainstateRole role, const std::shared_ptr<const CBlock>& pblock, const CBlockIndex* pindexConnected) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex);
    void BlockDisconnected(const std::shared_ptr<const CBlock> &block, const CBlockIndex* pindex) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex);
    void UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex);
    void BlockChecked(const std::shared_ptr<const CBlock>& block, const BlockValidationState& state) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex);
    void NewPoWValidBlock(const CBlockIndex *pindex, const std::shared_ptr<const CBlock>& pblock) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_most_recent_block_mutex);

    /** Implement NetEventsInterface */
    void InitializeNode(CNode& node, ServiceFlags our_services) override EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex, !m_tx_download_mutex);
    void FinalizeNode(const CNode& node) override EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex, !m_headers_presync_mutex, !m_tx_download_mutex);
    bool ProcessMessages(CNode* pfrom, std::atomic<bool>& interrupt) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex, !m_most_recent_block_mutex, !m_headers_presync_mutex, g_msgproc_mutex, !m_tx_download_mutex);
    bool SendMessages(CNode* pto) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex, !m_most_recent_block_mutex, g_msgproc_mutex, !m_tx_download_mutex);

    /** Implement PeerManager */
    void StartScheduledTasks(CScheduler& scheduler) override;
    void CheckForStaleTipAndEvictPeers() override;
    util::Expected<void, std::string> FetchBlock(NodeId peer_id, const CBlockIndex& block_index) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex);
    size_t GetNodeCount(ConnectionDirection) const override;
    bool GetNodeStateStats(NodeId nodeid, CNodeStateStats& stats) const override EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex);
    std::vector<node::TxOrphanage::OrphanInfo> GetOrphanTransactions() override EXCLUSIVE_LOCKS_REQUIRED(!m_tx_download_mutex);
    PeerManagerInfo GetInfo() const override EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex);
    void SendPings() override EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex);
    void RelayTransaction(const Txid& txid, const Wtxid& wtxid) override EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex);
    void SetBestBlock(int height, std::chrono::seconds time) override
    {
        m_best_height = height;
        m_best_block_time = time;
    };
    void UnitTestMisbehaving(NodeId peer_id) override EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex) { Misbehaving(*Assert(GetPeerRef(peer_id)), ""); };
    void ProcessMessage(CNode& pfrom, const std::string& msg_type, DataStream& vRecv,
                        const std::chrono::microseconds time_received, const std::atomic<bool>& interruptMsgProc) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex, !m_most_recent_block_mutex, !m_headers_presync_mutex, g_msgproc_mutex, !m_tx_download_mutex);
    void UpdateLastBlockAnnounceTime(NodeId node, int64_t time_in_seconds) override;
    ServiceFlags GetDesirableServiceFlags(ServiceFlags services) const override;

    void Start(CScheduler& scheduler, const CConnman::Options& connOptions) override;
    void Interrupt() override;
    void Stop() override;

private:
    bool HasAllDesirableServiceFlags(ServiceFlags services) const;

    /** Consider evicting an outbound peer based on the amount of time they've been behind our tip */
    void ConsiderEviction(CNode& pto, Peer& peer, std::chrono::seconds time_in_seconds) EXCLUSIVE_LOCKS_REQUIRED(cs_main, g_msgproc_mutex);

    /** If we have extra outbound peers, try to disconnect the one with the oldest block announcement */
    void EvictExtraOutboundPeers(std::chrono::seconds now) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /** Retrieve unbroadcast transactions from the mempool and reattempt sending to peers */
    void ReattemptInitialBroadcast(CScheduler& scheduler) EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex);

    /** Get a shared pointer to the Peer object.
     *  May return an empty shared_ptr if the Peer object can't be found. */
    PeerRef GetPeerRef(NodeId id) const EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex);

    /** Get a shared pointer to the Peer object and remove it from m_peer_map.
     *  May return an empty shared_ptr if the Peer object can't be found. */
    PeerRef RemovePeer(NodeId id) EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex);

    /** Mark a peer as misbehaving, which will cause it to be disconnected and its
     *  address discouraged. */
    void Misbehaving(Peer& peer, const std::string& message);

    /**
     * Potentially mark a node discouraged based on the contents of a BlockValidationState object
     *
     * @param[in] via_compact_block this bool is passed in because net_processing should
     * punish peers differently depending on whether the data was provided in a compact
     * block message or not. If the compact block had a valid header, but contained invalid
     * txs, the peer should not be punished. See BIP 152.
     */
    void MaybePunishNodeForBlock(NodeId nodeid, const BlockValidationState& state,
                                 bool via_compact_block, const std::string& message = "")
        EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex);

    /** Maybe disconnect a peer and discourage future connections from its address.
     *
     * @param[in]   pnode     The node to check.
     * @param[in]   peer      The peer object to check.
     * @return                True if the peer was marked for disconnection in this function
     */
    bool MaybeDiscourageAndDisconnect(CNode& pnode, Peer& peer);

    /** Handle a transaction whose result was not MempoolAcceptResult::ResultType::VALID.
     * @param[in]   first_time_failure            Whether we should consider inserting into vExtraTxnForCompact, adding
     *                                            a new orphan to resolve, or looking for a package to submit.
     *                                            Set to true for transactions just received over p2p.
     *                                            Set to false if the tx has already been rejected before,
     *                                            e.g. is already in the orphanage, to avoid adding duplicate entries.
     * Updates m_txrequest, m_lazy_recent_rejects, m_lazy_recent_rejects_reconsiderable, m_orphanage, and vExtraTxnForCompact.
     *
     * @returns a PackageToValidate if this transaction has a reconsiderable failure and an eligible package was found,
     * or std::nullopt otherwise.
     */
    std::optional<node::PackageToValidate> ProcessInvalidTx(NodeId nodeid, const CTransactionRef& tx, const TxValidationState& result,
                                                      bool first_time_failure)
        EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex, g_msgproc_mutex, m_tx_download_mutex);

    /** Handle a transaction whose result was MempoolAcceptResult::ResultType::VALID.
     * Updates m_txrequest, m_orphanage, and vExtraTxnForCompact. Also queues the tx for relay. */
    void ProcessValidTx(NodeId nodeid, const CTransactionRef& tx, const std::list<CTransactionRef>& replaced_transactions)
        EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex, g_msgproc_mutex, m_tx_download_mutex);

    /** Handle the results of package validation: calls ProcessValidTx and ProcessInvalidTx for
     * individual transactions, and caches rejection for the package as a group.
     */
    void ProcessPackageResult(const node::PackageToValidate& package_to_validate, const PackageMempoolAcceptResult& package_result)
        EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex, g_msgproc_mutex, m_tx_download_mutex);

    /**
     * Reconsider orphan transactions after a parent has been accepted to the mempool.
     *
     * @peer[in]  peer     The peer whose orphan transactions we will reconsider. Generally only
     *                     one orphan will be reconsidered on each call of this function. If an
     *                     accepted orphan has orphaned children, those will need to be
     *                     reconsidered, creating more work, possibly for other peers.
     * @return             True if meaningful work was done (an orphan was accepted/rejected).
     *                     If no meaningful work was done, then the work set for this peer
     *                     will be empty.
     */
    bool ProcessOrphanTx(Peer& peer)
        EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex, g_msgproc_mutex, !m_tx_download_mutex);

    /** Process a single headers message from a peer.
     *
     * @param[in]   pfrom     CNode of the peer
     * @param[in]   peer      The peer sending us the headers
     * @param[in]   headers   The headers received. Note that this may be modified within ProcessHeadersMessage.
     * @param[in]   via_compact_block   Whether this header came in via compact block handling.
    */
    void ProcessHeadersMessage(CNode& pfrom, Peer& peer,
                               std::vector<CBlockHeader>&& headers,
                               bool via_compact_block)
        EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex, !m_headers_presync_mutex, g_msgproc_mutex);
    /** Various helpers for headers processing, invoked by ProcessHeadersMessage() */
    /** Return true if headers are continuous and have valid proof-of-work (DoS points assigned on failure) */
    bool CheckHeadersPoW(const std::vector<CBlockHeader>& headers, const Consensus::Params& consensusParams, Peer& peer);
    /** Calculate an anti-DoS work threshold for headers chains */
    arith_uint256 GetAntiDoSWorkThreshold();
    /** Deal with state tracking and headers sync for peers that send
     * non-connecting headers (this can happen due to BIP 130 headers
     * announcements for blocks interacting with the 2hr (MAX_FUTURE_BLOCK_TIME) rule). */
    void HandleUnconnectingHeaders(CNode& pfrom, Peer& peer, const std::vector<CBlockHeader>& headers) EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex);
    /** Return true if the headers connect to each other, false otherwise */
    bool CheckHeadersAreContinuous(const std::vector<CBlockHeader>& headers) const;
    /** Try to continue a low-work headers sync that has already begun.
     * Assumes the caller has already verified the headers connect, and has
     * checked that each header satisfies the proof-of-work target included in
     * the header.
     *  @param[in]  peer                            The peer we're syncing with.
     *  @param[in]  pfrom                           CNode of the peer
     *  @param[in,out] headers                      The headers to be processed.
     *  @return     True if the passed in headers were successfully processed
     *              as the continuation of a low-work headers sync in progress;
     *              false otherwise.
     *              If false, the passed in headers will be returned back to
     *              the caller.
     *              If true, the returned headers may be empty, indicating
     *              there is no more work for the caller to do; or the headers
     *              may be populated with entries that have passed anti-DoS
     *              checks (and therefore may be validated for block index
     *              acceptance by the caller).
     */
    bool IsContinuationOfLowWorkHeadersSync(Peer& peer, CNode& pfrom,
            std::vector<CBlockHeader>& headers)
        EXCLUSIVE_LOCKS_REQUIRED(peer.m_headers_sync_mutex, !m_headers_presync_mutex, g_msgproc_mutex);
    /** Check work on a headers chain to be processed, and if insufficient,
     * initiate our anti-DoS headers sync mechanism.
     *
     * @param[in]   peer                The peer whose headers we're processing.
     * @param[in]   pfrom               CNode of the peer
     * @param[in]   chain_start_header  Where these headers connect in our index.
     * @param[in,out]   headers             The headers to be processed.
     *
     * @return      True if chain was low work (headers will be empty after
     *              calling); false otherwise.
     */
    bool TryLowWorkHeadersSync(Peer& peer, CNode& pfrom,
                                  const CBlockIndex* chain_start_header,
                                  std::vector<CBlockHeader>& headers)
        EXCLUSIVE_LOCKS_REQUIRED(!peer.m_headers_sync_mutex, !m_peer_mutex, !m_headers_presync_mutex, g_msgproc_mutex);

    /** Return true if the given header is an ancestor of
     *  m_chainman.m_best_header or our current tip */
    bool IsAncestorOfBestHeaderOrTip(const CBlockIndex* header) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /** Request further headers from this peer with a given locator.
     * We don't issue a getheaders message if we have a recent one outstanding.
     * This returns true if a getheaders is actually sent, and false otherwise.
     */
    bool MaybeSendGetHeaders(CNode& pfrom, const CBlockLocator& locator, Peer& peer) EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex);
    /** Potentially fetch blocks from this peer upon receipt of a new headers tip */
    void HeadersDirectFetchBlocks(CNode& pfrom, const Peer& peer, const CBlockIndex& last_header);
    /** Update peer state based on received headers message */
    void UpdatePeerStateForReceivedHeaders(CNode& pfrom, Peer& peer, const CBlockIndex& last_header, bool received_new_header, bool may_have_more_headers)
        EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex);

    void SendBlockTransactions(CNode& pfrom, Peer& peer, const CBlock& block, const BlockTransactionsRequest& req);

    /** Send a message to a peer */
    void PushMessage(CNode& node, CSerializedNetMsg&& msg) const { m_connman.PushMessage(&node, std::move(msg)); }
    template <typename... Args>
    void MakeAndPushMessage(CNode& node, std::string msg_type, Args&&... args) const
    {
        m_connman.PushMessage(&node, NetMsg::Make(std::move(msg_type), std::forward<Args>(args)...));
    }

    /** Send a version message to a peer */
    void PushNodeVersion(CNode& pnode, const Peer& peer);

    /** Send a ping message every PING_INTERVAL or if requested via RPC. May
     *  mark the peer to be disconnected if a ping has timed out.
     *  We use mockable time for ping timeouts, so setmocktime may cause pings
     *  to time out. */
    void MaybeSendPing(CNode& node_to, Peer& peer, std::chrono::microseconds now);

    /** Send `addr` messages on a regular schedule. */
    void MaybeSendAddr(CNode& node, Peer& peer, std::chrono::microseconds current_time) EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex);

    /** Send a single `sendheaders` message, after we have completed headers sync with a peer. */
    void MaybeSendSendHeaders(CNode& node, Peer& peer) EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex);

    /** Relay (gossip) an address to a few randomly chosen nodes.
     *
     * @param[in] originator   The id of the peer that sent us the address. We don't want to relay it back.
     * @param[in] addr         Address to relay.
     * @param[in] fReachable   Whether the address' network is reachable. We relay unreachable
     *                         addresses less.
     */
    void RelayAddress(NodeId originator, const CAddress& addr, bool fReachable) EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex, g_msgproc_mutex);

    /** Send `feefilter` message. */
    void MaybeSendFeefilter(CNode& node, Peer& peer, std::chrono::microseconds current_time) EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex);

    FastRandomContext m_rng GUARDED_BY(NetEventsInterface::g_msgproc_mutex);

    FeeFilterRounder m_fee_filter_rounder GUARDED_BY(NetEventsInterface::g_msgproc_mutex);

    const CChainParams& m_chainparams;
    CConnman& m_connman;
    AddrMan& m_addrman;
    /** Pointer to this node's banman. May be nullptr - check existence before dereferencing. */
    BanMan* const m_banman;
    ChainstateManager& m_chainman;
    CTxMemPool& m_mempool;

    /** Synchronizes tx download including TxRequestTracker, rejection filters, and TxOrphanage.
     * Lock invariants:
     * - A txhash (txid or wtxid) in m_txrequest is not also in m_orphanage.
     * - A txhash (txid or wtxid) in m_txrequest is not also in m_lazy_recent_rejects.
     * - A txhash (txid or wtxid) in m_txrequest is not also in m_lazy_recent_rejects_reconsiderable.
     * - A txhash (txid or wtxid) in m_txrequest is not also in m_lazy_recent_confirmed_transactions.
     * - Each data structure's limits hold (m_orphanage max size, m_txrequest per-peer limits, etc).
     */
    Mutex m_tx_download_mutex ACQUIRED_BEFORE(m_mempool.cs);
    node::TxDownloadManager m_txdownloadman GUARDED_BY(m_tx_download_mutex);

    std::unique_ptr<TxReconciliationTracker> m_txreconciliation;

    /** The height of the best chain */
    std::atomic<int> m_best_height{-1};
    /** The time of the best chain tip block */
    std::atomic<std::chrono::seconds> m_best_block_time{0s};

    /** Next time to check for stale tip */
    std::chrono::seconds m_stale_tip_check_time GUARDED_BY(cs_main){0s};

    node::Warnings& m_warnings;
    TimeOffsets m_outbound_time_offsets{m_warnings};

    const Options m_opts;

    bool RejectIncomingTxs(const CNode& peer) const;

    /** Whether we've completed initial sync yet, for determining when to turn
      * on extra block-relay-only peers. */
    bool m_initial_sync_finished GUARDED_BY(cs_main){false};

    /** Protects m_peer_map. This mutex must not be locked while holding a lock
     *  on any of the mutexes inside a Peer object. */
    mutable Mutex m_peer_mutex;
    /**
     * Map of all Peer objects, keyed by peer id. This map is protected
     * by the m_peer_mutex. Once a shared pointer reference is
     * taken, the lock may be released. Individual fields are protected by
     * their own locks.
     */
    std::map<NodeId, PeerRef> m_peer_map GUARDED_BY(m_peer_mutex);

    /** Map maintaining per-node state. */
    std::map<NodeId, CNodeState> m_node_states GUARDED_BY(cs_main);

    /** Get a pointer to a const CNodeState, used when not mutating the CNodeState object. */
    const CNodeState* State(NodeId pnode) const EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    /** Get a pointer to a mutable CNodeState. */
    CNodeState* State(NodeId pnode) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    uint32_t GetFetchFlags(const Peer& peer) const;

    std::map<uint64_t, std::chrono::microseconds> m_next_inv_to_inbounds_per_network_key GUARDED_BY(g_msgproc_mutex);

    /** Number of nodes with fSyncStarted. */
    int nSyncStarted GUARDED_BY(cs_main) = 0;

    /** Hash of the last block we received via INV */
    uint256 m_last_block_inv_triggering_headers_sync GUARDED_BY(g_msgproc_mutex){};

    /**
     * Sources of received blocks, saved to be able punish them when processing
     * happens afterwards.
     * Set mapBlockSource[hash].second to false if the node should not be
     * punished if the block is invalid.
     */
    std::map<uint256, std::pair<NodeId, bool>> mapBlockSource GUARDED_BY(cs_main);

    /** Number of peers with wtxid relay. */
    std::atomic<int> m_wtxid_relay_peers{0};

    /** Number of outbound peers with m_chain_sync.m_protect. */
    int m_outbound_peers_with_protect_from_disconnect GUARDED_BY(cs_main) = 0;

    /** Number of preferable block download peers. */
    int m_num_preferred_download_peers GUARDED_BY(cs_main){0};

    /** Stalling timeout for blocks in IBD */
    std::atomic<std::chrono::seconds> m_block_stalling_timeout{BLOCK_STALLING_TIMEOUT_DEFAULT};

    /**
     * For sending `inv`s to inbound peers, we use a single (exponentially
     * distributed) timer for all peers with the same network key. If we used a separate timer for each
     * peer, a spy node could make multiple inbound connections to us to
     * accurately determine when we received a transaction (and potentially
     * determine the transaction's origin). Each network key has its own timer
     * to make fingerprinting harder. */
    std::chrono::microseconds NextInvToInbounds(std::chrono::microseconds now,
                                                std::chrono::seconds average_interval,
                                                uint64_t network_key) EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex);


    // All of the following cache a recent block, and are protected by m_most_recent_block_mutex
    Mutex m_most_recent_block_mutex;
    std::shared_ptr<const CBlock> m_most_recent_block GUARDED_BY(m_most_recent_block_mutex);
    std::shared_ptr<const CBlockHeaderAndShortTxIDs> m_most_recent_compact_block GUARDED_BY(m_most_recent_block_mutex);
    uint256 m_most_recent_block_hash GUARDED_BY(m_most_recent_block_mutex);
    std::unique_ptr<const std::map<GenTxid, CTransactionRef>> m_most_recent_block_txs GUARDED_BY(m_most_recent_block_mutex);

    // Data about the low-work headers synchronization, aggregated from all peers' HeadersSyncStates.
    /** Mutex guarding the other m_headers_presync_* variables. */
    Mutex m_headers_presync_mutex;
    /** A type to represent statistics about a peer's low-work headers sync.
     *
     * - The first field is the total verified amount of work in that synchronization.
     * - The second is:
     *   - nullopt: the sync is in REDOWNLOAD phase (phase 2).
     *   - {height, timestamp}: the sync has the specified tip height and block timestamp (phase 1).
     */
    using HeadersPresyncStats = std::pair<arith_uint256, std::optional<std::pair<int64_t, uint32_t>>>;
    /** Statistics for all peers in low-work headers sync. */
    std::map<NodeId, HeadersPresyncStats> m_headers_presync_stats GUARDED_BY(m_headers_presync_mutex) {};
    /** The peer with the most-work entry in m_headers_presync_stats. */
    NodeId m_headers_presync_bestpeer GUARDED_BY(m_headers_presync_mutex) {-1};
    /** The m_headers_presync_stats improved, and needs signalling. */
    std::atomic_bool m_headers_presync_should_signal{false};

    /** Height of the highest block announced using BIP 152 high-bandwidth mode. */
    int m_highest_fast_announce GUARDED_BY(::cs_main){0};

    /** Have we requested this block from a peer */
    bool IsBlockRequested(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /** Have we requested this block from an outbound peer */
    bool IsBlockRequestedFromOutbound(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main, !m_peer_mutex);

    /** Remove this block from our tracked requested blocks. Called if:
     *  - the block has been received from a peer
     *  - the request for the block has timed out
     * If "from_peer" is specified, then only remove the block if it is in
     * flight from that peer (to avoid one peer's network traffic from
     * affecting another's state).
     */
    void RemoveBlockRequest(const uint256& hash, std::optional<NodeId> from_peer) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /* Mark a block as in flight
     * Returns false, still setting pit, if the block was already in flight from the same peer
     * pit will only be valid as long as the same cs_main lock is being held
     */
    bool BlockRequested(NodeId nodeid, const CBlockIndex& block, std::list<QueuedBlock>::iterator** pit = nullptr) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    bool TipMayBeStale() EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /** Update pindexLastCommonBlock and add not-in-flight missing successors to vBlocks, until it has
     *  at most count entries.
     */
    void FindNextBlocksToDownload(const Peer& peer, unsigned int count, std::vector<const CBlockIndex*>& vBlocks, NodeId& nodeStaller) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /** Request blocks for the background chainstate, if one is in use. */
    void TryDownloadingHistoricalBlocks(const Peer& peer, unsigned int count, std::vector<const CBlockIndex*>& vBlocks, const CBlockIndex* from_tip, const CBlockIndex* target_block) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /**
    * \brief Find next blocks to download from a peer after a starting block.
    *
    * \param vBlocks      Vector of blocks to download which will be appended to.
    * \param peer         Peer which blocks will be downloaded from.
    * \param state        Pointer to the state of the peer.
    * \param pindexWalk   Pointer to the starting block to add to vBlocks.
    * \param count        Maximum number of blocks to allow in vBlocks. No more
    *                     blocks will be added if it reaches this size.
    * \param nWindowEnd   Maximum height of blocks to allow in vBlocks. No
    *                     blocks will be added above this height.
    * \param activeChain  Optional pointer to a chain to compare against. If
    *                     provided, any next blocks which are already contained
    *                     in this chain will not be appended to vBlocks, but
    *                     instead will be used to update the
    *                     state->pindexLastCommonBlock pointer.
    * \param nodeStaller  Optional pointer to a NodeId variable that will receive
    *                     the ID of another peer that might be causing this peer
    *                     to stall. This is set to the ID of the peer which
    *                     first requested the first in-flight block in the
    *                     download window. It is only set if vBlocks is empty at
    *                     the end of this function call and if increasing
    *                     nWindowEnd by 1 would cause it to be non-empty (which
    *                     indicates the download might be stalled because every
    *                     block in the window is in flight and no other peer is
    *                     trying to download the next block).
    */
    void FindNextBlocks(std::vector<const CBlockIndex*>& vBlocks, const Peer& peer, CNodeState *state, const CBlockIndex *pindexWalk, unsigned int count, int nWindowEnd, const CChain* activeChain=nullptr, NodeId* nodeStaller=nullptr) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /* Multimap used to preserve insertion order */
    typedef std::multimap<uint256, std::pair<NodeId, std::list<QueuedBlock>::iterator>> BlockDownloadMap;
    BlockDownloadMap mapBlocksInFlight GUARDED_BY(cs_main);

    /** When our tip was last updated. */
    std::atomic<std::chrono::seconds> m_last_tip_update{0s};

    /** Determine whether or not a peer can request a transaction, and return it (or nullptr if not found or not allowed). */
    CTransactionRef FindTxForGetData(const Peer::TxRelay& tx_relay, const GenTxid& gtxid)
        EXCLUSIVE_LOCKS_REQUIRED(!m_most_recent_block_mutex, !tx_relay.m_tx_inventory_mutex);

    void ProcessGetData(CNode& pfrom, Peer& peer, const std::atomic<bool>& interruptMsgProc)
        EXCLUSIVE_LOCKS_REQUIRED(!m_most_recent_block_mutex, peer.m_getdata_requests_mutex, NetEventsInterface::g_msgproc_mutex)
        LOCKS_EXCLUDED(::cs_main);

    /** Process a new block. Perform any post-processing housekeeping */
    void ProcessBlock(CNode& node, const std::shared_ptr<const CBlock>& block, bool force_processing, bool min_pow_checked);

    /** Process compact block txns  */
    void ProcessCompactBlockTxns(CNode& pfrom, Peer& peer, const BlockTransactions& block_transactions)
        EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex, !m_most_recent_block_mutex);

    /**
     * When a peer sends us a valid block, instruct it to announce blocks to us
     * using CMPCTBLOCK if possible by adding its nodeid to the end of
     * lNodesAnnouncingHeaderAndIDs, and keeping that list under a certain size by
     * removing the first element if necessary.
     */
    void MaybeSetPeerAsAnnouncingHeaderAndIDs(NodeId nodeid) EXCLUSIVE_LOCKS_REQUIRED(cs_main, !m_peer_mutex);

    /** Stack of nodes which we have set to announce using compact blocks */
    std::list<NodeId> lNodesAnnouncingHeaderAndIDs GUARDED_BY(cs_main);

    /** Number of peers from which we're downloading blocks. */
    int m_peers_downloading_from GUARDED_BY(cs_main) = 0;

    void AddToCompactExtraTransactions(const CTransactionRef& tx) EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex);

    /** Orphan/conflicted/etc transactions that are kept for compact block reconstruction.
     *  The last -blockreconstructionextratxn/DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN of
     *  these are kept in a ring buffer */
    std::vector<std::pair<Wtxid, CTransactionRef>> vExtraTxnForCompact GUARDED_BY(g_msgproc_mutex);
    /** Offset into vExtraTxnForCompact to insert the next tx */
    size_t vExtraTxnForCompactIt GUARDED_BY(g_msgproc_mutex) = 0;

    /** Check whether the last unknown block a peer advertised is not yet known. */
    void ProcessBlockAvailability(NodeId nodeid) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    /** Update tracking information about which blocks a peer is assumed to have. */
    void UpdateBlockAvailability(NodeId nodeid, const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    bool CanDirectFetch() EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /**
     * Estimates the distance, in blocks, between the best-known block and the network chain tip.
     * Utilizes the best-block time and the chainparams blocks spacing to approximate it.
     */
    int64_t ApproximateBestBlockDepth() const;

    /**
     * To prevent fingerprinting attacks, only send blocks/headers outside of
     * the active chain if they are no more than a month older (both in time,
     * and in best equivalent proof of work) than the best header chain we know
     * about and we fully-validated them at some point.
     */
    bool BlockRequestAllowed(const CBlockIndex* pindex) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    bool AlreadyHaveBlock(const uint256& block_hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void ProcessGetBlockData(CNode& pfrom, Peer& peer, const CInv& inv)
        EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex, !m_most_recent_block_mutex);

    /**
     * Validation logic for compact filters request handling.
     *
     * May disconnect from the peer in the case of a bad request.
     *
     * @param[in]   node            The node that we received the request from
     * @param[in]   peer            The peer that we received the request from
     * @param[in]   filter_type     The filter type the request is for. Must be basic filters.
     * @param[in]   start_height    The start height for the request
     * @param[in]   stop_hash       The stop_hash for the request
     * @param[in]   max_height_diff The maximum number of items permitted to request, as specified in BIP 157
     * @param[out]  stop_index      The CBlockIndex for the stop_hash block, if the request can be serviced.
     * @param[out]  filter_index    The filter index, if the request can be serviced.
     * @return                      True if the request can be serviced.
     */
    bool PrepareBlockFilterRequest(CNode& node, Peer& peer,
                                   BlockFilterType filter_type, uint32_t start_height,
                                   const uint256& stop_hash, uint32_t max_height_diff,
                                   const CBlockIndex*& stop_index,
                                   BlockFilterIndex*& filter_index);

    /**
     * Handle a cfilters request.
     *
     * May disconnect from the peer in the case of a bad request.
     *
     * @param[in]   node            The node that we received the request from
     * @param[in]   peer            The peer that we received the request from
     * @param[in]   vRecv           The raw message received
     */
    void ProcessGetCFilters(CNode& node, Peer& peer, DataStream& vRecv);

    /**
     * Handle a cfheaders request.
     *
     * May disconnect from the peer in the case of a bad request.
     *
     * @param[in]   node            The node that we received the request from
     * @param[in]   peer            The peer that we received the request from
     * @param[in]   vRecv           The raw message received
     */
    void ProcessGetCFHeaders(CNode& node, Peer& peer, DataStream& vRecv);

    /**
     * Handle a getcfcheckpt request.
     *
     * May disconnect from the peer in the case of a bad request.
     *
     * @param[in]   node            The node that we received the request from
     * @param[in]   peer            The peer that we received the request from
     * @param[in]   vRecv           The raw message received
     */
    void ProcessGetCFCheckPt(CNode& node, Peer& peer, DataStream& vRecv);

    /** Checks if address relay is permitted with peer. If needed, initializes
     * the m_addr_known bloom filter and sets m_addr_relay_enabled to true.
     *
     *  @return   True if address relay is enabled with peer
     *            False if address relay is disallowed
     */
    bool SetupAddressRelay(const CNode& node, Peer& peer) EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex);

    void AddAddressKnown(Peer& peer, const CAddress& addr) EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex);
    void PushAddress(Peer& peer, const CAddress& addr) EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex);

    void LogBlockHeader(const CBlockIndex& index, const CNode& peer, bool via_compact_block);

    std::thread threadMessageHandler;
    std::thread threadDNSAddressSeed;
    std::thread threadOpenConnections;
    std::thread threadOpenAddedConnections;

    void ThreadMessageHandler() EXCLUSIVE_LOCKS_REQUIRED(!NetEventsInterface::g_msgproc_mutex, !m_peer_mutex, !m_most_recent_block_mutex, !m_headers_presync_mutex, !m_tx_download_mutex);

    void ThreadDNSAddressSeed() EXCLUSIVE_LOCKS_REQUIRED(!NetEventsInterface::g_msgproc_mutex, !m_peer_mutex, !m_most_recent_block_mutex, !m_headers_presync_mutex, !m_tx_download_mutex);

    void ThreadOpenConnections(const std::vector<std::string> connect, std::span<const std::string> seed_nodes);

    void ThreadOpenAddedConnections();

    // Count the number of full-relay peer we have.
    int GetFullOutboundConnCount() const;
    // Return the number of outbound peers we have in excess of our target (eg,
    // if we previously called SetTryNewOutboundPeer(true), and have since set
    // to false, we may have extra peers that we wish to disconnect). This may
    // return a value less than (num_outbound_connections - num_outbound_slots)
    // in cases where some outbound connections are not yet fully connected, or
    // not yet fully disconnected.
    int GetExtraFullOutboundCount() const;
    // Count the number of block-relay-only peers we have over our limit.
    int GetExtraBlockRelayCount() const;
};
