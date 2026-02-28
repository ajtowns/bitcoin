// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_TEMPLATEMAN_H
#define BITCOIN_NODE_TEMPLATEMAN_H

#include <blockencodings.h>
#include <primitives/transaction.h>
#include <streams.h>
#include <uint256.h>
#include <util/bitset.h>
#include <random.h>
#include <util/check.h>
#include <util/hasher.h>
#include <util/overloaded.h>
#include <util/time.h>
#include <util/vecdeque.h>

#include <chrono>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <unordered_map>
#include <utility>
#include <vector>

class CTxMemPool;
typedef int64_t NodeId;

namespace node {

static constexpr int SHORTTXIDS_LENGTH = 6;

/** Maximum number of templates to keep. */
static constexpr size_t MAX_TEMPLATES{10};

/** How frequently to update templates for compact block reconstruction. */
static constexpr auto TEMPLATE_UPDATE_INTERVAL{std::chrono::seconds{30}};

/** How frequently to request templates from a peer. */
static constexpr auto TEMPLATE_REQUEST_INTERVAL{std::chrono::seconds{120}};

/** Maximum number of inbound peers to actively request templates from. */
static constexpr int MAX_INBOUND_TEMPLATE_PEERS{10};

/** Average number of request cycles before rotating out an active inbound. */
static constexpr int INBOUND_TEMPLATE_ROTATION_FREQ{8};

/** How long to keep completed peer templates (as delta bases). */
static constexpr auto PEER_TEMPLATE_EXPIRY{std::chrono::seconds{150}};

/** Template weight limit (larger than consensus to capture more txs). */
static constexpr unsigned int MAX_TEMPLATE_WEIGHT{8000000};

/** Entry in the shared template tx pool. Ordered by wtxid. */
struct TemplateTx {
    CTransactionRef tx;
    mutable int32_t weight{0};         //!< cached GetTransactionWeight result
    mutable uint32_t num_templates{0}; //!< refcount: number of templates referencing this tx
    mutable size_t scannable_idx{0};   //!< index into m_scannable_txns
    mutable NodeClock::time_point next_mempool_check{NodeClock::time_point::min()}; //!< earliest time to retry ATMP

    friend auto operator<=>(const TemplateTx& a, const TemplateTx& b)
    {
        return a.tx->GetWitnessHash() <=> b.tx->GetWitnessHash();
    }
    friend bool operator==(const TemplateTx& a, const TemplateTx& b)
    {
        return a.tx->GetWitnessHash() == b.tx->GetWitnessHash();
    }

    /** Allow lookup by Wtxid in the set via std::less<>. */
    friend auto operator<=>(const TemplateTx& a, const Wtxid& b)
    {
        return a.tx->GetWitnessHash() <=> b;
    }
    friend bool operator==(const TemplateTx& a, const Wtxid& b)
    {
        return a.tx->GetWitnessHash() == b;
    }
};

using TemplateTxSet = std::set<TemplateTx, std::less<>>;
using TemplateTxRef = TemplateTxSet::iterator;

class Template {
public:
    std::vector<TemplateTxRef> m_txs;    //!< ordered tx list
    uint256 m_hash;                      //!< SHA256 of concatenated wtxids
    int64_t m_weight{0};                 //!< total transaction weight

    /** Compute template hash: SHA256 of concatenated wtxids. */
    void ComputeHash();
};

/** Pre-encoded delta from a basis template to this template. */
using TemplateDelta = std::vector<std::byte>;

/** A locally-generated block template for the sendtemplate protocol. */
class LocalTemplate : public Template {
public:
    /** Lazily-computed deltas from basis templates, keyed by basis hash. */
    mutable std::unordered_map<uint256, TemplateDelta, SaltedUint256Hasher> m_deltas;

    /** Get (or compute) the delta from a basis template to this one. */
    const TemplateDelta& GetDelta(const Template& basis) const;

    /**
     * Build a tmplt message payload.
     *
     * If no basis template: flat list of 6-byte short IDs.
     * If basis template: CompactIntVec delta encoding + appended raw
     * 6-byte IDs for new transactions.
     */
    DataStream MakeTmpltMsg(uint64_t nonce, const LocalTemplate* basis) const;
};

/** Bitset-based tracking of template positions.
 *
 *  Positions are stored as a vector of bitsets (each covering 1024 positions).
 */
class MissingTemplateTxns
{
protected:
    static constexpr unsigned CHUNK_SIZE{1024};
    std::vector<BitSet<CHUNK_SIZE>> m_positions;

public:
    bool empty() const { return m_positions.empty(); }

    /** Release all state and free memory. */
    void Reset()
    {
        std::vector<BitSet<CHUNK_SIZE>>{}.swap(m_positions);
    }

    /** Return all set positions in order. */
    std::vector<int32_t> GetPositions() const;

};

/** Provider side: ProcessMessage populates via Queue(); SendMessages drains
 *  via GetNextChunk().
 */
class RequestedTemplateTxns : public MissingTemplateTxns
{
    uint256 m_template_hash;
public:
    const uint256& template_hash() const { return m_template_hash; }

    void Reset()
    {
        MissingTemplateTxns::Reset();
        m_template_hash.SetNull();
    }

    /** Populate from sorted absolute positions. Replaces any prior queue.
     *  Returns false (and leaves the queue empty) if any position is out of range. */
    [[nodiscard]] bool Queue(const uint256& hash, const LocalTemplate& tmpl, const std::vector<uint16_t>& positions);

    /** Drain up to max_bytes of transactions, resolving positions via tmpl.
     *  Returns the collected transactions. Clears state when fully drained. */
    std::vector<CTransactionRef> GetNextChunk(const LocalTemplate& tmpl, size_t max_bytes);
};

/** Receiver side: ExtendMissing() marks ranges as missing; ReceivedTxn()
 *  clears individual matched positions; FillTxs() fills from tmplttxn chunks.
 */
class WantedTemplateTxns : public MissingTemplateTxns
{
public:
    /** Mark positions from..to (inclusive) as missing. Allocates chunks as needed. */
    void ExtendMissing(int32_t from, int32_t to);

    /** Mark a single position as received (clear its bit). */
    void ReceivedTxn(int32_t pos);

    /** Fill the next missing positions in tmpl.m_txs from refs.
     *  Iterates set bits in order, placing each ref at that position, clearing the bit.
     *  Returns the number of positions filled. */
    size_t FillTxs(Template& tmpl, std::span<const TemplateTxRef> refs);
};

/** A partially-received template from a peer, being populated via tmplttxn chunks. */
class PartialPeerTemplate : public Template {
public:
    size_t m_tx_count;              //!< expected total (from tmplt message)
    size_t m_filled{0};             //!< how many slots are filled so far
    WantedTemplateTxns m_missing;   //!< tracks unfilled positions

    bool IsComplete() const { return m_filled == m_tx_count; }
};

/** A completed template received from a peer. */
class PeerTemplate : public Template {
public:
    NodeId m_nodeid;
    NodeClock::time_point m_time;
    mutable size_t m_last_validated_idx{0}; //!< next position to try for mempool validation

    PeerTemplate() = default;
    PeerTemplate(NodeId nodeid, NodeClock::time_point now, PartialPeerTemplate&& partial);
};

struct TemplateInfo {
    size_t num_templates{0};
    size_t max_templates{0};
    size_t pool_size{0};
    int64_t pool_weight{0};
    size_t latest_tx_count{0};
    int64_t latest_weight{0};
    std::chrono::seconds update_interval{};
    NodeClock::time_point next_update{};
    size_t num_peer_templates{0};
    size_t num_partial_peer_templates{0};
};

/**
 * Manages block templates for the sendtemplate protocol.
 *
 * Maintains a shared tx pool (refcounted) across all templates,
 * and provides provider-side template generation and encoding.
 */
class TemplateManager
{
    TemplateTxSet m_pool;
    int64_t m_pool_weight{0};            //!< total weight of all txs in m_pool
    std::deque<LocalTemplate> m_templates;
    NodeClock::time_point m_next_update{NodeClock::time_point::min()};

    /**
     * Vector of (wtxid, iterator) pairs for cache-local linear scans
     * of all transactions in m_pool.
     * The inline wtxid avoids dereferencing the set node during scans,
     * so that use in compact block reconstruction is fast.
     */
    std::vector<std::pair<Wtxid, TemplateTxRef>> m_scannable_txns;

    std::map<NodeId, PartialPeerTemplate> m_partial_peer_templates;
    /** Completed peer templates. Newest at front (push_front), oldest at back (pop_back). */
    VecDeque<PeerTemplate> m_peer_templates;
    /** Cache from NodeId to most recent PeerTemplate. Invalidated on reallocation. */
    mutable std::unordered_map<NodeId, const PeerTemplate*> m_peer_template_cache;


    /** Find transaction in the pool, adding if necessary. Bumps refcount. */
    TemplateTxRef AddTx(CTransactionRef tx);

    /** Find transactions in the pool, adding if necessary. Bumps refcounts. */
    std::vector<TemplateTxRef> AddTxs(std::span<CTransactionRef> txs);

    /** Decrement refcounts and erase txs with zero refs. */
    void RemoveTxs(std::vector<TemplateTxRef>&& vec);

    /** Trim old templates beyond MAX_TEMPLATES. */
    void TrimLocalTemplates();

    /** Add a completed peer template. Handles cache invalidation on reallocation. */
    void AddPeerTemplate(PeerTemplate&& pt);

    /** Clean up partial template state for a peer. */
    void ForgetPartialTemplate(NodeId nodeid);

public:
    /**
     * Generate a new template from block transactions (sans coinbase).
     * Computes template hash, adds txs to pool, and trims old templates.
     */
    void GenerateTemplate(std::span<CTransactionRef> txs);

    /** Look up a template by its hash. */
    const LocalTemplate* GetTemplate(const uint256& hash) const
    {
        for (const auto& tmpl : m_templates) {
            if (tmpl.m_hash == hash) return &tmpl;
        }
        return nullptr;
    }

    /** Get the most recent template (or nullptr if none). */
    const LocalTemplate* GetBestTemplate() const
    {
        if (m_templates.empty()) return nullptr;
        return &m_templates.back();
    }

    /**
     * Resolve transaction positions to actual transaction references.
     * Used for tmplttxn responses.
     */
    static std::vector<CTransactionRef> GetTxsByPosition(const LocalTemplate& tmpl, const std::vector<uint16_t>& positions);

    /** Cache-local (wtxid, iter) vector for compact block reconstruction. */
    const auto& GetScannableTxns() const { return m_scannable_txns; }

    /** Number of transactions in the shared pool. */
    size_t PoolSize() const { return m_pool.size(); }

    /** Number of stored templates. */
    size_t NumTemplates() const { return m_templates.size(); }

    /** Check if it's time to generate a new template, and if so, advance the timer. */
    bool CheckTimer(NodeClock::time_point now, FastRandomContext& rng)
    {
        if (now < m_next_update) return false;
        m_next_update = now + TEMPLATE_UPDATE_INTERVAL / 2 + rng.randrange<std::chrono::milliseconds>(TEMPLATE_UPDATE_INTERVAL);
        return true;
    }

    /** Find the most recent completed template from a peer, or nullptr.
     *  O(n) scan of m_peer_templates. */
    const PeerTemplate* GetPeerTemplate(NodeId nodeid) const;

    /** Find a completed template from a peer with a specific hash, or nullptr.
     *  O(n) scan of m_peer_templates. */
    const PeerTemplate* GetPeerTemplate(NodeId nodeid, const uint256& hash) const;

    /** Create (or reset) a partial peer template, optionally filling from a basis.
     *  For flat tmplt: basis = nullptr, delta_ints empty.
     *  For delta tmplt: fills positions from basis using decoded delta instructions.
     *  Returns false if delta offsets are out of range. */
    [[nodiscard]] bool PartialInitFromBasis(NodeId nodeid, const uint256& hash,
                                             const Template* basis, const std::vector<int32_t>& delta_ints);

    /** Fill unfilled positions by matching short IDs against mempool, template pool,
     *  and extra transactions. short_ids are in order of unfilled positions.
     *  Returns false on absence, hash mismatch, or wrong number of short IDs. */
    [[nodiscard]] bool PartialFillShortIDs(NodeId nodeid, const uint256& hash,
                                            uint64_t nonce,
                                            const std::vector<uint64_t>& short_ids,
                                            const CTxMemPool& mempool,
                                            ExtraTransactions& extra_txns);

    /** Fill the next missing positions from a tmplttxn chunk.
     *  Returns false on error (no partial, hash mismatch, more txs than positions). */
    [[nodiscard]] bool PartialFillTxns(NodeId nodeid, const uint256& hash,
                                        std::span<CTransactionRef> txs);

    /** If the partial is complete, validate hash and move to completed peer templates.
     *  Returns true if OK (still in progress or completed successfully).
     *  Returns false if complete but computed hash doesn't match (discards partial). */
    [[nodiscard]] bool PartialTryFinalize(NodeId nodeid);

    /** Get missing positions for a partial, or nullopt if no partial exists. */
    std::optional<std::vector<int32_t>> GetPartialMissing(NodeId nodeid, const uint256& hash) const;

    /** Clean up all template state for a peer (partial + cache). */
    void ForgetPeer(NodeId nodeid);

    /** Expire completed peer templates older than cutoff. */
    void TrimPeerTemplates(NodeClock::time_point cutoff);

    /** Return the next peer-template tx ready for mempool validation, or nullptr.
     *  Advances the peer's m_last_validated_idx, skipping txs not yet ready
     *  and txs already in the mempool.
     *  If non-null, sets pos_out and total_out for progress reporting. */
    CTransactionRef GetNextTemplateTx(NodeId nodeid, NodeClock::time_point now,
                                      const CTxMemPool& mempool,
                                      size_t& pos_out, size_t& total_out);

    /** Update next_mempool_check for a tx in the shared pool.
     *  No-op if the tx has been evicted. */
    void BumpMempoolCheck(const Wtxid& wtxid, NodeClock::time_point next);

    /** Get template manager statistics. */
    TemplateInfo GetInfo() const
    {
        TemplateInfo stats;
        stats.num_templates = m_templates.size();
        stats.max_templates = MAX_TEMPLATES;
        stats.pool_size = m_pool.size();
        stats.pool_weight = m_pool_weight;
        if (!m_templates.empty()) {
            stats.latest_tx_count = m_templates.back().m_txs.size();
            stats.latest_weight = m_templates.back().m_weight;
        }
        stats.update_interval = std::chrono::duration_cast<std::chrono::seconds>(TEMPLATE_UPDATE_INTERVAL);
        stats.next_update = m_next_update;
        stats.num_peer_templates = m_peer_templates.size();
        stats.num_partial_peer_templates = m_partial_peer_templates.size();
        return stats;
    }
};

} // namespace node

#endif // BITCOIN_NODE_TEMPLATEMAN_H
