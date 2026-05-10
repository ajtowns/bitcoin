// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_TEMPLATEMAN_H
#define BITCOIN_NODE_TEMPLATEMAN_H

#include <crypto/siphash.h>
#include <primitives/transaction.h>
#include <random.h>
#include <serialize.h>
#include <uint256.h>
#include <util/bitset.h>
#include <util/hasher.h>
#include <util/time.h>

#include <array>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

class CBlockIndex;
class CTxMemPool;
class ExtraTransactions;
class GenTxid;
typedef int64_t NodeId;

namespace node {

/** Number of buckets; the low bits of a shortid select its bucket. */
static constexpr int TOTAL_BUCKETS = 32;

/** Per-bucket sketch capacity. */
static constexpr int SKETCH_CAPACITY = 64;

/** A mask with one bit per bucket. */
using BucketMask = BitSet<TOTAL_BUCKETS>;

/** A mask over sketch groups at a given round; only the low bits are meaningful,
 *  with fewer bits used at earlier rounds. */
class GroupMask : public BitSet<TOTAL_BUCKETS>
{
public:
    GroupMask() = default;
    GroupMask(const BitSet<TOTAL_BUCKETS>& bs) : BitSet<TOTAL_BUCKETS>{bs} { }

    /** Restrict to the valid group indices for wire rounds 1-4 (bits 0..4<<(round-1)-1). */
    void LimitToRound(int round) { *this &= BitSet<TOTAL_BUCKETS>::Fill(4 << (round - 1)); }
};

/** How long to keep local templates before expiry. */
static constexpr auto LOCAL_TEMPLATE_EXPIRY{std::chrono::seconds{300}};

/** How long to keep completed peer templates before expiry. */
static constexpr auto PEER_TEMPLATE_EXPIRY{std::chrono::seconds{180}};

/** Average interval between local template generation cycles. */
static constexpr auto TEMPLATE_GENERATE_INTERVAL{std::chrono::seconds{30}};

/** Average interval between gettmplt requests to each peer. */
static constexpr auto TEMPLATE_REQUEST_INTERVAL{std::chrono::minutes{2}};

/** Maximum number of inbound peers to actively request templates from. */
static constexpr int MAX_INBOUND_TEMPLATE_PEERS{10};

/** Average number of request cycles before rotating out an active inbound. */
static constexpr int INBOUND_TEMPLATE_ROTATION_FREQ{8};

/** Skip transactions that entered the mempool this recently (prefer relaying txs normally) */
static constexpr std::chrono::seconds MIN_TEMPLATE_TX_AGE{10};

/** Template weight limit (larger than consensus to capture more txs). */
static constexpr unsigned int MAX_TEMPLATE_WEIGHT{8000000};

/** Entry in the shared template tx pool. Ordered by wtxid. */
struct TemplateTx {
    CTransactionRef tx;
    int32_t weight{0};                 //!< cached GetTransactionWeight result
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

class TemplateTxVec {
private:
    friend class TemplateManager;
    std::vector<TemplateTxRef> values;

public:
    TemplateTxVec() = default;
    TemplateTxVec(TemplateTxVec&& other) { values.swap(other.values); }
    TemplateTxVec& operator=(TemplateTxVec&& other)
    {
        Assume(values.empty());
        values.swap(other.values);
        return *this;
    }

    void reserve(size_t cap) { values.reserve(cap); }
    bool empty() const { return values.empty(); }
    size_t size() const { return values.size(); }
    const TemplateTxRef& operator[](size_t i) const { return values[i]; }

    auto begin() const { return values.begin(); }
    auto end() const { return values.end(); }

    // Used by tests
    void push_back_placeholder(const TemplateTxSet& pool) { values.push_back(pool.end()); }
    void clear_placeholders(const TemplateTxSet& pool) {
        std::erase_if(values, [&pool](const TemplateTxRef& v) { return v == pool.end(); });
    }

    ~TemplateTxVec() { Assume(empty()); }
};

class Template {
public:
    TemplateTxVec m_txs;    //!< ordered tx list
    const CBlockIndex* m_tip{nullptr};   //!< chain tip this template targets
    uint256 m_hash;                      //!< SHA256(tip_hash || wtxid1 || wtxid2 || ...) in m_txs order
    int64_t m_weight{0};                 //!< total transaction weight

    /** Compute template hash: SHA256 of tip hash (if set) then concatenated wtxids. */
    uint256 ComputeHash() const;
};

/** Computes 46-bit short IDs for template transactions.
 *  Initialized from (tip_hash, nonce), reused across all lookups. */
class ShortIDHasher
{
    PresaltedSipHasher m_hasher;

public:
    ShortIDHasher(const uint256& tip_hash, uint64_t nonce);

    /** Return a 46-bit short ID in [1, 2^46-1]. */
    uint64_t GetShortID(const Wtxid& wtxid) const;
};

/** A locally-generated block template for the sendtemplate protocol. */
class LocalTemplate : public Template {
public:
    /* m_txs is ordered by shortid, based on m_nonce and m_tip */

    NodeClock::time_point m_time; //!< generation time
    uint64_t m_nonce;             //!< template-level nonce

    /** A serialized sketch in wire format. */
    struct Sketch {
        uint32_t elements;              //!< number of elements in this sketch
        std::vector<unsigned char> ser; //!< serialized sketch bytes

        SERIALIZE_METHODS(Sketch, obj) { READWRITE(obj.elements, obj.ser); }
    };

    /** Pre-computed sketches at four levels of granularity, stored flat.
     *  slots 0..3   -- 4 stride-4 groups (round 0; each group covers 8 buckets)
     *  slots 4..7   -- 4 stride-8 groups (round 1; receiver XORs into slots 0..3 → 8 groups of 4)
     *  slots 8..15  -- 8 stride-16 groups (round 2; receiver XORs into slots 0..7 → 16 groups of 2)
     *  slots 16..31 -- 16 individual buckets (round 3; receiver XORs into slots 0..15 → 32 groups of 1)
     *
     *  Caller filters by mask before sending if not all sketches in a round are needed. */
    std::array<Sketch, TOTAL_BUCKETS> sketches;

    /** All short IDs; in parallel order to m_txs */
    std::vector<uint64_t> shortids;

    /** Compute and store all sketch levels from shortids. Call after shortids is populated. */
    void GenerateSketches();

    /** Return the sketches for a wire round (0..3). Returns empty span for out-of-range round.
     *  Round 0 and 1 each have 4 sketches; rounds 2 and 3 have 8 and 16 respectively.
     *  Formula: count = 4<<(round?round-1:0), offset = round?count:0. */
    std::span<const Sketch> GetSketches(int round) const
    {
        if (round < 0 || round > 3) return {};
        int count = 4 << (round ? round - 1 : 0);
        return std::span{sketches}.subspan(round ? count : 0, count);
    }

    /** GR-encode shortids for wire: for each group in mask, skip the first SKETCH_CAPACITY
     *  shortids (covered by sketch) and encode the rest.
     *  At round R (1-4), the group index is the low (R+1) bits of the bucket index.
     *  Format: uint32_t(N) + P + GR-encoded gaps over sorted 46-bit shortids. */
    std::vector<uint8_t> GetShortIdBytes(int round, GroupMask mask) const;

    /** Retained-tx positions from a basis template to a new template, Golomb-Rice encoded.
     *  Format: compact_size(n) + P + GR-encoded gaps between retained positions
     *  (in basis shortid order). Empty vector means no txs retained. */
    using Delta = std::vector<uint8_t>;

    /** Lazily-computed retained-tx encodings keyed by basis hash. */
    std::unordered_map<uint256, Delta, SaltedUint256Hasher> m_deltas;

    /** Get (or compute) the GR-encoded retained-tx positions from basis to this template. */
    const Delta& GetDelta(const Template& basis);
};

/** Bitset-based tracking of template positions.
 *
 *  Positions are stored as a vector of bitsets (each covering 1024 positions).
 */
class TemplateTxnsSelection
{
public:
    static constexpr unsigned CHUNK_SIZE{1024};
    std::vector<BitSet<CHUNK_SIZE>> m_positions;

    virtual ~TemplateTxnsSelection() = default;

    size_t Count() const;
    bool empty() const;

    /** Set position p, extending m_positions with empty chunks as needed. */
    void Add(uint32_t p);

    /** Clear position p. */
    void Remove(uint32_t p);

    // Golomb-Rice encode positions: compact_size(n) + P + GR-encoded gaps, or empty if none.
    std::vector<uint8_t> GREncode() const;

    // Golomb-Rice decode; opposite of GREncode
    void GRDecode(std::span<const uint8_t> grenc);

    /** Release all state and free memory. */
    virtual void Reset()
    {
        std::vector<BitSet<CHUNK_SIZE>>{}.swap(m_positions);
    }

    template <typename Stream>
    void Serialize(Stream& s) const { s << GREncode(); }

    template <typename Stream>
    void Deserialize(Stream& s)
    {
        std::vector<uint8_t> v;
        s >> v;
        GRDecode(v);
    }
};

/** Provider side: ProcessMessage populates via Queue(); SendMessages drains
 *  via GetNextChunk().
 */
class RequestedTemplateTxns : public TemplateTxnsSelection
{
    uint256 m_template_hash;
public:
    const uint256& template_hash() const { return m_template_hash; }

    void Reset() override
    {
        TemplateTxnsSelection::Reset();
        m_template_hash.SetNull();
    }

    /** Populate from GR-encoded positions (compact_size(n)+P+GR-gaps). Replaces any prior queue.
     *  Returns false (and resets) if the encoding is invalid or any position is out of range. */
    [[nodiscard]] bool Queue(const uint256& hash, const LocalTemplate& tmpl, std::span<const uint8_t> grenc);

    /** Drain up to max_bytes of transactions, resolving positions via tmpl.
     *  Returns the collected transactions. Clears state when fully drained. */
    std::vector<CTransactionRef> GetNextChunk(const LocalTemplate& tmpl, size_t max_bytes);
};

/** Result of submitting a peer-template tx to ATMP. */
enum class TemplateATMPResult {
    ACCEPTED,             //!< VALID
    ALREADY_IN_MEMPOOL,   //!< MEMPOOL_ENTRY or DIFFERENT_WITNESS
    CONFLICT,             //!< TX_CONFLICT
    MISSING_INPUTS,       //!< TX_MISSING_INPUTS
    RECONSIDERABLE,       //!< TX_RECONSIDERABLE -- 1p1c candidate
    PREMATURE_SPEND,      //!< TX_PREMATURE_SPEND
    UNACCEPTABLE,         //!< consensus/policy failures -- permanent reject
};

const char* TemplateATMPResultString(TemplateATMPResult result);

/** Entry in PeerTemplate::m_pending (reverse topo order; pop_back for topo order). */
struct TxPendingATMP {
    uint32_t pos;
    uint32_t nchildren;
};

/** A parent tx that failed as RECONSIDERABLE, stashed for 1p1c attempts with its children. */
struct PackageCandidate {
    CTransactionRef tx;
    uint32_t remaining_children;
};

/** A completed, hash-verified template received from a peer. */
class PeerTemplate : public Template {
public:
    /* m_txs is ordered by shortid, calculated at construction time */

    NodeId m_nodeid; //!< peer that sent us this template
    NodeClock::time_point m_time; //!< received time

    /** Reverse-topo-ordered work queue; pop_back() yields next tx to validate. */
    mutable std::vector<TxPendingATMP> m_pending;

    /** Parent txs that failed as RECONSIDERABLE, keyed by txid for 1p1c lookup. */
    mutable std::unordered_map<Txid, PackageCandidate, SaltedTxidHasher> m_package_candidates;

    /** Build m_pending via reverse Kahn's algorithm. Called once on template completion. */
    void TopoSort();

    /** Find a 1p1c package parent for this tx, then decrement remaining_children
     *  for all parent candidates (erasing when zero).
     *  Returns {true, parent} if usable (parent may be nullptr if no candidate),
     *  or {false, nullptr} if multiple candidates found (1p1c doesn't apply). */
    std::pair<bool, CTransactionRef> ConsumeParentCandidates(const CTransaction& tx) const;

    /** Stash a tx as a 1p1c package candidate for its children. */
    void StashPackageCandidate(CTransactionRef tx, uint32_t nchildren) const;
};

/** Receiver-side sketch reconciliation state for a peer template request.
 *
 *  Maintains three parallel arrays of TOTAL_BUCKETS Minisketch objects at the current round
 *  level (4 → 8 → 16 → 32 groups): basis, local, and provider.  At each round
 *  the groups are split in parallel using the received provider odd-child sketches.
 *  TryDecodeGroups() attempts ((basis+local)^provider) then (basis^provider) for
 *  each unresolved group, early-exiting per group on first success.
 */
class PeerTemplateSketch : public Template {
public:
    /* m_txs is constructed from the basis txs followed by local txs
     *  [0 .. m_basis_count-1]: from retained basis positions
     *  [m_basis_count .. end]:  from local pool scan (excl. basis)
     * ordering of txs is otherwise arbitrary
     */
    size_t m_basis_count{0};

    uint64_t m_nonce{0};  //!< peer's nonce

    /** Shortids parallel to m_txs. */
    std::vector<uint64_t> m_shortids;

    /** Bitmask: bit b set once bucket b is reconciled. */
    BucketMask m_bucket_resolved;

    /** Bitmask: bucket resolved via basis-only sketch decode.
     *  decoded_shortids for these buckets = provider \ basis. */
    BucketMask m_decoded_by_basis;

    /** Bitmask: bucket resolved via shortid fallback (provided + decoded).
     *  Provider set = provided_shortids ∪ decoded_shortids for these buckets. */
    BucketMask m_has_provided;

    /** Decoded shortids from sketch decode (≤64 per sketch). */
    std::vector<uint64_t> m_decoded_shortids;

    /** Explicitly provided shortids (from shortid fallback). */
    std::vector<uint64_t> m_provided_shortids;

    /** Current sketch split level: sketches are partitioned into 2^m_sketch_level groups.
     *  Set to 0 after Init, updated to `round` after PrepareRound(round). During
     *  ProcessShortidFallback at the start of Process(round), equals round-1. */
    int m_sketch_level{-1};

    PeerTemplateSketch();
    ~PeerTemplateSketch();
    PeerTemplateSketch(PeerTemplateSketch&&) = default;
    PeerTemplateSketch& operator=(PeerTemplateSketch&&) = default;

    struct ProcessResult {
        bool resolved;          //!< all TOTAL_BUCKETS buckets reconciled
        GroupMask shortidmask;  //!< unresolved groups to request shortids for
        GroupMask sketchmask;   //!< unresolved groups to request sketches for
    };

    /** Initialise sketch reconciliation.
     *  txs[0..basis_count) are basis txs, txs[basis_count..] are local txs.
     *  shortids is parallel to txs.
     *  May throw on malformed sketch data. */
    ProcessResult Init(TemplateTxVec&& txs,
                       std::vector<uint64_t>&& shortids,
                       size_t basis_count,
                       std::span<const LocalTemplate::Sketch> combined_sketches);

    /** Process incoming data for rounds 1-4.
     *  shortidmask_sent: the shortidmask field from the gettmplt we sent (groups we requested shortids for).
     *  sketchmask_sent: the sketchmask field from the gettmplt we sent (groups we requested sketches for).
     *  May throw on malformed shortid/sketch data. */
    ProcessResult Process(int round, GroupMask shortidmask_sent, GroupMask sketchmask_sent,
                          std::span<const uint8_t> shortid_bytes,
                          std::span<const LocalTemplate::Sketch> sketches);

private:
    struct Sketches;
    std::unique_ptr<Sketches> m_sketches;

    /** For each unresolved group at the current level, try (basis^provider)
     *  then ((basis+local)^provider), early-exiting per group on first success.
     *  Returns true when all buckets are resolved. */
    bool TryDecodeGroups();

    /** Round-4 shortid fallback: parse shortid_bytes, diff against our m_shortids. */
    void ProcessShortidFallback(std::span<const uint8_t> shortid_bytes, GroupMask shortidmask);

    /** Once all buckets are resolved, update m_shortids to reflect the provider's set.
     *  Local shortids absent from the provider are zeroed; provider-only shortids are appended.
     *  After this call, the non-zero entries of m_shortids equal the provider's shortid set. */
    void FinalizeShortids();
};

/** Receiver-side reconstruction state after sketch reconciliation completes.
 *
 *  m_txs holds the full peer template in position (shortid-sorted) order.
 *  Positions that couldn't be matched locally are pool.end() until filled
 *  by incoming tmplttxn data.
 */
class PeerTemplatePartial : public Template {
public:
    /* m_txs ordered by shortid, with holes (nullptr) for missing txs */

    TemplateTxnsSelection m_missing; //!< bitset of unfilled positions
    size_t m_filled{0};              //!< number of positions filled so far

    /** Short ID info for local fill, cleared after use. */
    struct ShortIDInfo {
        uint64_t nonce;
        std::vector<uint64_t> missing_shortids; //!< parallel to m_missing positions
    };
    std::unique_ptr<ShortIDInfo> m_shortid_info;

    /** Check whether all positions are filled and the hash matches.
     *  Returns true on hash match (ready to promote to PeerTemplate). */
    bool CompletedSuccessfully() const;
};

struct TemplateInfo {
    size_t num_templates{0};
    size_t pool_size{0};
    int64_t pool_weight{0};
    size_t latest_tx_count{0};
    int64_t latest_weight{0};
    std::chrono::seconds generate_interval{};
    NodeClock::time_point next_update{};
    size_t peer_templates{0};
    std::map<int, std::vector<NodeId>> pending_peer_templates; //!< round (0=waiting, 1-4=sketch, 5=partial) -> nodeids
};

/**
 * Manages block templates for the gettmplt protocol
 *
 * Maintains a shared tx pool (refcounted) across all templates,
 * and provides provider-side template generation and sketch encoding.
 */
class TemplateManager
{
public:
    explicit TemplateManager(bool deterministic = false) : m_rng{deterministic} {}

    ~TemplateManager();

    enum class TmpltState { FAILED, UNRESOLVED, NEEDS_TXS, DONE };

    struct TmpltResult {
        TmpltState state;
        uint256 hash;                    //!< template hash
        GroupMask shortidmask, sketchmask; //!< only meaningful when state == UNRESOLVED
    };

    /** Return a jittered time point uniformly distributed in [now + avg/2, now + 3*avg/2). */
    NodeClock::time_point Jitter(NodeClock::time_point now, std::chrono::seconds avg)
    {
        return m_rng.rand_uniform_delay(now + avg / 2, avg);
    }

private:
    FastRandomContext m_rng;

    TemplateTxSet m_pool;

    /**
     * Vector of (wtxid, iterator) pairs for cache-local linear scans
     * of all transactions in m_pool.
     * The inline wtxid avoids dereferencing the set node during scans,
     * so that use in compact block reconstruction is fast.
     */
    std::vector<std::pair<Wtxid, TemplateTxRef>> m_scannable_txns;

    int64_t m_pool_weight{0};            //!< total weight of all txs in m_pool

    /** Locally generated templates */
    std::deque<LocalTemplate> m_templates;

    /** Next time to attempt template generation; min() triggers immediately. */
    NodeClock::time_point m_next_gen{NodeClock::time_point::min()};

    /** Per-peer reconciliation state.
     *  monostate = gettmplt n=0 sent, awaiting tmplt n=0.
     *  PeerTemplateSketch = reconciling (rounds 1-4).
     *  PeerTemplatePartial = filling missing txs via tmplttxn. */
    using PeerReconcileMap = std::unordered_map<NodeId, std::variant<std::monostate, PeerTemplateSketch, PeerTemplatePartial>>;
    PeerReconcileMap m_peer_reconcile;

    /** Completed peer templates (FIFO). */
    std::deque<PeerTemplate> m_peer_templates;

    /** Most recent completed template per peer (pointer into m_peer_templates). */
    std::unordered_map<NodeId, PeerTemplate*> m_peer_template_cache;

    /** Replace a peer's reconciliation state, releasing pool refs from the old value. */
    template <typename T>
    PeerReconcileMap::iterator SetPeerReconcile(NodeId nodeid, T&& new_value);

    /** Handle a sketch round result: if resolved, transition to partial/complete;
     *  if not, store masks and return UNRESOLVED.
     *  Iterator must point to a PeerTemplateSketch entry. May erase it. */
    TmpltResult CompleteSketchRound(PeerReconcileMap::iterator it,
                                    const PeerTemplateSketch::ProcessResult& pr,
                                    NodeClock::time_point now);

    /** Find transaction in the pool, adding if necessary. Bumps refcount. */
    TemplateTxRef AddTx(CTransactionRef tx);

    /** Find transactions in the pool, adding if necessary. Bumps refcounts. */
    TemplateTxVec AddTxs(std::span<CTransactionRef> txs);

    /** Decrement refcount and erase tx with zero refs. */
    void RemoveTx(TemplateTxRef ref);

    /** Decrement refcounts and erase txs with zero refs. */
    void RemoveTxs(TemplateTxVec&& vec);

    /** Fill the next missing positions in partial using the provided txrefs (in position order).
     *  Returns true if all positions are now filled. */
    bool FillPartialTxs(PeerTemplatePartial& partial, TemplateTxVec&& refs);

public:
    /** Check if it's time to generate a template. Updates the timer if so.
     *  Returns nullopt if not yet time, true if first template, false otherwise. */
    std::optional<bool> ShouldGenerate(NodeClock::time_point now);

    /**
     * Generate a new template from block transactions (sans coinbase).
     * Assigns a random nonce, computes template hash, sorts m_txs by shortid,
     * and adds txs to the shared pool. Returns template hash.
     */
    uint256 GenerateTemplate(NodeClock::time_point now,
                             const CBlockIndex* tip, std::span<CTransactionRef> txs);

    /** Trim expired local and peer templates. */
    void TrimTemplates(NodeClock::time_point now);

    /** Look up a template by its hash. */
    const LocalTemplate* GetLocalTemplate(const uint256& hash) const;

    struct LocalTemplateAndDelta
    {
        const LocalTemplate* tmpl; // nullptr if no local templates available
        uint256 basis_hash; // ZERO if basis not found
        const LocalTemplate::Delta* basis_delta; // nullptr if basis not found
    };

    /** Request parameters for GetRequestedTemplate. */
    struct Req {
        NodeClock::time_point request_time;
        uint256 basis_hash;
    };

    /** Get the most recent template (if newer than request_time) and its delta from the given basis.
     *  Returns nullptr tmpl if no templates exist or none is newer than request_time. */
    LocalTemplateAndDelta GetRequestedTemplate(const Req& req);

    /** Cache-local (wtxid, iter) vector for compact block reconstruction. */
    const auto& GetScannableTxns() const { return m_scannable_txns; }

    /** Number of transactions in the shared pool. */
    size_t PoolSize() const { return m_pool.size(); }

    /** Whether we have generated at least one local template (needed before requesting peer templates). */
    bool HaveLocalTemplate() const { return !m_templates.empty(); }

    TemplateInfo GetInfo() const;

    /** Validate internal invariants. Asserts on failure. */
    void Check();

    // -- Receiver-side methods (called from net_processing) --

    /** Mark that we've sent gettmplt n=0 and are awaiting the response.
     *  Releases any in-progress reconciliation state for this peer. */
    void WaitingForPeerSketch(NodeId nodeid);

    /** Start a new peer sketch from a round-0 tmplt message.
     *  Scans mempool+pool for matching txs, initialises PeerTemplateSketch.
     *  Returns UNRESOLVED (with masks for gettmplt n=1), NEEDS_TXS, or DONE. */
    TmpltResult InitPeerSketch(NodeId nodeid, const CBlockIndex* tip, uint256 templatehash,
                               uint64_t nonce, uint256 basis_hash,
                               std::span<const uint8_t> basis_delta,
                               std::span<const LocalTemplate::Sketch> sketches,
                               NodeClock::time_point now);

    /** Feed round 1-4 data into an existing peer sketch.
     *  shortidmask/sketchmask are parsed from the peer's tmplt message; must partition
     *  unresolved groups at the current level (no overlap, full coverage).
     *  Returns UNRESOLVED (with masks for the next round), NEEDS_TXS, DONE, or ERROR. */
    TmpltResult UpdatePeerSketch(NodeId nodeid, uint256 templatehash, int round,
                                 GroupMask shortidmask, GroupMask sketchmask,
                                 std::span<const uint8_t> shortid_bytes,
                                 std::span<const LocalTemplate::Sketch> sketches,
                                 NodeClock::time_point now);

    /** Feed incoming tmplttxn transactions into a PeerTemplatePartial.
     *  On completion, verifies hash and promotes to PeerTemplate.
     *  Returns {ERROR, 0} on unexpected state or hash mismatch,
     *  {NEEDS_TXS, 0} if more data is needed, or {DONE, ntxs} on success. */
    std::pair<TmpltState, uint32_t> FillPeerPartial(NodeId nodeid, const uint256& hash, std::vector<CTransactionRef> txs, NodeClock::time_point now);

    struct LocalFillResult {
        size_t still_missing;  //!< positions still unfilled after local scan
        size_t from_templates; //!< matched from template tx pool (TemplateTxRef)
        size_t from_txns;      //!< matched from mempool or extra txns (CTransactionRef)
        size_t collisions;     //!< short ID collisions (left unfilled)
        bool oversize{false};  //!< estimated weight exceeds MAX_TEMPLATE_WEIGHT
    };

    /** Try to fill missing partial positions from local sources (template pool,
     *  mempool, extra txns). Consumes and clears m_shortid_info. */
    LocalFillResult FillPeerPartialLocally(NodeId nodeid, const CTxMemPool& mempool, ExtraTransactions& extra_txns);

    /** GR-encode the current missing positions for a peer's partial template. */
    std::vector<uint8_t> GetPeerPartialMissingGR(NodeId nodeid);

    /** Return the hash of the most recent completed template from this peer,
     *  for use as a basis hint in the next gettmplt n=0. */
    uint256 GetLastPeerTemplateHash(NodeId nodeid);

    /** Clean up all state for a disconnected peer. */
    void ForgetPeer(NodeId nodeid);

    struct NextTemplateTx {
        CTransactionRef tx;
        CTransactionRef package_parent;  //!< non-null if 1p1c opportunity
        size_t pos{0};
        size_t total{0};
        uint32_t nchildren{0};           //!< passed back to ReportATMPResult
        explicit operator bool() const { return tx != nullptr; }
    };

    /** Return the next peer-template tx ready for mempool validation.
     *  Pops from m_pending (topo order), skipping txs not yet ready,
     *  txs already in the mempool, and txs confirmed in a recent block.
     *  Checks package candidates for 1p1c opportunity before returning.
     *  @param recent_block_txs  if non-null, txs from the most recent block (for stale templates) */
    NextTemplateTx GetNextTemplateTx(NodeId nodeid, NodeClock::time_point now,
                                     const CTxMemPool& mempool,
                                     const uint256& active_tip_hash,
                                     const std::map<GenTxid, CTransactionRef>* recent_block_txs);

    /** Report ATMP result for a peer-template tx. Updates retry timing and
     *  stashes RECONSIDERABLE parents for 1p1c attempts with their children. */
    void ReportATMPResult(NodeId nodeid, const CTransactionRef& tx,
                          NodeClock::time_point now,
                          TemplateATMPResult result, uint32_t nchildren);

    /** Transition a fully-resolved PeerTemplateSketch to a PeerTemplatePartial.
     *  Releases pool refs for local txs absent from the peer's template.
     *  Returns nullopt on shortid collision. */
    std::optional<PeerTemplatePartial> MakePeerTemplatePartial(PeerTemplateSketch&& sketch);
};

} // namespace node

#endif // BITCOIN_NODE_TEMPLATEMAN_H
