// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_TEMPLATEMAN_H
#define BITCOIN_NODE_TEMPLATEMAN_H

#include <crypto/siphash.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>
#include <util/bitset.h>
#include <util/hasher.h>
#include <util/time.h>

#include <array>
#include <cstdint>
#include <deque>
#include <set>
#include <span>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

class CBlockIndex;
class FastRandomContext;

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

/** How frequently to update templates for compact block reconstruction. */
static constexpr auto TEMPLATE_UPDATE_INTERVAL{std::chrono::seconds{30}};

/** Skip transactions that entered the mempool this recently (prefer relaying txs normally) */
static constexpr std::chrono::seconds MIN_TEMPLATE_TX_AGE{10};

/** Template weight limit (larger than consensus to capture more txs). */
static constexpr unsigned int MAX_TEMPLATE_WEIGHT{8000000};

/** Maximum number of transactions in a template (minimum tx weight = 60 bytes * 4 = 240). */
static constexpr unsigned int MAX_TEMPLATE_TXS{MAX_TEMPLATE_WEIGHT / 240};

/** Entry in the shared template tx pool. Ordered by wtxid. */
struct TemplateTx {
    CTransactionRef tx;
    int32_t weight{0};                 //!< cached GetTransactionWeight result
    mutable uint32_t num_templates{0}; //!< refcount: number of templates referencing this tx
    mutable size_t scannable_idx{0};   //!< index into m_scannable_txns

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

    /** All short IDs; in parallel order to m_txs (which should be sorted by shortid). */
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
protected:
    static constexpr unsigned CHUNK_SIZE{1024};
    std::vector<BitSet<CHUNK_SIZE>> m_positions;

public:
    virtual ~TemplateTxnsSelection() = default;

    size_t Count() const;
    bool empty() const;

    /** Set position p, extending m_positions with empty chunks as needed. */
    void Add(uint32_t p);

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

/**
 * Manages block templates for the gettmplt protocol
 *
 * Maintains a shared tx pool (refcounted) across all templates,
 * and provides provider-side template generation and sketch encoding.
 */
class TemplateManager
{
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

    /** Find transaction in the pool, adding if necessary. Bumps refcount. */
    TemplateTxRef AddTx(CTransactionRef tx);

    /** Find transactions in the pool, adding if necessary. Bumps refcounts. */
    std::vector<TemplateTxRef> AddTxs(std::span<CTransactionRef> txs);

    /** Decrement refcounts and erase txs with zero refs. */
    void RemoveTxs(std::vector<TemplateTxRef>&& vec);

public:
    /** Check if it's time to generate a template. Updates the timer if so.
     *  Returns nullopt if not yet time, true if first template, false otherwise. */
    std::optional<bool> ShouldGenerate(NodeClock::time_point now);

    /**
     * Generate a new template from block transactions (sans coinbase).
     * Assigns a random nonce, computes template hash, sorts m_txs by shortid,
     * and adds txs to the shared pool. Returns template hash.
     */
    uint256 GenerateTemplate(NodeClock::time_point now, FastRandomContext& rng,
                          const CBlockIndex* tip, std::span<CTransactionRef> txs);

    /** Trim local templates older than cutoff. */
    void TrimLocalTemplates(NodeClock::time_point cutoff);

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
};

} // namespace node

#endif // BITCOIN_NODE_TEMPLATEMAN_H
