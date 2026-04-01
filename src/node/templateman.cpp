// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/templateman.h>
#include <node/minisketchwrapper.h>

#include <blockencodings.h>
#include <chain.h>
#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <primitives/transaction.h>
#include <primitives/transaction_identifier.h>
#include <random.h>
#include <serialize.h>
#include <streams.h>
#include <txmempool.h>

#include <util/golombrice.h>
#include <util/overloaded.h>

#include <algorithm>
#include <bit>
#include <type_traits>
#include <unordered_set>
#include <variant>

namespace {
/** Average recheck interval for txs already accepted into the mempool or confirmed in a block. */
static constexpr auto ATMP_RECHECK_INTERVAL{std::chrono::seconds{60}};

/** Average retry interval for transient ATMP failures (missing inputs, conflict, reconsiderable). */
static constexpr auto ATMP_RETRY_INTERVAL{std::chrono::seconds{120}};

/** Average retry interval for premature-spend ATMP failures. */
static constexpr auto ATMP_RETRY_SLOW_INTERVAL{std::chrono::seconds{1200}};
} // namespace

namespace node {

/** Minimum transaction weight (60 bytes * 4 = 240 wu). */
static constexpr int64_t MIN_TRANSACTION_WEIGHT{240};

/** Maximum number of transactions in a template. */
static constexpr unsigned int MAX_TEMPLATE_TXS{MAX_TEMPLATE_WEIGHT / MIN_TRANSACTION_WEIGHT};

const char* TemplateATMPResultString(TemplateATMPResult result)
{
    using enum TemplateATMPResult;
    switch (result) {
    case ACCEPTED:           return "Accepted";
    case ALREADY_IN_MEMPOOL: return "Rejected[already-in-mempool]";
    case CONFLICT:           return "Rejected[conflict]";
    case MISSING_INPUTS:     return "Rejected[missing-inputs]";
    case RECONSIDERABLE:     return "Rejected[reconsiderable]";
    case PREMATURE_SPEND:    return "Rejected[premature-spend]";
    case UNACCEPTABLE:       return "Rejected[unacceptable]";
    } // no default, compiler warns on missing case
    assert(false);
}

static PresaltedSipHasher MakeShortIDHasher(const uint256& template_hash, uint64_t nonce)
{
    DataStream ds{};
    ds << template_hash << nonce;
    uint256 key;
    CSHA256{}.Write(MakeUCharSpan(ds)).Finalize(key.begin());
    return PresaltedSipHasher{key.GetUint64(0), key.GetUint64(1)};
}

ShortIDHasher::ShortIDHasher(const uint256& tip_hash, uint64_t nonce)
    : m_hasher{MakeShortIDHasher(tip_hash, nonce)} {}

uint64_t ShortIDHasher::GetShortID(const Wtxid& wtxid) const
{
    uint64_t h{m_hasher(wtxid.ToUint256())};

    // (h >> 18) gives a 46-bit value;
    //  - if it's 0 then the low-18 bits of h right shifted will be >= h
    //  - if it's 2**46-1 then the low-18 bits of h left shifted will still be < h
    return (h >> 18) + (((h & 0x3ffff) << 46) >= h);
}

uint256 Template::ComputeHash() const
{
    CSHA256 hasher;
    const uint256& tip_hash = (m_tip ? m_tip->GetBlockHash() : uint256::ZERO);
    hasher.Write(MakeUCharSpan(tip_hash));
    for (const auto& it : m_txs) {
        hasher.Write(MakeUCharSpan(it->tx->GetWitnessHash()));
    }
    uint256 hash;
    hasher.Finalize(hash.begin());
    return hash;
}

const LocalTemplate::Delta& LocalTemplate::GetDelta(const Template& basis)
{
    auto [it, inserted] = m_deltas.try_emplace(basis.m_hash);
    if (inserted) {
        // Build pointer set of txs in this template for O(1) lookup.
        // Both templates share the same pool, so pointer identity implies same tx.
        std::unordered_set<const CTransaction*> retained_set;
        retained_set.reserve(m_txs.size());
        for (const auto& ref : m_txs) {
            retained_set.insert(ref->tx.get());
        }

        // Collect retained positions (in basis order) into a TemplateTxnsSelection
        TemplateTxnsSelection sel;
        for (size_t i = 0; i < basis.m_txs.size(); ++i) {
            if (retained_set.count(basis.m_txs[i]->tx.get())) {
                sel.Add(i);
            }
        }
        it->second = sel.GREncode();
    }
    return it->second;
}

std::vector<uint8_t> LocalTemplate::GetShortIdBytes(int round, GroupMask mask) const
{
    // At round R (1-4) the group index is the low (R+1) bits of the shortid (and bucket index).
    // Skip the first SKETCH_CAPACITY shortids per group (covered by sketch); encode the rest.
    // Shortids are globally sorted, so the filtered list is also sorted.
    mask.LimitToRound(round);
    if (mask.None()) return {};

    // Estimate n to compute GR parameter P (shortids are roughly evenly distributed).
    size_t n_estimate = shortids.size() / TOTAL_BUCKETS * mask.Count();
    uint8_t P = static_cast<uint8_t>(std::max(0, 46 - (int)std::bit_width(n_estimate)));

    // Single pass: reserve 4 bytes for n, write P, GR-encode qualifying shortids,
    // then patch the actual count into the first 4 bytes.
    std::vector<uint8_t> result;
    VectorWriter stream{result, 0};
    uint32_t n{0};
    stream << n; // placeholder
    stream << P;
    BitStreamWriter bitwriter{stream};
    std::array<int, TOTAL_BUCKETS> group_count{};
    uint64_t last = 0;
    for (uint64_t sid : shortids) {
        int b = sid & ((4 << (round - 1)) - 1);
        if (!mask[b]) continue;
        if (++group_count[b] <= SKETCH_CAPACITY) continue;
        GolombRiceEncode(bitwriter, P, sid - last - 1);
        last = sid;
        ++n;
    }
    if (n == 0) return {};
    bitwriter.Flush();
    WriteLE32(result.data(), n);
    return result;
}

void LocalTemplate::GenerateSketches()
{
    // Build 32 per-bucket sketches directly into slots 0..31.
    class MS : public Minisketch
    {
    public:
        // Minisketch, but with a default initializer
        MS() : Minisketch{MakeMinisketch46(SKETCH_CAPACITY)} { }
    };
    std::array<MS, TOTAL_BUCKETS> ms;
    std::array<uint32_t, TOTAL_BUCKETS> count{};
    for (uint64_t sid : shortids) {
        int b = sid & (TOTAL_BUCKETS - 1);
        ms[b].Add(sid);
        ++count[b];
    }

    // Merge the sketch tree bottom-up in-place.
    // At each step, merge into the lower half, leaving the upper half unchanged.
    auto merge_level = [&](int n) {
        for (int i = 0; i < n; ++i) {
            ms[i].Merge(ms[i+n]);
            count[i] += count[i + n];
        }
    };

    // slots 16..31 = individual buckets (round 3); merge into 0..15
    merge_level(16);
    // slots 8..15 = stride-16 groups (round 2); merge into 0..7
    merge_level(8);
    // slots 4..7 = stride-8 groups (round 1); merge into 0..3
    merge_level(4);
    // slots 0..3 = stride-4 groups (round 0)

    for (int i = 0; i < TOTAL_BUCKETS; ++i) {
        sketches[i].ser = ms[i].Serialize();
        sketches[i].elements = count[i];
    }
}

TemplateTxRef TemplateManager::AddTx(CTransactionRef tx)
{
    const int32_t w = GetTransactionWeight(*tx);
    auto [it, inserted] = m_pool.insert(TemplateTx{.tx = std::move(tx), .weight = w});
    if (inserted) {
        m_pool_weight += it->weight;
        it->scannable_idx = m_scannable_txns.size();
        m_scannable_txns.emplace_back(it->tx->GetWitnessHash(), it);
    }
    ++it->num_templates;
    return it;
}

std::vector<TemplateTxRef> TemplateManager::AddTxs(std::span<CTransactionRef> txs)
{
    std::vector<TemplateTxRef> refs;
    refs.reserve(txs.size());
    for (auto& tx : txs) {
        refs.push_back(AddTx(std::move(tx)));
    }
    return refs;
}

void TemplateManager::RemoveTxs(std::vector<TemplateTxRef>&& vec)
{
    const auto pool_end = m_pool.end();
    for (auto& it : vec) {
        if (it == pool_end) continue;
        if (--it->num_templates == 0) {
            m_pool_weight -= it->weight;
            // Swap-to-back removal from m_scannable_txns
            size_t idx = it->scannable_idx;
            if (idx != m_scannable_txns.size() - 1) {
                m_scannable_txns[idx] = std::move(m_scannable_txns.back());
                m_scannable_txns[idx].second->scannable_idx = idx;
            }
            m_scannable_txns.pop_back();
            m_pool.erase(it);
        }
    }
}

const LocalTemplate* TemplateManager::GetLocalTemplate(const uint256& hash) const
{
    for (const auto& tmpl : m_templates) {
        if (tmpl.m_hash == hash) return &tmpl;
    }
    return nullptr;
}

std::optional<bool> TemplateManager::ShouldGenerate(NodeClock::time_point now)
{
    if (now < m_next_gen) return std::nullopt;
    m_next_gen = Jitter(now, TEMPLATE_GENERATE_INTERVAL);
    return m_templates.empty();
}

void TemplateManager::TrimTemplates(NodeClock::time_point now)
{
    auto cutoff = now - LOCAL_TEMPLATE_EXPIRY;
    while (!m_templates.empty() && m_templates.front().m_time < cutoff) {
        RemoveTxs(std::move(m_templates.front().m_txs));
        m_templates.pop_front();
    }
    auto peer_cutoff = now - PEER_TEMPLATE_EXPIRY;
    while (!m_peer_templates.empty() && m_peer_templates.front().m_time < peer_cutoff) {
        auto& front = m_peer_templates.front();
        // Only erase cache if it points to this entry (peer may have a newer one).
        auto it = m_peer_template_cache.find(front.m_nodeid);
        if (it != m_peer_template_cache.end() && it->second == &front) {
            m_peer_template_cache.erase(it);
        }
        RemoveTxs(std::move(front.m_txs));
        m_peer_templates.pop_front();
    }
    Check();
}

uint256 TemplateManager::GenerateTemplate(NodeClock::time_point now,
                                        const CBlockIndex* tip, std::span<CTransactionRef> txs)
{
    LocalTemplate tmpl;
    tmpl.m_time = now;
    tmpl.m_tip = tip;
    tmpl.m_nonce = m_rng.rand64();

    // Add txs in fee/priority order from BlockAssembler
    tmpl.m_txs = AddTxs(txs);
    for (const auto& ref : tmpl.m_txs) {
        tmpl.m_weight += ref->weight;
    }

    // Compute shortids and sort m_txs by shortid.
    // Uses (tip_hash, nonce) so the hash can be computed afterwards over the sorted order.
    const uint256& tip_hash = tip ? tip->GetBlockHash() : uint256::ZERO;
    ShortIDHasher hasher(tip_hash, tmpl.m_nonce);

    std::vector<std::pair<uint64_t, TemplateTxRef>> pairs;
    pairs.reserve(tmpl.m_txs.size());
    for (const auto& ref : tmpl.m_txs) {
        pairs.emplace_back(hasher.GetShortID(ref->tx->GetWitnessHash()), ref);
    }
    std::stable_sort(pairs.begin(), pairs.end(), [](const auto& a, const auto& b) {
        return a.first < b.first;
    });
    tmpl.m_txs.clear();
    uint64_t dup_check = std::numeric_limits<uint64_t>::max();
    for (auto& [sid, ref] : pairs) {
        if (sid == dup_check) continue; // duplicates can't by expressed by sketches, so drop them
        dup_check = sid;
        tmpl.shortids.push_back(sid);
        tmpl.m_txs.push_back(ref);
    }

    // Hash over tip_hash then wtxids in shortid order; receiver can verify independently.
    tmpl.m_hash = tmpl.ComputeHash();

    tmpl.GenerateSketches();

    uint256 template_hash = tmpl.m_hash;

    m_templates.push_back(std::move(tmpl));

    return template_hash;
}

TemplateManager::LocalTemplateAndDelta TemplateManager::GetRequestedTemplate(const Req& req)
{
    if (m_templates.empty()) return {nullptr, uint256::ZERO, nullptr};

    LocalTemplate& best = m_templates.back();
    if (best.m_time <= req.request_time) return {nullptr, uint256::ZERO, nullptr};

    const LocalTemplate* basis = req.basis_hash.IsNull() ? nullptr : GetLocalTemplate(req.basis_hash);
    if (!basis) return {&best, uint256::ZERO, nullptr};

    const LocalTemplate::Delta& delta = best.GetDelta(*basis);
    return {&best, req.basis_hash, &delta};
}

void TemplateTxnsSelection::Add(uint32_t p)
{
    size_t chunk_idx = p / CHUNK_SIZE;
    while (m_positions.size() <= chunk_idx) m_positions.emplace_back();
    m_positions[chunk_idx].Set(p % CHUNK_SIZE);
}

void TemplateTxnsSelection::Remove(uint32_t p)
{
    size_t chunk_idx = p / CHUNK_SIZE;
    if (chunk_idx < m_positions.size()) {
        m_positions[chunk_idx].Reset(p % CHUNK_SIZE);
    }
}

size_t TemplateTxnsSelection::Count() const
{
    size_t n = 0;
    for (const auto& chunk : m_positions) n += chunk.Count();
    return n;
}

bool TemplateTxnsSelection::empty() const
{
    for (auto it = m_positions.rbegin(); it != m_positions.rend(); ++it) {
        if (!it->None()) return false;
    }
    return true;
}

std::vector<uint8_t> TemplateTxnsSelection::GREncode() const
{
    size_t n = Count();
    if (n == 0) return {};
    uint8_t P = static_cast<uint8_t>(std::bit_width(m_positions.size() * CHUNK_SIZE / n) - 1);
    std::vector<uint8_t> result;
    VectorWriter stream{result, 0};
    WriteCompactSize(stream, n);
    stream << P;
    BitStreamWriter bitwriter{stream};
    uint64_t last = 0;
    for (size_t chunk_idx = 0; chunk_idx < m_positions.size(); ++chunk_idx) {
        for (unsigned bit : m_positions[chunk_idx]) {
            uint64_t pos = chunk_idx * CHUNK_SIZE + bit;
            GolombRiceEncode(bitwriter, P, pos - last);
            last = pos;
        }
    }
    bitwriter.Flush();
    return result;
}

void TemplateTxnsSelection::GRDecode(std::span<const uint8_t> grenc)
{
    Reset();
    if (grenc.empty()) return;
    SpanReader stream{grenc};
    size_t n = ReadCompactSize(stream);
    uint8_t P;
    stream >> P;
    BitStreamReader bitreader{stream};
    uint64_t pos = 0;
    for (size_t i = 0; i < n; ++i) {
        pos += GolombRiceDecode(bitreader, P);
        if (pos > MAX_TEMPLATE_TXS) throw std::ios_base::failure("GRDecode: position out of range");
        Add(static_cast<uint32_t>(pos));
    }
}

bool RequestedTemplateTxns::Queue(const uint256& hash, const LocalTemplate& tmpl, std::span<const uint8_t> grenc)
{
    Reset();
    try {
        GRDecode(grenc);
    } catch (...) {
        Reset();
        return false;
    }
    // Validate decoded positions are within the template's tx count.
    // Since positions are sorted, only the last set bit in the last chunk needs checking.
    if (!m_positions.empty()) {
        auto& b = m_positions.back();
        if (b.None() || b.Last() + (m_positions.size() - 1) * CHUNK_SIZE >= tmpl.m_txs.size()) {
            Reset();
            return false;
        }
    }
    m_template_hash = hash;
    return true;
}

std::vector<CTransactionRef> RequestedTemplateTxns::GetNextChunk(const LocalTemplate& tmpl, size_t max_bytes)
{
    std::vector<CTransactionRef> txs;
    size_t msg_size = 0;
    bool hit_limit = false;

    for (size_t chunk_idx = 0; chunk_idx < m_positions.size() && !hit_limit; ++chunk_idx) {
        auto& chunk = m_positions[chunk_idx];
        if (chunk.None()) continue;

        for (unsigned bit : chunk) {
            size_t abs_pos = chunk_idx * CHUNK_SIZE + bit;
            if (!Assume(abs_pos < tmpl.m_txs.size())) {
                Reset();
                return {};
            }
            const CTransactionRef& tx = tmpl.m_txs[abs_pos]->tx;
            size_t tx_size = GetSerializeSize(TX_WITH_WITNESS(tx));
            txs.push_back(tx);
            msg_size += tx_size;
            chunk.Reset(bit);
            if (msg_size >= max_bytes) {
                hit_limit = true;
                break;
            }
        }
    }

    // Cleared every bit, so can delete all the chunks
    if (!hit_limit) Reset();

    return txs;
}

struct PeerTemplateSketch::Sketches {
    struct MSC {
        int count{0};
        Minisketch sketch{MakeMinisketch46(SKETCH_CAPACITY)};
        void Add(uint64_t shortid) { sketch.Add(shortid); ++count; }
    };
    using MSCArr = std::array<MSC, TOTAL_BUCKETS>;

    // Slot invariant for all three MSCArr arrays:
    // - After InitialMerge (level=0): slots 0..3 hold the 4 stride-4 combined groups;
    //   slots 4..31 hold stale intermediate merged values used by PrepareRound.
    // - After PrepareRound(r): there are 4<<r active groups in slots 0..(4<<r)-1.
    //   Slot gi = group gi. Slots >= 4<<r hold stale data and must not be read.
    // - All three arrays follow the same slot structure at all times.
    MSCArr m_basis_sketches;   //!< basis shortids only
    MSCArr m_local_sketches;   //!< basis+local shortids (pre-merged so TryDecodeGroups needs one fewer Merge())
    MSCArr m_provider_sketches;

    void InitialMerge()
    {
        auto merge = [&](int i, int j) {
            m_basis_sketches[i].sketch.Merge(m_basis_sketches[j].sketch);
            m_basis_sketches[i].count += m_basis_sketches[j].count;
            m_local_sketches[i].sketch.Merge(m_local_sketches[j].sketch);
            m_local_sketches[i].count += m_local_sketches[j].count;
        };

        // 32 → 16: merge x += x+16 for x in 0..15
        for (int x = 0; x < 16; ++x) merge(x, x + 16);
        // 16 → 8: merge x += x+8 for x in 0..7
        for (int x = 0; x < 8; ++x) merge(x, x + 8);
        // 8 → 4: merge x += x+4 for x in 0..3
        for (int x = 0; x < 4; ++x) merge(x, x + 4);
        // slots 0..3 now hold the 4 stride-4 combined groups
    }

    void ProviderDeser(int round, GroupMask mask, std::span<const LocalTemplate::Sketch> sketches)
    {
        size_t sketch_idx = 0;
        if (round == 0) {
            // Round 0: store 4 sketches into slots 0..3 (mask unused)
            for (int gi = 0; gi < TOTAL_BUCKETS / 8 && sketch_idx < sketches.size(); ++gi) {
                const auto& s = sketches[sketch_idx++];
                m_provider_sketches[gi].sketch.Deserialize(s.ser);
                m_provider_sketches[gi].count = s.elements;
            }
        } else {
            // Round 1..3: for each set bit gi in mask, store into slot n+gi
            // where n = 4 << (round-1) (the new "odd child" slots for this round)
            int n = 4 << (round - 1);
            for (int gi = 0; gi < n && sketch_idx < sketches.size(); ++gi) {
                if (!mask[gi]) continue;
                const auto& s = sketches[sketch_idx++];
                m_provider_sketches[n + gi].sketch.Deserialize(s.ser);
                m_provider_sketches[n + gi].count = s.elements;
            }
        }
    }

    void PrepareRound(int round)
    {
        // n = current number of groups (before splitting)
        // For each x in 0..n-1: XOR parent[x] with odd-child[x+n] to get even-child[x]
        int n = 4 << (round - 1);
        for (int x = 0; x < n; ++x) {
            m_basis_sketches[x].sketch.Merge(m_basis_sketches[x + n].sketch);
            m_basis_sketches[x].count -= m_basis_sketches[x + n].count;
            m_local_sketches[x].sketch.Merge(m_local_sketches[x + n].sketch);
            m_local_sketches[x].count -= m_local_sketches[x + n].count;
            m_provider_sketches[x].sketch.Merge(m_provider_sketches[x + n].sketch);
            m_provider_sketches[x].count -= m_provider_sketches[x + n].count;
        }
    }
};

PeerTemplateSketch::PeerTemplateSketch() = default;
PeerTemplateSketch::~PeerTemplateSketch() = default;

bool PeerTemplateSketch::TryDecodeGroups()
{
    auto& sk = *m_sketches;
    // n = number of active groups at current sketch level
    const int n = 4 << m_sketch_level;
    // stride = n (buckets in group gi are: gi, gi+n, gi+2n, ...)
    for (int gi = 0; gi < n; ++gi) {
        // Check if all buckets in group gi are already resolved
        bool all_resolved = true;
        for (int b = gi; b < TOTAL_BUCKETS; b += n) {
            if (!m_bucket_resolved[b]) { all_resolved = false; break; }
        }
        if (all_resolved) continue;

        int basis_count    = sk.m_basis_sketches[gi].count;
        int local_count    = sk.m_local_sketches[gi].count; // basis+local
        int provider_count = sk.m_provider_sketches[gi].count;

        // Try basis XOR provider (only when diff is small enough to decode).
        // Assumes basis is a subset of provider (guaranteed by the protocol: basis is
        // a previously-sent template that the provider retains). Under this assumption,
        // basis^provider == provider\basis and the feasibility check
        // provider_count - basis_count <= SKETCH_CAPACITY is tight. If the assumption is
        // violated by a misbehaving peer, the sketch may fail to decode or produce wrong
        // diff elements; correctness is recovered by template-hash verification at the
        // PeerTemplatePartial stage.
        if (basis_count + SKETCH_CAPACITY >= provider_count) {
            Minisketch diff = sk.m_basis_sketches[gi].sketch;
            diff.Merge(sk.m_provider_sketches[gi].sketch);
            if (auto decoded = diff.Decode(SKETCH_CAPACITY)) {
                for (uint64_t sid : *decoded) m_decoded_shortids.push_back(sid);
                for (int b = gi; b < TOTAL_BUCKETS; b += n) {
                    m_bucket_resolved.Set(b);
                    m_decoded_by_basis.Set(b);
                }
                continue;
            }
        }

        // Try (basis + local) XOR provider (only when diff is small enough to decode).
        // m_local_sketches holds basis+local pre-merged, so only one Merge() needed here.
        if (std::abs(provider_count - local_count) <= SKETCH_CAPACITY) {
            Minisketch diff = sk.m_local_sketches[gi].sketch;
            diff.Merge(sk.m_provider_sketches[gi].sketch);
            if (auto decoded = diff.Decode(SKETCH_CAPACITY)) {
                for (uint64_t sid : *decoded) m_decoded_shortids.push_back(sid);
                for (int b = gi; b < TOTAL_BUCKETS; b += n) {
                    m_bucket_resolved.Set(b);
                }
                continue;
            }
        }
    }
    return m_bucket_resolved.Count() == TOTAL_BUCKETS;
}

PeerTemplateSketch::ProcessResult PeerTemplateSketch::Init(
    std::vector<TemplateTxRef>&& txs,
    std::vector<uint64_t>&& shortids,
    size_t basis_count,
    std::span<const LocalTemplate::Sketch> combined_sketches)
{
    m_txs = std::move(txs);
    m_shortids = std::move(shortids);
    m_basis_count = basis_count;

    // Build per-bucket sketches
    m_sketches = std::make_unique<Sketches>();
    auto& sk = *m_sketches;
    for (size_t i = 0; i < m_basis_count; ++i) {
        sk.m_basis_sketches[m_shortids[i] & (TOTAL_BUCKETS - 1)].Add(m_shortids[i]);
    }
    for (size_t i = m_basis_count; i < m_shortids.size(); ++i) {
        sk.m_local_sketches[m_shortids[i] & (TOTAL_BUCKETS - 1)].Add(m_shortids[i]);
    }
    if (m_basis_count > 0) {
        // Pre-merge basis into local so m_local_sketches holds basis+local;
        // TryDecodeGroups can then use it directly without an extra Merge().
        for (int b = 0; b < TOTAL_BUCKETS; ++b) {
            sk.m_local_sketches[b].sketch.Merge(sk.m_basis_sketches[b].sketch);
            sk.m_local_sketches[b].count += sk.m_basis_sketches[b].count;
        }
    }
    sk.InitialMerge();

    // Store provider's 4 combined sketches (round 0) into slots 0..3
    sk.ProviderDeser(0, GroupMask{}, combined_sketches);
    m_sketch_level = 0;

    bool resolved = TryDecodeGroups();
    if (resolved) {
        FinalizeShortids();
        return {true, {}, {}};
    }

    // Request sketches for unresolved groups only
    GroupMask unresolved_groups;
    for (int gi = 0; gi < 4; ++gi) {
        for (int b = gi; b < TOTAL_BUCKETS; b += 4) {
            if (!m_bucket_resolved[b]) {
                unresolved_groups.Set(gi);
                break;
            }
        }
    }
    return {false, {}, unresolved_groups};
}

void PeerTemplateSketch::ProcessShortidFallback(std::span<const uint8_t> shortid_bytes,
                                                 GroupMask shortidmask)
{
    // At the start of round r, m_sketch_level = r-1 and sketches are at that granularity.
    // num_groups = 4 << m_sketch_level; group index = low bits of bucket index.
    const int num_groups = 4 << m_sketch_level;

    // Parse the provider's outer shortids (positions SKETCH_CAPACITY+1 per sketch group) into per-group lists.
    std::vector<std::vector<uint64_t>> received(num_groups);
    {
        SpanReader stream{shortid_bytes};
        uint32_t n;
        stream >> n;
        uint8_t P;
        stream >> P;
        BitStreamReader<SpanReader> bitreader{stream};
        uint64_t last = 0;
        for (uint32_t i = 0; i < n; ++i) {
            uint64_t delta = GolombRiceDecode(bitreader, P);
            if (delta >= (1ULL << 46)) return;
            last += delta + 1;
            if (last >= (1ULL << 46)) return;
            int gi = static_cast<int>(last & (num_groups - 1));
            // Include if the group is requested and not fully resolved
            if (!shortidmask[gi]) continue;
            bool group_resolved = true;
            for (int bx = gi; bx < TOTAL_BUCKETS; bx += num_groups) {
                if (!m_bucket_resolved[bx]) { group_resolved = false; break; }
            }
            if (!group_resolved) received[gi].push_back(last);
        }
    }

    // For each unresolved group, XOR provided shortids with provider sketch
    // to recover the inner shortids (≤SKETCH_CAPACITY). Full provider set for
    // this group = provided + decoded inner.
    auto& sk = *m_sketches;
    for (int gi = 0; gi < num_groups; ++gi) {
        // Check if group is already fully resolved
        bool group_resolved = true;
        for (int b = gi; b < TOTAL_BUCKETS; b += num_groups) {
            if (!m_bucket_resolved[b]) { group_resolved = false; break; }
        }
        if (group_resolved) continue;

        auto& recv = received[gi];
        if (recv.empty()) continue;

        // recv XOR provider = inner shortids (outer cancels)
        Minisketch recv_sketch = MakeMinisketch46(SKETCH_CAPACITY);
        for (uint64_t sid : recv) recv_sketch.Add(sid);
        recv_sketch.Merge(sk.m_provider_sketches[gi].sketch);

        if (auto decoded = recv_sketch.Decode(SKETCH_CAPACITY)) {
            for (uint64_t sid : *decoded) m_decoded_shortids.push_back(sid);
            for (uint64_t sid : recv) m_provided_shortids.push_back(sid);
            for (int b = gi; b < TOTAL_BUCKETS; b += num_groups) {
                m_bucket_resolved.Set(b);
                m_has_provided.Set(b);
            }
        }
    }
}

void PeerTemplateSketch::FinalizeShortids()
{
    std::unordered_set<uint64_t> decoded_set(m_decoded_shortids.begin(), m_decoded_shortids.end());
    std::unordered_set<uint64_t> provided_set(m_provided_shortids.begin(), m_provided_shortids.end());
    std::unordered_set<uint64_t> our_set(m_shortids.begin(), m_shortids.end());

    // Discard shortids from local set that didn't turn out to be in the template:
    //  - has_provided: provider = provided ∪ decoded
    //  - decoded_by_basis: provider = basis ∪ decoded
    //  - else (basis+local): provider = basis ∪ (local XOR decoded)
    for (size_t i = m_basis_count; i < m_shortids.size(); ++i) {
        uint64_t sid = m_shortids[i];
        int b = sid & (TOTAL_BUCKETS - 1);
        bool keep_in_template;
        if (m_has_provided[b]) {
            keep_in_template = provided_set.contains(sid) || decoded_set.contains(sid);
        } else if (m_decoded_by_basis[b]) {
            keep_in_template = decoded_set.contains(sid);
        } else {
            keep_in_template = !decoded_set.contains(sid);
        }
        if (!keep_in_template) m_shortids[i] = 0;
    }

    // Append provider shortids we didn't have in our original basis/local set
    for (uint64_t sid : m_decoded_shortids) {
        if (our_set.insert(sid).second) m_shortids.push_back(sid);
    }
    for (uint64_t sid : m_provided_shortids) {
        if (our_set.insert(sid).second) m_shortids.push_back(sid);
    }
}

PeerTemplateSketch::ProcessResult PeerTemplateSketch::Process(
    int round, GroupMask shortidmask_sent, GroupMask sketchmask_sent,
    std::span<const uint8_t> shortid_bytes,
    std::span<const LocalTemplate::Sketch> sketches)
{
    // Try shortid fallback first using sketches already prepared at round m_sketch_level = (round-1).
    // GetShortIdBytes(round, mask) groups shortids at that same granularity.
    if (!shortid_bytes.empty()) {
        ProcessShortidFallback(shortid_bytes, shortidmask_sent);
    }

    if (m_bucket_resolved.Count() != TOTAL_BUCKETS && round >= 1 && round <= 3) {
        // Write provider sketches into their slots, then split all three arrays.
        m_sketches->ProviderDeser(round, sketchmask_sent, sketches);
        m_sketches->PrepareRound(round);
        m_sketch_level = round;
        TryDecodeGroups();
    }

    bool all_resolved = (m_bucket_resolved.Count() == TOTAL_BUCKETS);
    if (all_resolved) FinalizeShortids();

    // Compute unresolved groups at current sketch level
    const int n = 4 << m_sketch_level;
    GroupMask unresolved_groups;
    if (!all_resolved) {
        for (int gi = 0; gi < n; ++gi) {
            for (int b = gi; b < TOTAL_BUCKETS; b += n) {
                if (!m_bucket_resolved[b]) {
                    unresolved_groups.Set(gi);
                    break;
                }
            }
        }
    }

    // Partition unresolved groups: request shortids (fallback) or sketches (continue).
    GroupMask shortidmask;
    if (round >= 3) shortidmask = unresolved_groups;
    GroupMask sketchmask = unresolved_groups - shortidmask;

    return {all_resolved, shortidmask, sketchmask};
}

bool PeerTemplatePartial::Fill(std::vector<TemplateTxRef>&& refs)
{
    auto ref_it = refs.begin();
    for (size_t chunk_idx = 0; chunk_idx < m_missing.m_positions.size() && ref_it != refs.end(); ++chunk_idx) {
        for (unsigned bit : m_missing.m_positions[chunk_idx]) {
            if (ref_it == refs.end()) break;
            uint32_t pos = chunk_idx * TemplateTxnsSelection::CHUNK_SIZE + bit;
            if (!Assume(pos < m_txs.size())) continue;
            m_weight += (*ref_it)->weight;
            m_txs[pos] = *ref_it++;
            m_missing.m_positions[chunk_idx].Reset(bit);
            ++m_filled;
        }
    }
    // Append any excess refs so they're tracked (hash check will catch mismatches).
    while (ref_it != refs.end()) {
        m_txs.push_back(*ref_it++);
    }
    return m_missing.empty();
}

bool PeerTemplatePartial::CompletedSuccessfully() const
{
    return m_missing.empty() && ComputeHash() == m_hash;
}

std::optional<PeerTemplatePartial> TemplateManager::MakePeerTemplatePartial(PeerTemplateSketch&& sketch)
{
    const TemplateTxRef pool_end = m_pool.end();
    const size_t orig_size = sketch.m_txs.size();

    // Pair up provider shortids with local refs; collect local-only refs to release.
    std::vector<std::pair<uint64_t, TemplateTxRef>> pairs;
    std::vector<TemplateTxRef> to_release;
    for (size_t i = 0; i < orig_size; ++i) {
        if (sketch.m_shortids[i] != 0) {
            pairs.emplace_back(sketch.m_shortids[i], sketch.m_txs[i]);
        } else {
            to_release.push_back(sketch.m_txs[i]);
        }
    }
    // Provider-only shortids (appended beyond m_txs, no local ref).
    for (size_t i = orig_size; i < sketch.m_shortids.size(); ++i) {
        pairs.emplace_back(sketch.m_shortids[i], pool_end);
    }
    // Clear sketch's refs — ownership is now split between pairs and to_release.
    sketch.m_txs.clear();
    RemoveTxs(std::move(to_release));

    std::sort(pairs.begin(), pairs.end(), [](const auto& a, const auto& b) { return a.first < b.first; });

    // Shortid collision → reject.
    for (size_t i = 1; i < pairs.size(); ++i) {
        if (pairs[i].first == pairs[i - 1].first) {
            std::vector<TemplateTxRef> collision_release;
            for (auto& [sid, ref] : pairs) {
                if (ref != pool_end) collision_release.push_back(ref);
            }
            RemoveTxs(std::move(collision_release));
            return std::nullopt;
        }
    }

    PeerTemplatePartial partial;
    partial.m_tip = sketch.m_tip;
    partial.m_hash = sketch.m_hash;
    auto shortid_info = std::make_unique<PeerTemplatePartial::ShortIDInfo>();
    shortid_info->nonce = sketch.m_nonce;
    int64_t min_missing_weight{0};
    partial.m_txs.reserve(pairs.size());
    for (size_t i = 0; i < pairs.size(); ++i) {
        partial.m_txs.push_back(pairs[i].second);
        if (pairs[i].second == pool_end) {
            partial.m_missing.Add(i);
            shortid_info->missing_shortids.push_back(pairs[i].first);
            min_missing_weight += MIN_TRANSACTION_WEIGHT;
        } else {
            partial.m_weight += pairs[i].second->weight;
        }
    }
    if (partial.m_weight + min_missing_weight > MAX_TEMPLATE_WEIGHT) {
        RemoveTxs(std::move(partial.m_txs));
        return std::nullopt;
    }
    partial.m_shortid_info = std::move(shortid_info);
    return partial;
}

TemplateInfo TemplateManager::GetInfo() const
{
    TemplateInfo info;
    info.num_templates = m_templates.size();
    info.pool_size = m_pool.size();
    info.pool_weight = m_pool_weight;
    if (!m_templates.empty()) {
        info.latest_tx_count = m_templates.back().m_txs.size();
        info.latest_weight = m_templates.back().m_weight;
    }
    info.generate_interval = std::chrono::duration_cast<std::chrono::seconds>(TEMPLATE_GENERATE_INTERVAL);
    info.next_update = m_next_gen;
    info.peer_templates = m_peer_templates.size();
    for (const auto& [nodeid, state] : m_peer_reconcile) {
        int round;
        if (std::holds_alternative<std::monostate>(state)) {
            round = 0;
        } else if (auto* sketch = std::get_if<PeerTemplateSketch>(&state)) {
            round = std::max(1, sketch->m_sketch_level + 1);
        } else {
            round = 5;
        }
        info.pending_peer_templates[round].push_back(nodeid);
    }
    return info;
}

void TemplateManager::Check() const
{
    const auto pool_end = m_pool.end();

    // 1. m_scannable_txns <-> m_pool consistency
    assert(m_scannable_txns.size() == m_pool.size());
    for (auto ref = m_pool.begin(); ref != pool_end; ++ref) {
        assert(ref->tx != nullptr);
        assert(ref->scannable_idx < m_scannable_txns.size());
        assert(m_scannable_txns[ref->scannable_idx].second == ref);
    }
    for (size_t i = 0; i < m_scannable_txns.size(); ++i) {
        const auto& [wtxid, ref] = m_scannable_txns[i];
        assert(ref != pool_end);
        assert(ref->tx != nullptr);
        assert(ref->tx->GetWitnessHash() == wtxid);
        assert(ref->scannable_idx == i);
    }

    // 2. m_pool_weight consistency
    int64_t total_weight = 0;
    for (const auto& entry : m_pool) {
        total_weight += entry.weight;
        assert(entry.num_templates > 0);
    }
    assert(total_weight == m_pool_weight);

    // 3. Count actual references to each pool entry
    std::vector<uint32_t> refcounts;
    refcounts.resize(m_pool.size());
    auto count_refs = [&](const std::vector<TemplateTxRef>& txs) {
        for (const auto& ref : txs) {
            if (ref != pool_end) ++refcounts[ref->scannable_idx];
        }
    };

    for (const auto& tmpl : m_templates) count_refs(tmpl.m_txs);
    for (const auto& pt : m_peer_templates) count_refs(pt.m_txs);
    for (const auto& [nodeid, state] : m_peer_reconcile) {
        std::visit([&](const auto& s) {
            if constexpr (!std::is_same_v<std::decay_t<decltype(s)>, std::monostate>) {
                count_refs(s.m_txs);
            }
        }, state);
    }

    for (const auto& entry : m_pool) {
        uint32_t expected = refcounts[entry.scannable_idx];
        if (entry.num_templates != expected) {
            fprintf(stderr, "CHECK FAILED: wtxid=%s num_templates=%u expected=%u\n",
                    entry.tx->GetWitnessHash().ToString().c_str(), entry.num_templates, expected);
            assert(false);
        }
    }

    // 4. m_peer_template_cache validity
    for (const auto& [nodeid, ptr] : m_peer_template_cache) {
        bool found = false;
        for (const auto& pt : m_peer_templates) {
            if (&pt == ptr) { found = true; break; }
        }
        assert(found);
        assert(ptr->m_nodeid == nodeid);
    }
}

/** Look up a peer's reconciliation state.
 *  Returns {true, it} if the entry exists and holds type T;
 *  {false, it} if it exists but holds a different type;
 *  {false, end} if no entry. */
template <typename T, typename Map>
static std::pair<bool, typename Map::iterator> GetPeerRecState(Map& map, NodeId nodeid)
{
    auto it = map.find(nodeid);
    if (it == map.end()) return {false, it};
    return {std::holds_alternative<T>(it->second), it};
}

template <typename T>
TemplateManager::PeerReconcileMap::iterator TemplateManager::SetPeerReconcile(NodeId nodeid, T&& new_value)
{
    auto [it, _] = m_peer_reconcile.try_emplace(nodeid);
    std::visit([this](auto& old) {
        if constexpr (!std::is_same_v<std::decay_t<decltype(old)>, std::monostate>) {
            RemoveTxs(std::move(old.m_txs));
        }
    }, it->second);
    it->second = std::forward<T>(new_value);
    return it;
}

TemplateManager::TmpltResult TemplateManager::CompleteSketchRound(
    PeerReconcileMap::iterator it,
    const PeerTemplateSketch::ProcessResult& pr)
{
    NodeId nodeid = it->first;
    auto& sketch = std::get<PeerTemplateSketch>(it->second);
    const uint256 templatehash = sketch.m_hash;

    if (sketch.m_shortids.size() > MAX_TEMPLATE_TXS) {
        RemoveTxs(std::move(sketch.m_txs));
        m_peer_reconcile.erase(it);
        return {TmpltState::FAILED, templatehash, {}, {}};
    }

    if (!pr.resolved) {
        // XXX store pr.shortidmask/pr.sketchmask on sketch for next round
        return {TmpltState::UNRESOLVED, templatehash, pr.shortidmask, pr.sketchmask};
    }

    auto partial = MakePeerTemplatePartial(std::move(sketch));
    if (!partial) {
        m_peer_reconcile.erase(it);
        return {TmpltState::FAILED, templatehash, {}, {}};
    }
    if (partial->CompletedSuccessfully()) {
        if (partial->m_weight > MAX_TEMPLATE_WEIGHT) {
            RemoveTxs(std::move(partial->m_txs));
            m_peer_reconcile.erase(it);
            return {TmpltState::FAILED, templatehash, {}, {}};
        }
        // All txs matched locally; promote directly.
        PeerTemplate pt;
        pt.m_txs = std::move(partial->m_txs);
        pt.m_weight = partial->m_weight;
        pt.m_tip = partial->m_tip;
        pt.m_hash = partial->m_hash;
        pt.m_nodeid = nodeid;
        pt.m_time = NodeClock::now();
        pt.TopoSort();
        m_peer_reconcile.erase(it);
        m_peer_templates.push_back(std::move(pt));
        m_peer_template_cache[nodeid] = &m_peer_templates.back();
        return {TmpltState::DONE, templatehash, {}, {}};
    }
    SetPeerReconcile(nodeid, std::move(*partial));
    return {TmpltState::NEEDS_TXS, templatehash, {}, {}};
}

void TemplateManager::WaitingForPeerSketch(NodeId nodeid)
{
    SetPeerReconcile(nodeid, std::monostate{});
}

TemplateManager::TmpltResult TemplateManager::InitPeerSketch(
    NodeId nodeid, const CBlockIndex* tip, uint256 templatehash,
    uint64_t nonce, uint256 basis_hash,
    std::span<const uint8_t> basis_delta,
    std::span<const LocalTemplate::Sketch> sketches)
{
    // Must be in monostate (awaiting round-0 response).
    auto [is_mono, it] = GetPeerRecState<std::monostate>(m_peer_reconcile, nodeid);
    if (!is_mono) {
        if (it != m_peer_reconcile.end()) {
            SetPeerReconcile(nodeid, std::monostate{});
            m_peer_reconcile.erase(nodeid);
        }
        return {TmpltState::FAILED, templatehash, {}, {}};
    }

    const uint256& tip_hash = tip ? tip->GetBlockHash() : uint256::ZERO;
    ShortIDHasher hasher(tip_hash, nonce);

    // Build txs and shortids arrays: basis segment then local.
    std::unordered_set<const CTransaction*> basis_tx_set;
    std::vector<TemplateTxRef> txs;
    std::vector<uint64_t> shortids;
    size_t basis_count = 0;

    if (!basis_hash.IsNull()) {
        auto cache_it = m_peer_template_cache.find(nodeid);
        if (cache_it != m_peer_template_cache.end() && cache_it->second->m_hash == basis_hash) {
            // null basis_hash, missing basis hash and incorrect basis hash are all treated the same
            const PeerTemplate& basis = *cache_it->second;
            TemplateTxnsSelection sel;
            try {
                sel.GRDecode(basis_delta);
            } catch (...) {
                // sending corrupt shortid data suggests sketches might be corrupt too,
                // so don't try to recover automatically
                return {TmpltState::FAILED, templatehash, {}, {}};
            }
            txs.reserve(sel.Count());
            shortids.reserve(sel.Count());
            for (size_t chunk_idx = 0; chunk_idx < sel.m_positions.size(); ++chunk_idx) {
                for (unsigned bit : sel.m_positions[chunk_idx]) {
                    uint32_t pos = chunk_idx * TemplateTxnsSelection::CHUNK_SIZE + bit;
                    if (pos >= basis.m_txs.size()) {
                        RemoveTxs(std::move(txs));
                        return {TmpltState::FAILED, templatehash, {}, {}};
                    }
                    const auto& ref = basis.m_txs[pos];
                    ++ref->num_templates;
                    shortids.push_back(hasher.GetShortID(ref->tx->GetWitnessHash()));
                    txs.push_back(ref);
                    basis_tx_set.insert(ref->tx.get());
                }
            }
        }
    }
    basis_count = txs.size();

    // Append local txs from our most recent local template, excluding basis txs.
    if (!m_templates.empty()) {
        const auto& local_tmpl = m_templates.back();
        txs.reserve(basis_count + local_tmpl.m_txs.size());
        shortids.reserve(basis_count + local_tmpl.m_txs.size());
        for (const auto& ref : local_tmpl.m_txs) {
            if (basis_tx_set.count(ref->tx.get())) continue;
            ++ref->num_templates;
            shortids.push_back(hasher.GetShortID(ref->tx->GetWitnessHash()));
            txs.push_back(ref);
        }
    }

    // Initialise the sketch and store it in m_peer_reconcile.
    PeerTemplateSketch sketch;
    sketch.m_hash = templatehash;
    sketch.m_tip = tip;
    sketch.m_nonce = nonce;

    PeerTemplateSketch::ProcessResult pr;
    try {
        pr = sketch.Init(std::move(txs), std::move(shortids), basis_count, sketches);
    } catch (...) {
        RemoveTxs(std::move(sketch.m_txs));
        return {TmpltState::FAILED, templatehash, {}, {}};
    }
    auto rec_it = SetPeerReconcile(nodeid, std::move(sketch));
    return CompleteSketchRound(rec_it, pr);
}

TemplateManager::TmpltResult TemplateManager::UpdatePeerSketch(
    NodeId nodeid, uint256 templatehash, int round,
    GroupMask shortidmask, GroupMask sketchmask,
    std::span<const uint8_t> shortid_bytes,
    std::span<const LocalTemplate::Sketch> sketches)
{
    // Must be a PeerTemplateSketch with matching hash.
    auto [is_sketch, it] = GetPeerRecState<PeerTemplateSketch>(m_peer_reconcile, nodeid);
    if (!is_sketch) {
        return {TmpltState::FAILED, templatehash, {}, {}};
    }
    auto& sketch = std::get<PeerTemplateSketch>(it->second);
    if (sketch.m_hash != templatehash) {
        return {TmpltState::FAILED, templatehash, {}, {}};
    }

    // Validate masks: must not overlap, and must cover exactly the unresolved groups.
    if ((shortidmask & sketchmask).Any()) {
        return {TmpltState::FAILED, templatehash, {}, {}};
    }
    // Compute resolved groups at current level: a group is resolved if all its buckets are.
    const int num_groups = 4 << sketch.m_sketch_level;
    GroupMask resolved_groups = GroupMask::Fill(num_groups) & sketch.m_bucket_resolved;
    if (((shortidmask | sketchmask) ^ resolved_groups) != GroupMask::Fill(num_groups)) {
        return {TmpltState::FAILED, templatehash, {}, {}};
    }

    PeerTemplateSketch::ProcessResult pr;
    try {
        pr = sketch.Process(round, shortidmask, sketchmask, shortid_bytes, sketches);
    } catch (...) {
        return {TmpltState::FAILED, templatehash, {}, {}};
    }

    return CompleteSketchRound(it, pr);
}

TemplateManager::LocalFillResult TemplateManager::FillPeerPartialLocally(NodeId nodeid, const CTxMemPool& mempool, ExtraTransactions& extra_txns)
{
    LocalFillResult res{};
    auto [is_partial, it] = GetPeerRecState<PeerTemplatePartial>(m_peer_reconcile, nodeid);
    if (!is_partial) return res;
    auto& partial = std::get<PeerTemplatePartial>(it->second);
    if (!partial.m_shortid_info) { res.still_missing = partial.m_missing.Count(); return res; }

    auto info = std::move(partial.m_shortid_info);
    partial.m_shortid_info.reset();

    const auto& missing_sids = info->missing_shortids;
    if (missing_sids.empty()) { res.still_missing = partial.m_missing.Count(); return res; }

    // Build shortid → position-in-m_txs map.
    std::unordered_map<uint64_t, uint32_t> sid_to_pos(missing_sids.size());
    {
        size_t i = 0;
        for (size_t chunk_idx = 0; chunk_idx < partial.m_missing.m_positions.size(); ++chunk_idx) {
            for (unsigned bit : partial.m_missing.m_positions[chunk_idx]) {
                if (i >= missing_sids.size()) break;
                uint32_t pos = chunk_idx * TemplateTxnsSelection::CHUNK_SIZE + bit;
                auto [sit, inserted] = sid_to_pos.emplace(missing_sids[i], pos);
                Assume(inserted); // already guaranteed by MakePeerTemplatePartial
                ++i;
            }
        }
    }

    const uint256& tip_hash = partial.m_tip ? partial.m_tip->GetBlockHash() : uint256::ZERO;
    ShortIDHasher hasher(tip_hash, info->nonce);

    // Candidates keyed by position in m_txs: false = no match,
    // CTransactionRef = mempool/extra hit, TemplateTxRef = pool hit, true = collision.
    using Hit = std::variant<bool, CTransactionRef, TemplateTxRef>;
    std::unordered_map<uint32_t, Hit> candidates;
    size_t match_count = 0;

    auto try_match = [&](const Wtxid& wtxid, const auto& tx) {
        uint64_t sid = hasher.GetShortID(wtxid);
        auto find_it = sid_to_pos.find(sid);
        if (find_it == sid_to_pos.end()) return;
        uint32_t pos = find_it->second;
        auto [cit, inserted] = candidates.try_emplace(pos, tx);
        if (inserted) {
            ++match_count;
        } else if (!std::holds_alternative<bool>(cit->second)) {
            // Already have a candidate — check if it's the same tx.
            const Wtxid* existing_wtxid = nullptr;
            if (auto* ref = std::get_if<CTransactionRef>(&cit->second)) {
                existing_wtxid = &(*ref)->GetWitnessHash();
            } else if (auto* ref = std::get_if<TemplateTxRef>(&cit->second)) {
                existing_wtxid = &(*ref)->tx->GetWitnessHash();
            }
            if (existing_wtxid && *existing_wtxid != wtxid) {
                cit->second = true; // collision
                --match_count;
            }
        }
    };

    // Scan template pool.
    for (const auto& [wtxid, ref] : m_scannable_txns) {
        try_match(wtxid, ref);
        if (match_count == sid_to_pos.size()) break;
    }

    // Scan mempool.
    if (match_count < sid_to_pos.size()) {
        LOCK(mempool.cs);
        for (const auto& [wtxid, txit] : mempool.txns_randomized) {
            try_match(wtxid, txit->GetSharedTx());
            if (match_count == sid_to_pos.size()) break;
        }
    }

    // Scan extra transactions.
    while (match_count < sid_to_pos.size()) {
        auto [wtxid, tx] = extra_txns.next();
        if (!tx) break;
        try_match(*wtxid, *tx);
    }

    // Fill matched positions, counting by source type.
    auto n_missing = partial.m_missing.Count();
    for (auto& [pos, hit] : candidates) {
        std::visit(util::Overloaded(
            [&](bool&& collision) { if (collision) ++res.collisions; },
            [&](CTransactionRef&& tx) {
                auto ref = AddTx(std::move(tx));
                partial.m_weight += ref->weight;
                --n_missing;
                partial.m_txs[pos] = std::move(ref);
                partial.m_missing.Remove(pos);
                ++partial.m_filled;
                ++res.from_txns;
            },
            [&](TemplateTxRef&& ref) {
                ++ref->num_templates;
                partial.m_weight += ref->weight;
                --n_missing;
                partial.m_txs[pos] = std::move(ref);
                partial.m_missing.Remove(pos);
                ++partial.m_filled;
                ++res.from_templates;
            }
        ), std::move(hit));
        if (partial.m_weight + n_missing * MIN_TRANSACTION_WEIGHT > MAX_TEMPLATE_WEIGHT) {
            RemoveTxs(std::move(partial.m_txs));
            m_peer_reconcile.erase(it);
            res.oversize = true;
            res.still_missing = 0;
            return res;
        }
    }

    res.still_missing = n_missing;
    return res;
}

std::vector<uint8_t> TemplateManager::GetPeerPartialMissingGR(NodeId nodeid)
{
    auto [is_partial, it] = GetPeerRecState<PeerTemplatePartial>(m_peer_reconcile, nodeid);
    if (!is_partial) return {};
    return std::get<PeerTemplatePartial>(it->second).m_missing.GREncode();
}

std::pair<TemplateManager::TmpltState, uint32_t> TemplateManager::FillPeerPartial(NodeId nodeid, const uint256& hash, std::vector<CTransactionRef> txs)
{
    auto [is_partial, it] = GetPeerRecState<PeerTemplatePartial>(m_peer_reconcile, nodeid);
    if (!is_partial) return {TmpltState::FAILED, 0};
    auto& partial = std::get<PeerTemplatePartial>(it->second);
    if (partial.m_hash != hash) return {TmpltState::FAILED, 0};

    auto refs = AddTxs(txs);
    if (!partial.Fill(std::move(refs))) {
        if (partial.m_weight + int64_t(partial.m_missing.Count()) * MIN_TRANSACTION_WEIGHT > MAX_TEMPLATE_WEIGHT) {
            RemoveTxs(std::move(partial.m_txs));
            m_peer_reconcile.erase(it);
            return {TmpltState::FAILED, 0};
        }
        return {TmpltState::NEEDS_TXS, 0};
    }
    if (!partial.CompletedSuccessfully()) {
        RemoveTxs(std::move(partial.m_txs));
        m_peer_reconcile.erase(it);
        return {TmpltState::FAILED, 0};
    }

    // Promote to completed PeerTemplate.
    if (partial.m_weight > MAX_TEMPLATE_WEIGHT) {
        RemoveTxs(std::move(partial.m_txs));
        m_peer_reconcile.erase(it);
        return {TmpltState::FAILED, 0};
    }
    uint32_t ntxs = partial.m_txs.size();
    PeerTemplate pt;
    pt.m_txs = std::move(partial.m_txs);
    pt.m_weight = partial.m_weight;
    pt.m_tip = partial.m_tip;
    pt.m_hash = partial.m_hash;
    pt.m_nodeid = nodeid;
    pt.m_time = NodeClock::now();
    pt.TopoSort();
    m_peer_reconcile.erase(it);
    m_peer_templates.push_back(std::move(pt));
    m_peer_template_cache[nodeid] = &m_peer_templates.back();
    return {TmpltState::DONE, ntxs};
}

uint256 TemplateManager::GetLastPeerTemplateHash(NodeId nodeid)
{
    auto it = m_peer_template_cache.find(nodeid);
    if (it == m_peer_template_cache.end()) return uint256::ZERO;
    return it->second->m_hash;
}

void TemplateManager::ForgetPeer(NodeId nodeid)
{
    auto it = SetPeerReconcile(nodeid, std::monostate{});
    m_peer_reconcile.erase(it);
    m_peer_template_cache.erase(nodeid);
}

void PeerTemplate::TopoSort()
{
    const uint32_t n = m_txs.size();

    std::unordered_map<Txid, uint32_t, SaltedTxidHasher> txid_pos;
    txid_pos.reserve(n);

    std::vector<uint32_t> out_degree(n, 0);
    std::vector<uint32_t> ready;

    // 1. Build txid -> position map
    for (uint32_t i = 0; i < n; ++i) {
        txid_pos.emplace(m_txs[i]->tx->GetHash(), i);
    }

    // 2. Count out-degree (number of in-template children) per tx
    for (uint32_t i = 0; i < n; ++i) {
        for (const auto& txin : m_txs[i]->tx->vin) {
            auto it = txid_pos.find(txin.prevout.hash);
            if (it != txid_pos.end()) {
                ++out_degree[it->second];
            }
        }
    }

    // 3. Reverse Kahn's: seed with leaves (out_degree == 0)
    for (uint32_t i = 0; i < n; ++i) {
        if (out_degree[i] == 0) ready.push_back(i);
    }

    // Save nchildren before Kahn's mutates out_degree
    std::vector<uint32_t> nchildren{out_degree};

    m_pending.clear();
    m_pending.reserve(n);
    while (!ready.empty()) {
        uint32_t pos = ready.back();
        ready.pop_back();

        m_pending.push_back({.pos = pos, .nchildren = nchildren[pos]});

        // Decrement out_degree of this tx's parents
        for (const auto& txin : m_txs[pos]->tx->vin) {
            auto it = txid_pos.find(txin.prevout.hash);
            if (it != txid_pos.end()) {
                if (--out_degree[it->second] == 0) {
                    ready.push_back(it->second);
                }
            }
        }
    }

    // m_pending is now in reverse topo order: pop_back() yields topo order
}

std::pair<bool, CTransactionRef> PeerTemplate::ConsumeParentCandidates(const CTransaction& tx) const
{
    // First pass: find a single package parent for 1p1c.
    // Dedupe to handle txs spending multiple outputs of the same parent.
    CTransactionRef package_parent{nullptr};
    bool usable{true};
    for (const auto& txin : tx.vin) {
        if (package_parent && txin.prevout.hash == package_parent->GetHash()) continue;
        auto it = m_package_candidates.find(txin.prevout.hash);
        if (it != m_package_candidates.end()) {
            if (package_parent) {
                usable = false;
                break;
            }
            package_parent = it->second.tx;
        }
    }

    // Second pass: decrement remaining_children for all parent candidates.
    // No dedupe: nchildren counted with duplicates, so decrement with duplicates.
    for (const auto& txin : tx.vin) {
        auto it = m_package_candidates.find(txin.prevout.hash);
        if (it != m_package_candidates.end()) {
            if (--it->second.remaining_children == 0) {
                m_package_candidates.erase(it);
            }
        }
    }

    return {usable, std::move(package_parent)};
}

void PeerTemplate::StashPackageCandidate(CTransactionRef tx, uint32_t nchildren) const
{
    const auto& txid = tx->GetHash();
    m_package_candidates.emplace(txid, PackageCandidate{std::move(tx), nchildren});
}

TemplateManager::NextTemplateTx TemplateManager::GetNextTemplateTx(
    NodeId nodeid, NodeClock::time_point now,
    const CTxMemPool& mempool,
    const uint256& active_tip_hash,
    const std::map<GenTxid, CTransactionRef>* recent_block_txs)
{
    auto cache_it = m_peer_template_cache.find(nodeid);
    if (cache_it == m_peer_template_cache.end()) return {};
    PeerTemplate& pt = *cache_it->second;

    // Can't reason about a template with no tip
    if (!pt.m_tip) return {};

    // Only check recent block txs when the template targets a different tip
    // (if tips match, all template txs are unconfirmed by definition)
    const bool check_recent_block = recent_block_txs
        && pt.m_tip->GetBlockHash() != active_tip_hash;

    const size_t total = pt.m_txs.size();

    auto in_mempool_or_block = [&](const auto& wtxid) -> bool {
        if (mempool.exists(wtxid)) return true;
        if (check_recent_block) {
            auto wit = recent_block_txs->find(GenTxid{wtxid});
            if (wit != recent_block_txs->end()) {
                return true;
            }
        }
        return false;
    };

    while (!pt.m_pending.empty()) {
        auto [pos, nchildren] = pt.m_pending.back();
        pt.m_pending.pop_back();

        auto& ttx = *pt.m_txs[pos];

        auto [usable, package_parent] = pt.ConsumeParentCandidates(*ttx.tx);

        // (1) Permanently rejected — skip entirely
        if (ttx.next_mempool_check == NodeClock::time_point::max()) continue;

        // (2) Already in mempool or confirmed in recent block — bump and skip
        if (in_mempool_or_block(ttx.tx->GetWitnessHash())) {
            // check this first to avoid stashing it as a package candidate,
            // which would interfere with 1p1c acceptance if another parent
            // isn't already accepted
            ttx.next_mempool_check = Jitter(now, ATMP_RECHECK_INTERVAL);
            continue;
        }

        // (3) Not ready for retry — stash for 1p1c and skip
        if (now < ttx.next_mempool_check) {
            if (nchildren > 0) {
                pt.StashPackageCandidate(ttx.tx, nchildren);
            }
            continue;
        }

        // (4) Multiple low-fee parents, 1p1c won't apply — skip
        if (!usable) {
            ttx.next_mempool_check = Jitter(now, ATMP_RETRY_INTERVAL);
            continue;
        }

        // (5) Return tx for ATMP
        return NextTemplateTx{ttx.tx, std::move(package_parent), total - pt.m_pending.size(), total, nchildren};
    }

    return {};
}

void TemplateManager::ReportATMPResult(NodeId nodeid, const CTransactionRef& tx,
                                       NodeClock::time_point now,
                                       TemplateATMPResult result, uint32_t nchildren)
{
    // 1. Update next_mempool_check based on result
    auto it = m_pool.find(tx->GetWitnessHash());
    if (it != m_pool.end()) {
        switch (result) {
        case TemplateATMPResult::ACCEPTED:
        case TemplateATMPResult::ALREADY_IN_MEMPOOL:
            it->next_mempool_check = Jitter(now, ATMP_RECHECK_INTERVAL);
            break;
        case TemplateATMPResult::CONFLICT:
        case TemplateATMPResult::RECONSIDERABLE:
        case TemplateATMPResult::MISSING_INPUTS:
            it->next_mempool_check = Jitter(now, ATMP_RETRY_INTERVAL);
            break;
        case TemplateATMPResult::PREMATURE_SPEND:
            it->next_mempool_check = Jitter(now, ATMP_RETRY_SLOW_INTERVAL);
            break;
        case TemplateATMPResult::UNACCEPTABLE:
            it->next_mempool_check = NodeClock::time_point::max();
            break;
        }
    }

    // 2. On RECONSIDERABLE with children: stash for potential 1p1c attempts.
    // Note: if we have a chain grandparent A -> parent B -> child C, and B
    // fails as reconsiderable, we still add B here, as there may be another
    // child of A which is tried before C and gets A accepted into the mempool.
    if (result == TemplateATMPResult::RECONSIDERABLE && nchildren > 0) {
        auto cache_it = m_peer_template_cache.find(nodeid);
        if (cache_it != m_peer_template_cache.end()) {
            cache_it->second->StashPackageCandidate(tx, nchildren);
        }
    }
}

} // namespace node
