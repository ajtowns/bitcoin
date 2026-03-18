// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/templateman.h>
#include <node/minisketchwrapper.h>

#include <chain.h>
#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <primitives/transaction.h>
#include <random.h>
#include <serialize.h>
#include <streams.h>

#include <util/golombrice.h>

#include <algorithm>
#include <bit>
#include <unordered_set>

namespace node {

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
    m_next_gen = now + TEMPLATE_UPDATE_INTERVAL;
    return m_templates.empty();
}

void TemplateManager::TrimLocalTemplates(NodeClock::time_point cutoff)
{
    while (!m_templates.empty() && m_templates.front().m_time < cutoff) {
        RemoveTxs(std::move(m_templates.front().m_txs));
        m_templates.pop_front();
    }
}

uint256 TemplateManager::GenerateTemplate(NodeClock::time_point now, FastRandomContext& rng,
                                        const CBlockIndex* tip, std::span<CTransactionRef> txs)
{
    LocalTemplate tmpl;
    tmpl.m_time = now;
    tmpl.m_tip = tip;
    tmpl.m_nonce = rng.rand64();

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
    for (auto& [sid, ref] : pairs) {
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
                for (uint64_t sid : *decoded) m_diff_shortids.push_back(sid);
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
                for (uint64_t sid : *decoded) m_diff_shortids.push_back(sid);
                for (int b = gi; b < TOTAL_BUCKETS; b += n) {
                    m_bucket_resolved.Set(b);
                }
                continue;
            }
        }
    }
    return m_bucket_resolved.Count() == TOTAL_BUCKETS;
}

bool PeerTemplateSketch::Init(std::vector<std::pair<uint64_t, TemplateTxRef>> basis_pairs,
                               std::vector<std::pair<uint64_t, TemplateTxRef>> local_pairs,
                               std::span<const LocalTemplate::Sketch> combined_sketches)
{
    // Populate shortids and m_txs: basis segment [0..m_basis_count), then local
    shortids.reserve(basis_pairs.size() + local_pairs.size());
    m_txs.reserve(basis_pairs.size() + local_pairs.size());
    for (auto& [sid, ref] : basis_pairs) {
        shortids.push_back(sid);
        m_txs.push_back(ref);
    }
    m_basis_count = basis_pairs.size();
    for (auto& [sid, ref] : local_pairs) {
        shortids.push_back(sid);
        m_txs.push_back(ref);
    }

    // Build per-bucket sketches from the two sorted segments
    m_sketches = std::make_unique<Sketches>();
    auto& sk = *m_sketches;
    for (size_t i = 0; i < m_basis_count; ++i) {
        sk.m_basis_sketches[shortids[i] & (TOTAL_BUCKETS - 1)].Add(shortids[i]);
    }
    for (size_t i = m_basis_count; i < shortids.size(); ++i) {
        sk.m_local_sketches[shortids[i] & (TOTAL_BUCKETS - 1)].Add(shortids[i]);
    }
    // Pre-merge basis into local so m_local_sketches holds basis+local;
    // TryDecodeGroups can then use it directly without an extra Merge().
    for (int b = 0; b < TOTAL_BUCKETS; ++b) {
        sk.m_local_sketches[b].sketch.Merge(sk.m_basis_sketches[b].sketch);
        sk.m_local_sketches[b].count += sk.m_basis_sketches[b].count;
    }
    sk.InitialMerge();

    // Store provider's 4 combined sketches (round 0) into slots 0..3
    sk.ProviderDeser(0, GroupMask{}, combined_sketches);
    m_sketch_level = 0;

    bool resolved = TryDecodeGroups();
    if (resolved) FinalizeShortids();
    return resolved;
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

    // For each unresolved group, try (basis + received_outer) XOR provider.
    // Since received_outer ⊆ provider, diff = provider_inner \ basis (≤SKETCH_CAPACITY elements).
    auto& sk = *m_sketches;
    for (int gi = 0; gi < num_groups; ++gi) {
        // Check if group is already fully resolved
        bool group_resolved = true;
        for (int b = gi; b < TOTAL_BUCKETS; b += num_groups) {
            if (!m_bucket_resolved[b]) { group_resolved = false; break; }
        }
        if (group_resolved) continue;

        auto& recv = received[gi];
        int basis_count    = sk.m_basis_sketches[gi].count;
        int received_count = static_cast<int>(recv.size());
        int provider_count = sk.m_provider_sketches[gi].count;

        if (basis_count + received_count + SKETCH_CAPACITY >= provider_count) {
            Minisketch recv_sketch = MakeMinisketch46(SKETCH_CAPACITY);
            for (uint64_t sid : recv) recv_sketch.Add(sid);

            Minisketch diff = sk.m_basis_sketches[gi].sketch;
            diff.Merge(recv_sketch);
            diff.Merge(sk.m_provider_sketches[gi].sketch);
            if (auto decoded = diff.Decode(SKETCH_CAPACITY)) {
                for (uint64_t sid : *decoded) m_diff_shortids.push_back(sid);
                for (int b = gi; b < TOTAL_BUCKETS; b += num_groups) {
                    m_bucket_resolved.Set(b);
                    m_decoded_by_basis.Set(b);
                }
                for (uint64_t sid : recv) m_extra_shortids.push_back(sid);
            }
        }
    }
}

void PeerTemplateSketch::FinalizeShortids()
{
    // diff semantics differ by decode type:
    //  - basis-only (m_decoded_by_basis bit set): diff = provider \ basis
    //      (assumes basis ⊆ provider; see TryDecodeGroups comment)
    //      → local in diff means local IS in provider (keep); local not in diff → zero
    //  - basis+local: diff = (basis+local) Δ provider
    //      → local in diff means local NOT in provider (zero); local not in diff → keep
    std::unordered_set<uint64_t> diff_set(m_diff_shortids.begin(), m_diff_shortids.end());
    std::unordered_set<uint64_t> our_set(shortids.begin(), shortids.end());

    for (size_t i = m_basis_count; i < shortids.size(); ++i) {
        uint64_t sid = shortids[i];
        bool in_diff = diff_set.count(sid);
        bool in_provider = m_decoded_by_basis[sid & (TOTAL_BUCKETS - 1)] ? in_diff : !in_diff;
        if (!in_provider) shortids[i] = 0;
    }

    // Append provider shortids we don't have in our local/basis set
    for (uint64_t sid : m_diff_shortids) {
        if (our_set.insert(sid).second) shortids.push_back(sid);
    }
    for (uint64_t sid : m_extra_shortids) {
        if (our_set.insert(sid).second) shortids.push_back(sid);
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
    BucketMask shortidmask = BucketMask::Fill(TOTAL_BUCKETS) - m_bucket_resolved; // unresolved buckets → request shortids

    // Compute sketchmask for next round: groups at current level with unresolved buckets
    GroupMask sketchmask;
    if (!all_resolved && round < 3) {
        const int n = 4 << m_sketch_level;
        for (int gi = 0; gi < n; ++gi) {
            for (int b = gi; b < TOTAL_BUCKETS; b += n) {
                if (!m_bucket_resolved[b]) {
                    sketchmask.Set(gi);
                    break;
                }
            }
        }
    }

    return {all_resolved, shortidmask, sketchmask};
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
    info.update_interval = std::chrono::duration_cast<std::chrono::seconds>(TEMPLATE_UPDATE_INTERVAL);
    info.next_update = m_next_gen;
    return info;
}

} // namespace node
