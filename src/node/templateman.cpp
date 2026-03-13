// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/templateman.h>

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

    // TODO: populate sketches here

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

} // namespace node
