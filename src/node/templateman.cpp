// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/templateman.h>

#include <crypto/sha256.h>
#include <crypto/siphash.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <util/compactintvec.h>

namespace node {

void Template::ComputeHash()
{
    CSHA256 hasher;
    for (const auto& it : m_txs) {
        const auto& wtxid = it->tx->GetWitnessHash();
        hasher.Write(UCharCast(wtxid.data()), 32);
    }
    hasher.Finalize(m_hash.begin());
}

/** Computes 6-byte short IDs for template transactions.
 *  Initialized from (template_hash, nonce), reused across all lookups. */
class ShortIDHasher
{
    static PresaltedSipHasher MakeHasher(const uint256& template_hash, uint64_t nonce)
    {
        DataStream ds{};
        ds << template_hash << nonce;
        uint256 key;
        CSHA256{}.Write(MakeUCharSpan(ds)).Finalize(key.begin());
        return PresaltedSipHasher{key.GetUint64(0), key.GetUint64(1)};
    }
    PresaltedSipHasher m_hasher;

public:
    ShortIDHasher(const uint256& template_hash, uint64_t nonce)
        : m_hasher{MakeHasher(template_hash, nonce)} {}

    uint64_t GetShortID(const Wtxid& wtxid) const
    {
        static_assert(SHORTTXIDS_LENGTH == 6, "shorttxids calculation assumes 6-byte shorttxids");
        return m_hasher(wtxid.ToUint256()) & 0xffffffffffffL;
    }
};

const TemplateDelta& LocalTemplate::GetDelta(const Template& basis) const
{
    auto [it, inserted] = m_deltas.try_emplace(basis.m_hash);
    if (inserted) {
        // Build a map from wtxid to position in the basis template
        std::unordered_map<Wtxid, uint32_t, SaltedWtxidHasher> old_pos;
        for (uint32_t i = 0; i < basis.m_txs.size(); ++i) {
            old_pos[basis.m_txs[i]->tx->GetWitnessHash()] = i;
        }

        // Walk this template, emitting delta instructions
        std::vector<int32_t> delta_ints;
        uint32_t old_cursor = 0;
        for (const auto& ref : m_txs) {
            const auto& wtxid = ref->tx->GetWitnessHash();
            auto found = old_pos.find(wtxid);
            if (found != old_pos.end()) {
                int32_t offset = static_cast<int32_t>(found->second) - static_cast<int32_t>(old_cursor);
                delta_ints.push_back(offset);
                old_cursor = found->second + 1;
            } else {
                delta_ints.push_back(-1);
            }
        }

        // Encode to bitstream
        DataStream ds{};
        ds << Using<util::CompactIntVecFormatter>(delta_ints);
        it->second.assign(ds.begin(), ds.end());
    }
    return it->second;
}

DataStream LocalTemplate::MakeTmpltMsg(uint64_t nonce, const LocalTemplate* basis) const
{
    DataStream stream{};
    stream << m_hash;
    stream << nonce;

    ShortIDHasher hasher(m_hash, nonce);

    std::vector<uint64_t> short_ids;

    if (!basis) {
        // Flat encoding: no basis, short IDs for all txs
        stream << uint256::ZERO;
        short_ids.reserve(m_txs.size());
        for (const auto& it : m_txs) {
            short_ids.push_back(hasher.GetShortID(it->tx->GetWitnessHash()));
        }
    } else {
        // Delta encoding against basis template
        stream << basis->m_hash;

        const auto& delta = GetDelta(*basis);
        stream.write(delta);

        // Short IDs for new entries (-1 in delta)
        std::vector<int32_t> delta_ints;
        DataStream{delta} >> Using<util::CompactIntVecFormatter>(delta_ints);

        size_t tx_idx = 0;
        for (int32_t d : delta_ints) {
            if (d == -1) {
                short_ids.push_back(hasher.GetShortID(m_txs[tx_idx]->tx->GetWitnessHash()));
            }
            ++tx_idx;
        }
    }

    stream << Using<VectorFormatter<CustomUintFormatter<SHORTTXIDS_LENGTH>>>(short_ids);

    return stream;
}

TemplateTxRef TemplateManager::AddTx(CTransactionRef tx)
{
    auto [it, inserted] = m_pool.insert(TemplateTx{std::move(tx)});
    ++it->num_templates;
    if (inserted) {
        it->scannable_idx = m_scannable_txns.size();
        m_scannable_txns.emplace_back(it->tx->GetWitnessHash(), it);
    }
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

void TemplateManager::TrimLocalTemplates()
{
    while (m_templates.size() > MAX_TEMPLATES) {
        RemoveTxs(std::move(m_templates.front().m_txs));
        m_templates.pop_front();
    }
}

void TemplateManager::GenerateTemplate(std::span<CTransactionRef> txs)
{
    LocalTemplate tmpl;
    tmpl.m_txs = AddTxs(std::move(txs));
    tmpl.ComputeHash();
    m_templates.push_back(std::move(tmpl));
    TrimLocalTemplates();
}

std::vector<CTransactionRef> TemplateManager::GetTxsByPosition(const LocalTemplate& tmpl, const std::vector<uint16_t>& positions)
{
    std::vector<CTransactionRef> result;
    result.reserve(positions.size());
    for (uint16_t pos : positions) {
        if (pos < tmpl.m_txs.size()) {
            result.push_back(tmpl.m_txs[pos]->tx);
        }
    }
    return result;
}

bool RequestedTemplateTxns::Queue(const uint256& hash, const LocalTemplate& tmpl, const std::vector<uint16_t>& positions)
{
    m_template_hash = hash;
    m_positions.clear();
    size_t limit = CHUNK_SIZE;
    BitSet<CHUNK_SIZE> chunk;
    for (uint16_t p : positions) {
        if (p >= tmpl.m_txs.size()) {
            Reset();
            return false;
        }
        while (limit <= p) {
            m_positions.push_back(chunk);
            chunk = BitSet<CHUNK_SIZE>{};
            limit += CHUNK_SIZE;
        }
        chunk.Set(p % CHUNK_SIZE);
    }
    if (chunk.Any()) {
        m_positions.push_back(chunk);
    }
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

    if (!hit_limit) Reset();

    return txs;
}

} // namespace node
