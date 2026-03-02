// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/templateman.h>

#include <chain.h>
#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <crypto/siphash.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <txmempool.h>
#include <util/compactintvec.h>

namespace node {

void Template::ComputeHash()
{
    CSHA256 hasher;
    const uint256& tip_hash = (m_tip ? m_tip->GetBlockHash() : uint256::ZERO);
    hasher.Write(UCharCast(tip_hash.data()), 32);
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
    stream << (m_tip ? m_tip->GetBlockHash() : uint256::ZERO);
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
    auto [it, inserted] = m_pool.insert(TemplateTx{.tx = std::move(tx)});
    if (inserted) {
        it->weight = GetTransactionWeight(*it->tx);
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

void TemplateManager::TrimLocalTemplates(NodeClock::time_point cutoff)
{
    for (auto it = m_templates.begin(); it != m_templates.end(); ) {
        auto& deq = it->second;
        while (!deq.empty() && deq.front().m_time < cutoff) {
            RemoveTxs(std::move(deq.front().m_txs));
            deq.pop_front();
        }
        if (deq.empty()) {
            it = m_templates.erase(it);
        } else {
            ++it;
        }
    }
}

void TemplateManager::GenerateTemplate(uint64_t network_key, NodeClock::time_point now,
                                        const CBlockIndex* tip, std::span<CTransactionRef> txs)
{
    LocalTemplate tmpl;
    tmpl.m_time = now;
    tmpl.m_tip = tip;
    tmpl.m_txs = AddTxs(std::move(txs));
    for (const auto& ref : tmpl.m_txs) {
        tmpl.m_weight += ref->weight;
    }
    tmpl.ComputeHash();
    m_templates[network_key].push_back(std::move(tmpl));
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

void WantedTemplateTxns::ExtendMissing(int32_t from, int32_t to)
{
    if (from > to) return;

    // Ensure enough chunks are allocated
    size_t needed_chunks = to / CHUNK_SIZE + 1;
    while (m_positions.size() < needed_chunks) {
        m_positions.emplace_back();
    }

    for (int32_t pos = from; pos <= to; ++pos) {
        m_positions[pos / CHUNK_SIZE].Set(pos % CHUNK_SIZE);
    }
}

void WantedTemplateTxns::ReceivedTxn(int32_t pos)
{
    size_t chunk_idx = pos / CHUNK_SIZE;
    if (Assume(chunk_idx < m_positions.size())) {
        m_positions[chunk_idx].Reset(pos % CHUNK_SIZE);
    }
}

std::vector<int32_t> MissingTemplateTxns::GetPositions() const
{
    std::vector<int32_t> positions;
    for (size_t chunk_idx = 0; chunk_idx < m_positions.size(); ++chunk_idx) {
        for (unsigned bit : m_positions[chunk_idx]) {
            positions.push_back(static_cast<int32_t>(chunk_idx * CHUNK_SIZE + bit));
        }
    }
    return positions;
}

size_t WantedTemplateTxns::FillTxs(Template& tmpl, std::span<const TemplateTxRef> refs)
{
    size_t ref_idx = 0;

    for (size_t chunk_idx = 0; chunk_idx < m_positions.size() && ref_idx < refs.size(); ++chunk_idx) {
        auto& chunk = m_positions[chunk_idx];
        if (chunk.None()) continue;

        for (unsigned bit : chunk) {
            if (ref_idx >= refs.size()) break;
            size_t abs_pos = chunk_idx * CHUNK_SIZE + bit;
            tmpl.m_txs[abs_pos] = refs[ref_idx++];
            chunk.Reset(bit);
        }
    }

    return ref_idx;
}

PeerTemplate::PeerTemplate(NodeId nodeid, NodeClock::time_point now, PartialPeerTemplate&& partial)
    : m_nodeid{nodeid}, m_time{now}
{
    m_txs = std::move(partial.m_txs);
    m_tip = partial.m_tip;
    m_hash = partial.m_hash;
}

const PeerTemplate* TemplateManager::GetPeerTemplate(NodeId nodeid) const
{
    auto it = m_peer_template_cache.find(nodeid);
    if (it != m_peer_template_cache.end()) return it->second;

    // Cache miss: linear scan, cache result (including nullptr)
    for (size_t i = 0; i < m_peer_templates.size(); ++i) {
        if (m_peer_templates[i].m_nodeid == nodeid) {
            const auto* ptr = &m_peer_templates[i];
            m_peer_template_cache[nodeid] = ptr;
            return ptr;
        }
    }
    m_peer_template_cache[nodeid] = nullptr;
    return nullptr;
}

const PeerTemplate* TemplateManager::GetPeerTemplate(NodeId nodeid, const uint256& hash) const
{
    // Check cache first — the most recent template is usually the one we want
    auto it = m_peer_template_cache.find(nodeid);
    if (it != m_peer_template_cache.end() && it->second && it->second->m_hash == hash) {
        return it->second;
    }

    // Linear scan for older templates from this peer
    for (size_t i = 0; i < m_peer_templates.size(); ++i) {
        if (m_peer_templates[i].m_nodeid == nodeid && m_peer_templates[i].m_hash == hash) {
            return &m_peer_templates[i];
        }
    }
    return nullptr;
}

void TemplateManager::AddPeerTemplate(PeerTemplate&& pt)
{
    if (m_peer_templates.size() == m_peer_templates.capacity()) {
        m_peer_template_cache.clear();
    }
    m_peer_templates.push_front(std::move(pt));
    m_peer_template_cache[m_peer_templates.front().m_nodeid] = &m_peer_templates.front();
}

bool TemplateManager::PartialInitFromBasis(NodeId nodeid, const uint256& hash,
                                            const CBlockIndex* tip,
                                            const Template* basis, const std::vector<int32_t>& delta_ints)
{
    // Create (or reset) the partial for this peer
    ForgetPartialTemplate(nodeid);

    PartialPeerTemplate partial;
    partial.m_hash = hash;
    partial.m_tip = tip;
    partial.m_tx_count = 0;
    partial.m_filled = 0;

    if (!basis || delta_ints.empty()) {
        Assume(delta_ints.empty());
        // Everything deferred to PartialFillShortIDs
    } else {
        partial.m_txs.reserve(delta_ints.size());
        int32_t last_missing = 0;
        int32_t basis_pos = 0;
        const int32_t basis_size = basis->m_txs.size();
        int32_t pos = -1;
        for (auto d : delta_ints) {
            ++pos;
            if (d == -1) {
                // new tx, will be matched via short IDs
                partial.m_txs.push_back(m_pool.end());
                continue;
            }
            if (last_missing < pos) {
                partial.m_missing.ExtendMissing(last_missing, pos - 1);
            }
            basis_pos += d;
            if (basis_pos < 0 || basis_pos >= basis_size) {
                RemoveTxs(std::move(partial.m_txs));
                return false;
            }
            ++partial.m_filled;
            partial.m_txs.push_back(basis->m_txs[basis_pos]);
            ++partial.m_txs.back()->num_templates;
            partial.m_weight += partial.m_txs.back()->weight;
            ++basis_pos;
            last_missing = pos + 1;
        }
        if (last_missing <= pos) {
            partial.m_missing.ExtendMissing(last_missing, pos);
        }
        partial.m_tx_count = partial.m_txs.size();

        if (partial.m_weight > MAX_TEMPLATE_WEIGHT) {
            RemoveTxs(std::move(partial.m_txs));
            return false; // definitely malicious (no short ID ambiguity yet)
        }
    }

    m_partial_peer_templates[nodeid] = std::move(partial);
    return true;
}

bool TemplateManager::PartialFillShortIDs(NodeId nodeid, const uint256& hash,
                                           uint64_t nonce,
                                           const std::vector<uint64_t>& short_ids,
                                           const CTxMemPool& mempool,
                                           ExtraTransactions& extra_txns)
{
    AssertLockNotHeld(mempool.cs);

    auto it = m_partial_peer_templates.find(nodeid);
    if (it == m_partial_peer_templates.end()) return true; // already dropped (e.g. overweight)
    auto& partial = it->second;
    if (partial.m_hash != hash) return true; // stale partial

    if (short_ids.empty()) {
        if (partial.m_tx_count == partial.m_filled) {
            return true; // basis was a perfect match
        } else {
            return false; // should have provided short ids for us
        }
    }

    // Extend partial to final size: tx_count = filled + short_ids
    int32_t tx_count = partial.m_filled + short_ids.size();
    int32_t old_size = partial.m_txs.size();

    // Are there too few shortids to fill known missing elements?
    if (tx_count < old_size) return false;

    // Are there more shortids than known previously missing elements?
    if (tx_count > old_size) {
        partial.m_txs.resize(tx_count, m_pool.end());
        partial.m_missing.ExtendMissing(old_size, tx_count - 1);
    }
    partial.m_tx_count = tx_count;

    // short_ids are in order of unfilled positions
    auto missing = partial.m_missing.GetPositions();
    if (!Assume(missing.size() == short_ids.size())) return false;

    ShortIDHasher hasher(partial.m_hash, nonce);

    // Build short ID to position map
    std::unordered_map<uint64_t, int32_t> sid_to_pos(missing.size());
    for (size_t i = 0; i < missing.size(); ++i) {
        auto [sit, inserted] = sid_to_pos.emplace(short_ids[i], i);
        // Duplicate short IDs: leave both unfilled (will be requested via gettmplttxn)
        if (!inserted) {
            sid_to_pos.erase(sit);
        }
        // Anti-DoS: reject if hash table distribution is highly uneven
        if (sid_to_pos.bucket_size(sid_to_pos.bucket(short_ids[i])) > 12) {
            return false;
        }
    }

    // Match candidates against short IDs
    using Hit = std::variant<bool, CTransactionRef, TemplateTxRef>;
    std::vector<Hit> have_txn(short_ids.size());
    size_t match_count = 0;

    auto try_match = [&](const Wtxid& wtxid, const auto& tx) {
        uint64_t sid = hasher.GetShortID(wtxid);
        auto find_it = sid_to_pos.find(sid);
        if (find_it == sid_to_pos.end()) return;
        int32_t pos = find_it->second;
        auto& have = have_txn[pos];
        if (std::holds_alternative<bool>(have)) {
            if (!std::get<bool>(have)) {
                have = tx;
                ++match_count;
            }
        } else if (std::holds_alternative<CTransactionRef>(have)) {
            if (std::get<CTransactionRef>(have)->GetWitnessHash() != wtxid) {
                // Two different txs match the same short ID: collision, leave unfilled
                have = true;
                --match_count;
            }
        } else if (std::holds_alternative<TemplateTxRef>(have)) {
            if (std::get<TemplateTxRef>(have)->tx->GetWitnessHash() != wtxid) {
                // Two different txs match the same short ID: collision, leave unfilled
                have = true;
                --match_count;
            }
        }
    };

    // Scan template pool (good chance of having all the desired txs)
    for (const auto& [wtxid, ref] : m_scannable_txns) {
        try_match(wtxid, ref);
        if (match_count == sid_to_pos.size()) break;
    }

    // Scan mempool
    if (match_count < sid_to_pos.size()) {
        LOCK(mempool.cs);
        for (const auto& [wtxid, txit] : mempool.txns_randomized) {
            try_match(wtxid, txit->GetSharedTx());
            if (match_count == sid_to_pos.size()) break;
        }
    }

    // Scan extra transactions
    while (match_count < sid_to_pos.size()) {
        auto [wtxid, tx] = extra_txns.next();
        if (!tx) break;
        try_match(*wtxid, *tx);
    }

    // Collect matched txs
    for (size_t i = 0; i < missing.size(); ++i) {
        auto pos = missing[i];
        std::visit(util::Overloaded(
            [&](bool&&) { /* nothing to do */ },
            [&](CTransactionRef&& tx) {
                partial.m_txs[pos] = AddTx(std::move(tx));
                partial.m_weight += partial.m_txs[pos]->weight;
                partial.m_missing.ReceivedTxn(pos);
                ++partial.m_filled;
            },
            [&](TemplateTxRef&& ttx) {
                ++ttx->num_templates;
                partial.m_weight += ttx->weight;
                partial.m_missing.ReceivedTxn(pos);
                ++partial.m_filled;
                partial.m_txs[pos] = std::move(ttx);
            }), std::move(have_txn[i])
        );
    }

    if (partial.m_weight > MAX_TEMPLATE_WEIGHT) {
        ForgetPartialTemplate(nodeid);
        return true; // overweight, likely wrong short ID match; don't disconnect
    }

    return true;
}

bool TemplateManager::PartialFillTxns(NodeId nodeid, const uint256& hash,
                                       std::span<CTransactionRef> txs)
{
    auto it = m_partial_peer_templates.find(nodeid);
    if (it == m_partial_peer_templates.end()) return true; // already dropped (e.g. overweight)
    auto& partial = it->second;
    if (partial.m_hash != hash) return true; // stale partial

    if (partial.m_filled + txs.size() > partial.m_txs.size()) return false;

    auto refs = AddTxs(txs);

    size_t filled = partial.m_missing.FillTxs(partial, refs);
    Assume(filled == refs.size());
    partial.m_filled += filled;

    for (const auto& ref : refs) {
        partial.m_weight += ref->weight;
    }

    if (partial.m_weight > MAX_TEMPLATE_WEIGHT) {
        ForgetPartialTemplate(nodeid);
        return true; // overweight, likely wrong short ID match; don't disconnect
    }

    return true;
}

bool TemplateManager::PartialTryFinalize(NodeId nodeid)
{
    auto it = m_partial_peer_templates.find(nodeid);
    if (it == m_partial_peer_templates.end()) return true; // no partial, nothing to do

    auto& partial = it->second;
    if (!partial.IsComplete()) return true; // still in progress

    // Verify reconstructed hash matches announced hash
    uint256 announced = partial.m_hash;
    partial.ComputeHash();
    if (partial.m_hash != announced) {
        ForgetPartialTemplate(nodeid);
        return false;
    }

    PeerTemplate completed(nodeid, NodeClock::now(), std::move(it->second));
    m_partial_peer_templates.erase(it);

    AddPeerTemplate(std::move(completed));
    return true;
}

std::optional<std::vector<int32_t>> TemplateManager::GetPartialMissing(NodeId nodeid, const uint256& hash) const
{
    auto it = m_partial_peer_templates.find(nodeid);
    if (it == m_partial_peer_templates.end()) return std::nullopt;
    if (it->second.m_hash != hash) return std::nullopt;
    return it->second.m_missing.GetPositions();
}

void TemplateManager::ForgetPartialTemplate(NodeId nodeid)
{
    auto it = m_partial_peer_templates.find(nodeid);
    if (it == m_partial_peer_templates.end()) return;

    RemoveTxs(std::move(it->second.m_txs));
    m_partial_peer_templates.erase(it);
}

void TemplateManager::ForgetPeer(NodeId nodeid)
{
    ForgetPartialTemplate(nodeid);
    m_peer_template_cache.erase(nodeid);
}

void TemplateManager::TrimPeerTemplates(NodeClock::time_point cutoff)
{
    while (!m_peer_templates.empty() && m_peer_templates.back().m_time < cutoff) {
        auto& back = m_peer_templates.back();
        auto it = m_peer_template_cache.find(back.m_nodeid);
        if (it != m_peer_template_cache.end() && it->second == &back) {
            m_peer_template_cache.erase(it);
        }
        RemoveTxs(std::move(back.m_txs));
        m_peer_templates.pop_back();
    }
}

CTransactionRef TemplateManager::GetNextTemplateTx(NodeId nodeid, NodeClock::time_point now,
                                                    const CTxMemPool& mempool,
                                                    const uint256& active_tip_hash,
                                                    const std::map<GenTxid, CTransactionRef>* recent_block_txs,
                                                    size_t& pos_out, size_t& total_out)
{
    const auto* pt = GetPeerTemplate(nodeid);
    if (!pt) return nullptr;

    // Only check recent block txs when the template targets a different tip
    // (if tips match, all template txs are unconfirmed by definition)
    const bool check_recent_block = recent_block_txs && pt->m_tip
        && pt->m_tip->GetBlockHash() != active_tip_hash;

    total_out = pt->m_txs.size();

    // Scan forward from last validated position
    while (pt->m_last_validated_idx < pt->m_txs.size()) {
        const auto& ttx = *pt->m_txs[pt->m_last_validated_idx];

        // Skip txs with future next_mempool_check
        if (now < ttx.next_mempool_check) {
            ++pt->m_last_validated_idx;
            continue;
        }

        // Skip txs already in the mempool (should be the most common case)
        const Wtxid& wtxid = ttx.tx->GetWitnessHash();
        if (mempool.exists(wtxid)) {
            ttx.next_mempool_check = now + 120s;
            ++pt->m_last_validated_idx;
            continue;
        }

        // Skip txs confirmed in a recent block (stale template only)
        if (check_recent_block) {
            auto wit = recent_block_txs->find(GenTxid{wtxid});
            if (wit != recent_block_txs->end()) {
                ttx.next_mempool_check = now + 120s;
                ++pt->m_last_validated_idx;
                continue;
            }
        }

        pos_out = pt->m_last_validated_idx;
        ++pt->m_last_validated_idx;
        return ttx.tx;
    }

    return nullptr;
}

void TemplateManager::BumpMempoolCheck(const Wtxid& wtxid, NodeClock::time_point next)
{
    auto it = m_pool.find(wtxid);
    if (it != m_pool.end()) {
        it->next_mempool_check = next;
    }
}

} // namespace node
