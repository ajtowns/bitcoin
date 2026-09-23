// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/templateman.h>
#include <node/templateman_impl.h>
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
#include <iostream>
#include <ranges>
#include <type_traits>
#include <unordered_set>
#include <variant>


namespace node {

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

static SipHasher13UJ MakeShortIDHasher(const uint256& tip_hash, uint64_t nonce)
{
    DataStream ds{};
    ds << tip_hash << nonce;
    uint256 key;
    CSHA256{}.Write(MakeUCharSpan(ds)).Finalize(key.begin());
    return SipHasher13UJ{key.GetUint64(0), key.GetUint64(1)};
}

ShortIDHasher::ShortIDHasher(const uint256& tip_hash, uint64_t nonce)
    : m_hasher{MakeShortIDHasher(tip_hash, nonce)} {}

uint64_t ShortIDHasher::GetShortID(const Wtxid& wtxid) const
{
    uint64_t h{m_hasher.Hash(wtxid.ToUint256())};

    // This function gives a 46-bit value that's never 0:
    // (h >> 18) gives a 46-bit value;
    //  - if it's 0 then the low-18 bits of h left shifted will be >= h, adding 1
    //  - if it's 2**46-1 then the low-18 bits of h left shifted will be < h, and not add 1
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

GRVector TemplateTxnsSelection::GREncode() const
{
    size_t n = Count();
    if (n == 0) return {};

    uint8_t P = static_cast<uint8_t>(std::bit_width(std::max<size_t>(1, m_positions.size() * CHUNK_SIZE / n - 1)) - 1);
    uint64_t pos = 0;
    size_t chunk_idx = 0;
    auto chunk_it = m_positions[chunk_idx].begin();

    return GRVectorEncode(P, [&]() -> std::optional<uint64_t> {
        while (chunk_idx < m_positions.size() && chunk_it == m_positions[chunk_idx].end()) {
            ++chunk_idx;
            if (chunk_idx < m_positions.size()) chunk_it = m_positions[chunk_idx].begin();
        }
        if (chunk_idx < m_positions.size()) {
            uint64_t old = pos + 1;
            pos = chunk_idx * CHUNK_SIZE + *chunk_it + 1;
            ++chunk_it;
            return pos - old;
        } else {
            return std::nullopt;
        }
    });
}

void TemplateTxnsSelection::GRDecode(const GRVector& grenc)
{
    Reset();

    uint64_t pos = 0;
    GRVectorDecode(grenc, [&](uint64_t delta) {
        pos += delta;
        if (std::max(pos, delta) >= MAX_TEMPLATE_TXS) throw std::ios_base::failure("GRDecode: position out of range");
        Add(static_cast<uint32_t>(pos));
        ++pos;
    });
}

bool RequestedTemplateTxns::Queue(const uint256& hash, const LocalTemplate& tmpl, const GRVector& grenc)
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

bool PeerTemplatePartial::CompletedSuccessfully() const
{
    return m_missing.empty() && ComputeHash() == m_hash;
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

std::pair<bool, CTransactionRef> PeerTemplate::ConsumePendingParents(const CTransaction& tx) const
{
    // First pass: find a single package parent for 1p1c.
    // Dedupe to handle txs spending multiple outputs of the same parent.
    CTransactionRef package_parent{nullptr};
    bool usable{true};
    for (const auto& txin : tx.vin) {
        auto it = m_pending_parents.find(txin.prevout.hash);
        if (it == m_pending_parents.end()) continue;

        if (usable) {
            if (package_parent == nullptr) {
                if (!it->second.package_candidate) {
                    usable = false;
                } else {
                    package_parent = it->second.tx;
                }
            } else if (package_parent->GetHash() != txin.prevout.hash) {
                // spending multiple outputs of the same tx is fine
            } else {
                // but spending multiple txs isn't 1p1c
                usable = false;
                package_parent.reset();
            }
        }

        // Decrement remaining children as we go.
        // No dedupe: nchildren counted with duplicates, so decrement with duplicates.
        if (--it->second.remaining_children == 0) {
            m_pending_parents.erase(it);
        }
    }

    return {usable, std::move(package_parent)};
}

void PeerTemplate::StashPendingParent(CTransactionRef tx, uint32_t nchildren, bool package_candidate) const
{
    const auto& txid = tx->GetHash();
    m_pending_parents.emplace(txid, PendingParent{std::move(tx), nchildren, package_candidate});
}


// Explicit instantiation of the production (full-capacity) class templates.
// Other translation units see only declarations; test/fuzz modules include
// templateman_impl.h directly for small-capacity instantiations.
template class LocalTemplateT<SKETCH_CAPACITY>;
template class PeerTemplateSketchT<SKETCH_CAPACITY>;
template class TemplateManagerT<SKETCH_CAPACITY>;

void MempoolSequenceTrack::Track(const CTxMemPool& mempool, NodeClock::time_point now)
{
    if (now < m_last_mempool_sequence) m_last_mempool_sequence = now; // time skip
    if (m_last_mempool_sequence + (MIN_TEMPLATE_TX_AGE*2/5) <= now) {
        m_last_mempool_sequence = now;
        std::ranges::copy(m_mempool_sequences.begin()+1, m_mempool_sequences.end(), m_mempool_sequences.begin());
        LOCK(mempool.cs);
        m_mempool_sequences.back() = mempool.GetSequence();
    }
}

} // namespace node
