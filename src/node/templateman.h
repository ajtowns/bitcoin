// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_TEMPLATEMAN_H
#define BITCOIN_NODE_TEMPLATEMAN_H

#include <primitives/transaction.h>
#include <streams.h>
#include <uint256.h>
#include <util/bitset.h>
#include <util/check.h>
#include <util/hasher.h>
#include <util/time.h>

#include <chrono>
#include <cstdint>
#include <deque>
#include <set>
#include <span>
#include <unordered_map>
#include <utility>
#include <vector>

namespace node {

static constexpr int SHORTTXIDS_LENGTH = 6;

/** Maximum number of templates to keep. */
static constexpr size_t MAX_TEMPLATES{10};

/** How frequently to update templates for compact block reconstruction. */
static constexpr auto TEMPLATE_UPDATE_INTERVAL{std::chrono::seconds{30}};

/** Template weight limit (larger than consensus to capture more txs). */
static constexpr unsigned int MAX_TEMPLATE_WEIGHT{8000000};

/** Entry in the shared template tx pool. Ordered by wtxid. */
struct TemplateTx {
    CTransactionRef tx;
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
    uint256 m_hash;                      //!< SHA256 of concatenated wtxids

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
 *  ProcessMessage populates via Queue(); SendMessages drains via GetNextChunk().
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

struct TemplateInfo {
    size_t num_templates{0};
    size_t max_templates{0};
    size_t pool_size{0};
    size_t latest_tx_count{0};
    std::chrono::seconds update_interval{};
    NodeClock::time_point next_update{};
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
    std::deque<LocalTemplate> m_templates;
    NodeClock::time_point m_next_update{NodeClock::time_point::min()};

    /**
     * Vector of (wtxid, iterator) pairs for cache-local linear scans
     * of all transactions in m_pool.
     * The inline wtxid avoids dereferencing the set node during scans,
     * so that use in compact block reconstruction is fast.
     */
    std::vector<std::pair<Wtxid, TemplateTxRef>> m_scannable_txns;

    /** Find transaction in the pool, adding if necessary. Bumps refcount. */
    TemplateTxRef AddTx(CTransactionRef tx);

    /** Find transactions in the pool, adding if necessary. Bumps refcounts. */
    std::vector<TemplateTxRef> AddTxs(std::span<CTransactionRef> txs);

    /** Decrement refcounts and erase txs with zero refs. */
    void RemoveTxs(std::vector<TemplateTxRef>&& vec);

    /** Trim old templates beyond MAX_TEMPLATES. */
    void TrimLocalTemplates();

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
    bool CheckTimer(NodeClock::time_point now)
    {
        if (now < m_next_update) return false;
        m_next_update = now + TEMPLATE_UPDATE_INTERVAL;
        return true;
    }

    /** Get template manager statistics. */
    TemplateInfo GetInfo() const
    {
        TemplateInfo stats;
        stats.num_templates = m_templates.size();
        stats.max_templates = MAX_TEMPLATES;
        stats.pool_size = m_pool.size();
        if (!m_templates.empty()) {
            stats.latest_tx_count = m_templates.back().m_txs.size();
        }
        stats.update_interval = std::chrono::duration_cast<std::chrono::seconds>(TEMPLATE_UPDATE_INTERVAL);
        stats.next_update = m_next_update;
        return stats;
    }
};

} // namespace node

#endif // BITCOIN_NODE_TEMPLATEMAN_H
