// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEMPLATEMAN_H
#define BITCOIN_TEMPLATEMAN_H

#include <blockencodings.h>
#include <node/miner.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <cstdint>
#include <deque>
#include <map>
#include <vector>

/** Template weight limit */
static constexpr unsigned int MAX_TEMPLATE_WEIGHT{MAX_BLOCK_WEIGHT};

struct TemplateTx
{
    CTransactionRef tx;
    uint32_t num_templates{0};

    explicit TemplateTx(CTransactionRef tx) : tx{std::move(tx)} { }
};

using TemplateTxSet = std::map<Wtxid, TemplateTx>;
using TemplateTxRefVec = std::vector<TemplateTxSet::iterator>;

struct MyTemplate {
    uint256 hash;
    TemplateTxRefVec txs;
    CBlockHeaderAndShortTxIDs compact;

    // don't relay this template to peers whose m_last_sequence isn't at least this value
    uint64_t inv_sequence;
    uint32_t weight;
};

class TemplateManager
{
public:
    TemplateTxSet template_txs;

    std::deque<MyTemplate> my_templates;

    size_t NumMyTemplates() const { return my_templates.size(); }

    void DiscardTxs(TemplateTxRefVec& txrv)
    {
        for (auto& it : txrv) {
            if (--it->second.num_templates == 0) {
                template_txs.erase(it);
            }
        }
        txrv.clear();
    }

    void TrimMyTemplates(uint32_t max_templates)
    {
        while (my_templates.size() > max_templates) {
            DiscardTxs(my_templates.back().txs);
            my_templates.pop_back();
        }
    }

    const MyTemplate* GetMyBestTemplate(uint64_t inv_seq)
    {
        for (const auto& mytmp : my_templates) {
            if (inv_seq >= mytmp.inv_sequence) {
                return &mytmp;
            }
        }
        return nullptr;
    }

    const MyTemplate* GetMyTemplate(const uint256& hash, uint64_t inv_seq)
    {
        for (const auto& mytmp : my_templates) {
            if (inv_seq >= mytmp.inv_sequence && mytmp.hash == hash) {
                return &mytmp;
            }
        }
        return nullptr;
    }

    const MyTemplate& AddMyTemplate(uint32_t inv_seq, std::vector<std::unique_ptr<node::CBlockTemplate>>&& block_templates)
    {
        auto& block = block_templates[0]->block;
        assert(block.vtx.size() > 0 && block.vtx[0]->IsCoinBase());
        block.vtx.erase(block.vtx.begin());
        block.nNonce = 0;
        block.nTime = std::numeric_limits<uint32_t>::max();
        block.hashMerkleRoot = BlockMerkleRoot(block);

        auto& new_template = my_templates.emplace_front();
        new_template.hash = block.GetHash();
        new_template.compact = CBlockHeaderAndShortTxIDs(block, FastRandomContext().rand64());
        new_template.weight = 0;
        for (auto& tx : block.vtx) {
            new_template.weight += GetTransactionWeight(*tx);
        }
        new_template.txs = AddTxs(block.vtx);
        new_template.inv_sequence = inv_seq;

        return new_template;
    }

    TemplateTxRefVec AddTxs(const std::vector<CTransactionRef>& txs)
    {
        TemplateTxRefVec result;
        result.reserve(txs.size());
        for (auto& tx : txs) {
            const auto& wtxid = tx->GetWitnessHash();
            auto [it, inserted] = template_txs.try_emplace(wtxid, tx);
            ++it->second.num_templates;
            result.emplace_back(it);
        }
        return result;
    }
};

#endif // BITCOIN_TEMPLATEMAN_H
