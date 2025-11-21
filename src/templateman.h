// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEMPLATEMAN_H
#define BITCOIN_TEMPLATEMAN_H

#include <blockencodings.h>
#include <net.h>
#include <node/miner.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>
#include <util/time.h>

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

struct MyTemplatePart {
    TemplateTxRefVec txs;
    uint256 hash;
    CBlockHeaderAndShortTxIDs compact;
};

struct MyTemplate {
    std::array<MyTemplatePart, 2> parts; // parts[1].txs.empty() if only one part

    // don't relay this template to peers whose m_last_sequence isn't at least this value
    uint64_t inv_sequence;
    uint32_t weight;

    uint32_t Parts() const {
        uint32_t n = 0;
        for (const auto& part : parts) {
            if (part.txs.empty()) break;
            ++n;
        }
        return n;
    }

    uint32_t Txs() const {
        uint32_t txs = 0;
        for (const auto& part : parts) {
            if (part.txs.empty()) break;
            txs += part.txs.size();
        }
        return txs;
    }

    CSerializedNetMsg MakeHeaderAndIdNetMsg(std::string msg_type) const
    {
        CSerializedNetMsg msg;
        msg.m_type = std::move(msg_type);
        VectorWriter vw{msg.data, 0};
        WriteCompactSize(vw, Parts());
        for (const auto& part : parts) {
            if (part.txs.empty()) break;
            vw << part.compact;
        }
        return msg;
    }
};

struct PeerTemplate {
    NodeId nodeid;
    NodeClock::time_point recv_time;
    TemplateTxRefVec txs;
    size_t last_validated_idx{0};
};

class TemplateManager
{
public:
    TemplateTxSet template_txs;

    std::deque<MyTemplate> my_templates;
    std::deque<PeerTemplate> peer_templates;

    using PeerTemplateIt = std::deque<PeerTemplate>::iterator;

    std::unordered_map<NodeId, PeerTemplateIt> map_peer_to_template;

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
            for (auto& part : my_templates.back().parts) {
                if (!part.txs.empty()) {
                    DiscardTxs(part.txs);
                }
            }
            my_templates.pop_back();
        }
    }

    const MyTemplate* GetMyBestTemplate()
    {
        return my_templates.empty() ? nullptr : &my_templates.front();
    }

    const MyTemplatePart* GetMyTemplatePart(const uint256& hash, uint64_t inv_seq)
    {
        for (const auto& mytmp : my_templates) {
            if (inv_seq >= mytmp.inv_sequence) {
                for (const auto& mypart : mytmp.parts) {
                    if (!mypart.txs.empty() && mypart.hash == hash) {
                        return &mypart;
                    }
                }
            }
        }
        return nullptr;
    }

    const MyTemplate& AddMyTemplate(uint32_t inv_seq, std::vector<std::unique_ptr<node::CBlockTemplate>>&& block_templates)
    {
        // always create a new template, even if it's empty, so that we
        // we expire out old templates

        auto& new_template = my_templates.emplace_front();
        new_template.weight = 0;
        new_template.inv_sequence = inv_seq;

        for (size_t i = 0; i < new_template.parts.size(); ++i) {
            if (i >= block_templates.size()) break;

            auto& block = block_templates[i]->block;

            // no coinbase, 0 nonce, max timestamp, calc merkleroot, prevhash
            if (block.vtx.size() > 0 && block.vtx[0]->IsCoinBase()) {
                block.vtx.erase(block.vtx.begin());
            }
            block.nNonce = 0;
            block.nTime = std::numeric_limits<uint32_t>::max();
            block.hashMerkleRoot = BlockMerkleRoot(block);
            if (i > 1) {
                block.hashPrevBlock = new_template.parts[i-1].hash;
            }

            new_template.parts[i].hash = block.GetHash();
            new_template.parts[i].compact = CBlockHeaderAndShortTxIDs(block, FastRandomContext().rand64());
            AddTxs(new_template.parts[i].txs, block.vtx);
            for (auto& tx : block.vtx) {
                new_template.weight += GetTransactionWeight(*tx);
            }
        }
        return new_template;
    }

    void AddPeerTemplate(NodeId nodeid, NodeClock::time_point now, const std::vector<CTransactionRef>& txs)
    {
        PeerTemplate& peertmp = peer_templates.emplace_back(nodeid, now);
        AddTxs(peertmp.txs, txs);
        map_peer_to_template.insert_or_assign(nodeid, peer_templates.end() - 1);
    }

    void ExtendPeerTemplate(NodeId nodeid, const std::vector<CTransactionRef>& txs)
    {
        if (auto it = map_peer_to_template.find(nodeid); it != map_peer_to_template.end()) {
            AddTxs(it->second->txs, txs);
        }
    }

    void DiscardPeerTemplate(PeerTemplateIt peertmpit) {
        if (auto it = map_peer_to_template.find(peertmpit->nodeid); it != map_peer_to_template.end()) {
            if (it->second == peertmpit) {
                map_peer_to_template.erase(it);
            }
        }
        DiscardTxs(peertmpit.txs);
    }

    void AddTxs(TemplateTxRefVec& track, const std::vector<CTransactionRef>& txs)
    {
        track.reserve(track.size() + txs.size());
        for (auto& tx : txs) {
            const auto& wtxid = tx->GetWitnessHash();
            auto [it, inserted] = template_txs.try_emplace(wtxid, tx);
            ++it->second.num_templates;
            track.emplace_back(it);
        }
    }
};

#endif // BITCOIN_TEMPLATEMAN_H
