// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_STALE_TIPS_H
#define BITCOIN_STALE_TIPS_H

#include <chain.h>
#include <kernel/cs_main.h>
#include <node/blockstorage.h>

#include <algorithm>
#include <set>
#include <deque>

class StaleTips
{
private:
    static constexpr int MAX_STALE_TIPS{10};

    static constexpr int MAX_HEIGHT_DELTA{1000};
    static constexpr int MAX_FORK_LENGTH{20};

    struct StaleTipInfo {
        const CBlockIndex* staletip{nullptr};
        uint32_t header_order{0};
        uint32_t block_order{0};
    };

    uint32_t m_count_header{0};
    uint32_t m_count_block{0};
    std::array<StaleTipInfo, MAX_STALE_TIPS> m_tips{};

    void Add(const CBlockIndex* pindex) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        StaleTipInfo* sti = nullptr;
        for (StaleTipInfo& s : m_tips) {
            if (s.staletip == pindex) {
                sti = &s; // update existing entry is the best possible case
                break;
            }
            if (s.staletip == nullptr) {
                if (sti == nullptr || sti->staletip != nullptr) {
                    sti = &s; // second best possible case
                }
                continue;
            }
            if (sti->staletip == nullptr) continue; // already got a good candidate
            if (s.staletip->nHeight >= pindex->nHeight) continue; // wouldn't replace this one
            if (sti != nullptr) {
                // we have an existing candidate; is it a better choice?
                if (s.staletip->nHeight > sti->staletip->nHeight) continue;
                if (s.staletip->nHeight == sti->staletip->nHeight && s.header_order >= sti->header_order) continue;
            }
            sti = &s;
        }

        if (sti == nullptr) return; // this stale block is worse than all our stale blocks

        if (sti->staletip == pindex) {
            // no op; updating block_order only
        } else {
            sti->staletip = pindex;
            sti->header_order = ++m_count_header;
            sti->block_order = 0;
        }
        if (sti->block_order == 0 && pindex->IsValid(BLOCK_VALID_TRANSACTIONS)) {
            sti->block_order = ++m_count_block;
        }
    }

public:
    StaleTips() = default;

    void Initialize(node::BlockManager& blockman, const CChain& chain) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        const CBlockIndex* tip = chain.Tip();
        const int tip_height = (tip == nullptr ? 0 : tip->nHeight);
        std::set<const CBlockIndex*, CompareBlocksByHeight> stale_tips;
        {
            const int min_height = std::max<int>(tip_height - MAX_HEIGHT_DELTA, 0);
            std::set<const CBlockIndex*> orphans;
            std::set<const CBlockIndex*> prevs;
            for (const auto& [_, block_index] : blockman.m_block_index) {
                if (!block_index.IsValid(BLOCK_VALID_TREE)) continue;
                if (block_index.nHeight < min_height) continue;
                if (chain.Contains(&block_index)) {
                    orphans.insert(&block_index);
                    prevs.insert(block_index.pprev);
                }
            }
            for (const auto& pindex : orphans) {
                if (prevs.erase(pindex) == 0) {
                    int length = 1;
                    const CBlockIndex* prev = pindex->pprev;
                    while (prev != nullptr && !chain.Contains(prev) && length <= MAX_FORK_LENGTH) {
                        ++length;
                        prev = prev->pprev;
                    }
                    if (length <= MAX_FORK_LENGTH) {
                        stale_tips.insert(pindex);
                        while (stale_tips.size() > MAX_STALE_TIPS) {
                            stale_tips.erase(std::prev(stale_tips.end()));
                        }
                    }
                }
            }
        }
        for (const auto& pindex : stale_tips) {
            Add(pindex);
        }
    }

    void AddStaleTip(const CChain& chain, const CBlockIndex* stale_tip) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        const CBlockIndex* tip = chain.Tip();
        const int tip_height = (tip == nullptr ? 0 : tip->nHeight);
        if (stale_tip == nullptr || stale_tip->nHeight < tip_height - MAX_HEIGHT_DELTA) return;

        int fork_length = 0;
        const CBlockIndex* bi = stale_tip;
        while (bi != nullptr && !chain.Contains(bi)) {
            if (++fork_length > MAX_FORK_LENGTH) return;
            bi = bi->pprev;
        }
        Add(stale_tip);
    }

    void CleanUp(int tip_height)
    {
        for (StaleTipInfo& s : m_tips) {
            if (s.staletip == nullptr) continue;
            if (s.staletip->nHeight < tip_height - MAX_HEIGHT_DELTA) {
                s.staletip = nullptr;
            }
        }
    }

    std::pair<uint32_t, std::vector<const CBlockIndex*>> GetStaleTipHeaders(uint32_t since) const
    {
        std::vector<const CBlockIndex*> res;
        if (since == 0) since = 1;
        if (m_count_header > since) {
            for (const auto& tipinfo : m_tips) {
                if (tipinfo.staletip == nullptr) continue;
                if (tipinfo.header_order >= since) res.push_back(tipinfo.staletip);
            }
        }
        return {m_count_header, res};
    }

    std::pair<uint32_t, std::vector<const CBlockIndex*>> GetStaleTipBlocks(uint32_t since) const
    {
        std::vector<const CBlockIndex*> res;
        if (since == 0) since = 1;
        if (m_count_block > since) {
            for (const auto& tipinfo : m_tips) {
                if (tipinfo.staletip == nullptr) continue;
                if (tipinfo.block_order >= since) res.push_back(tipinfo.staletip);
            }
        }
        return {m_count_block, res};
    }

};

#endif // BITCOIN_STALE_TIPS_H
