// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <staletips.h>

#include <chain.h>
#include <node/blockstorage.h>

#include <algorithm>
#include <set>

StaleTipData::StaleTipData(const StaleFork& fork)
{
    AssertLockHeld(::cs_main);
    m_hash_fork_point = fork.fork_point->GetBlockHash();
    m_have_block = (fork.tip->nStatus & BLOCK_HAVE_DATA);

    if (fork.tip->nHeight <= fork.fork_point->nHeight) return;

    // Build headers in reverse, from tip to fork_point
    const CBlockIndex* pindex = fork.tip;
    size_t index = fork.tip->nHeight - fork.fork_point->nHeight;
    m_headers.resize(index);
    while (index > 0) {
        --index;
        m_headers[index] = {
            .nVersion = pindex->nVersion,
            .hashMerkleRoot = pindex->hashMerkleRoot,
            .nTime = pindex->nTime,
            .nBits = pindex->nBits,
            .nNonce = pindex->nNonce,
        };
        pindex = pindex->pprev;
    }
}

std::pair<uint256, std::vector<CBlockHeader>> StaleTipData::ReconstructHeaders() const
{
    std::vector<CBlockHeader> result;
    result.reserve(m_headers.size());

    uint256 prev_hash = m_hash_fork_point;
    for (const auto& compressed : m_headers) {
        CBlockHeader header;
        header.nVersion = compressed.nVersion;
        header.hashPrevBlock = prev_hash;
        header.hashMerkleRoot = compressed.hashMerkleRoot;
        header.nTime = compressed.nTime;
        header.nBits = compressed.nBits;
        header.nNonce = compressed.nNonce;

        result.push_back(header);
        prev_hash = header.GetHash();
    }

    return {prev_hash, result};
}

bool StaleTips::IsAncestor(const CBlockIndex* ancestor, const CBlockIndex* descendant)
{
    return ancestor->nHeight < descendant->nHeight &&
           ancestor == descendant->GetAncestor(ancestor->nHeight);
}

const CBlockIndex* StaleTips::GetForkPoint(const CChain& chain, const CBlockIndex* stale_tip) const
{
    const CBlockIndex* tip = chain.Tip();
    if (tip == nullptr) return nullptr;
    if (stale_tip->nHeight < tip->nHeight - MAX_HEIGHT_DELTA) return nullptr;

    const CBlockIndex* fork_point = chain.FindFork(stale_tip);
    if (fork_point == nullptr) return nullptr;

    int fork_depth = stale_tip->nHeight - fork_point->nHeight;
    if (fork_depth > MAX_FORK_LENGTH || fork_depth <= 0) return nullptr;

    return fork_point;
}

void StaleTips::Add(const CBlockIndex* stale_tip)
{
    AssertLockHeld(::cs_main);
    bool have_block = (stale_tip->nStatus & BLOCK_HAVE_DATA);

    int target_slot = -1;
    int lowest_height_slot = -1;

    for (size_t i = 0; i < MAX_STALE_TIPS; ++i) {
        if (m_tips[i].pindex == nullptr) {
            if (target_slot == -1) target_slot = i;
            continue;
        }

        const CBlockIndex* existing = m_tips[i].pindex;

        // Already tracking this tip
        if (existing == stale_tip) {
            if (have_block && m_tips[i].block_seqno == 0) {
                m_tips[i].block_seqno = ++m_last_seqno;
            }
            return;
        }

        // New tip extends an existing entry - remove the old one
        if (IsAncestor(existing, stale_tip)) {
            m_tips[i].pindex = nullptr;
            if (target_slot == -1) target_slot = i;
        }
        // New tip is ancestor of existing - don't add it
        else if (IsAncestor(stale_tip, existing)) {
            return;
        }

        // Track lowest height for potential eviction
        if (m_tips[i].pindex != nullptr) {
            if (lowest_height_slot == -1 ||
                m_tips[i].pindex->nHeight < m_tips[lowest_height_slot].pindex->nHeight) {
                lowest_height_slot = i;
            }
        }
    }

    // No empty slot found - evict lowest height if new tip is higher
    if (target_slot == -1) {
        if (lowest_height_slot != -1 &&
            stale_tip->nHeight > m_tips[lowest_height_slot].pindex->nHeight) {
            target_slot = lowest_height_slot;
        } else {
            return; // New tip is worse than all existing tips
        }
    }

    m_tips[target_slot].pindex = stale_tip;
    m_tips[target_slot].header_seqno = ++m_last_seqno;
    m_tips[target_slot].block_seqno = have_block ? m_last_seqno : 0;
}

void StaleTips::Initialize(node::BlockManager& blockman, const CChain& chain)
{
    AssertLockHeld(::cs_main);
    const CBlockIndex* tip = chain.Tip();
    if (tip == nullptr) return;

    const int min_height = std::max<int>(tip->nHeight - MAX_HEIGHT_DELTA, 0);

    std::set<const CBlockIndex*> candidates;
    std::set<const CBlockIndex*> has_children;

    for (const auto& [hash, block_index] : blockman.m_block_index) {
        if (!block_index.IsValid(BLOCK_VALID_TREE)) continue;
        if (block_index.nHeight < min_height) continue;
        if (chain.Contains(&block_index)) continue; // Skip blocks on active chain

        if (GetForkPoint(chain, &block_index) != nullptr) {
            candidates.insert(&block_index);
            if (block_index.pprev != nullptr) {
                has_children.insert(block_index.pprev);
            }
        }
    }

    // Only add tips (blocks with no children in our candidate set)
    for (const CBlockIndex* pindex : candidates) {
        if (!has_children.contains(pindex)) {
            Add(pindex);
        }
    }
}

void StaleTips::AddStaleTip(const CChain& chain, const CBlockIndex* stale_tip)
{
    AssertLockHeld(::cs_main);
    if (stale_tip == nullptr) return;
    if (GetForkPoint(chain, stale_tip) == nullptr) return;
    Add(stale_tip);
}

std::pair<std::vector<StaleFork>, uint32_t> StaleTips::GetTipsToAnnounce(
    const CChain& chain,
    uint32_t last_announced_seqno,
    bool want_blocks) const
{
    AssertLockHeld(::cs_main);
    std::vector<StaleFork> result;

    for (const auto& entry : m_tips) {
        if (entry.pindex == nullptr) continue;

        uint32_t relevant_seqno = want_blocks ? entry.block_seqno : entry.header_seqno;
        if (relevant_seqno == 0) continue; // No seqno means not ready (for blocks mode)
        if (relevant_seqno <= last_announced_seqno) continue;

        const CBlockIndex* fork_point = GetForkPoint(chain, entry.pindex);
        if (fork_point != nullptr) {
            result.push_back({fork_point, entry.pindex});
        }
    }

    return {result, m_last_seqno};
}
