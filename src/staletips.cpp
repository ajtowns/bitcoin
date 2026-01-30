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

const CBlockIndex* StaleTips::GetEligibleForkPoint(const CChain& chain, const CBlockIndex* stale_tip) const
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

    Entry* target_slot = nullptr;

    for (size_t i = 0; i < MAX_STALE_TIPS; ++i) {
        if (m_tips[i].pindex == nullptr) {
            if (target_slot == nullptr) target_slot = &m_tips[i];
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

        if (IsAncestor(existing, stale_tip)) {
            // New tip extends an existing entry - remove the old one
            m_tips[i].pindex = nullptr;
            if (target_slot == nullptr) target_slot = &m_tips[i];
            continue;
        } else if (IsAncestor(stale_tip, existing)) {
            // New tip is ancestor of existing - don't add it
            return;
        }

        // Replace a lower-height stale tip if we haven't found an empty slot
        if (target_slot == nullptr || target_slot->pindex != nullptr) {
            auto height_limit = (target_slot == nullptr ? stale_tip->nHeight : target_slot->pindex->nHeight);
            if (m_tips[i].pindex->nHeight < height_limit) {
                target_slot = &m_tips[i];
            }
        }
    }
    if (target_slot != nullptr) {
        target_slot->pindex = stale_tip;
        target_slot->header_seqno = ++m_last_seqno;
        target_slot->block_seqno = have_block ? m_last_seqno : 0;
    }
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
        if (!block_index.IsValid(BLOCK_VALID_TREE)) continue; // Insufficiently connected
        if (block_index.nHeight < min_height) continue; // Too old to be interesting
        if (chain.Contains(&block_index)) continue; // Skip blocks on active chain

        if (GetEligibleForkPoint(chain, &block_index) != nullptr) {
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
    if (GetEligibleForkPoint(chain, stale_tip) == nullptr) return;
    Add(stale_tip);
}

std::pair<std::vector<StaleFork>, uint32_t> StaleTips::GetTipsToAnnounce(
    const CChain& chain,
    uint32_t last_announced_seqno,
    bool want_blocks)
{
    AssertLockHeld(::cs_main);
    std::vector<StaleFork> result;

    for (auto& entry : m_tips) {
        if (entry.pindex == nullptr) continue;

        uint32_t relevant_seqno = want_blocks ? entry.block_seqno : entry.header_seqno;
        if (relevant_seqno <= last_announced_seqno) continue;

        const CBlockIndex* fork_point = GetEligibleForkPoint(chain, entry.pindex);
        if (fork_point == nullptr) {
            // No longer eligible (too old, no longer stale, etc), clear it
            entry.pindex = nullptr;
        } else {
            result.push_back({fork_point, entry.pindex});
        }
    }

    return {result, m_last_seqno};
}
