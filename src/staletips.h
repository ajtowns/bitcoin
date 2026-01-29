// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_STALE_TIPS_H
#define BITCOIN_STALE_TIPS_H

#include <chain.h>
#include <kernel/cs_main.h>
#include <primitives/block.h>
#include <serialize.h>

#include <array>
#include <vector>

namespace node {
class BlockManager;
}

/** Mode for stale tip sharing with a peer */
enum class StaleTipMode {
    NONE,    //!< Don't share stale tips
    HEADERS, //!< Share headers immediately when we learn of them
    BLOCKS,  //!< Only share after we have full block data
};

/** A stale fork: the fork point on the active chain and the tip of the stale branch */
struct StaleFork {
    const CBlockIndex* fork_point;
    const CBlockIndex* tip;
};

/** Compressed block header for serialization (omits hashPrevBlock which can be reconstructed) */
struct CompressedBlockHeader {
    int32_t nVersion;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;

    SERIALIZE_METHODS(CompressedBlockHeader, obj)
    {
        READWRITE(obj.nVersion, obj.hashMerkleRoot, obj.nTime, obj.nBits, obj.nNonce);
    }
};

/** Serializable data for a stale tip announcement */
class StaleTipData {
public:
    uint256 m_hash_fork_point;
    std::vector<CompressedBlockHeader> m_headers;
    bool m_have_block{false};

    StaleTipData() = default;
    explicit StaleTipData(const StaleFork& fork) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Reconstruct tip hash and full headers from compressed form */
    std::pair<uint256, std::vector<CBlockHeader>> ReconstructHeaders() const;

    SERIALIZE_METHODS(StaleTipData, obj)
    {
        READWRITE(obj.m_hash_fork_point, obj.m_headers, obj.m_have_block);
    }
};

/** Cache of recent stale tips to share with peers */
class StaleTips
{
private:
    static constexpr size_t MAX_STALE_TIPS{10};
    static constexpr int MAX_HEIGHT_DELTA{1000};
    static constexpr int MAX_FORK_LENGTH{20};

    struct Entry {
        const CBlockIndex* pindex{nullptr};
        uint32_t header_seqno{0};
        uint32_t block_seqno{0};
    };

    std::array<Entry, MAX_STALE_TIPS> m_tips{};
    uint32_t m_last_seqno{0};

    /** Check if ancestor is an ancestor of descendant */
    static bool IsAncestor(const CBlockIndex* ancestor, const CBlockIndex* descendant);

    /** Returns fork_point if stale_tip is eligible, nullptr otherwise */
    const CBlockIndex* GetForkPoint(const CChain& chain, const CBlockIndex* stale_tip) const;

    void Add(const CBlockIndex* stale_tip) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

public:
    StaleTips() = default;

    void Initialize(node::BlockManager& blockman, const CChain& chain) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    void AddStaleTip(const CChain& chain, const CBlockIndex* stale_tip) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Get stale tips to announce, filtering by mode and sequence number */
    std::pair<std::vector<StaleFork>, uint32_t> GetTipsToAnnounce(
        const CChain& chain,
        uint32_t last_announced_seqno,
        bool want_blocks) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    uint32_t GetLastSeqno() const { return m_last_seqno; }
};

#endif // BITCOIN_STALE_TIPS_H
