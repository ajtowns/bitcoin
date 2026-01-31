// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <staletips.h>
#include <sync.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <memory>
#include <vector>

namespace {

/** Simple test harness that manages a synthetic block tree for fuzzing StaleTips */
class StaleTipsFuzzer {
private:
    /** Owns all CBlockIndex objects - never removed from to keep pointers stable */
    std::vector<std::unique_ptr<CBlockIndex>> m_blocks;
    /** Current tips of all branches (subset of m_blocks) */
    std::vector<CBlockIndex*> m_tips;
    /** The active chain */
    CChain m_chain;
    /** Counter for unique block hashes */
    uint64_t m_hash_counter{0};
    /** Storage for block hashes (CBlockIndex::phashBlock points here) */
    std::vector<std::unique_ptr<uint256>> m_hashes;

    /** Create a new unique block hash */
    const uint256* NewHash() {
        m_hashes.push_back(std::make_unique<uint256>());
        // Use counter to ensure unique hashes
        *m_hashes.back() = uint256(m_hash_counter++);
        return m_hashes.back().get();
    }

public:
    StaleTips staletips;

    StaleTipsFuzzer() {
        // Create genesis block
        auto genesis = std::make_unique<CBlockIndex>();
        genesis->nHeight = 0;
        genesis->pprev = nullptr;
        genesis->phashBlock = NewHash();
        genesis->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        genesis->nChainWork = arith_uint256(1);
        genesis->BuildSkip();

        CBlockIndex* genesis_ptr = genesis.get();
        m_blocks.push_back(std::move(genesis));
        m_tips.push_back(genesis_ptr);

        // Set genesis as active chain tip
        m_chain.SetTip(*genesis_ptr);
    }

    /** Create a new block extending from a given tip, going back 'back' blocks */
    CBlockIndex* CreateBlock(FuzzedDataProvider& fuzzed, bool have_data) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        if (m_tips.empty()) return nullptr;

        // Pick a tip to extend from
        CBlockIndex* parent_tip = m_tips[fuzzed.ConsumeIntegralInRange<size_t>(0, m_tips.size() - 1)];

        // How far back to branch (0 = extend tip, >0 = create fork)
        int back = fuzzed.ConsumeIntegralInRange<int>(0, std::min(20, parent_tip->nHeight));
        CBlockIndex* parent = parent_tip->GetAncestor(parent_tip->nHeight - back);
        if (parent == nullptr) parent = parent_tip;

        // Create new block
        auto block = std::make_unique<CBlockIndex>();
        block->pprev = parent;
        block->nHeight = parent->nHeight + 1;
        block->phashBlock = NewHash();
        block->nStatus = BLOCK_VALID_TREE;
        if (have_data) {
            block->nStatus |= BLOCK_HAVE_DATA;
        }
        block->nChainWork = parent->nChainWork + arith_uint256(1);
        // Fuzz some header fields that might be checked
        block->hashMerkleRoot = uint256(fuzzed.ConsumeIntegral<uint64_t>());
        block->nTime = fuzzed.ConsumeIntegral<uint32_t>();
        block->nBits = fuzzed.ConsumeIntegral<uint32_t>();
        block->nNonce = fuzzed.ConsumeIntegral<uint32_t>();

        CBlockIndex* block_ptr = block.get();
        m_blocks.push_back(std::move(block));

        // BuildSkip must be called for GetAncestor to work properly
        block_ptr->BuildSkip();

        // Update tips: remove parent_tip if we extended it, add new block
        if (back == 0) {
            // Remove the old tip that we extended
            for (auto it = m_tips.begin(); it != m_tips.end(); ++it) {
                if (*it == parent_tip) {
                    m_tips.erase(it);
                    break;
                }
            }
        }
        m_tips.push_back(block_ptr);

        return block_ptr;
    }

    /** Change the active chain to a different tip */
    void SetActiveTip(FuzzedDataProvider& fuzzed) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        if (m_tips.empty()) return;
        CBlockIndex* new_tip = m_tips[fuzzed.ConsumeIntegralInRange<size_t>(0, m_tips.size() - 1)];
        m_chain.SetTip(*new_tip);
    }

    /** Extend the active chain by one block */
    CBlockIndex* ExtendActiveChain(FuzzedDataProvider& fuzzed) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        CBlockIndex* tip = m_chain.Tip();
        if (tip == nullptr) return nullptr;

        auto block = std::make_unique<CBlockIndex>();
        block->pprev = tip;
        block->nHeight = tip->nHeight + 1;
        block->phashBlock = NewHash();
        block->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        block->nChainWork = tip->nChainWork + arith_uint256(1);
        block->hashMerkleRoot = uint256(fuzzed.ConsumeIntegral<uint64_t>());
        block->nTime = fuzzed.ConsumeIntegral<uint32_t>();
        block->nBits = fuzzed.ConsumeIntegral<uint32_t>();
        block->nNonce = fuzzed.ConsumeIntegral<uint32_t>();

        CBlockIndex* block_ptr = block.get();
        m_blocks.push_back(std::move(block));
        block_ptr->BuildSkip();

        // Update tips
        for (auto it = m_tips.begin(); it != m_tips.end(); ++it) {
            if (*it == tip) {
                *it = block_ptr;
                break;
            }
        }

        m_chain.SetTip(*block_ptr);
        return block_ptr;
    }

    CChain& Chain() { return m_chain; }
};

} // namespace

FUZZ_TARGET(staletips)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    StaleTipsFuzzer fuzzer;

    // Build initial chain of random length
    {
        LOCK(cs_main);
        int initial_chain_length = fuzzed_data_provider.ConsumeIntegralInRange<int>(10, 200);
        for (int i = 0; i < initial_chain_length; ++i) {
            fuzzer.ExtendActiveChain(fuzzed_data_provider);
        }
    }

    uint32_t last_seqno = 0;

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 1000)
    {
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                // Create a new block (potentially a stale branch)
                LOCK(cs_main);
                bool have_data = fuzzed_data_provider.ConsumeBool();
                CBlockIndex* new_block = fuzzer.CreateBlock(fuzzed_data_provider, have_data);
                if (new_block && !fuzzer.Chain().Contains(new_block)) {
                    // It's a stale block, try to add it
                    fuzzer.staletips.AddStaleTip(fuzzer.Chain(), new_block);
                }
            },
            [&] {
                // Extend active chain (may make stale tips ineligible)
                LOCK(cs_main);
                fuzzer.ExtendActiveChain(fuzzed_data_provider);
            },
            [&] {
                // Switch active chain to a different tip (simulates reorg)
                LOCK(cs_main);
                fuzzer.SetActiveTip(fuzzed_data_provider);
            },
            [&] {
                // Query tips to announce
                LOCK(cs_main);
                bool want_blocks = fuzzed_data_provider.ConsumeBool();
                auto [tips, seqno] = fuzzer.staletips.GetTipsToAnnounce(fuzzer.Chain(), last_seqno, want_blocks);
                // Update seqno occasionally
                if (fuzzed_data_provider.ConsumeBool()) {
                    last_seqno = seqno;
                }
                // Verify returned tips are valid
                for (const auto& fork : tips) {
                    assert(fork.fork_point != nullptr);
                    assert(fork.tip != nullptr);
                    assert(fork.tip->nHeight > fork.fork_point->nHeight);
                    // Fork point should be on active chain or at least a valid ancestor
                    assert(fork.tip->HasAncestor(fork.fork_point));
                }
            },
            [&] {
                // Create and add multiple stale tips in succession
                LOCK(cs_main);
                int count = fuzzed_data_provider.ConsumeIntegralInRange<int>(1, 5);
                for (int i = 0; i < count; ++i) {
                    bool have_data = fuzzed_data_provider.ConsumeBool();
                    CBlockIndex* new_block = fuzzer.CreateBlock(fuzzed_data_provider, have_data);
                    if (new_block && !fuzzer.Chain().Contains(new_block)) {
                        fuzzer.staletips.AddStaleTip(fuzzer.Chain(), new_block);
                    }
                }
            });
    }

    // Final check: query all tips
    {
        LOCK(cs_main);
        auto [tips, seqno] = fuzzer.staletips.GetTipsToAnnounce(fuzzer.Chain(), 0, false);
        for (const auto& fork : tips) {
            assert(fork.fork_point != nullptr);
            assert(fork.tip != nullptr);
            // Tip height should be within MAX_HEIGHT_DELTA of chain tip
            int chain_height = fuzzer.Chain().Height();
            assert(fork.tip->nHeight >= chain_height - StaleTips::MAX_HEIGHT_DELTA);
            // Fork length should be within limit
            int fork_length = fork.tip->nHeight - fork.fork_point->nHeight;
            assert(fork_length <= StaleTips::MAX_FORK_LENGTH);
            assert(fork_length > 0);
        }
    }
}
