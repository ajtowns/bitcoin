// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// TODO: Add signet fuzz coverage to exercise CheckVariantHeader and
// signet-specific code paths in Add() and AddStaleTip().

#include <chain.h>
#include <chainparams.h>
#include <staletips.h>
#include <sync.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <uint256.h>
#include <validation.h>

#include <memory>
#include <vector>

namespace {

const TestingSetup* g_staletips_setup;

CBlockHeader ConsumeBlockHeaderForStaleTips(FuzzedDataProvider& provider, uint256 prev_hash, int& nonce_counter)
{
    CBlockHeader header;
    header.nVersion = provider.ConsumeIntegral<decltype(header.nVersion)>();
    header.hashPrevBlock = prev_hash;
    header.hashMerkleRoot = uint256(provider.ConsumeIntegral<uint64_t>());
    header.nTime = provider.ConsumeIntegral<decltype(header.nTime)>();
    header.nBits = Params().GenesisBlock().nBits;
    header.nNonce = nonce_counter++;
    return header;
}

/** Create a duplicate header variation (same pprev + merkle root, different nonce) */
CBlockHeader CreateDuplicateVariation(FuzzedDataProvider& provider, const CBlockIndex* original, int& nonce_counter)
{
    CBlockHeader header;
    header.nVersion = provider.ConsumeIntegral<decltype(header.nVersion)>();
    header.hashPrevBlock = original->pprev ? original->pprev->GetBlockHash() : uint256{};
    header.hashMerkleRoot = original->hashMerkleRoot;  // Same merkle root
    header.nTime = provider.ConsumeIntegral<decltype(header.nTime)>();
    header.nBits = original->nBits;
    header.nNonce = nonce_counter++;  // Different nonce -> different hash
    return header;
}

} // namespace

void initialize_staletips()
{
    static const auto testing_staletips_setup = MakeNoLogFileContext<const TestingSetup>();
    g_staletips_setup = testing_staletips_setup.get();
}

FUZZ_TARGET(staletips, .init = initialize_staletips)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    SetMockTime(ConsumeTime(fuzzed_data_provider));

    auto& chainman = static_cast<TestChainstateManager&>(*g_staletips_setup->m_node.chainman);
    auto& blockman = static_cast<TestBlockManager&>(chainman.m_blockman);
    CBlockIndex* genesis = chainman.ActiveChainstate().m_chain[0];

    int nonce_counter = 0;
    std::vector<CBlockIndex*> blocks;
    blocks.push_back(genesis);

    // Track stale tips we've added for re-adding tests
    std::vector<CBlockIndex*> added_stale_tips;
    // Track tips added without block data (for testing "now have block" path)
    std::vector<CBlockIndex*> tips_without_block_data;

    // Use smaller limits to make edge cases reachable with shorter chains
    constexpr int TEST_MAX_HEIGHT_DELTA{40};
    constexpr int TEST_MAX_FORK_LENGTH{10};
    StaleTips staletips{TEST_MAX_HEIGHT_DELTA, TEST_MAX_FORK_LENGTH};
    uint32_t last_seqno = 0;

    // Build initial chain
    {
        LOCK(cs_main);
        int initial_length = fuzzed_data_provider.ConsumeIntegralInRange<int>(10, 100);
        CBlockIndex* prev = genesis;
        for (int i = 0; i < initial_length; ++i) {
            CBlockHeader header = ConsumeBlockHeaderForStaleTips(fuzzed_data_provider, prev->GetBlockHash(), nonce_counter);
            CBlockIndex* index = blockman.AddToBlockIndex(header, chainman.m_best_header);
            index->nStatus |= BLOCK_HAVE_DATA;
            blocks.push_back(index);
            chainman.ActiveChain().SetTip(*index);
            prev = index;
        }
    }

    // Initialize StaleTips (tests Initialize() code path and sets m_is_signet)
    {
        LOCK(cs_main);
        staletips.Initialize(Params().GetChainType(), blockman, chainman.ActiveChain());
    }

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 1000)
    {
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                // Create a new block (potentially a stale branch)
                LOCK(cs_main);
                CBlockIndex* prev_block = PickValue(fuzzed_data_provider, blocks);
                if (!(prev_block->nStatus & BLOCK_FAILED_MASK)) {
                    CBlockHeader header = ConsumeBlockHeaderForStaleTips(fuzzed_data_provider, prev_block->GetBlockHash(), nonce_counter);
                    CBlockIndex* index = blockman.AddToBlockIndex(header, chainman.m_best_header);
                    bool have_data = fuzzed_data_provider.ConsumeBool();
                    if (have_data) {
                        index->nStatus |= BLOCK_HAVE_DATA;
                    }
                    blocks.push_back(index);

                    // Try to add as stale tip if not on active chain
                    if (!chainman.ActiveChain().Contains(index)) {
                        if (staletips.AddStaleTip(chainman.ActiveChain(), index)) {
                            added_stale_tips.push_back(index);
                            // Track tips without block data for later "now have block" test
                            if (!have_data) {
                                tips_without_block_data.push_back(index);
                            }
                        }
                    }
                }
            },
            [&] {
                // Extend active chain
                LOCK(cs_main);
                CBlockIndex* tip = chainman.ActiveChain().Tip();
                CBlockHeader header = ConsumeBlockHeaderForStaleTips(fuzzed_data_provider, tip->GetBlockHash(), nonce_counter);
                CBlockIndex* index = blockman.AddToBlockIndex(header, chainman.m_best_header);
                index->nStatus |= BLOCK_HAVE_DATA;
                blocks.push_back(index);
                chainman.ActiveChain().SetTip(*index);
            },
            [&] {
                // Switch active chain to a different block (simulates reorg)
                LOCK(cs_main);
                CBlockIndex* new_tip = PickValue(fuzzed_data_provider, blocks);
                if (!(new_tip->nStatus & BLOCK_FAILED_MASK) && (new_tip->nStatus & BLOCK_HAVE_DATA)) {
                    chainman.ActiveChain().SetTip(*new_tip);
                }
            },
            [&] {
                // Query tips to announce and test StaleTipData
                LOCK(cs_main);
                bool want_blocks = fuzzed_data_provider.ConsumeBool();
                auto [tips, seqno] = staletips.GetTipsToAnnounce(chainman.ActiveChain(), last_seqno, want_blocks);
                if (fuzzed_data_provider.ConsumeBool()) {
                    last_seqno = seqno;
                }
                // Test StaleTipData constructor and ReconstructHeaders for each fork
                for (const auto& fork : tips) {
                    assert(fork.fork_point != nullptr);
                    assert(fork.tip != nullptr);
                    assert(fork.tip->nHeight > fork.fork_point->nHeight);
                    assert(fork.tip->HasAncestor(fork.fork_point));

                    StaleTipData data(fork);
                    auto [tip_hash, headers] = data.ReconstructHeaders();
                    assert(headers.size() == static_cast<size_t>(fork.tip->nHeight - fork.fork_point->nHeight));
                }
            },
            [&] {
                // Re-add an existing stale tip (tests "already tracking" path)
                LOCK(cs_main);
                if (!added_stale_tips.empty()) {
                    CBlockIndex* tip = PickValue(fuzzed_data_provider, added_stale_tips);
                    staletips.AddStaleTip(chainman.ActiveChain(), tip);
                }
            },
            [&] {
                // Create a duplicate header variation (tests signet CheckVariantHeader)
                LOCK(cs_main);
                if (!added_stale_tips.empty()) {
                    CBlockIndex* original = PickValue(fuzzed_data_provider, added_stale_tips);
                    if (original->pprev) {
                        CBlockHeader dup_header = CreateDuplicateVariation(fuzzed_data_provider, original, nonce_counter);
                        CBlockIndex* dup = blockman.AddToBlockIndex(dup_header, chainman.m_best_header);
                        bool have_data = fuzzed_data_provider.ConsumeBool();
                        if (have_data) {
                            dup->nStatus |= BLOCK_HAVE_DATA;
                        }
                        blocks.push_back(dup);
                        if (!chainman.ActiveChain().Contains(dup)) {
                            staletips.AddStaleTip(chainman.ActiveChain(), dup);
                        }
                    }
                }
            },
            [&] {
                // Re-initialize (tests Initialize with existing stale tips)
                LOCK(cs_main);
                staletips.Initialize(Params().GetChainType(), blockman, chainman.ActiveChain());
            },
            [&] {
                // Simulate receiving block data for a tip we only had headers for
                // This tests the "already tracking + now have block data" path (line 147)
                LOCK(cs_main);
                if (!tips_without_block_data.empty()) {
                    size_t idx = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, tips_without_block_data.size() - 1);
                    CBlockIndex* tip = tips_without_block_data[idx];
                    // Set block data flag
                    tip->nStatus |= BLOCK_HAVE_DATA;
                    // Re-add - should trigger block_seqno update
                    staletips.AddStaleTip(chainman.ActiveChain(), tip);
                    // Remove from tracking list
                    tips_without_block_data.erase(tips_without_block_data.begin() + idx);
                }
            });
    }

    // Final check
    {
        LOCK(cs_main);
        auto [tips, seqno] = staletips.GetTipsToAnnounce(chainman.ActiveChain(), 0, false);
        for (const auto& fork : tips) {
            assert(fork.fork_point != nullptr);
            assert(fork.tip != nullptr);
            int chain_height = chainman.ActiveChain().Height();
            assert(fork.tip->nHeight >= chain_height - TEST_MAX_HEIGHT_DELTA);
            int fork_length = fork.tip->nHeight - fork.fork_point->nHeight;
            assert(fork_length <= TEST_MAX_FORK_LENGTH);
            assert(fork_length > 0);
        }
    }

    // Cleanup for next iteration
    {
        LOCK(cs_main);
        chainman.m_best_header = genesis;
        chainman.ActiveChain().SetTip(*genesis);
        blockman.m_blocks_unlinked.clear();
        blockman.CleanupForFuzzing();
        // Delete all blocks but Genesis
        uint256 genesis_hash = genesis->GetBlockHash();
        for (auto it = blockman.m_block_index.begin(); it != blockman.m_block_index.end();) {
            if (it->first != genesis_hash) {
                it = blockman.m_block_index.erase(it);
            } else {
                ++it;
            }
        }
    }
}
