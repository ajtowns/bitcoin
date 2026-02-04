// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <staletips.h>
#include <streams.h>
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

/** Generate a plausible nBits value: (A << 24) | B where A in [0x10, 0x1d], B in [0x0100, 0xffff] */
uint32_t ConsumePlausibleNBits(FuzzedDataProvider& provider)
{
    uint32_t exponent = provider.ConsumeIntegralInRange<uint8_t>(0x10, 0x1d);
    uint32_t mantissa = provider.ConsumeIntegralInRange<uint16_t>(0x0100, 0xffff);
    return (exponent << 24) | mantissa;
}

CBlockHeader ConsumeBlockHeaderForStaleTips(FuzzedDataProvider& provider, uint256 prev_hash, uint32_t default_nbits, uint32_t min_difficulty_nbits)
{
    CBlockHeader header;
    header.nVersion = 4;
    header.hashPrevBlock = prev_hash;
    header.hashMerkleRoot = uint256(provider.ConsumeIntegral<uint8_t>());
    header.nTime = provider.ConsumeIntegral<decltype(header.nTime)>();
    // Occasionally use min difficulty to test testnet rejection path
    header.nBits = provider.ConsumeBool() ? min_difficulty_nbits : default_nbits;
    header.nNonce = provider.ConsumeIntegral<decltype(header.nNonce)>();
    return header;
}

/** Create a duplicate header variation (same pprev + merkle root, different nonce) */
CBlockHeader CreateDuplicateVariation(FuzzedDataProvider& provider, const CBlockIndex* original)
{
    CBlockHeader header;
    header.nVersion = original->nVersion;
    header.hashPrevBlock = original->pprev ? original->pprev->GetBlockHash() : uint256{};
    header.hashMerkleRoot = original->hashMerkleRoot;  // Same merkle root
    header.nTime = original->nTime;
    header.nBits = original->nBits;
    header.nNonce = original->nNonce + 1 + provider.ConsumeIntegral<uint8_t>();
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

    // Pick chain type to test different code paths (signet, testnet, mainnet)
    ChainType chain_type = fuzzed_data_provider.PickValueInArray<ChainType>(
        {ChainType::MAIN, ChainType::SIGNET, ChainType::TESTNET, ChainType::TESTNET4});
    SelectParams(chain_type);

    // Compute nBits values for this chain
    uint32_t min_difficulty_nbits = UintToArith256(Params().GetConsensus().powLimit).GetCompact();
    uint32_t default_nbits = ConsumePlausibleNBits(fuzzed_data_provider);

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
    uint32_t last_announced_seqno = 0;
    uint32_t last_observed_seqno = 0;  // For checking monotonicity

    // we want to only call staletips.Initialize() once, and not call other
    // functions until we've called that
    bool have_initialized = false;

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 1000)
    {
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                if (!have_initialized) {
                    // Initialize (tests Initialize with existing stale tips)
                    LOCK(cs_main);
                    staletips.Initialize(chain_type, blockman, chainman.ActiveChain());
                    have_initialized = true;
                }
            },
            [&] {
                // Create a new block (potentially a stale branch)
                LOCK(cs_main);
                CBlockIndex* prev_block = PickValue(fuzzed_data_provider, blocks);
                if (!(prev_block->nStatus & BLOCK_FAILED_MASK)) {
                    CBlockHeader header = ConsumeBlockHeaderForStaleTips(fuzzed_data_provider, prev_block->GetBlockHash(), default_nbits, min_difficulty_nbits);
                    CBlockIndex* index = blockman.AddToBlockIndex(header, chainman.m_best_header);
                    bool have_data = fuzzed_data_provider.ConsumeBool();
                    if (have_data) {
                        index->nStatus |= BLOCK_HAVE_DATA;
                    }
                    blocks.push_back(index);

                    // Try to add as stale tip if not on active chain
                    if (have_initialized && !chainman.ActiveChain().Contains(index)) {
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
                CBlockHeader header = ConsumeBlockHeaderForStaleTips(fuzzed_data_provider, tip->GetBlockHash(), default_nbits, min_difficulty_nbits);
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
                // Query tips to announce and verify invariants
                if (!have_initialized) return;

                LOCK(cs_main);
                bool want_blocks = fuzzed_data_provider.ConsumeBool();
                auto [tips, seqno] = staletips.GetTipsToAnnounce(chainman.ActiveChain(), last_announced_seqno, want_blocks);

                // Sequence number must never decrease, and is always positive
                assert(seqno > 0);
                assert(seqno >= last_observed_seqno);
                last_observed_seqno = seqno;

                if (fuzzed_data_provider.ConsumeBool()) {
                    last_announced_seqno = seqno;
                }

                int chain_height = chainman.ActiveChain().Height();
                for (const auto& fork : tips) {
                    // Basic structure checks
                    assert(fork.fork_point != nullptr);
                    assert(fork.tip != nullptr);
                    assert(fork.tip->HasAncestor(fork.fork_point));

                    // fork_point must be on active chain
                    assert(chainman.ActiveChain().Contains(fork.fork_point));

                    // tip must NOT be on active chain (that's what makes it stale)
                    assert(!chainman.ActiveChain().Contains(fork.tip));

                    // Fork length must be within limits
                    int fork_length = fork.tip->nHeight - fork.fork_point->nHeight;
                    assert(fork_length > 0);
                    assert(fork_length <= TEST_MAX_FORK_LENGTH);

                    // Tip must be within height delta of active chain tip
                    assert(fork.tip->nHeight >= chain_height - TEST_MAX_HEIGHT_DELTA);

                    // On signet, tips must have block data
                    if (chain_type == ChainType::SIGNET) {
                        assert(fork.tip->nStatus & BLOCK_HAVE_DATA);
                    }

                    // On testnet, tips must have sufficient difficulty
                    if (chain_type == ChainType::TESTNET || chain_type == ChainType::TESTNET4) {
                        arith_uint256 tip_target;
                        tip_target.SetCompact(fork.tip->nBits);
                        assert(tip_target <= UintToArith256(StaleTips::MAX_TIP_TARGET));
                    }

                    // Test StaleTipData round-trip
                    StaleTipData data(fork);
                    auto [tip_hash, headers] = data.ReconstructHeaders();
                    assert(headers.size() == static_cast<size_t>(fork_length));
                    // Verify reconstructed tip hash matches original
                    assert(tip_hash == fork.tip->GetBlockHash());

                    // Test serialization round-trip
                    DataStream ss{};
                    ss << data;
                    StaleTipData deserialized;
                    ss >> deserialized;
                    assert(deserialized == data);
                }
            },
            [&] {
                // Re-add an existing stale tip (tests "already tracking" path)
                if (!have_initialized) return;

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
                        CBlockHeader dup_header = CreateDuplicateVariation(fuzzed_data_provider, original);
                        CBlockIndex* dup = blockman.AddToBlockIndex(dup_header, chainman.m_best_header);
                        bool have_data = fuzzed_data_provider.ConsumeBool();
                        if (have_data) {
                            dup->nStatus |= BLOCK_HAVE_DATA;
                        }
                        blocks.push_back(dup);
                        if (have_initialized && !chainman.ActiveChain().Contains(dup)) {
                            staletips.AddStaleTip(chainman.ActiveChain(), dup);
                        }
                    }
                }
            },
            [&] {
                // Simulate receiving block data for a tip we only had headers for
                // This tests the "already tracking + now have block data" path (line 147)
                if (!have_initialized) return;

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

    // Final invariant check on all tips
    {
        LOCK(cs_main);
        auto [tips, seqno] = staletips.GetTipsToAnnounce(chainman.ActiveChain(), 0, false);

        if (!have_initialized) {
            assert(tips.empty());
            assert(seqno == 1);
        }

        // Final seqno should still be monotonic and positive
        assert(seqno > 0);
        assert(seqno >= last_observed_seqno);

        int chain_height = chainman.ActiveChain().Height();
        for (const auto& fork : tips) {
            assert(fork.fork_point != nullptr);
            assert(fork.tip != nullptr);
            assert(fork.tip->HasAncestor(fork.fork_point));
            assert(chainman.ActiveChain().Contains(fork.fork_point));
            assert(!chainman.ActiveChain().Contains(fork.tip));

            int fork_length = fork.tip->nHeight - fork.fork_point->nHeight;
            assert(fork_length > 0);
            assert(fork_length <= TEST_MAX_FORK_LENGTH);
            assert(fork.tip->nHeight >= chain_height - TEST_MAX_HEIGHT_DELTA);

            if (chain_type == ChainType::SIGNET) {
                assert(fork.tip->nStatus & BLOCK_HAVE_DATA);
            }
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
