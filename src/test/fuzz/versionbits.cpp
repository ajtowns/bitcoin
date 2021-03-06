// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <primitives/block.h>
#include <versionbits.h>

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace {
class TestConditionChecker : public ThresholdConditionChecker
{
private:
    mutable ThresholdConditionCache m_cache;

public:
    TestConditionChecker(const Consensus::BIP9Deployment& dep, int period, int threshold) : ThresholdConditionChecker(dep, period, threshold) { assert(m_threshold <= m_period); }

    ThresholdState GetStateFor(const CBlockIndex* pindexPrev) const { return ThresholdConditionChecker::GetStateFor(pindexPrev, m_cache); }
    int GetStateSinceHeightFor(const CBlockIndex* pindexPrev) const { return ThresholdConditionChecker::GetStateSinceHeightFor(pindexPrev, m_cache); }
};
} // namespace

static void initialize()
{
    SelectParams(CBaseChainParams::MAIN);
}

FUZZ_TARGET_INIT(versionbits, initialize)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    // const Consensus::Params& params = Params().GetConsensus();

    const int period = 100; // params.nMinerConfirmationWindow;
    const int threshold = 90; // params.nRuleChangeActivationThreshold;

    assert(0 < threshold && threshold <= period - 2);

    const size_t n_blocks = period * 23;

    // pick the timestamp to switch based on a block
    // note states will change *after* these blocks because mediantime lags
    int start_block = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, period * 20);
    int end_block = fuzzed_data_provider.ConsumeIntegralInRange<int>(start_block, period * 20);

    // between genesis and 2100-01-01
    const uint32_t block_start_time = fuzzed_data_provider.ConsumeIntegralInRange<uint32_t>(1231006505, 4102444800);

    // otherwise 10min blocks might cause uint32_t time to overflow if
    // block_start_time is at the end of the region
    assert(n_blocks < 320000);

    Consensus::BIP9Deployment dep;
    dep.bit = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, VERSIONBITS_NUM_BITS-1);
    dep.nStartTime = block_start_time + start_block*600;
    dep.nTimeout = block_start_time + end_block*600;
    dep.min_activation_height = 0;

    TestConditionChecker checker(dep, period, threshold);

    int32_t ver_signal = fuzzed_data_provider.ConsumeIntegral<int32_t>();
    int32_t ver_nosignal = fuzzed_data_provider.ConsumeIntegral<int32_t>();

    // just early abort if the versions don't signal right
    auto is_signalling = [&](int32_t ver) { return (ver & checker.Mask()) != 0 && (ver & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS; };
    if (!is_signalling(ver_signal)) return;
    if (is_signalling(ver_nosignal)) return;
    if (ver_nosignal < 0) return;
    assert(ver_signal > 0);

    // DEFINED -> STARTED/FAILED -> LOCKED_IN/FAILED -> ACTIVE
    //  signal bits, non-signal bits (choice from 4?)
    //  what block do we bump the time to starttime/timeout
    //    -- have predictable block times, and this is equal to choosing the times
    //  for each retarget period, how many blocks signal? first block signal? last block signal?

    std::vector<CBlockIndex*> blocks;
    std::optional<ThresholdState> last_state = std::nullopt;
    int last_since = 0;
    std::optional<BIP9Stats> last_stats = std::nullopt;

    int total_signalling = 0;
    int middle_signalling = 0;
    bool first_signals = false;
    bool last_signals = false;
    int signalling_offset = period/2;

    while (blocks.size() < n_blocks) {
        const int block_offset = blocks.size() % period;

        const CBlockIndex* prev = blocks.empty() ? nullptr : blocks.back();

        if (block_offset == 0 || block_offset == 1 || last_state == ThresholdState::STARTED || blocks.size() % 19 == 3) {
            const ThresholdState state = checker.GetStateFor(prev);
            const int since = checker.GetStateSinceHeightFor(prev);
            const BIP9Stats stats = checker.GetStateStatisticsFor(prev);

            if (!last_state) {
                assert(state == ThresholdState::DEFINED);
                assert(since == 0);
            } else if (state == last_state) {
                assert(since == last_since);
            } else {
                assert(since >= last_since);
                assert((size_t)since == blocks.size());
                assert(block_offset == 0);

                switch(state) {
                case ThresholdState::DEFINED:
                    assert(false);
                    break;
                case ThresholdState::STARTED:
                    assert(last_state == ThresholdState::DEFINED);
                    break;
                case ThresholdState::LOCKED_IN:
                    assert(last_state == ThresholdState::STARTED);
                    break;
                case ThresholdState::ACTIVE:
                    assert(last_state == ThresholdState::LOCKED_IN);
                    assert(since == last_since + period);
                    break;
                case ThresholdState::FAILED:
                    assert(last_state == ThresholdState::STARTED || last_state == ThresholdState::DEFINED);
                    break;
                }
            }

            if (block_offset == 0 && last_state == ThresholdState::STARTED) {
                assert(last_stats && last_stats->elapsed == period - 1);
                assert(last_stats->count == first_signals + middle_signalling);
                if (total_signalling >= threshold) {
                    // could be FAILED or LOCKED_IN, depending on timeout
                    assert(state != ThresholdState::STARTED);
                } else {
                    // could be FAILED or STARTED
                    assert(state != ThresholdState::LOCKED_IN);
                }
            }

            assert(stats.period == period);
            assert(stats.threshold == threshold);
            if (state == ThresholdState::STARTED) {
                // GetStateStatistics is only interesting if we're in STARTED
                assert(0 <= stats.elapsed && stats.elapsed < period);
                assert(stats.elapsed == block_offset);
                assert(0 <= stats.count && stats.count <= stats.elapsed);
                assert(stats.possible == (stats.elapsed - stats.count <= stats.period - stats.threshold));

                if (block_offset > 0 && last_stats) {
                    assert(stats.elapsed == last_stats->elapsed + 1);
                    assert(stats.count == last_stats->count || stats.count == last_stats->count + 1);
                    if (last_stats->possible) {
                        assert(stats.possible || last_stats->count == stats.count);
                    } else {
                        assert(!stats.possible);
                    }
                }

                last_stats = stats;
            } else {
                last_stats = std::nullopt;
            }

            if (prev != nullptr && block_offset == 0) {
                int64_t prev_mtp = prev->GetMedianTimePast();
                if (prev_mtp >= dep.nTimeout) {
                    assert(state == ThresholdState::ACTIVE || state == ThresholdState::FAILED);
                } else if (prev_mtp >= dep.nStartTime) {
                    assert(state != ThresholdState::DEFINED);
                }
            }

            last_state = state;
            last_since = since;
        }

        if (block_offset == 0) {
            int x = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, (period-1) * 4);

            first_signals = (x & 1);
            last_signals = (x & 2);

            // bias towards edge cases:
            middle_signalling = x / 4 - 1;
            if (last_state == ThresholdState::STARTED) {
                if (middle_signalling == -1) middle_signalling = threshold - 1;
                // if neither first or last signals, will not meet threshold,
                // if only one does, will exactly meet threshold,
                // if both first and last signal, will exceed threshld by 1
            } else {
                if (middle_signalling < 0) middle_signalling = 0;
            }

            assert(middle_signalling <= period - 2);

            signalling_offset = (period - middle_signalling) / 2;
            assert(signalling_offset > 0); // no overlap with first signal
            assert(signalling_offset + middle_signalling < period); // no overlap with last signal

            total_signalling = middle_signalling + first_signals + last_signals;
            assert(0 <= total_signalling && total_signalling <= period);
        }

        bool signal = false;
        if (block_offset == 0 && first_signals) signal = true;
        if (block_offset + 1 == period && last_signals) signal = true;
        if (block_offset >= signalling_offset && block_offset < signalling_offset + middle_signalling) signal = true;

        CBlockHeader header;
        header.nVersion = signal ? ver_signal : ver_nosignal;
        header.nTime = block_start_time + blocks.size() * 600;
        header.nBits = 0x1d00ffff;

        CBlockIndex* current_block = new CBlockIndex{header};
        current_block->pprev = blocks.empty() ? nullptr : blocks.back();
        current_block->nHeight = blocks.size();
        current_block->BuildSkip();

        assert(checker.Condition(current_block) == signal);

        blocks.push_back(current_block);
    }

    assert(last_state == ThresholdState::ACTIVE || last_state == ThresholdState::FAILED);

    for (auto& v : blocks) {
        delete v;
        v = nullptr;
    }
}
