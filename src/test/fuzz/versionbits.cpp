// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <primitives/block.h>
#include <util/system.h>
#include <versionbits.h>

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <cstdint>
#include <limits>
#include <memory>
#include <vector>

using State = BIP9DeploymentLogic::State;

namespace {
/** Track blocks mined for test */
class Blocks
{
private:
    std::vector<std::unique_ptr<CBlockIndex>> m_blocks;
    const uint32_t m_start_time;
    const uint32_t m_interval;
    const int32_t m_signal;
    const int32_t m_no_signal;
    uint32_t m_signalling_mask = 0;

    bool Signal(size_t height)
    {
        return (m_signalling_mask >> (height % 32)) & 1;
    }

    CBlockIndex* Tip() const
    {
        return m_blocks.empty() ? nullptr : m_blocks.back().get();
    }

    CBlockIndex* MineBlock(bool signal)
    {
        CBlockHeader header;
        header.nVersion = signal ? m_signal : m_no_signal;
        header.nTime = m_start_time + m_blocks.size() * m_interval;
        header.nBits = 0x1d00ffff;

        auto current_block = std::make_unique<CBlockIndex>(header);
        current_block->pprev = Tip();
        current_block->nHeight = m_blocks.size();
        current_block->BuildSkip();

        return m_blocks.emplace_back(std::move(current_block)).get();
    }

public:
    Blocks(uint32_t start_time, uint32_t interval, int32_t signal, int32_t no_signal)
        : m_start_time{start_time}, m_interval{interval}, m_signal{signal}, m_no_signal{no_signal} {}

    size_t size() const { return m_blocks.size(); }

    void MineBlocks(size_t period, size_t max_blocks, FuzzedDataProvider& fuzzed_data_provider)
    {
        /* Strategy:
         *  * mine some randomised number of prior periods;
         *    with either all or no blocks in the period signalling
         *  * then mine a final period worth of blocks, with
         *    randomised signalling according to a mask
         *
         * We establish the mask first, then consume "bools" until
         * we run out of fuzz data to work out how many prior periods
         * there are and which ones will signal.
         */

        // establish the mask
        m_signalling_mask = fuzzed_data_provider.ConsumeIntegral<uint32_t>();

        // mine prior periods
        while (fuzzed_data_provider.remaining_bytes() > 0) { // early exit; no need for LIMITED_WHILE
            // all blocks in these periods either do or don't signal
            for (size_t b = 0; b < period; ++b) {
                MineBlock(/*signal=*/fuzzed_data_provider.ConsumeBool());
            }

            // don't risk exceeding max_blocks or times may wrap around
            if (size() + 2 * period > max_blocks) break;
        }
        // NOTE: fuzzed_data_provider may be fully consumed at this point and should not be used further

        // mine (period-1) blocks and check state
        for (size_t b = 0; b < period; ++b) {
            MineBlock(Signal(size()));
        }
    }

    const CBlockIndex* FirstBlockInFinalPeriod(size_t period)
    {
        assert(size() > 0);
        const size_t last = size() - 1;
        return m_blocks.at(last - (last % period)).get();
    }

    template<typename Fn>
    void ForEachBlockFinalPeriod(size_t period, const Fn& fn)
    {
        assert(size() > 0);
        const size_t last = size() - 1;
        for (size_t i = last - (last % period); i <= last; ++i) {
            fn(m_blocks.at(i).get(), Signal(i));
        }
    }
};

std::unique_ptr<const CChainParams> g_params;

void initialize()
{
    // this is actually comparatively slow, so only do it once
    g_params = CreateChainParams(ArgsManager{}, CBaseChainParams::MAIN);
    assert(g_params != nullptr);
}

constexpr uint32_t MAX_START_TIME = 4102444800; // 2100-01-01

FUZZ_TARGET_INIT(versionbits, initialize)
{
    const CChainParams& params = *g_params;
    const int64_t interval = params.GetConsensus().nPowTargetSpacing;
    assert(interval > 1); // need to be able to halve it
    assert(interval < std::numeric_limits<int32_t>::max());

    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    // making period/max_periods larger slows these tests down significantly
    const int period = 32;
    const size_t max_periods = 16;
    const size_t max_blocks = 2 * period * max_periods;

    const int threshold = fuzzed_data_provider.ConsumeIntegralInRange(1, period);
    assert(0 < threshold && threshold <= period); // must be able to both pass and fail threshold!

    // too many blocks at 10min each might cause uint32_t time to overflow if
    // block_start_time is at the end of the range above
    assert(std::numeric_limits<uint32_t>::max() - MAX_START_TIME > interval * max_blocks);

    const int64_t block_start_time = fuzzed_data_provider.ConsumeIntegralInRange<uint32_t>(params.GenesisBlock().nTime, MAX_START_TIME);

    // what values for version will we use to signal / not signal?
    const int32_t ver_signal = fuzzed_data_provider.ConsumeIntegral<int32_t>();
    const int32_t ver_nosignal = fuzzed_data_provider.ConsumeIntegral<int32_t>();

    // select deployment parameters: bit, start time, timeout
    const int bit = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, VERSIONBITS_NUM_BITS - 1);

    // Early exit if the versions don't signal sensibly for the deployment
    if (!VersionBits::IsBitSet(bit, ver_signal)) return;
    if (VersionBits::IsBitSet(bit, ver_nosignal)) return;
    if (ver_nosignal < 0) return;

    const bool always_test = fuzzed_data_provider.ConsumeBool();
    const bool always_active_test = (always_test ? fuzzed_data_provider.ConsumeBool() : false);
    const bool never_active_test = (always_test ? !always_active_test : false);

    auto pick_time = [&](int low_block, int high_block) -> int64_t {
        return block_start_time + interval * low_block + fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(0, interval * (high_block - low_block) + interval/2 - 1);
    };

    int64_t start_time;
    int64_t timeout;
    if (always_active_test) {
        start_time = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        timeout = fuzzed_data_provider.ConsumeBool() ? Consensus::BIP9Deployment::NO_TIMEOUT : fuzzed_data_provider.ConsumeIntegral<int64_t>();
    } else if (never_active_test) {
        start_time = Consensus::BIP9Deployment::NEVER_ACTIVE;
        timeout = fuzzed_data_provider.ConsumeBool() ? Consensus::BIP9Deployment::NO_TIMEOUT : fuzzed_data_provider.ConsumeIntegral<int64_t>();
    } else {
        // pick the timestamp to switch based on a block
        // note states will change *after* these blocks because mediantime lags
        start_time = pick_time(0, period * (max_periods - 3));
        timeout = pick_time(0, period * max_periods);
    }
    int min_activation = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, period * max_periods);

    // sanity checks
    assert(period > 0);
    assert(0 <= threshold && threshold <= period);
    assert(0 <= bit && bit < 32 && bit < VERSIONBITS_NUM_BITS);
    assert(0 <= min_activation);

    const auto dep = [&]() {
        Consensus::BIP341Deployment dep;
        dep.bit = bit;
        dep.nStartTime = start_time;
        dep.nTimeout = timeout;
        dep.period = period;
        dep.threshold = threshold;
        dep.min_activation_height = min_activation;
        return dep;
    }();

    const BIP341DeploymentLogic logic(dep);
    BIP341DeploymentLogic::Cache cache;

    // IsBitSet should ensure version will be positive and meet min
    // version requirement
    assert(ver_signal > 0);
    assert(ver_signal >= VERSIONBITS_LAST_OLD_BLOCK_VERSION);

    // Now that we have chosen time and versions, setup to mine blocks
    Blocks blocks(block_start_time, interval, ver_signal, ver_nosignal);
    blocks.MineBlocks(period, max_blocks, fuzzed_data_provider);
    // NOTE: fuzzed_data_provider may be fully consumed at this point and should not be used further

    // now we check the final period looks sane

    // get the info for the first block of the period

    CBlockIndex* prev = blocks.FirstBlockInFinalPeriod(period)->pprev;

    const int orig_since = logic.GetStateSinceHeightFor(cache, prev);
    const State orig_state = logic.GetStateFor(cache, prev);

    // statistics for a null period
    VersionBits::Stats last_stats;
    last_stats.period = period;
    last_stats.threshold = threshold;
    last_stats.count = last_stats.elapsed = 0;
    last_stats.possible = (period >= threshold);
    std::vector<bool> last_signals{};

    int prev_next_height = (prev == nullptr ? 0 : prev->nHeight + 1);
    assert(0 <= orig_since && orig_since <= prev_next_height);

    // count the number of signalling blocks
    int blocks_sig = 0;

    blocks.ForEachBlockFinalPeriod(period, [&](const CBlockIndex* current_block, bool signal) {
        // verify that signalling attempt was interpreted correctly
        assert(logic.Condition(current_block) == signal);

        if (signal) ++blocks_sig;

        const int in_period = (current_block->nHeight % period) + 1;

        // check that after mining this block stats change as expected
        std::vector<bool> signals;
        const auto stats = logic.GetStateStatisticsFor(current_block, &signals);
        const auto stats_no_signals = logic.GetStateStatisticsFor(current_block);
        assert(stats.period == stats_no_signals.period && stats.threshold == stats_no_signals.threshold
               && stats.elapsed == stats_no_signals.elapsed && stats.count == stats_no_signals.count
               && stats.possible == stats_no_signals.possible);

        assert(stats.period == period);
        assert(stats.threshold == threshold);
        assert(stats.elapsed == in_period);
        assert(stats.elapsed == last_stats.elapsed + 1);
        assert(stats.count == last_stats.count + (signal ? 1 : 0));
        assert(stats.count == blocks_sig);
        assert(stats.possible == (stats.count + period >= stats.elapsed + threshold));
        last_stats = stats;

        assert(signals.size() == (size_t)stats.elapsed && stats.elapsed > 0);
        assert(signals.size() == last_signals.size() + 1);
        assert(signals.back() == signal);
        last_signals.push_back(signal);
        assert(signals == last_signals);

        const State state = logic.GetStateFor(cache, current_block);
        const int since = logic.GetStateSinceHeightFor(cache, current_block);
        if (in_period != period) {
            // state and since don't change within the period
            assert(state == orig_state);
            assert(since == orig_since);
        } else {
            // check possible state transition at final block

            // since is straightforward:
            assert(since % period == 0);
            assert(orig_since <= current_block->nHeight);
            assert(0 <= since && since <= current_block->nHeight + 1);
            if (since > 0) {
                assert(!always_active_test && !never_active_test);
            }
            assert(orig_since <= since);
            if (state == orig_state) {
                assert(since == orig_since);
            } else {
                assert(since == current_block->nHeight + 1);
            }
            if (always_active_test || never_active_test) {
                assert(since == 0);
            } else {
                assert((since == 0) == (state == State::DEFINED));
            }

            // state is where everything interesting is
            if (always_active_test) assert(state == State::ACTIVE);
            if (never_active_test) assert(state == State::FAILED);

            switch (state) {
            case State::DEFINED:
                assert(orig_state == State::DEFINED);
                assert(current_block->GetMedianTimePast() < dep.nStartTime);
                break;
            case State::STARTED:
                assert(current_block->GetMedianTimePast() >= dep.nStartTime);
                if (orig_state == State::STARTED) {
                    assert(blocks_sig < threshold);
                    assert(current_block->GetMedianTimePast() < dep.nTimeout);
                } else {
                    assert(orig_state == State::DEFINED);
                }
                break;
            case State::LOCKED_IN:
                if (orig_state == State::LOCKED_IN) {
                    assert(current_block->nHeight + 1 < min_activation);
                } else {
                    assert(orig_state == State::STARTED);
                    assert(blocks_sig >= threshold);
                }
                break;
            case State::ACTIVE:
                assert(always_active_test || min_activation <= current_block->nHeight + 1);
                assert(orig_state == State::ACTIVE || orig_state == State::LOCKED_IN);
                break;
            case State::FAILED:
                assert(never_active_test || current_block->GetMedianTimePast() >= dep.nTimeout);
                if (orig_state == State::STARTED) {
                    assert(blocks_sig < threshold);
                } else {
                    assert(orig_state == State::FAILED);
                }
                break;
            default:
                assert(false);
            }

            if (blocks.size() >= period * max_periods) {
                // we chose the timeout (and block times) so that by the time we have this many blocks it's all over
                assert(state == State::ACTIVE || state == State::FAILED);
            }
        }
    });

}
} // namespace
