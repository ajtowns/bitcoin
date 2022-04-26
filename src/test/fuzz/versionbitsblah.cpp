// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
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

using State = BIPBlahDeploymentLogic::StateCode;

namespace {
constexpr size_t MAX_BLOCKS = 2048;

/** Track blocks mined for test */
class Blocks
{
private:
    std::vector<std::unique_ptr<CBlockIndex>> m_blocks;
    std::array<uint256, MAX_BLOCKS> m_blockhash;
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
        assert(size() + 1 < MAX_BLOCKS);

        CBlockHeader header;
        header.nVersion = signal ? m_signal : m_no_signal;
        header.nTime = m_start_time + m_blocks.size() * m_interval;
        header.nBits = 0x1d00ffff;
        if (size() > 0) {
            header.hashPrevBlock = m_blockhash.at(size()-1);
        }

        m_blockhash.at(size()) = ArithToUint256(uint64_t{size()});

        auto current_block = std::make_unique<CBlockIndex>(header);
        current_block->phashBlock = &m_blockhash.at(size());
        current_block->pprev = Tip();
        current_block->nHeight = m_blocks.size();
        current_block->BuildSkip();

        return m_blocks.emplace_back(std::move(current_block)).get();
    }

public:
    Blocks(Blocks&&) = delete;
    Blocks(const Blocks&) = delete;

    Blocks(uint32_t start_time, uint32_t interval, int32_t signal, int32_t no_signal)
        : m_start_time{start_time}, m_interval{interval}, m_signal{signal}, m_no_signal{no_signal}
    {
        m_blocks.reserve(MAX_BLOCKS);
    }

    size_t size() const { return m_blocks.size(); }

    const uint256& GetBlockHash(size_t height) { assert(height < size()); return m_blockhash.at(height); }

    void MineBlocks(size_t period, FuzzedDataProvider& fuzzed_data_provider)
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
                assert(size()+1 < MAX_BLOCKS);
                MineBlock(/*signal=*/fuzzed_data_provider.ConsumeBool());
            }

            // don't risk exceeding max_blocks or times may wrap around
            if (size() + 2 * period >= MAX_BLOCKS) break;
        }
        // NOTE: fuzzed_data_provider may be fully consumed at this point and should not be used further

        // mine (period-1) blocks and check state
        for (size_t b = 0; b < period; ++b) {
            assert(size()+1 < MAX_BLOCKS);
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


int64_t g_genesis_time = 0;
int64_t g_interval = 600;

void initialize()
{
    std::unique_ptr<const CChainParams> g_params;
    // this is actually comparatively slow, so only do it once
    g_params = CreateChainParams(ArgsManager{}, CBaseChainParams::MAIN);
    assert(g_params != nullptr);
    g_genesis_time = g_params->GenesisBlock().nTime;
    g_interval = g_params->GetConsensus().nPowTargetSpacing;
}

constexpr uint32_t MAX_START_TIME = 4102444800; // 2100-01-01

FUZZ_TARGET_INIT(versionbitsblah, initialize)
{
    const int64_t interval = g_interval;
    assert(interval > 1); // need to be able to halve it
    assert(interval < std::numeric_limits<int32_t>::max());

    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    // making period/max_periods larger slows these tests down significantly
    constexpr int period = 32;
    constexpr size_t max_periods = 16;
    static_assert(MAX_BLOCKS >= period*max_periods);

    // too many blocks at 10min each might cause uint32_t time to overflow if
    // block_start_time is at the end of the range above
    assert(std::numeric_limits<uint32_t>::max() - MAX_START_TIME > interval * MAX_BLOCKS);

    const int64_t block_start_time = fuzzed_data_provider.ConsumeIntegralInRange<uint32_t>(g_genesis_time, MAX_START_TIME);

    // what values for version will we use to signal / not signal?
    const int32_t ver_signal = fuzzed_data_provider.ConsumeIntegral<int32_t>();
    const int32_t ver_nosignal = fuzzed_data_provider.ConsumeIntegral<int32_t>();

    // select deployment parameters: bit, start time, timeout
    const int bit = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, VERSIONBITS_NUM_BITS - 1);

    // Early exit if the versions don't signal sensibly for the deployment
    if (!VersionBits::IsBitSet(bit, ver_signal)) return;
    if (VersionBits::IsBitSet(bit, ver_nosignal)) return;
    if (ver_nosignal < 0) return;

    auto pick_time = [&](int low_block, int high_block) -> int64_t {
        return block_start_time + interval * low_block + fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(0, interval * (high_block - low_block) + interval/2 - 1);
    };

    // sanity checks
    assert(period > 0);
    assert(0 <= bit && bit < 32 && bit < VERSIONBITS_NUM_BITS);

    const bool always_test = fuzzed_data_provider.ConsumeBool();
    const bool always_active_test = (always_test ? fuzzed_data_provider.ConsumeBool() : false);
    const bool never_active_test = (always_test ? !always_active_test : false);

    const int optout_block_height = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, period * (max_periods - 4) + period/2);
    const bool optout_correct_block = fuzzed_data_provider.ConsumeBool();

    const auto optin_dep = [&]() {
        Consensus::BIPBlahDeployment dep;

        dep.period = period;
        dep.bit = bit;
        dep.optin_threshold = fuzzed_data_provider.ConsumeIntegralInRange(0, period + 1);
        dep.optout_threshold = fuzzed_data_provider.ConsumeIntegralInRange(0, period + 1);

        if (always_active_test) {
            dep.optin_start = Consensus::BIPBlahDeployment::ALWAYS_ACTIVE;
            dep.optin_timeout = fuzzed_data_provider.ConsumeBool() ? Consensus::BIPBlahDeployment::NO_TIMEOUT : fuzzed_data_provider.ConsumeIntegral<int64_t>();
        } else if (never_active_test) {
            dep.optin_start = Consensus::BIPBlahDeployment::NEVER_ACTIVE;
            dep.optin_timeout = fuzzed_data_provider.ConsumeBool() ? Consensus::BIPBlahDeployment::NO_TIMEOUT : fuzzed_data_provider.ConsumeIntegral<int64_t>();
        } else {
            // pick the timestamp to switch
            dep.optin_start = pick_time(0, period * (max_periods - 5));
            dep.optin_timeout = pick_time(0, period * (max_periods - 4));
            dep.optin_earliest_activation = pick_time(0, period * (max_periods - 1));

            dep.optout_block_height = 0;
            dep.optout_block_hash = uint256::ZERO;
            const int64_t optout_block_time = block_start_time + interval * optout_block_height;
            const int64_t target_optout_signal = pick_time(optout_block_height, period * (max_periods - 3));
            const int64_t target_optout_active = fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(target_optout_signal, block_start_time + interval * period * (max_periods - 2));
            dep.optout_delay_mins = (target_optout_signal - optout_block_time)/60;
            dep.optout_delay_activation_mins = (target_optout_active - target_optout_signal)/60;
        }
        return dep;
    }();

    // IsBitSet should ensure version will be positive and meet min
    // version requirement
    assert(ver_signal > 0);
    assert(ver_signal >= VERSIONBITS_LAST_OLD_BLOCK_VERSION);

    // Now that we have chosen time and versions, setup to mine blocks
    Blocks blocks(block_start_time, interval, ver_signal, ver_nosignal);
    blocks.MineBlocks(period, fuzzed_data_provider);
    // NOTE: fuzzed_data_provider may be fully consumed at this point and should not be used further

    const auto dep = [&]() {
        Consensus::BIPBlahDeployment dep{optin_dep};
        dep.optout_block_height = optout_block_height;
        if (optout_correct_block && optout_block_height < (int)blocks.size()) {
            dep.optout_block_hash = blocks.GetBlockHash(optout_block_height);
        } else {
            dep.optout_block_hash = uint256::ZERO;
        }
        return dep;
    }();

    const BIPBlahDeploymentLogic logic(dep), optin_logic(optin_dep);
    BIPBlahDeploymentLogic::Cache cache, optin_cache;

    // now we check the final period looks sane

    // get the info for the first block of the period

    const CBlockIndex* prev = blocks.FirstBlockInFinalPeriod(period)->pprev;

    const int orig_since = logic.GetStateSinceHeightFor(cache, prev);
    const auto orig_state = logic.GetStateFor(cache, prev);

    // statistics for a null period
    VersionBits::Stats last_stats;
    last_stats.period = period;
    last_stats.threshold = dep.optin_threshold;
    last_stats.count = last_stats.elapsed = 0;
    last_stats.possible = (last_stats.period >= last_stats.threshold);
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
        const auto state = logic.GetStateFor(cache, current_block);
        const int since = logic.GetStateSinceHeightFor(cache, current_block);
        std::vector<bool> signals;
        const auto stats = logic.GetStateStatisticsFor(current_block, state, &signals);
        const auto stats_no_signals = logic.GetStateStatisticsFor(current_block, state);
        assert(stats.period == stats_no_signals.period && stats.threshold == stats_no_signals.threshold
               && stats.elapsed == stats_no_signals.elapsed && stats.count == stats_no_signals.count
               && stats.possible == stats_no_signals.possible);

        assert(stats.period == period);
        if (state.code == State::OPT_OUT || state.code == State::OPT_OUT_WAIT) {
            assert(stats.threshold == dep.optout_threshold);
        } else {
            assert(stats.threshold == dep.optin_threshold);
        }

        assert(stats.elapsed == in_period);
        assert(stats.elapsed == last_stats.elapsed + 1);
        assert(stats.count == last_stats.count + (signal ? 1 : 0));
        assert(stats.count == blocks_sig);

        if (stats.threshold > stats.period) {
            assert(!stats.possible);
        } else {
            assert(stats.possible == (stats.elapsed - stats.count <= stats.period - stats.threshold));
        }

        last_stats = stats;

        assert(signals.size() == (size_t)stats.elapsed && stats.elapsed > 0);
        assert(signals.size() == last_signals.size() + 1);
        assert(signals.back() == signal);
        last_signals.push_back(signal);
        assert(signals == last_signals);

        if (in_period != period) {
            // state and since don't change within the period
            assert(state == orig_state);
            assert(since == orig_since);
        } else {
            // check consitency with optin-only deployment params
            const auto optin_state = optin_logic.GetStateFor(optin_cache, current_block);
            const int optin_since = optin_logic.GetStateSinceHeightFor(optin_cache, current_block);
            std::vector<bool> optin_signals;
            const auto optin_stats = optin_logic.GetStateStatisticsFor(current_block, optin_state, &optin_signals);

            assert(stats.period == optin_stats.period
                   && stats.elapsed == optin_stats.elapsed && stats.count == optin_stats.count);
            if (optin_stats.threshold > optin_stats.period) {
                assert(!optin_stats.possible);
            } else {
                assert(optin_stats.possible == (optin_stats.elapsed - optin_stats.count <= optin_stats.period - optin_stats.threshold));
            }
            if (optin_state.code == state.code) {
                assert(optin_state.data == state.data);
                if (state.code == State::FAILED) {
                    assert(optin_since <= since);
                } else {
                    assert(optin_since == since);
                }
                assert(optin_stats.threshold == stats.threshold);
                assert(state.code != State::OPT_OUT_WAIT && state.code != State::OPT_OUT);
            } else {
                assert(optin_state.code == State::FAILED);
                assert(optin_state.data == 0);
                assert(optin_since <= since);
                assert(state.code == State::OPT_OUT_WAIT || state.code == State::OPT_OUT || state.code == State::LOCKED_IN || state.code == State::ACTIVE);
                assert(optin_stats.threshold == optin_dep.optin_threshold);
            }
            assert(optin_signals == signals);

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
                assert((since == 0) == (state.code == State::DEFINED));
            }

            // state is where everything interesting is
            if (always_active_test) assert(state.code == State::ACTIVE);
            if (never_active_test) assert(state.code == State::FAILED);

            // state data only changes when state code does
            if (state.code == orig_state.code) {
                assert(state.data == orig_state.data);
            }

            switch (state.code) {
            case State::DEFINED:
                assert(state.data == 0);
                assert(orig_state.code == State::DEFINED);
                assert(current_block->GetMedianTimePast() < dep.optin_start);
                break;
            case State::OPT_IN:
                assert(state.data == 0);
                assert(current_block->GetMedianTimePast() >= dep.optin_start);
                if (orig_state.code == State::OPT_IN) {
                    assert(blocks_sig < dep.optin_threshold);
                    assert(current_block->GetMedianTimePast() < dep.optin_timeout);
                } else {
                    assert(orig_state.code == State::DEFINED);
                }
                break;
            case State::OPT_OUT_WAIT:
                assert(dep.optout_block_height % period == 0); // unreachable otherwise
                assert(state.data == 0);
                assert(current_block->nHeight < dep.optout_block_height);
                if (orig_state.code == State::OPT_IN) {
                    assert(blocks_sig < dep.optin_threshold);
                    assert(current_block->GetMedianTimePast() >= dep.optin_timeout);
                } else {
                    assert(orig_state.code == State::OPT_OUT_WAIT);
                }
                break;
            case State::OPT_OUT: // count if first block in period has MTP greater than data
                assert(dep.optout_block_height % period == 0 && optout_correct_block); // unreachable otherwise
                assert(dep.optout_block_height <= current_block->nHeight);
                assert(dep.optout_block_hash == blocks.GetBlockHash(dep.optout_block_height));
                if (orig_state.code == State::OPT_OUT) {
                    const CBlockIndex* first_block = current_block->GetAncestor(current_block->nHeight + 1 - period);
                    assert(first_block->GetMedianTimePast() < state.data * 60);
                } else {
                    assert(orig_state.code == State::OPT_OUT_WAIT);
                    assert(current_block->nHeight + 1 == dep.optout_block_height + period);
                }
                break;
            case State::LOCKED_IN: // switch to ACTIVE when MTP greater than data
                if (orig_state.code == State::LOCKED_IN) {
                    assert(current_block->GetMedianTimePast() < state.data * 60);
                } else {
                    if (orig_state.code == State::OPT_IN) {
                        assert(blocks_sig >= dep.optin_threshold);
                    } else {
                        assert(orig_state.code == State::OPT_OUT);
                        assert(blocks_sig < dep.optout_threshold);
                    }
                }
                break;
            case State::ACTIVE: // data = period + (height of first block greater than LOCKED_IN data)
                if (orig_state.code == State::LOCKED_IN) {
                    assert(current_block->GetMedianTimePast() >= orig_state.data);
                    assert(state.data > current_block->nHeight);
                } else {
                    assert(orig_state.code == State::ACTIVE);
                    assert(state.data >= 0 && state.data <= current_block->nHeight);
                }
                break;
            case State::FAILED:
                assert(state.data == 0);
                assert(never_active_test || current_block->GetMedianTimePast() >= dep.optin_timeout);
                if (orig_state.code == State::OPT_IN) {
                    assert(blocks_sig < dep.optin_threshold);
                } else if (orig_state.code == State::OPT_OUT) {
                    const CBlockIndex* first_block = current_block->GetAncestor(current_block->nHeight + 1 - period);
                    assert(first_block->GetMedianTimePast() >= state.data * 60);
                    assert(blocks_sig >= dep.optout_threshold);
                } else if (orig_state.code == State::OPT_OUT_WAIT) {
                    assert(dep.optout_block_height % period == 0); // would not have entered WAIT otherwise
                    assert(dep.optout_block_height <= current_block->nHeight); // should still be WAITing otherwise
                    assert(dep.optout_block_hash != blocks.GetBlockHash(dep.optout_block_height));
                         // should not have FAILED
                    assert(!optout_correct_block); // test case bug?
                } else {
                    assert(orig_state.code == State::FAILED);
                }
                break;
            default:
                assert(false);
            }

            if (blocks.size() >= period * max_periods) {
                // we chose the timeout (and block times) so that by the time we have this many blocks it's all over
                assert(state.code == State::ACTIVE || state.code == State::FAILED);
            }
        }
    });
}
} // namespace
