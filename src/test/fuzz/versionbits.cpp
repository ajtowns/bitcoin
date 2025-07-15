// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <common/args.h>
#include <consensus/params.h>
#include <primitives/block.h>
#include <util/chaintype.h>
#include <versionbits.h>
#include <versionbits_impl.h>

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <memory>
#include <vector>


bool operator==(const SignalInfo& a, const SignalInfo& b)
{
    return a.height == b.height && a.revision == b.revision && a.activate == b.activate;
}

namespace {
class TestConditionChecker : public VersionBitsConditionChecker
{
private:
    mutable ThresholdConditionCache m_cache;

public:
    TestConditionChecker(const Consensus::HereticalDeployment& dep) : VersionBitsConditionChecker{dep}
    {
        assert(dep.period > 0);
    }

    ThresholdState GetStateFor(const CBlockIndex* pindexPrev) const { return AbstractThresholdConditionChecker::GetStateFor(pindexPrev, m_cache); }
    int GetStateSinceHeightFor(const CBlockIndex* pindexPrev) const { return AbstractThresholdConditionChecker::GetStateSinceHeightFor(pindexPrev, m_cache); }
};

/** Track blocks mined for test */
class Blocks
{
private:
    std::vector<std::unique_ptr<CBlockIndex>> m_blocks;
    const uint32_t m_start_time;
    const uint32_t m_interval;

public:
    Blocks(uint32_t start_time, uint32_t interval)
        : m_start_time{start_time}, m_interval{interval} { }

    size_t size() const { return m_blocks.size(); }

    CBlockIndex* tip() const
    {
        return m_blocks.empty() ? nullptr : m_blocks.back().get();
    }

    CBlockIndex* mine_block(int32_t version)
    {
        CBlockHeader header;
        header.nVersion = version;
        header.nTime = m_start_time + m_blocks.size() * m_interval;
        header.nBits = 0x1d00ffff;

        auto current_block = std::make_unique<CBlockIndex>(header);
        current_block->pprev = tip();
        current_block->nHeight = m_blocks.size();
        current_block->BuildSkip();

        return m_blocks.emplace_back(std::move(current_block)).get();
    }
};

std::unique_ptr<const CChainParams> g_params;

void initialize()
{
    // this is actually comparatively slow, so only do it once
    g_params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    assert(g_params != nullptr);
}

constexpr uint32_t MAX_START_TIME = 4102444800; // 2100-01-01

FUZZ_TARGET(versionbits, .init = initialize)
{
    const CChainParams& params = *g_params;
    const int64_t interval = params.GetConsensus().nPowTargetSpacing;
    assert(interval > 1); // need to be able to halve it
    assert(interval < std::numeric_limits<int32_t>::max());

    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    // making period/max_periods larger slows these tests down significantly
    const uint32_t period = 32;
    const size_t max_periods = 16;
    const size_t max_blocks = 2 * period * max_periods;

    // too many blocks at 10min each might cause uint32_t time to overflow if
    // block_start_time is at the end of the range above
    assert(std::numeric_limits<uint32_t>::max() - MAX_START_TIME > interval * max_blocks);

    const int64_t block_start_time = fuzzed_data_provider.ConsumeIntegralInRange<uint32_t>(params.GenesisBlock().nTime, MAX_START_TIME);

    // what values for version will we use to signal
    const int32_t ver_activate = fuzzed_data_provider.ConsumeIntegral<int32_t>();
    const int32_t ver_abandon = fuzzed_data_provider.ConsumeIntegral<int32_t>();

    // Now that we have chosen time and versions, setup to mine blocks
    Blocks blocks(block_start_time, interval);

    const bool always_active_test = fuzzed_data_provider.ConsumeBool();
    const bool never_active_test = !always_active_test && fuzzed_data_provider.ConsumeBool();

    const Consensus::HereticalDeployment dep{[&]() {
        Consensus::HereticalDeployment dep;
        dep.period = period;
        dep.signal_activate = ver_activate;
        dep.signal_abandon = ver_abandon;

        if (always_active_test) {
            dep.nStartTime = Consensus::HereticalDeployment::ALWAYS_ACTIVE;
            dep.nTimeout = fuzzed_data_provider.ConsumeBool() ? Consensus::HereticalDeployment::NO_TIMEOUT : fuzzed_data_provider.ConsumeIntegral<int64_t>();
        } else if (never_active_test) {
            dep.nStartTime = Consensus::HereticalDeployment::NEVER_ACTIVE;
            dep.nTimeout = fuzzed_data_provider.ConsumeBool() ? Consensus::HereticalDeployment::NO_TIMEOUT : fuzzed_data_provider.ConsumeIntegral<int64_t>();
        } else {
            // pick the timestamp to switch based on a block
            // note states will change *after* these blocks because mediantime lags
            int start_block = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, period * (max_periods - 3));
            int end_block = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, period * (max_periods - 3));

            dep.nStartTime = block_start_time + start_block * interval;
            dep.nTimeout = block_start_time + end_block * interval;

            // allow for times to not exactly match a block
            if (fuzzed_data_provider.ConsumeBool()) dep.nStartTime += interval / 2;
            if (fuzzed_data_provider.ConsumeBool()) dep.nTimeout += interval / 2;
        }
        return dep;
    }()};
    TestConditionChecker checker(dep);

    // Early exit if the versions don't signal sensibly for the deployment
    assert(checker.ActivateVersion() == ver_activate);
    assert(checker.AbandonVersion() == ver_abandon);

    // negative values are uninteresting
    if (ver_activate < 0) return;
    if (ver_abandon < 0) return;

    // not testing the equality case
    if (ver_activate == ver_abandon) return;

    // Pick a non-signalling version
    const int32_t ver_nosignal = fuzzed_data_provider.ConsumeIntegral<int32_t>();
    if (ver_nosignal < 0) return; // only positive versions are interesting
    if (ver_nosignal == ver_activate) return;
    if (ver_nosignal == ver_abandon) return;

    /* Strategy:
     *  * we mine n*period blocks, with zero/one of
     *    those blocks signalling activation, and zero/one of
     *    them signalling abandonment
     *  * we then mine a final period worth of blocks, with
     *    randomised signalling
     */

    // mine prior periods
    const int prior_periods = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, max_periods);
    assert(prior_periods * period + period <= (int64_t)max_blocks); // fuzzer bug if this triggers

    const size_t activate_block = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, prior_periods * period);
    const size_t abandon_block = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, prior_periods * period);

    bool sig_active = false;
    bool sig_abandon = false;
    auto mine_block = [&]() -> CBlockIndex* {
        int32_t ver = ver_nosignal;
        if (blocks.size() == abandon_block) {
            ver = ver_abandon;
            sig_abandon = true;
        } else if (blocks.size() == activate_block) {
            ver = ver_activate;
            sig_active = true;
        }
        return blocks.mine_block(ver);
    };

    for (int i = 0; i < prior_periods; ++i) {
        for (uint32_t b = 0; b < period; ++b) {
            mine_block();
        }
    }

    // helpers to track expected SignalInfo
    const auto siginfo_nosignal = [&]() -> std::optional<SignalInfo> {
        int year, number, revision;
        if (checker.BINANA(year, number, revision)) {
            if ((ver_nosignal & 0xFFFFFF00l) == (ver_activate & 0xFFFFFF00l)) {
                return SignalInfo{.height = 0, .revision = static_cast<uint8_t>(ver_nosignal & 0xFF), .activate = true};
            } else if ((ver_nosignal & 0xFFFFFF00l) == (ver_abandon & 0xFFFFFF00l)) {
                return SignalInfo{.height = 0, .revision = static_cast<uint8_t>(ver_nosignal & 0xFF), .activate = false};
            }
        }
        return std::nullopt;
    }();

    std::vector<SignalInfo> exp_siginfo = checker.GetSignalInfo(nullptr); // dummy
    assert(exp_siginfo.empty());

    auto update_exp_siginfo = [&]() {
        size_t height = blocks.size() - 1;
        int h = static_cast<int>(height);
        if (height == abandon_block) {
            exp_siginfo.push_back({.height = h, .revision = -1, .activate = false});
        } else if (height == activate_block) {
            exp_siginfo.push_back({.height = h, .revision = -1, .activate = true});
        } else if (siginfo_nosignal) {
            exp_siginfo.push_back(*siginfo_nosignal);
            exp_siginfo.back().height = h;
        }
    };

    // now we mine the final period and check that everything looks sane

    // get the info for the first block of the period
    CBlockIndex* prev = blocks.tip();
    const int exp_since = checker.GetStateSinceHeightFor(prev);
    const ThresholdState exp_state = checker.GetStateFor(prev);

    int prev_next_height = (prev == nullptr ? 0 : prev->nHeight + 1);
    assert(exp_since <= prev_next_height);

    // reset sig_active/sig_abandon -- only track last period's signalling
    sig_active = sig_abandon = false;

    // mine (period-1) blocks and check state
    for (uint32_t b = 1; b < period; ++b) {
        CBlockIndex* current_block = mine_block();
        update_exp_siginfo();

        // state and since don't change within the period
        const ThresholdState state = checker.GetStateFor(current_block);
        const int since = checker.GetStateSinceHeightFor(current_block);
        assert(state == exp_state);
        assert(since == exp_since);

        // check SignalInfo
        const std::vector<SignalInfo> siginfo = checker.GetSignalInfo(blocks.tip());
        assert(siginfo.size() == exp_siginfo.size());
        assert(std::equal(siginfo.begin(), siginfo.end(), exp_siginfo.rbegin(), exp_siginfo.rend()));
    }

    // mine the final block
    CBlockIndex* current_block = mine_block();
    update_exp_siginfo();

    // More interesting is whether the state changed.
    const ThresholdState state = checker.GetStateFor(current_block);
    const int since = checker.GetStateSinceHeightFor(current_block);

    // check final SignalInfo
    const std::vector<SignalInfo> siginfo = checker.GetSignalInfo(blocks.tip());
    assert(siginfo.size() == exp_siginfo.size());
    assert(std::equal(siginfo.begin(), siginfo.end(), exp_siginfo.rbegin(), exp_siginfo.rend()));

    // since is straightforward:
    assert(since % period == 0);
    assert(0 <= since && since <= current_block->nHeight + 1);
    if (state == exp_state) {
        assert(since == exp_since);
    } else {
        assert(since == current_block->nHeight + 1);
    }

    // state is where everything interesting is
    switch (state) {
    case ThresholdState::DEFINED:
        assert(since == 0);
        assert(exp_state == ThresholdState::DEFINED);
        assert(current_block->GetMedianTimePast() < dep.nStartTime);
        assert(current_block->GetMedianTimePast() < dep.nTimeout);
        break;
    case ThresholdState::STARTED:
        assert(current_block->GetMedianTimePast() >= dep.nStartTime);
        assert(current_block->GetMedianTimePast() < dep.nTimeout);
        if (exp_state == ThresholdState::STARTED) {
            assert(!sig_active && !sig_abandon);
        } else {
            assert(exp_state == ThresholdState::DEFINED);
        }
        break;
    case ThresholdState::LOCKED_IN:
        assert(current_block->GetMedianTimePast() >= dep.nStartTime);
        assert(current_block->GetMedianTimePast() < dep.nTimeout);
        assert(exp_state == ThresholdState::STARTED);
        assert(sig_active && !sig_abandon);
        break;
    case ThresholdState::ACTIVE:
        if (!always_active_test) {
            assert(current_block->GetMedianTimePast() >= dep.nStartTime);
            assert(current_block->GetMedianTimePast() < dep.nTimeout);
            assert(exp_state == ThresholdState::ACTIVE || exp_state == ThresholdState::LOCKED_IN);
            assert(!sig_abandon);
        }
        break;
    case ThresholdState::DEACTIVATING:
        assert(current_block->GetMedianTimePast() >= dep.nStartTime);
        assert(exp_state == ThresholdState::ACTIVE || exp_state == ThresholdState::LOCKED_IN);
        assert(sig_abandon || current_block->GetMedianTimePast() >= dep.nTimeout);
        break;
    case ThresholdState::ABANDONED:
        if (exp_state == ThresholdState::DEFINED || exp_state == ThresholdState::STARTED) {
            assert(sig_abandon || current_block->GetMedianTimePast() >= dep.nTimeout);
        } else {
            assert(exp_state == ThresholdState::DEACTIVATING || exp_state == ThresholdState::ABANDONED);
        }
        break;
    default:
        assert(false);
    }

    if (always_active_test) {
        // "always active" has additional restrictions
        assert(state == ThresholdState::ACTIVE);
        assert(exp_state == ThresholdState::ACTIVE);
        assert(since == 0);
    } else if (never_active_test) {
        // "never active" does too
        assert(state == ThresholdState::ABANDONED);
        assert(exp_state == ThresholdState::ABANDONED);
        assert(since == 0);
    } else {
        // for signalled deployments, the initial state is always DEFINED
        assert(since > 0 || state == ThresholdState::DEFINED);
        assert(exp_since > 0 || exp_state == ThresholdState::DEFINED);

        if (blocks.size() >= period * max_periods) {
            // we chose the timeout (and block times) so that by the time we have this many blocks it's all over
            assert(state == ThresholdState::ABANDONED);
        }
    }
}
} // namespace
