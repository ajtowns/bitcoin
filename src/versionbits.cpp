// Copyright (c) 2016-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <versionbits.h>

#include <consensus/params.h>

constexpr int MAX_HEIGHT = std::numeric_limits<int>::max();

inline int period_to_height(int previous_height, int previous_periods, int period) {
    if (previous_height < MAX_HEIGHT && previous_periods >= 0) {
        return previous_height + previous_periods * period;
    } else {
        return MAX_HEIGHT;
    }
}

ThresholdConditionChecker ThresholdConditionChecker::FromModernDeployment(const Consensus::ModernDeployment& dep)
{
    int signal_height, quiet_height, uasf_height, mandatory_height;

    signal_height = dep.signal_height;
    quiet_height = period_to_height(signal_height, dep.signal_periods, dep.period);
    if (dep.uasf_enabled) {
        uasf_height = period_to_height(quiet_height, dep.quiet_periods, dep.period);
        mandatory_height = period_to_height(uasf_height, dep.uasf_periods, dep.period);
    } else {
        uasf_height = mandatory_height = MAX_HEIGHT;
    }

    return ThresholdConditionChecker(signal_height, quiet_height, uasf_height, mandatory_height, dep.period, dep.threshold, dep.bit);
}

bool ThresholdConditionChecker::Condition(const CBlockIndex* pindex) const
{
    return ((pindex->nVersion & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS) && (pindex->nVersion & (1L << bit)) != 0;
}

// What would the state be if there was no signalling?
template<int N>
static ThresholdStateHeight non_signalled_state(const ThresholdStateHeight (&states)[N], int height)
{
    for (const auto& s : states) {
        if (height >= s.height) {
            return s;
        }
    }
    return {ThresholdState::DEFINED, 0};
}

ThresholdState ThresholdConditionChecker::GetStateFor(const CBlockIndex* pindexPrev, ThresholdConditionCache& cache) const
{
    int height = pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1;
    if (height >= mandatory_height) return ThresholdState::ACTIVE;
    return GetStateHeightFor(pindexPrev, cache).state;
}

ThresholdStateHeight ThresholdConditionChecker::GetStateHeightFor(const CBlockIndex* pindexPrev, ThresholdConditionCache& cache) const
{
    if (signal_height == quiet_height && uasf_height == MAX_HEIGHT) return {ThresholdState::DISABLED, 0};

    const ThresholdStateHeight states[] = {
        { ThresholdState::ACTIVE,    mandatory_height },
        { ThresholdState::LOCKED_IN, mandatory_height - (mandatory_height == MAX_HEIGHT ? 0 : period)},
        { ThresholdState::UASF,      uasf_height },
        { ThresholdState::QUIET,     quiet_height },
        { ThresholdState::SIGNAL,    signal_height },
    };

    // A block's state is always the same as that of the first of its period, so it is computed based on a pindexPrev whose height equals a multiple of nPeriod - 1.
    if (pindexPrev != nullptr) {
        int height = pindexPrev->nHeight;
        if (height >= mandatory_height) {
            // after mandatory_height, results won't change
            height = mandatory_height - 1;
        } else if (uasf_height == MAX_HEIGHT && height - period >= quiet_height) {
            // if UASF/mandatory activation is disabled, first quiet period can be LOCKED_IN
            // but otherwise results won't change
            height = quiet_height + period - 1;
        } else {
            height = height - ((height + 1) % period);
        }
        pindexPrev = pindexPrev->GetAncestor(height);
        assert(pindexPrev == nullptr || pindexPrev->nHeight % period == period - 1);
    }

    // walk backwards until a known state

    std::vector<const CBlockIndex*> to_compute;
    while (cache.count(pindexPrev) == 0) {
        if (pindexPrev == nullptr) {
            cache.insert({pindexPrev, non_signalled_state(states, 0)});
            break;
        } else if (pindexPrev->nHeight + 1 < signal_height) {
            cache.insert({pindexPrev, {ThresholdState::DEFINED, 0}});
            break;
        }

        to_compute.push_back(pindexPrev);

        pindexPrev = pindexPrev->GetAncestor(pindexPrev->nHeight - period);
    }

    // can pull from cache
    assert(cache.count(pindexPrev));
    ThresholdStateHeight stateheight = cache[pindexPrev];

    // Now walk forward and compute the state of descendants of pindexPrev
    while (!to_compute.empty()) {
        pindexPrev = to_compute.back();
        to_compute.pop_back();

        int height = pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1;

        if (stateheight.state == ThresholdState::ACTIVE) {
             // final state, so stays the same
        } else if (stateheight.state == ThresholdState::LOCKED_IN) {
             stateheight = {ThresholdState::ACTIVE, height};
        } else {
             bool lock_in = false;
             if (stateheight.state == ThresholdState::SIGNAL || stateheight.state == ThresholdState::UASF) {
                 ModernDeploymentStats stats = GetStateStatisticsFor(pindexPrev);
                 if (stats.count >= threshold) {
                     lock_in = true;
                 }
             }
             if (lock_in) {
                 stateheight = {ThresholdState::LOCKED_IN, height};
             } else {
                 stateheight = non_signalled_state(states, height);
             }
        }

        cache.insert({pindexPrev, stateheight});
    }

    // report failed activations specially
    if (stateheight.state == ThresholdState::QUIET && uasf_height == MAX_HEIGHT) stateheight.state = ThresholdState::FAILED;

    return stateheight;
}

ModernDeploymentStats ThresholdConditionChecker::GetStateStatisticsFor(const CBlockIndex* pindex) const
{
    if (pindex == nullptr)
        return ModernDeploymentStats{0,0,false};

    ModernDeploymentStats stats;

    // Find beginning of period
    int blocks_to_check = (pindex->nHeight % period) + 1;
    stats.elapsed = blocks_to_check;

    // Count from current block to beginning of period
    int count = 0;
    const CBlockIndex* currentIndex = pindex;
    while (blocks_to_check > 0) {
        if (Condition(currentIndex)) count++;
        currentIndex = currentIndex->pprev;
        --blocks_to_check;
    }

    stats.count = count;
    stats.possible = (period - threshold) >= (stats.elapsed - count);

    return stats;
}

ThresholdState VersionBitsState(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos pos, VersionBitsCache& cache)
{
    return ThresholdConditionChecker::FromModernDeployment(params.vDeployments[pos]).GetStateFor(pindexPrev, cache.caches[pos]);
}

uint32_t VersionBitsMask(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
     return 1L << params.vDeployments[pos].bit;
}

void VersionBitsCache::Clear()
{
    for (unsigned int d = 0; d < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; d++) {
        caches[d].clear();
    }
}

bool DeploymentActiveAfter(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos dep)
{
    return ThresholdState::ACTIVE == ThresholdConditionChecker::FromModernDeployment(params.vDeployments[dep]).GetStateFor(pindexPrev, versionbitscache.caches[dep]);
}

int32_t ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    LOCK(cs_main);
    int32_t nVersion = VERSIONBITS_TOP_BITS;

    for (int i = 0; i < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++i) {
        const Consensus::DeploymentPos dep = static_cast<Consensus::DeploymentPos>(i);
        ThresholdState state = VersionBitsState(pindexPrev, params, dep, versionbitscache);
        switch (state) {
        case ThresholdState::SIGNAL:
        case ThresholdState::QUIET:
        case ThresholdState::UASF:
        case ThresholdState::LOCKED_IN:
            nVersion |= VersionBitsMask(params, dep);
            break;
        default:
            break;
        }
    }

    return nVersion;
}

VersionBitsCache versionbitscache;
