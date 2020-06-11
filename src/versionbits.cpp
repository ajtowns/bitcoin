// Copyright (c) 2016-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <versionbits.h>

#include <consensus/params.h>

bool ThresholdConditionChecker::Condition(const CBlockIndex* pindex) const
{
    return ((pindex->nVersion & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS) && (pindex->nVersion & (1L << dep.bit)) != 0;
}

ThresholdState ThresholdConditionChecker::GetStateFor(const CBlockIndex* pindexPrev, ThresholdConditionCache& cache) const
{
    return GetStateHeightFor(pindexPrev, cache).state;
}

ThresholdStateHeight ThresholdConditionChecker::GetStateHeightFor(const CBlockIndex* pindexPrev, ThresholdStateHeight prev_state) const
{
    int height = (pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1);

    if (height % dep.period != 0) return prev_state;

    switch (prev_state.state) {
    case ThresholdState::ACTIVE:
    case ThresholdState::FAILED:
    case ThresholdState::DISABLED:
        // Final state
        return prev_state;

    case ThresholdState::LOCKED_IN:
        // LOCKED_IN transitions to ACTIVE at next period boundary
        return {ThresholdState::ACTIVE, height};

    case ThresholdState::PRIMARY:
    case ThresholdState::SECONDARY:
        // Check for signalling in previous period
        {
            int matched = 0;
            const CBlockIndex* walk = pindexPrev;
            for (int i = 0; i < dep.period; ++i) {
                if (walk == nullptr) break;
                if (Condition(walk)) ++matched;
                walk = walk->pprev;
            }
            if (matched >= dep.threshold) return {ThresholdState::LOCKED_IN, height};
        }
        break;

    case ThresholdState::QUIET:
    case ThresholdState::DEFINED:
        // Remaining cases only transition on height
        break;
    }

    if (height < dep.start_height) {
        return {ThresholdState::DEFINED, 0};
    }

    const int periods = (height - dep.start_height) / dep.period;
    ThresholdState next;
    if (periods < dep.primary_periods) {
        next = ThresholdState::PRIMARY;
    } else if (!dep.guaranteed) {
        next = ThresholdState::FAILED;
    } else if (periods < dep.primary_periods + dep.quiet_periods) {
        next = ThresholdState::QUIET;
    } else if (periods < dep.primary_periods + dep.quiet_periods + dep.secondary_periods) {
        next = ThresholdState::SECONDARY;
    } else {
        next = ThresholdState::LOCKED_IN;
    }

    if (next != prev_state.state) return {next, height};
    return prev_state;
}

ThresholdStateHeight ThresholdConditionChecker::GetStateHeightFor(const CBlockIndex* pindexPrev, ThresholdConditionCache& cache) const
{
    if (!dep.guaranteed && dep.primary_periods == 0) return {ThresholdState::DISABLED, 0};

    if (dep.guaranteed && dep.primary_periods == 0 && dep.secondary_periods == 0 && dep.quiet_periods == 0 && dep.start_height % dep.period == 0) {
        int height = (pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1);
        if (height >= dep.start_height + dep.period) {
            return {ThresholdState::ACTIVE, dep.start_height + dep.period};
        } else if (height >= dep.start_height) {
            return {ThresholdState::LOCKED_IN, dep.start_height};
        } else {
            return {ThresholdState::DEFINED, 0};
        }
    }

    // A block's state is always the same as that of the first of its period, so it is computed based on a pindexPrev whose height equals a multiple of nPeriod - 1.
    if (pindexPrev != nullptr) {
        int height = pindexPrev->nHeight;
        height = height - ((height + 1) % dep.period);
        pindexPrev = pindexPrev->GetAncestor(height);
        assert(pindexPrev == nullptr || pindexPrev->nHeight % dep.period == dep.period - 1);
    }

    // walk backwards until a known state

    std::vector<const CBlockIndex*> to_compute;
    while (cache.count(pindexPrev) == 0) {
        if (pindexPrev == nullptr || pindexPrev->nHeight + 1 < dep.start_height) {
            cache.insert({pindexPrev, {ThresholdState::DEFINED, 0}});
            break;
        }

        to_compute.push_back(pindexPrev);
        pindexPrev = pindexPrev->GetAncestor(pindexPrev->nHeight - dep.period);
    }

    // can pull from cache
    assert(cache.count(pindexPrev));
    ThresholdStateHeight stateheight = cache[pindexPrev];

    // Now walk forward and compute the state of descendants of pindexPrev
    while (!to_compute.empty()) {
        pindexPrev = to_compute.back();
        to_compute.pop_back();

        stateheight = GetStateHeightFor(pindexPrev, stateheight);
        cache.insert({pindexPrev, stateheight});
    }

    return stateheight;
}

ModernDeploymentStats ThresholdConditionChecker::GetStateStatisticsFor(const CBlockIndex* pindex) const
{
    if (pindex == nullptr) return ModernDeploymentStats{0,0,false};

    ModernDeploymentStats stats;

    // Find beginning of period
    int blocks_to_check = (pindex->nHeight % dep.period) + 1;
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
    stats.possible = (dep.period - dep.threshold) >= (stats.elapsed - count);

    return stats;
}

ThresholdState VersionBitsState(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos pos, VersionBitsCache& cache)
{
    return ThresholdConditionChecker(params.vDeployments[pos]).GetStateFor(pindexPrev, cache.caches[pos]);
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
    return ThresholdState::ACTIVE == ThresholdConditionChecker(params.vDeployments[dep]).GetStateFor(pindexPrev, versionbitscache.caches[dep]);
}

int32_t ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    LOCK(cs_main);
    int32_t nVersion = VERSIONBITS_TOP_BITS;

    for (int i = 0; i < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++i) {
        const Consensus::DeploymentPos dep = static_cast<Consensus::DeploymentPos>(i);
        ThresholdState state = VersionBitsState(pindexPrev, params, dep, versionbitscache);
        switch (state) {
        case ThresholdState::PRIMARY:
        case ThresholdState::QUIET:
        case ThresholdState::SECONDARY:
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
