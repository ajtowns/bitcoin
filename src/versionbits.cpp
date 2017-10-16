// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "versionbits.h"
#include "consensus/params.h"
#include "sync.h"
#include "util.h"
#include "chainparams.h"
#include "validation.h"

struct VersionBitsCache
{
    ThresholdConditionCache caches[Consensus::MAX_VERSION_BITS_DEPLOYMENTS];
};

// Protected by cs_main
static VersionBitsCache versionbitscache;

const struct VBDeploymentInfo VersionBitsDeploymentInfo[Consensus::MAX_VERSION_BITS_DEPLOYMENTS] = {
    {
        /*.name =*/ "testdummy",
        /*.gbt_force =*/ true,
    },
    {
        /*.name =*/ "csv",
        /*.gbt_force =*/ true,
    },
    {
        /*.name =*/ "segwit",
        /*.gbt_force =*/ true,
    }
};

ThresholdState AbstractThresholdConditionChecker::GetStateFor(const CBlockIndex* pindexPrev, const Consensus::Params& params, ThresholdConditionCache& cache) const
{
    int nPeriod = Period(params);
    int nThreshold = Threshold(params);
    int64_t nTimeStart = BeginTime(params);
    int64_t nTimeTimeout = EndTime(params);

    // A block's state is always the same as that of the first of its period, so it is computed based on a pindexPrev whose height equals a multiple of nPeriod - 1.
    if (pindexPrev != nullptr) {
        pindexPrev = pindexPrev->GetAncestor(pindexPrev->nHeight - ((pindexPrev->nHeight + 1) % nPeriod));
    }

    // Walk backwards in steps of nPeriod to find a pindexPrev whose information is known
    std::vector<const CBlockIndex*> vToCompute;
    while (cache.count(pindexPrev) == 0) {
        if (pindexPrev == nullptr) {
            // The genesis block is by definition defined.
            cache[pindexPrev] = THRESHOLD_DEFINED;
            break;
        }
        if (pindexPrev->GetMedianTimePast() < nTimeStart) {
            // Optimization: don't recompute down further, as we know every earlier block will be before the start time
            cache[pindexPrev] = THRESHOLD_DEFINED;
            break;
        }
        vToCompute.push_back(pindexPrev);
        pindexPrev = pindexPrev->GetAncestor(pindexPrev->nHeight - nPeriod);
    }

    // At this point, cache[pindexPrev] is known
    assert(cache.count(pindexPrev));
    ThresholdState state = cache[pindexPrev];

    // Now walk forward and compute the state of descendants of pindexPrev
    while (!vToCompute.empty()) {
        ThresholdState stateNext = state;
        pindexPrev = vToCompute.back();
        vToCompute.pop_back();

        switch (state) {
            case THRESHOLD_DEFINED: {
                if (pindexPrev->GetMedianTimePast() >= nTimeTimeout) {
                    stateNext = THRESHOLD_FAILED;
                } else if (pindexPrev->GetMedianTimePast() >= nTimeStart) {
                    stateNext = THRESHOLD_STARTED;
                }
                break;
            }
            case THRESHOLD_STARTED: {
                if (pindexPrev->GetMedianTimePast() >= nTimeTimeout) {
                    stateNext = THRESHOLD_FAILED;
                    break;
                }
                // We need to count
                const CBlockIndex* pindexCount = pindexPrev;
                int count = 0;
                for (int i = 0; i < nPeriod; i++) {
                    if (Condition(pindexCount, params)) {
                        count++;
                    }
                    pindexCount = pindexCount->pprev;
                }
                if (count >= nThreshold) {
                    stateNext = THRESHOLD_LOCKED_IN;
                }
                break;
            }
            case THRESHOLD_LOCKED_IN: {
                // Always progresses into ACTIVE.
                stateNext = THRESHOLD_ACTIVE;
                break;
            }
            case THRESHOLD_FAILED:
            case THRESHOLD_ACTIVE: {
                // Nothing happens, these are terminal states.
                break;
            }
        }
        cache[pindexPrev] = state = stateNext;
    }

    return state;
}

// return the numerical statistics of blocks signalling the specified BIP9 condition in this current period
BIP9Stats AbstractThresholdConditionChecker::GetStateStatisticsFor(const CBlockIndex* pindex, const Consensus::Params& params) const
{
    BIP9Stats stats = {};

    stats.period = Period(params);
    stats.threshold = Threshold(params);

    if (pindex == nullptr)
        return stats;

    // Find beginning of period
    const CBlockIndex* pindexEndOfPrevPeriod = pindex->GetAncestor(pindex->nHeight - ((pindex->nHeight + 1) % stats.period));
    stats.elapsed = pindex->nHeight - pindexEndOfPrevPeriod->nHeight;

    // Count from current block to beginning of period
    int count = 0;
    const CBlockIndex* currentIndex = pindex;
    while (pindexEndOfPrevPeriod->nHeight != currentIndex->nHeight){
        if (Condition(currentIndex, params))
            count++;
        currentIndex = currentIndex->pprev;
    }

    stats.count = count;
    stats.possible = (stats.period - stats.threshold ) >= (stats.elapsed - count);

    return stats;
}

int AbstractThresholdConditionChecker::GetStateSinceHeightFor(const CBlockIndex* pindexPrev, const Consensus::Params& params, ThresholdConditionCache& cache) const
{
    const ThresholdState initialState = GetStateFor(pindexPrev, params, cache);

    // BIP 9 about state DEFINED: "The genesis block is by definition in this state for each deployment."
    if (initialState == THRESHOLD_DEFINED) {
        return 0;
    }

    const int nPeriod = Period(params);

    // A block's state is always the same as that of the first of its period, so it is computed based on a pindexPrev whose height equals a multiple of nPeriod - 1.
    // To ease understanding of the following height calculation, it helps to remember that
    // right now pindexPrev points to the block prior to the block that we are computing for, thus:
    // if we are computing for the last block of a period, then pindexPrev points to the second to last block of the period, and
    // if we are computing for the first block of a period, then pindexPrev points to the last block of the previous period.
    // The parent of the genesis block is represented by nullptr.
    pindexPrev = pindexPrev->GetAncestor(pindexPrev->nHeight - ((pindexPrev->nHeight + 1) % nPeriod));

    const CBlockIndex* previousPeriodParent = pindexPrev->GetAncestor(pindexPrev->nHeight - nPeriod);

    while (previousPeriodParent != nullptr && GetStateFor(previousPeriodParent, params, cache) == initialState) {
        pindexPrev = previousPeriodParent;
        previousPeriodParent = pindexPrev->GetAncestor(pindexPrev->nHeight - nPeriod);
    }

    // Adjust the result because right now we point to the parent block.
    return pindexPrev->nHeight + 1;
}

namespace
{
/**
 * Class to implement versionbits logic.
 */
class VersionBitsConditionChecker : public AbstractThresholdConditionChecker {
private:
    const Consensus::DeploymentPos id;

protected:
    int64_t BeginTime(const Consensus::Params& params) const override { return params.vDeployments[id].XnStartTime; }
    int64_t EndTime(const Consensus::Params& params) const override { return params.vDeployments[id].XnTimeout; }
    int Period(const Consensus::Params& params) const override { return params.nMinerConfirmationWindow; }
    int Threshold(const Consensus::Params& params) const override { return params.nRuleChangeActivationThreshold; }

    bool Condition(const CBlockIndex* pindex, const Consensus::Params& params) const override
    {
        return (((pindex->nVersion & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS) && (pindex->nVersion & Mask(params)) != 0);
    }

public:
    explicit VersionBitsConditionChecker(Consensus::DeploymentPos id_) : id(id_) {}
    uint32_t Mask(const Consensus::Params& params) const { return ((uint32_t)1) << params.vDeployments[id].Xbit; }
};

} // namespace

ThresholdState VersionBitsState(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    AssertLockHeld(cs_main);
    return VersionBitsConditionChecker(pos).GetStateFor(pindexPrev, params, versionbitscache.caches[pos]);
}

bool VersionBitsActive(const CBlockIndex* pindex, const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    AssertLockHeld(cs_main);
    return VersionBitsState(pindex, params, pos) == THRESHOLD_ACTIVE;
}

static BIP9Stats VersionBitsStatistics(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    return VersionBitsConditionChecker(pos).GetStateStatisticsFor(pindexPrev, params);
}

static int VersionBitsStateSinceHeight(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos pos, VersionBitsCache& cache)
{
    return VersionBitsConditionChecker(pos).GetStateSinceHeightFor(pindexPrev, params, cache.caches[pos]);
}

uint32_t VersionBitsMask(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    return VersionBitsConditionChecker(pos).Mask(params);
}

int32_t ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    LOCK(cs_main);
    int32_t nVersion = VERSIONBITS_TOP_BITS;

    for (int i = 0; i < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; i++) {
        ThresholdState state = VersionBitsState(pindexPrev, params, (Consensus::DeploymentPos)i);
        if (state == THRESHOLD_LOCKED_IN || state == THRESHOLD_STARTED) {
            nVersion |= VersionBitsMask(params, (Consensus::DeploymentPos)i);
        }
    }

    return nVersion;
}

/**
 * Threshold condition checker that triggers when unknown versionbits are seen on the network.
 */
class WarningBitsConditionChecker : public AbstractThresholdConditionChecker
{
private:
    int bit;

public:
    explicit WarningBitsConditionChecker(int bitIn) : bit(bitIn) {}

    int64_t BeginTime(const Consensus::Params& params) const override { return 0; }
    int64_t EndTime(const Consensus::Params& params) const override { return std::numeric_limits<int64_t>::max(); }
    int Period(const Consensus::Params& params) const override { return params.nMinerConfirmationWindow; }
    int Threshold(const Consensus::Params& params) const override { return params.nRuleChangeActivationThreshold; }

    bool Condition(const CBlockIndex* pindex, const Consensus::Params& params) const override
    {
        return ((pindex->nVersion & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS) &&
               ((pindex->nVersion >> bit) & 1) != 0 &&
               ((ComputeBlockVersion(pindex->pprev, params) >> bit) & 1) == 0;
    }
};

// Protected by cs_main
static ThresholdConditionCache warningcache[VERSIONBITS_NUM_BITS];

ThresholdState VersionBitsTipState(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(cs_main);
    return VersionBitsState(chainActive.Tip(), params, pos);
}

BIP9Stats VersionBitsTipStatistics(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(cs_main);
    return VersionBitsStatistics(chainActive.Tip(), params, pos);
}

int VersionBitsTipStateSinceHeight(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(cs_main);
    return VersionBitsStateSinceHeight(chainActive.Tip(), params, pos, versionbitscache);
}

void VersionBitsCachesClear()
{
    AssertLockHeld(cs_main);

    for (unsigned int d = 0; d < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; d++) {
        versionbitscache.caches[d].clear();
    }
    for (int b = 0; b < VERSIONBITS_NUM_BITS; b++) {
        warningcache[b].clear();
    }
}

void Consensus::Params::CheckUnknownRules(const CBlockIndex* pindex, UnknownDeploymentWarning *warn) const
{
    AssertLockHeld(cs_main);

    int nUpgraded = 0;

    for (int bit = 0; bit < VERSIONBITS_NUM_BITS; bit++) {
        WarningBitsConditionChecker checker(bit);
        ThresholdState state = checker.GetStateFor(pindex, *this, warningcache[bit]);
        if (state == THRESHOLD_ACTIVE || state == THRESHOLD_LOCKED_IN) {
            const std::string strWarning = strprintf(_("Warning: unknown new rules activated (versionbit %i)"), bit);
            if (state == THRESHOLD_ACTIVE) {
                warn->DoWarning(strWarning);
            } else {
                warn->warningMessages.push_back(strWarning);
            }
        }
    }

    // Check the version of the last 100 blocks to see if we need to upgrade:
    for (int i = 0; i < 100 && pindex != nullptr; i++)
    {
        int32_t nExpectedVersion = ComputeBlockVersion(pindex->pprev, *this);
        if (pindex->nVersion > VERSIONBITS_LAST_OLD_BLOCK_VERSION && (pindex->nVersion & ~nExpectedVersion) != 0)
        {
            ++nUpgraded;
        }
        pindex = pindex->pprev;
    }
    if (nUpgraded > 0)
        warn->warningMessages.push_back(strprintf(_("%d of last 100 blocks have unexpected version"), nUpgraded));
    if (nUpgraded > 100/2)
    {
        std::string strWarning = _("Warning: Unknown block versions being mined! It's possible unknown rules are in effect");
        // notify GetWarnings(), called by Qt and the JSON-RPC code to warn the user:
        warn->DoWarning(strWarning);
    }
}
