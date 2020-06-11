// Copyright (c) 2016-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VERSIONBITS_H
#define BITCOIN_VERSIONBITS_H

#include <chain.h>
#include <map>
#include <sync.h>

/** What block version to use for new blocks (pre versionbits) */
static const int32_t VERSIONBITS_LAST_OLD_BLOCK_VERSION = 4;
/** What bits to set in version for versionbits blocks */
static const int32_t VERSIONBITS_TOP_BITS = 0x20000000UL;
/** What bitmask determines whether versionbits is in use */
static const int32_t VERSIONBITS_TOP_MASK = 0xE0000000UL;
/** Total bits available for versionbits */
static const uint8_t VERSIONBITS_NUM_BITS = 29;

template<uint8_t bit, int start_height, uint16_t signal_periods, uint16_t quiet_periods, uint16_t secondary_periods, uint16_t period, uint16_t threshold>
inline constexpr Consensus::ModernDeployment Deployment(bool guaranteed) {
    static_assert(0 <= bit && bit < VERSIONBITS_NUM_BITS && ((1L << bit) & VERSIONBITS_TOP_MASK) == 0, "Invalid version bit");
    static_assert(0 < period && period <= 52416, "Period out of range");
    static_assert(0 < threshold && threshold <= period, "Threshold out of range");
    static_assert(start_height >= 0 || start_height + period == 0, "Deployment start_height cannot be negative unless using DeploymentAlwaysActive");
    static_assert(start_height % period == 0, "Deployment start_height must be divisible by period");

    return Consensus::ModernDeployment{start_height, signal_periods, quiet_periods, secondary_periods, period, threshold, bit, guaranteed};
}

template<int bit>
inline Consensus::ModernDeployment DeploymentDisabled() {
    return Deployment<bit,std::numeric_limits<int>::max(),0,0,0,1,1>(false);
}

template<int bit,int height>
inline Consensus::ModernDeployment DeploymentBuried() {
    return Deployment<bit,height-1,0,0,0,1,1>(true);
}

template<int bit>
inline Consensus::ModernDeployment DeploymentAlwaysActive() {
    return Deployment<bit,-1,0,0,0,1,1>(true);
}

template<int bit, uint16_t period=2016, uint16_t threshold=1916>
inline Consensus::ModernDeployment DeploymentAlwaysSignal() {
    // actually DEFINED for a period, then signal
    return Deployment<bit,period,std::numeric_limits<uint16_t>::max(),0,0,period,threshold>(false);
}

/** Display status of an in-progress ModernDeployment softfork */
struct ModernDeploymentStats {
    /** Number of blocks elapsed since the beginning of the current period */
    int elapsed;
    /** Number of blocks with the version bit set since the beginning of the current period */
    int count;
    /** False if there are not enough blocks left in this period to pass activation threshold */
    bool possible;
};

/** BIP 9 defines a finite-state-machine to deploy a softfork in multiple stages.
 *  State transitions happen during retarget period if conditions are met
 *  In case of reorg, transitions can go backward. Without transition, state is
 *  inherited between periods. All blocks of a period share the same state.
 */
enum class ThresholdState {
    DEFINED,   // First state that each softfork starts out as. The genesis block is by definition in this state for each deployment.
    PRIMARY,   // For blocks in the primary signalling phase.
    QUIET,     // For blocks within the quiet period.
    SECONDARY, // For blocks in the secondary signalling phase.
    LOCKED_IN, // For one retarget period after the first period in PRIMARY or SECONDARY of which at least threshold have the associated bit set in nVersion, or after SECONDARY
    ACTIVE,    // For all blocks after the LOCKED_IN period (final state)
    FAILED,    // For all blocks after PRIMARY if activation is not guaranteed(final state)
    DISABLED,  // If activation is never possible (final state)
};

struct ThresholdStateHeight {
    ThresholdState state;
    int height;
};

// A map that gives the signalling state for blocks at the end of each signalling
// period. (All keys in the map will be a block with (height + 1) % Period() == 0)
// Value is 0 if signalling has failed to this point, or the number of periods
// since signalling succeeded including the period in which signalling succeeded.
typedef std::map<const CBlockIndex*, ThresholdStateHeight> ThresholdConditionCache;

/**
 * Class that implements ModernDeployment-style threshold logic, and caches results.
 */
class ThresholdConditionChecker {
protected:
    // can be overridden
    virtual bool Condition(const CBlockIndex* pindex) const;

    /** Returns the state/height for pindex A based on parent pindexPrev B and parent's state */
    ThresholdStateHeight GetStateHeightFor(const CBlockIndex* pindexPrev, ThresholdStateHeight prev_state) const;

public:
    const Consensus::ModernDeployment dep;

    explicit ThresholdConditionChecker(const Consensus::ModernDeployment& _dep) : dep{_dep} { }

    virtual ~ThresholdConditionChecker() { }

    /** Returns the state/height for pindex A based on parent pindexPrev B using cache. */
    ThresholdStateHeight GetStateHeightFor(const CBlockIndex* pindexPrev, ThresholdConditionCache& cache) const;

    /** Returns the state for pindex A based on parent pindexPrev B. */
    ThresholdState GetStateFor(const CBlockIndex* pindexPrev, ThresholdConditionCache& cache) const;

    /** Returns the numerical statistics of an in-progress ModernDeployment softfork in the current period */
    ModernDeploymentStats GetStateStatisticsFor(const CBlockIndex* pindex) const;
};

/** BIP 9 allows multiple softforks to be deployed in parallel. We cache per-period state for every one of them
 *  keyed by the bit position used to signal support. */
struct VersionBitsCache
{
    ThresholdConditionCache caches[Consensus::MAX_VERSION_BITS_DEPLOYMENTS];

    void Clear();
};

extern RecursiveMutex cs_main;
extern VersionBitsCache versionbitscache GUARDED_BY(cs_main);

ThresholdState VersionBitsState(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos pos, VersionBitsCache& cache);
uint32_t VersionBitsMask(const Consensus::Params& params, Consensus::DeploymentPos pos);

inline bool DeploymentActive_height(int height, const Consensus::Params& params, Consensus::DeploymentFixed dep)
{
    switch(dep) {
    case Consensus::DEPLOYMENT_CLTV:
        return height >= params.BIP65Height;
    case Consensus::DEPLOYMENT_DERSIG:
        return height >= params.BIP66Height;
    case Consensus::DEPLOYMENT_CSV:
        return height >= params.CSVHeight;
    case Consensus::DEPLOYMENT_SEGWIT:
        return height >= params.SegwitHeight;
    }
}

inline bool DeploymentActiveAfter(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentFixed dep)
{
    const int height = (pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1);
    return DeploymentActive_height(height, params, dep);
}
inline bool DeploymentActiveAt(const CBlockIndex* pindex, const Consensus::Params& params, Consensus::DeploymentFixed dep)
{
    return DeploymentActive_height(pindex->nHeight, params, dep);
}

bool DeploymentActiveAfter(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos dep) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
inline bool DeploymentActiveAt(const CBlockIndex* pindex, const Consensus::Params& params, Consensus::DeploymentPos dep) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    return DeploymentActiveAfter(pindex->pprev, params, dep);
}

/**
 * Determine what nVersion a new block should use.
 */
int32_t ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params);

#endif // BITCOIN_VERSIONBITS_H
