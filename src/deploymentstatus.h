// Copyright (c) 2016-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DEPLOYMENTSTATUS_H
#define BITCOIN_DEPLOYMENTSTATUS_H

#include <chain.h>
#include <sync.h>

#include <limits>
#include <map>

extern RecursiveMutex cs_main;

/**
 * Determine if deployment is active
 * DeploymentFixed variants are inline since they can be almost entirely optimised out
 */
inline bool DeploymentActiveAfter(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::BuriedDeployment dep)
{
    const int height = (pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1);
    return height >= params.DeploymentHeight(dep);
}

inline bool DeploymentActiveAt(const CBlockIndex* pindex, const Consensus::Params& params, Consensus::BuriedDeployment dep)
{
    return pindex->nHeight >= params.DeploymentHeight(dep);
}

inline bool DeploymentDisabled(const Consensus::Params& params, Consensus::BuriedDeployment dep)
{
    return params.DeploymentHeight(dep) == std::numeric_limits<int>::max();
}

bool DeploymentActiveAfter(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::SignalledDeployment pos) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
bool DeploymentActiveAt(const CBlockIndex* pindex, const Consensus::Params& params, Consensus::SignalledDeployment pos) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
bool DeploymentDisabled(const Consensus::Params& params, Consensus::SignalledDeployment dep);

/** Implementation of BIP xxx logic for conditional/guaranteed soft fork activation
 *  Provides a cache to avoid repeated recalculations */
class SignalledDeploymentStatus
{
public:
    /** Evaluates if a block signals for activation */
    class Condition {
    public:
        virtual bool operator()(const CBlockIndex* pindex, const Consensus::SignalledDeploymentParams& dep) const = 0;
    };

    /** BIP xxx defines a finite-state-machine to deploy a softfork in multiple stages.
     *  State transitions happen during retarget period if conditions are met
     *  In case of reorg, transitions can go backward. Without transition, state is
     *  inherited between periods. All blocks of a period share the same state.
     */
    enum class State {
        DEFINED,   // First state that each softfork starts out as. The genesis block is by definition in this state for each deployment.
        PRIMARY,   // For blocks in the primary signalling phase.
        QUIET,     // For blocks within the quiet period.
        SECONDARY, // For blocks in the secondary signalling phase.
        LOCKED_IN, // For one retarget period after the first period in PRIMARY or SECONDARY of which at least threshold have the associated bit set in nVersion, or after SECONDARY
        ACTIVE,    // For all blocks after the LOCKED_IN period (final state)
        FAILED,    // For all blocks after PRIMARY if activation is not guaranteed(final state)
    };

    /** Returns the state for pindex A based on parent pindexPrev B */
    State GetStateFor(const CBlockIndex* pindexPrev, const Consensus::SignalledDeploymentParams& dep, const Condition& condition);

    /** Represents the current soft-fork state, and the height at which the chain entered the state */
    struct StateHeight {
        State state;
        int height;
    };

    /** Returns the state/entry height for pindex A based on parent pindexPrev B */
    StateHeight GetStateHeightFor(const CBlockIndex* pindexPrev, const Consensus::SignalledDeploymentParams& dep, const Condition& condition);

    /** Holds the status of an in-progress SignalledDeployment softfork */
    struct Stats {
        /** Number of blocks elapsed since the beginning of the current period */
        uint16_t elapsed;
        /** Number of blocks with the version bit set since the beginning of the current period */
        uint16_t count;
        /** False if there are not enough blocks left in this period to pass activation threshold */
        bool possible;
    };

    /** Returns the numerical statistics of an in-progress SignalledDeployment softfork in the current period */
    static Stats GetStateStatisticsFor(const CBlockIndex* pindex, const Consensus::SignalledDeploymentParams& dep, const Condition& condition);

    /** Returns if a deployment is always disabled */
    static bool AlwaysDisabled(const Consensus::SignalledDeploymentParams& dep);

    /** Resets the cache */
    void clear() { return m_cache.clear(); }

private:
    // A map that gives the signalling state for blocks at the end of each signalling
    // period. (All keys in the map will be a block with (height + 1) % Period() == 0)
    // Value is 0 if signalling has failed to this point, or the number of periods
    // since signalling succeeded including the period in which signalling succeeded.
    std::map<const CBlockIndex*, StateHeight> m_cache;
};

class DeploymentStatus
{
private:
    /** BIP xxx allows multiple softforks to be deployed in parallel. We cache per-period state for every one of them. */
    SignalledDeploymentStatus m_mds[Consensus::MAX_VERSION_BITS_DEPLOYMENTS];

public:
    using State = SignalledDeploymentStatus::State;
    using StateHeight = SignalledDeploymentStatus::StateHeight;
    using Stats = SignalledDeploymentStatus::Stats;

    State GetStateFor(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::SignalledDeployment pos);
    StateHeight GetStateHeightFor(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::SignalledDeployment pos);

    static uint32_t Mask(const Consensus::Params& params, Consensus::SignalledDeployment pos);
    static Stats GetStateStatisticsFor(const CBlockIndex* pindex, const Consensus::Params& params, Consensus::SignalledDeployment pos);

    void Clear();

    class Condition : public SignalledDeploymentStatus::Condition
    {
        bool operator()(const CBlockIndex* pindex, const Consensus::SignalledDeploymentParams& dep) const override;
    };

    /**
     * Determine what nVersion a new block should use.
     */
    int32_t ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params);

    static const Condition g_condition; // no guard needed for const object with no data
};

extern DeploymentStatus g_deploymentstatus GUARDED_BY(cs_main);

#endif // BITCOIN_DEPLOYMENTSTATUS_H
