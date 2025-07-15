// Copyright (c) 2016-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VERSIONBITS_IMPL_H
#define BITCOIN_VERSIONBITS_IMPL_H

#include <chain.h>
#include <sync.h>
#include <versionbits.h>

/** BIP 9 defines a finite-state-machine to deploy a softfork in multiple stages.
 *  State transitions happen during retarget period if conditions are met
 *  In case of reorg, transitions can go backward. Without transition, state is
 *  inherited between periods. All blocks of a period share the same state.
 *
 *  States here are updated for heretical activations.
 */
enum class ThresholdState : uint8_t {
    DEFINED,   // Inactive, waiting for begin time
    STARTED,   // Inactive, waiting for signal/timeout
    LOCKED_IN, // Activation signalled, will be active next period
    ACTIVE,    // Active; will deactivate on signal or timeout
    DEACTIVATING, // Still active, will be abandoned next period
    ABANDONED, // Not active, terminal state
};

/** Get a string with the state name */
std::string StateName(ThresholdState state);

/**
 * Abstract class that implements BIP9-style threshold logic, and caches results.
 */
class AbstractThresholdConditionChecker {
protected:
    virtual int64_t BeginTime() const =0;
    virtual int64_t EndTime() const =0;
    virtual int Period() const =0;
    virtual int32_t ActivateVersion() const =0;
    virtual int32_t AbandonVersion() const =0;

public:
    virtual ~AbstractThresholdConditionChecker() = default;

    /** Returns the state for pindex A based on parent pindexPrev B. Applies any state transition if conditions are present.
     *  Caches state from first block of period. */
    ThresholdState GetStateFor(const CBlockIndex* pindexPrev, ThresholdConditionCache& cache) const;
    /** Returns the height since when the ThresholdState has started for pindex A based on parent pindexPrev B, all blocks of a period share the same */
    int GetStateSinceHeightFor(const CBlockIndex* pindexPrev, ThresholdConditionCache& cache) const;

    /** Report BINANA id, based on nVersion signalling standard */
    bool BINANA(int& year, int& number, int& revision) const;

    /** Returns signalling information */
    std::vector<SignalInfo> GetSignalInfo(const CBlockIndex* pindex) const;
};

/**
 * Class to implement versionbits logic.
 */
class VersionBitsConditionChecker : public AbstractThresholdConditionChecker {
private:
    const Consensus::HereticalDeployment& dep;

protected:
    int64_t BeginTime() const override { return dep.nStartTime; }
    int64_t EndTime() const override { return dep.nTimeout; }
    int Period() const override { return dep.period; }

public:
    explicit VersionBitsConditionChecker(const Consensus::HereticalDeployment& dep) : dep{dep} {}
    explicit VersionBitsConditionChecker(const Consensus::Params& params, Consensus::DeploymentPos id) : VersionBitsConditionChecker{params.vDeployments[id]} {}

    int32_t ActivateVersion() const override { return dep.signal_activate; }
    int32_t AbandonVersion() const override { return dep.signal_abandon; }

    BIP9Info Info(const CBlockIndex& block_index, ThresholdConditionCache& cache);
};

#endif // BITCOIN_VERSIONBITS_IMPL_H
