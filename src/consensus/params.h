// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <uint256.h>
#include <limits>

namespace Consensus {

enum BuriedDeployment
{
    // buried deployments get negative values to avoid overlap with BIP8Deployment
    DEPLOYMENT_CLTV = -255,
    DEPLOYMENT_DERSIG,
    DEPLOYMENT_CSV,
    DEPLOYMENT_SEGWIT,
};

enum BIP8Deployment
{
    DEPLOYMENT_TESTDUMMY,
    // NOTE: Also add new deployments to DeploymentInfo in consensus/deployment.cpp
    MAX_BIP8_DEPLOYMENTS
};

/**
 * Per-chain parameters for each signalled consensus rule change
 * See Deployment<>() in consensus/deployment.h for safe initialisation.
 */
struct BIP8DeploymentParams {
    /** Length of each period (normally same as nMinerConfirmationWindow)
     */
    uint16_t period;

    /** Number of blocks signalling in a period to move to locked in */
    uint16_t threshold;

    /** Start height for version bits miner confirmation. */
    int start_height;

    /** Number of periods in signalling phase. */
    uint16_t signal_periods;

    /** Bit position to select the particular bit in nVersion. */
    uint8_t bit;

    /** Guaranteed activation? */
    bool guaranteed;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    /* Block hash that is excepted from BIP16 enforcement */
    uint256 BIP16Exception;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;
    /** Block height at which CSV (BIP68, BIP112 and BIP113) becomes active */
    int CSVHeight;
    /** Block height at which Segwit (BIP141, BIP143 and BIP147) becomes active.
     * Note that segwit v0 script rules are enforced on all blocks except the
     * BIP 16 exception blocks. */
    int SegwitHeight;
    /** Don't warn about unknown potential signalled activations below this height.
     * This prevents us from warning about the CSV and segwit activations. */
    int MinBIP8DeploymentWarningHeight;
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint16_t nRuleChangeActivationThreshold;
    uint16_t nMinerConfirmationWindow;
    BIP8DeploymentParams vDeployments[MAX_BIP8_DEPLOYMENTS];
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }
    uint256 nMinimumChainWork;
    uint256 defaultAssumeValid;

    inline int DeploymentHeight(BuriedDeployment dep) const
    {
        return (dep == Consensus::DEPLOYMENT_CLTV)   ? BIP65Height :
               (dep == Consensus::DEPLOYMENT_DERSIG) ? BIP66Height :
               (dep == Consensus::DEPLOYMENT_CSV)    ? CSVHeight :
               (dep == Consensus::DEPLOYMENT_SEGWIT) ? SegwitHeight :
               std::numeric_limits<int>::max();
    }
};

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
