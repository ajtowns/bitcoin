// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <uint256.h>
#include <limits>

namespace Consensus {

enum DeploymentFixed
{
    // buried deployments get negative values to avoid overlap with DeploymentPos
    DEPLOYMENT_CLTV = -255,
    DEPLOYMENT_DERSIG,
    DEPLOYMENT_CSV,
    DEPLOYMENT_SEGWIT,
};

enum DeploymentPos
{
    DEPLOYMENT_TESTDUMMY,
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in versionbitsinfo.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};

/**
 * Struct for each individual consensus rule change using a ModernDeployment
 * See Deployment<>() in versionbits.h for safe initialisation.
 */
struct ModernDeployment {
    /** Start height for version bits miner confirmation. */
    int start_height;

    /** Number of periods in each phase. */
    uint16_t primary_periods;
    uint16_t quiet_periods;
    uint16_t secondary_periods;

    /** Length of each period (normally same as nMinerConfirmationWindow)
     */
    uint16_t period;

    /** Number of blocks signalling in a period to move to locked in */
    uint16_t threshold;

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
    /** Don't warn about unknown ModernDeployment activations below this height.
     * This prevents us from warning about the CSV and segwit activations. */
    int MinModernDeploymentWarningHeight;
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint16_t nRuleChangeActivationThreshold;
    uint16_t nMinerConfirmationWindow;
    ModernDeployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }
    uint256 nMinimumChainWork;
    uint256 defaultAssumeValid;
};
} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
