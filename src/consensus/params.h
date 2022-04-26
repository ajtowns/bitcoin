// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <uint256.h>

#include <limits>
#include <map>

namespace Consensus {

/**
 * A buried deployment is one where the height of the activation has been hardcoded into
 * the client implementation long after the consensus change has activated. See BIP 90.
 */
struct BuriedDeployment {
    int height = std::numeric_limits<int>::max();
};

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit{28};
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime{NEVER_ACTIVE};
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout{NEVER_ACTIVE};

    /** Number of blocks in period */
    int period = std::numeric_limits<int>::max();
    /** Number of signalling blocks required to achieve lock in */
    int threshold = std::numeric_limits<int>::max();

    /** Constant for nTimeout very far in the future. */
    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();

    /** Special value for nStartTime indicating that the deployment is always active.
     *  This is useful for testing, as it means tests don't need to deal with the activation
     *  process (which takes at least 3 BIP9 intervals). Only tests that specifically test the
     *  behaviour during activation cannot use this. */
    static constexpr int64_t ALWAYS_ACTIVE = -1;

    /** Special value for nStartTime indicating that the deployment is never active.
     *  This is useful for integrating the code changes for a new feature
     *  prior to deploying it on some or all networks. */
    static constexpr int64_t NEVER_ACTIVE = -2;
};

struct BIP341Deployment : public BIP9Deployment
{
    /** If lock in occurs, delay activation until at least this block
     *  height.  Note that activation will only occur on a retarget
     *  boundary.
     */
    int min_activation_height{0};
};

struct BIPBlahDeployment
{
    int period{MAX};
    int bit{28};
    int64_t optin_start{NEVER_ACTIVE};
    int64_t optin_timeout{NEVER_ACTIVE};
    int64_t optin_earliest_activation{MAX64};
    int optin_threshold{MAX};

    /* height and hash of the final OPT_IN block */
    int optout_block_height{0};
    uint256 optout_block_hash{};

    int64_t optout_start{MAX64};
    int64_t optout_earliest_activation{MAX64};
    int optout_threshold{0};

    static constexpr int ALWAYS_ACTIVE{-1};
    static constexpr int NEVER_ACTIVE{-2};
    static constexpr int MAX{std::numeric_limits<int>::max()};
    static constexpr int64_t MAX64{std::numeric_limits<int64_t>::max()};
    static constexpr int64_t NO_TIMEOUT{MAX64};
};

enum DeploymentPos {
    DEPLOYMENT_HEIGHTINCB,
    DEPLOYMENT_CLTV,
    DEPLOYMENT_DERSIG,
    DEPLOYMENT_CSV,
    DEPLOYMENT_SEGWIT,
    DEPLOYMENT_SIGNET,
    DEPLOYMENT_TAPROOT, // Deployment of Schnorr/Taproot (BIPs 340-342)

    DEPLOYMENT_TESTDUMMY,
    MAX_VERSION_BITS_DEPLOYMENTS
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in deploymentinfo.cpp
};

/** Deployment type (buried, bip9)
 * Usually buried, but overridden for specific deployments
 */
template<size_t pos> struct DeploymentType { using T = BuriedDeployment; };
template<> struct DeploymentType<DEPLOYMENT_SEGWIT> { using T = BIP9Deployment; };
template<> struct DeploymentType<DEPLOYMENT_TAPROOT> { using T = BIP341Deployment; };
template<> struct DeploymentType<DEPLOYMENT_TESTDUMMY> { using T = BIP341Deployment; };

template<typename T> struct DepParams_impl;
template<size_t... I>
struct DepParams_impl<std::index_sequence<I...>>
{
    using T = std::tuple<typename DeploymentType<static_cast<DeploymentPos>(I)>::T...>;
};

/** Tuple type for the parameters for each deployment */
using DeploymentParams = DepParams_impl<std::make_index_sequence<MAX_VERSION_BITS_DEPLOYMENTS>>::T;

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    /**
     * Hashes of blocks that
     * - are known to be consensus valid, and
     * - buried in the chain, and
     * - fail if the default script verify flags are applied.
     */
    std::map<uint256, uint32_t> script_flag_exceptions;
    /** Hash at which HEIGHTINCB/BIP34 becomes active */
    uint256 BIP34Hash;
    /** Don't warn about unknown BIP 9 activations below this height.
     * This prevents us from warning about the CSV and segwit activations. */
    int MinBIP9WarningHeight;
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    DeploymentParams vDeployments;
    static_assert(std::tuple_size_v<decltype(vDeployments)> == MAX_VERSION_BITS_DEPLOYMENTS);
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }
    /** The best chain should have at least this much work */
    uint256 nMinimumChainWork;
    /** By default assume that the signatures in ancestors of this block are valid */
    uint256 defaultAssumeValid;

    /**
     * If true, witness commitments contain a payload equal to a Bitcoin Script solution
     * to the signet challenge. See BIP325.
     */
    bool signet_blocks{false};
    std::vector<uint8_t> signet_challenge;
};

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
