// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <uint256.h>

#include <array>
#include <chrono>
#include <limits>
#include <map>
#include <vector>

namespace Consensus {

/**** HELPERS ****/
enum DeploymentPos : uint16_t;
template<DeploymentPos D> struct DeploymentParams;

template<template<DeploymentPos> typename TT, typename T> struct MkDepTuple;

template<template<DeploymentPos> typename TT, size_t... N>
struct MkDepTuple<TT, std::integer_sequence<size_t, N...>> {
    using type = std::tuple<typename TT<DeploymentPos{N}>::type...>;
};

template<template<DeploymentPos> typename TT, size_t MAX>
using DepTuple = typename MkDepTuple<TT, std::make_integer_sequence<size_t, size_t{MAX}>>::type;

enum DeploymentPos : uint16_t {
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_HEIGHTINCB,
    DEPLOYMENT_CLTV,
    DEPLOYMENT_DERSIG,
    DEPLOYMENT_CSV,
    DEPLOYMENT_SEGWIT,
    DEPLOYMENT_TAPROOT, // Deployment of Schnorr/Taproot (BIPs 340-342)
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in deploymentinfo.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};

/**
 * A buried deployment is one where the height of the activation has been hardcoded into
 * the client implementation long after the consensus change has activated. See BIP 90.
 */
struct BuriedDeploymentParams {
    int height = std::numeric_limits<int>::max();
};

// Default
template<DeploymentPos D> struct DeploymentParams { using type = BuriedDeploymentParams; };

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
    /** If lock in occurs, delay activation until at least this block
     *  height.  Note that activation will only occur on a retarget
     *  boundary.
     */
    int min_activation_height{0};
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t threshold{1916};
    uint32_t window{2016};

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

template<> struct DeploymentParams<DEPLOYMENT_TESTDUMMY> { using type = BIP9Deployment; };
template<> struct DeploymentParams<DEPLOYMENT_TAPROOT> { using type = BIP9Deployment; };

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
    /** Block hash at which BIP34 becoming active allows ignoring BIP30... */
    uint256 BIP34Hash;
    /** Don't warn about unknown BIP 9 activations below this height.
     * This prevents us from warning about the CSV and segwit activations. */
    int MinBIP9WarningHeight;
    DepTuple<DeploymentParams, MAX_VERSION_BITS_DEPLOYMENTS> vDeployments;
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    std::chrono::seconds PowTargetSpacing() const
    {
        return std::chrono::seconds{nPowTargetSpacing};
    }
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

    int BIP34Height() const
    {
        return std::get<DEPLOYMENT_HEIGHTINCB>(vDeployments).height;
    }

    template <typename Fn>
    void ForEachDeployment(Fn&& fn) const { _ForEachDeployment(*this, fn); }

    template <typename Fn>
    void ForEachDeployment(Fn&& fn) { _ForEachDeployment(*this, fn); }

private:
    template <size_t I=0, typename P, typename Fn>
    static void _ForEachDeployment(P& params, Fn&& fn)
    {
        if constexpr (I < std::tuple_size_v<decltype(params.vDeployments)>) {
            fn(static_cast<DeploymentPos>(I), std::get<I>(params.vDeployments));
            _ForEachDeployment<I+1>(params, fn);
        }
    }
};

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
