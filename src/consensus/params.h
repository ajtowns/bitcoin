// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include "consensus/deployments.h"
#include "uint256.h"
#include <map>
#include <string>

class CBlockIndex;

namespace Consensus {

struct UnknownDeploymentWarning {
    virtual void DoWarning(const std::string&) = 0;
    std::vector<std::string> warningMessages;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;

private:
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;

public:
    inline void SetBIP34Params(int height) { BIP34Height = height; BIP34Hash = uint256(); }
    inline void SetBIP34Params(int height, const char* hash) { BIP34Height = height; BIP34Hash = uint256S(hash); }
    inline void SetBIP65Params(int height) { BIP65Height = height; }
    inline void SetBIP66Params(int height) { BIP66Height = height; }

    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }
    uint256 nMinimumChainWork;
    uint256 defaultAssumeValid;

    /** Determine if a given deployment is active at the given block.
     * Expects cs_main to be already locked */
    bool DeploymentActivePrev(Consensus::DeploymentPos pos, const CBlockIndex* pindexPrev) const;
    bool DeploymentActive(Consensus::DeploymentPos pos, const CBlockIndex* pindex) const;
    /** Check for activation of unknown warnings
     * Expects cs_main to be already locked */
    void CheckUnknownRules(const CBlockIndex* pindex, UnknownDeploymentWarning *warn) const;
};

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
