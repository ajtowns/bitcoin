// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DEPLOYMENTSTATUS_H
#define BITCOIN_DEPLOYMENTSTATUS_H

#include <chain.h>
#include <validation.h>
#include <versionbits.h>

#include <limits>

/** Determine if a deployment is active for the next block */
inline bool DeploymentActiveAfter(const CBlockIndex* pindexPrev, const ChainstateManager& chainman, Consensus::BuriedDeployment dep)
{
    assert(Consensus::ValidDeployment(dep));
    return (pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1) >= chainman.GetConsensus().DeploymentHeight(dep);
}

inline bool DeploymentActiveAfter(const CBlockIndex* pindexPrev, const ChainstateManager& chainman, Consensus::DeploymentPos dep)
{
    assert(Consensus::ValidDeployment(dep));
    return chainman.m_versionbitscache.IsActive(pindexPrev, chainman.GetConsensus(), dep);
}

/** Determine if a deployment is active for this block */
inline bool DeploymentActiveAt(const CBlockIndex& index, const ChainstateManager& chainman, Consensus::BuriedDeployment dep)
{
    assert(Consensus::ValidDeployment(dep));
    return index.nHeight >= chainman.GetConsensus().DeploymentHeight(dep);
}

inline bool DeploymentActiveAt(const CBlockIndex& index, const ChainstateManager& chainman, Consensus::DeploymentPos dep)
{
    assert(Consensus::ValidDeployment(dep));
    return DeploymentActiveAfter(index.pprev, chainman, dep);
}

/** Determine if a deployment is enabled (can ever be active) */
inline bool DeploymentEnabled(const ChainstateManager& chainman, Consensus::BuriedDeployment dep)
{
    assert(Consensus::ValidDeployment(dep));
    return chainman.GetConsensus().DeploymentHeight(dep) != std::numeric_limits<int>::max();
}

inline bool DeploymentEnabled(const ChainstateManager& chainman, Consensus::DeploymentPos dep)
{
    assert(Consensus::ValidDeployment(dep));
    return chainman.GetConsensus().vDeployments[dep].nStartTime != Consensus::BIP9Deployment::NEVER_ACTIVE;
}

#endif // BITCOIN_DEPLOYMENTSTATUS_H
