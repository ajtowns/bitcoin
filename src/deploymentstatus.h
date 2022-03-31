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
template<Consensus::BuriedDeployment dep>
inline bool DeploymentActiveAfter(const CBlockIndex* pindexPrev, const ChainstateManager& chainman)
{
    static_assert(Consensus::ValidDeployment(dep));
    return (pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1) >= chainman.GetConsensus().DeploymentHeight(dep);
}

template<Consensus::DeploymentPos dep>
inline bool DeploymentActiveAfter(const CBlockIndex* pindexPrev, const ChainstateManager& chainman)
{
    static_assert(Consensus::ValidDeployment(dep));
    return chainman.m_versionbitscache.IsActive(pindexPrev, chainman.GetConsensus(), dep);
}

/** Determine if a deployment is active for this block */
template<Consensus::BuriedDeployment dep>
inline bool DeploymentActiveAt(const CBlockIndex& index, const ChainstateManager& chainman)
{
    static_assert(Consensus::ValidDeployment(dep));
    return index.nHeight >= chainman.GetConsensus().DeploymentHeight(dep);
}

template<Consensus::DeploymentPos dep>
inline bool DeploymentActiveAt(const CBlockIndex& index, const ChainstateManager& chainman)
{
    static_assert(Consensus::ValidDeployment(dep));
    return DeploymentActiveAfter<dep>(index.pprev, chainman);
}

/** Determine if a deployment is enabled (can ever be active) */
template<typename T>
inline bool DeploymentEnabled(const ChainstateManager& chainman, T dep)
{
    assert(Consensus::ValidDeployment(dep));
    return chainman.m_versionbitscache.GetLogic(chainman.GetConsensus(), dep).Enabled();
}

#endif // BITCOIN_DEPLOYMENTSTATUS_H
