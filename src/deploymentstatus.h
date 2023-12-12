// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DEPLOYMENTSTATUS_H
#define BITCOIN_DEPLOYMENTSTATUS_H

#include <chain.h>
#include <versionbits.h>

#include <limits>

/** Determine if a deployment is active for the next block */
template<Consensus::BuriedDeployment dep>
inline bool DeploymentActiveAfter(const CBlockIndex* pindexPrev, const Consensus::Params& params, [[maybe_unused]] VersionBitsCache& versionbitscache)
{
    static_assert(Consensus::ValidDeployment(dep));
    return (pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1) >= params.DeploymentHeight(dep);
}

template<Consensus::DeploymentPos dep>
inline bool DeploymentActiveAfter(const CBlockIndex* pindexPrev, const Consensus::Params& params, VersionBitsCache& versionbitscache)
{
    static_assert(Consensus::ValidDeployment(dep));
    return versionbitscache.IsActiveAfter(pindexPrev, params, dep);
}

/** Determine if a deployment is active for this block */
template<Consensus::BuriedDeployment dep>
inline bool DeploymentActiveAt(const CBlockIndex& index, const Consensus::Params& params, [[maybe_unused]] VersionBitsCache& versionbitscache)
{
    static_assert(Consensus::ValidDeployment(dep));
    return index.nHeight >= params.DeploymentHeight(dep);
}

template<Consensus::DeploymentPos dep>
inline bool DeploymentActiveAt(const CBlockIndex& index, const Consensus::Params& params, VersionBitsCache& versionbitscache)
{
    static_assert(Consensus::ValidDeployment(dep));
    return DeploymentActiveAfter<dep>(index.pprev, params, versionbitscache);
}

/** Determine if a deployment is enabled (can ever be active) */
template<Consensus::BuriedDeployment dep>
inline bool DeploymentEnabled(const Consensus::Params& params)
{
    static_assert(Consensus::ValidDeployment(dep));
    return params.DeploymentHeight(dep) != std::numeric_limits<int>::max();
}

template<Consensus::DeploymentPos dep>
inline bool DeploymentEnabled(const Consensus::Params& params)
{
    static_assert(Consensus::ValidDeployment(dep));
    return params.vDeployments[dep].nStartTime != Consensus::BIP9Deployment::NEVER_ACTIVE;
}

#endif // BITCOIN_DEPLOYMENTSTATUS_H
