// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DEPLOYMENTSTATUS_H
#define BITCOIN_DEPLOYMENTSTATUS_H

#include <chain.h>
#include <versionbits.h>

#include <limits>

/** Determine if a deployment is active for the next block */
template<Consensus::DeploymentPos dep>
inline bool DeploymentActiveAfter(const CBlockIndex* pindexPrev, const Consensus::Params& params, VersionBitsCache& versionbitscache)
{
    return versionbitscache.IsActiveAfter<dep>(pindexPrev, params);
}

/** Determine if a deployment is active for this block */
template<Consensus::DeploymentPos dep>
inline bool DeploymentActiveAt(const CBlockIndex& index, const Consensus::Params& params, VersionBitsCache& versionbitscache)
{
    return DeploymentActiveAfter<dep>(index.pprev, params, versionbitscache);
}

/** Determine if a deployment is enabled (can ever be active) */
template <Consensus::DeploymentPos dep>
inline bool DeploymentEnabled(const Consensus::Params& params, const VersionBitsCache& versionbitscache)
{
    return versionbitscache.Enabled<dep>(params);
}

#endif // BITCOIN_DEPLOYMENTSTATUS_H
