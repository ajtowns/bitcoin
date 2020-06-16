// Copyright (c) 2016-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DEPLOYMENTSTATUS_H
#define BITCOIN_DEPLOYMENTSTATUS_H

#include <chain.h>
#include <sync.h>

#include <limits>
#include <map>

/**
 * Determine if deployment is active
 * DeploymentFixed variants are inline since they can be almost entirely optimised out
 */
inline bool DeploymentActiveAfter(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::BuriedDeployment dep)
{
    const int height = (pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1);
    return height >= params.DeploymentHeight(dep);
}

inline bool DeploymentActiveAt(const CBlockIndex* pindex, const Consensus::Params& params, Consensus::BuriedDeployment dep)
{
    return pindex->nHeight >= params.DeploymentHeight(dep);
}

inline bool DeploymentDisabled(const Consensus::Params& params, Consensus::BuriedDeployment dep)
{
    return params.DeploymentHeight(dep) == std::numeric_limits<int>::max();
}

#endif // BITCOIN_DEPLOYMENTSTATUS_H
