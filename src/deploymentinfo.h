// Copyright (c) 2016-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DEPLOYMENTINFO_H
#define BITCOIN_DEPLOYMENTINFO_H

#include <consensus/params.h>

#include <string>

struct VBDeploymentInfo {
    /** Deployment name */
    const char *name;
    /** Whether GBT clients can safely ignore this rule in simplified usage */
    bool gbt_force;
    /** Whether GBT clients should be told about this rule */
    bool gbt_hide;
};

VBDeploymentInfo GetDeploymentInfo(Consensus::DeploymentPos pos);
inline std::string DeploymentName(Consensus::DeploymentPos pos) { return GetDeploymentInfo(pos).name; }

#endif // BITCOIN_DEPLOYMENTINFO_H
