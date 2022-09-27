// Copyright (c) 2016-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <deploymentinfo.h>

#include <consensus/params.h>

const struct VBDeploymentInfo VersionBitsDeploymentInfo[Consensus::MAX_VERSION_BITS_DEPLOYMENTS] = {
    {
        /*.name =*/ "testdummy",
        /*.gbt_force =*/ true,
    },
    {
        /*.name =*/ "taproot",
        /*.gbt_force =*/ true,
    },
};

static const std::map<Consensus::BuriedDeployment, std::string> g_buried_deployment_names = {
    {Consensus::DEPLOYMENT_HEIGHTINCB, "bip34"},
    {Consensus::DEPLOYMENT_CLTV, "bip65"},
    {Consensus::DEPLOYMENT_DERSIG, "bip66"},
    {Consensus::DEPLOYMENT_CSV, "csv"},
    {Consensus::DEPLOYMENT_SEGWIT, "segwit"},
};

std::optional<Consensus::BuriedDeployment> GetBuriedDeployment(const std::string& depname)
{
    for (const auto& [dep, name] : g_buried_deployment_names) {
        if (name == depname) return dep;
    }
    // special cases for compat
    if (depname == "dersig") {
        return Consensus::DEPLOYMENT_DERSIG;
    } else if (depname == "cltv") {
        return Consensus::DEPLOYMENT_CLTV;
    }

    // unknown
    return std::nullopt;
}

std::string DeploymentName(Consensus::BuriedDeployment dep)
{
    assert(ValidDeployment(dep));
    const auto& it = g_buried_deployment_names.find(dep);
    if (it != g_buried_deployment_names.end()) return it->second;
    return "";
}
