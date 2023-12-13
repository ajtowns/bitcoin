// Copyright (c) 2016-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <deploymentinfo.h>

#include <consensus/params.h>

#include <string_view>

static std::array<VBDeploymentInfo,Consensus::MAX_VERSION_BITS_DEPLOYMENTS> MakeDefaults()
{
    std::array<VBDeploymentInfo,Consensus::MAX_VERSION_BITS_DEPLOYMENTS> result;

    std::get<Consensus::DEPLOYMENT_TESTDUMMY>(result) = { .name = "testdummy", .gbt_force = true };
    std::get<Consensus::DEPLOYMENT_HEIGHTINCB>(result) = { .name = "bip34", .gbt_force = true };
    std::get<Consensus::DEPLOYMENT_CLTV>(result) = { .name = "cltv", .gbt_force = true };
    std::get<Consensus::DEPLOYMENT_DERSIG>(result) = { .name = "dersig", .gbt_force = true };
    std::get<Consensus::DEPLOYMENT_CSV>(result) = { .name = "csv", .gbt_force = true };
    std::get<Consensus::DEPLOYMENT_SEGWIT>(result) = { .name = "segwit", .gbt_force = true };
    std::get<Consensus::DEPLOYMENT_TAPROOT>(result) = { .name = "taproot", .gbt_force = true };

    return result;
}

const std::array<VBDeploymentInfo,Consensus::MAX_VERSION_BITS_DEPLOYMENTS> VersionBitsDeploymentInfo = MakeDefaults();

std::optional<Consensus::DeploymentPos> GetBIP9Deployment(const std::string_view name)
{
    for (size_t i = 0; i < std::tuple_size_v<decltype(VersionBitsDeploymentInfo)>; ++i) {
        if (name == VersionBitsDeploymentInfo[i].name) {
            return static_cast<Consensus::DeploymentPos>(i);
        }
    }
    return std::nullopt;
}

std::optional<Consensus::BuriedDeployment> GetBuriedDeployment(const std::string_view name)
{
    return std::nullopt;
}
