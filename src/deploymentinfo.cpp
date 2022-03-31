// Copyright (c) 2016-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <deploymentinfo.h>

#include <consensus/params.h>

const struct VBDeploymentInfo VersionBitsDeploymentInfo[Consensus::MAX_VERSION_BITS_DEPLOYMENTS] = {
    {
        /*.name =*/ "testdummy",
        /*.gbt_force =*/ true,
        /*.gbt_hide =*/ false,
    },
    {
        /*.name =*/ "taproot",
        /*.gbt_force =*/ true,
        /*.gbt_hide =*/ false,
    },
};

VBDeploymentInfo GetDeploymentInfo(Consensus::BuriedDeployment dep)
{
    assert(ValidDeployment(dep));
    switch (dep) {
    case Consensus::DEPLOYMENT_HEIGHTINCB:
        return {"bip34", /*.gbt_force=*/true, /*.gbt_hide=*/true};
    case Consensus::DEPLOYMENT_CLTV:
        return {"bip65", /*.gbt_force=*/true, /*.gbt_hide=*/true};
    case Consensus::DEPLOYMENT_DERSIG:
        return {"bip66", /*.gbt_force=*/true, /*.gbt_hide=*/true};
    case Consensus::DEPLOYMENT_CSV:
        return {"csv", /*.gbt_force=*/true, /*.gbt_hide=*/false};
    case Consensus::DEPLOYMENT_SEGWIT:
        return {"segwit", /*.gbt_force=*/false, /*.gbt_hide=*/false};
    case Consensus::DEPLOYMENT_SIGNET:
        return {"signet", /*.gbt_force=*/false, /*.gbt_hide=*/false};
    } // no default case, so the compiler can warn about missing cases
    return {"undef", true, true};
}
