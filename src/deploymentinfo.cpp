// Copyright (c) 2016-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <deploymentinfo.h>

#include <consensus/params.h>

VBDeploymentInfo GetDeploymentInfo(Consensus::DeploymentPos pos)
{
    switch (pos) {
    case Consensus::DEPLOYMENT_HEIGHTINCB:
        return {"bip34", /*.gbt_force=*/true, /*.gbt_hide=*/true};
    case Consensus::DEPLOYMENT_CLTV:
        return {"cltv", /*.gbt_force=*/true, /*.gbt_hide=*/true};
    case Consensus::DEPLOYMENT_DERSIG:
        return {"dersig", /*.gbt_force=*/true, /*.gbt_hide=*/true};
    case Consensus::DEPLOYMENT_CSV:
        return {"csv", /*.gbt_force=*/true, /*.gbt_hide=*/false};
    case Consensus::DEPLOYMENT_SEGWIT:
        return {"segwit", /*.gbt_force=*/false, /*.gbt_hide=*/false};
    case Consensus::DEPLOYMENT_SIGNET:
        return {"signet", /*.gbt_force=*/false, /*.gbt_hide=*/false};
    case Consensus::DEPLOYMENT_TESTDUMMY:
        return {
            /*.name =*/ "testdummy",
            /*.gbt_force =*/ true,
            /*.gbt_hide =*/ false,
        };
    case Consensus::DEPLOYMENT_TAPROOT:
        return {
            /*.name =*/ "taproot",
            /*.gbt_force =*/ true,
            /*.gbt_hide =*/ false,
        };
    case Consensus::MAX_VERSION_BITS_DEPLOYMENTS:
        break;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}
