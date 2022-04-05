// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <deploymentstatus.h>

#include <consensus/params.h>
#include <versionbits.h>
#include <chainparams.h>

#include <type_traits>

int32_t VersionBitsCache::ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    int32_t nVersion = VERSIONBITS_TOP_BITS;
    ForEachDeployment(params, [&](auto pos, const auto& logic, auto& cache) {
        if (logic.VersionBitToSet(cache, pindexPrev)) {
            nVersion |= logic.Mask();
        }
    });

    return nVersion;
}

void VersionBitsCache::Clear()
{
    ForEachDeployment(Params().GetConsensus(), [&](auto pos, const auto& logic, auto& cache) {
        logic.ClearCache(cache);
    });
}
