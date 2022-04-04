// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <deploymentstatus.h>

#include <consensus/params.h>
#include <versionbits.h>
#include <chainparams.h>

#include <type_traits>

using ThresholdState = ConditionLogic::State;

/* Basic sanity checking for BuriedDeployment/DeploymentPos enums and
 * ValidDeployment check */

static_assert(ValidDeployment(Consensus::DEPLOYMENT_TESTDUMMY), "sanity check of DeploymentPos failed (TESTDUMMY not valid)");
static_assert(!ValidDeployment(Consensus::MAX_VERSION_BITS_DEPLOYMENTS), "sanity check of DeploymentPos failed (MAX value considered valid)");
static_assert(!ValidDeployment(static_cast<Consensus::BuriedDeployment>(Consensus::DEPLOYMENT_TESTDUMMY)), "sanity check of BuriedDeployment failed (overlaps with DeploymentPos)");

/* ValidDeployment only checks upper bounds for ensuring validity.
 * This checks that the lowest possible value or the type is also a
 * (specific) valid deployment so that lower bounds don't need to be checked.
 */

template<typename T, T x>
static constexpr bool is_minimum()
{
    using U = typename std::underlying_type<T>::type;
    return x == std::numeric_limits<U>::min();
}

static_assert(is_minimum<Consensus::BuriedDeployment, Consensus::DEPLOYMENT_HEIGHTINCB>(), "heightincb is not minimum value for BuriedDeployment");
static_assert(is_minimum<Consensus::DeploymentPos, Consensus::DEPLOYMENT_TESTDUMMY>(), "testdummy is not minimum value for DeploymentPos");

uint32_t VersionBitsCache::Mask(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    return GetLogic(params, pos).Mask();
}

int32_t VersionBitsCache::ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    int32_t nVersion = VERSIONBITS_TOP_BITS;
    ForEachDeployment(params, [&](auto pos, const auto& logic, auto& cache) {
        if (logic.ShouldSetVersionBit(cache, pindexPrev)) {
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
