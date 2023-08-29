// Copyright (c) 2016-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/params.h>
#include <deploymentinfo.h>
#include <kernel/chainparams.h>
#include <util/check.h>
#include <versionbits.h>
#include <versionbits_impl.h>

using enum ThresholdState;

std::string StateName(ThresholdState state)
{
    switch (state) {
    case DEFINED: return "defined";
    case STARTED: return "started";
    case LOCKED_IN: return "locked_in";
    case ACTIVE: return "active";
    case DEACTIVATING: return "deactivating";
    case ABANDONED: return "abandoned";
    }
    return "invalid";
}

bool AbstractThresholdConditionChecker::BINANA(int& year, int& number, int& revision) const
{
    const int32_t activate = ActivateVersion();
    const int32_t abandon = AbandonVersion();

    if ((activate & ~VERSIONBITS_TOP_MASK) != (abandon & ~VERSIONBITS_TOP_MASK)) {
        return false;
    }
    if ((activate & 0x18000000) != 0) return false;
    if ((activate & VERSIONBITS_TOP_MASK) != VERSIONBITS_TOP_ACTIVE) return false;
    if ((abandon & VERSIONBITS_TOP_MASK) != VERSIONBITS_TOP_ABANDON) return false;

    year = ((activate & 0x07c00000) >> 22) + 2016;
    number = (activate & 0x003fff00) >> 8;
    revision = (activate & 0x000000ff);

    return true;
}

ThresholdState AbstractThresholdConditionChecker::GetStateFor(const CBlockIndex* pindexPrev, ThresholdConditionCache& cache) const
{
    int nPeriod = Period();
    int64_t nTimeStart = BeginTime();
    int64_t nTimeTimeout = EndTime();
    const int32_t activate = ActivateVersion();
    const int32_t abandon = AbandonVersion();

    // Check if this deployment is always active.
    if (nTimeStart == Consensus::HereticalDeployment::ALWAYS_ACTIVE) {
        return ThresholdState::ACTIVE;
    }

    // Check if this deployment is never active.
    if (nTimeStart == Consensus::HereticalDeployment::NEVER_ACTIVE) {
        return ThresholdState::ABANDONED;
    }

    // A block's state is always the same as that of the first of its period, so it is computed based on a pindexPrev whose height equals a multiple of nPeriod - 1.
    if (pindexPrev != nullptr) {
        pindexPrev = pindexPrev->GetAncestor(pindexPrev->nHeight - ((pindexPrev->nHeight + 1) % nPeriod));
    }

    // Walk backwards in steps of nPeriod to find a pindexPrev whose information is known
    std::vector<const CBlockIndex*> vToCompute;
    while (cache.count(pindexPrev) == 0) {
        if (pindexPrev == nullptr) {
            // The genesis block is by definition defined.
            cache[pindexPrev] = ThresholdState::DEFINED;
            break;
        }
        if (pindexPrev->GetMedianTimePast() < nTimeStart && pindexPrev->GetMedianTimePast() < nTimeTimeout) {
            // Optimization: don't recompute down further, as we know every earlier block will be before the start time
            cache[pindexPrev] = ThresholdState::DEFINED;
            break;
        }
        vToCompute.push_back(pindexPrev);
        pindexPrev = pindexPrev->GetAncestor(pindexPrev->nHeight - nPeriod);
    }

    // At this point, cache[pindexPrev] is known
    assert(cache.count(pindexPrev));
    ThresholdState state = cache[pindexPrev];

    // Now walk forward and compute the state of descendants of pindexPrev
    while (!vToCompute.empty()) {
        ThresholdState stateNext = state;
        pindexPrev = vToCompute.back();
        vToCompute.pop_back();

        const bool finished = pindexPrev->GetMedianTimePast() >= nTimeTimeout;
        switch (state) {
            case ThresholdState::DEFINED: {
                if (finished) {
                    stateNext = ThresholdState::ABANDONED;
                } else if (pindexPrev->GetMedianTimePast() >= nTimeStart) {
                    stateNext = ThresholdState::STARTED;
                }
                break;
            }
            case ThresholdState::STARTED: {
                if (finished) {
                    stateNext = ThresholdState::ABANDONED;
                    break;
                }
                // We need to look for the signal
                const CBlockIndex* pindexCheck = pindexPrev;
                bool sig_active = false;
                bool sig_abandon = false;
                for (int i = 0; i < nPeriod; i++) {
                    if (pindexCheck->nVersion == abandon) {
                        sig_abandon = true;
                    } else if (pindexCheck->nVersion == activate) {
                        sig_active = true;
                    }
                    pindexCheck = pindexCheck->pprev;
                }
                if (sig_abandon) {
                    stateNext = ThresholdState::ABANDONED;
                } else if (sig_active) {
                    stateNext = ThresholdState::LOCKED_IN;
                }
                break;
            }
            case ThresholdState::LOCKED_IN:
                stateNext = ThresholdState::ACTIVE;
                [[fallthrough]]; // to check for abandonment signalling
            case ThresholdState::ACTIVE: {
                if (finished) {
                    stateNext = ThresholdState::DEACTIVATING;
                    break;
                }
                const CBlockIndex* pindexCheck = pindexPrev;
                for (int i = 0; i < nPeriod; ++i) {
                    if (pindexCheck->nVersion == abandon) {
                        stateNext = ThresholdState::DEACTIVATING;
                        break;
                    }
                    pindexCheck = pindexCheck->pprev;
                }
                break;
            }
            case ThresholdState::DEACTIVATING: {
                stateNext = ThresholdState::ABANDONED;
                break;
            }
            case ThresholdState::ABANDONED: {
                // Nothing happens, terminal state.
                break;
            }
        }
        cache[pindexPrev] = state = stateNext;
    }

    return state;
}

int AbstractThresholdConditionChecker::GetStateSinceHeightFor(const CBlockIndex* pindexPrev, ThresholdConditionCache& cache) const
{
    int64_t start_time = BeginTime();
    if (start_time == Consensus::HereticalDeployment::ALWAYS_ACTIVE || start_time == Consensus::HereticalDeployment::NEVER_ACTIVE) {
        return 0;
    }

    const ThresholdState initialState = GetStateFor(pindexPrev, cache);

    // BIP 9 about state DEFINED: "The genesis block is by definition in this state for each deployment."
    if (initialState == ThresholdState::DEFINED) {
        return 0;
    }

    const int nPeriod = Period();

    // A block's state is always the same as that of the first of its period, so it is computed based on a pindexPrev whose height equals a multiple of nPeriod - 1.
    // To ease understanding of the following height calculation, it helps to remember that
    // right now pindexPrev points to the block prior to the block that we are computing for, thus:
    // if we are computing for the last block of a period, then pindexPrev points to the second to last block of the period, and
    // if we are computing for the first block of a period, then pindexPrev points to the last block of the previous period.
    // The parent of the genesis block is represented by nullptr.
    pindexPrev = Assert(pindexPrev->GetAncestor(pindexPrev->nHeight - ((pindexPrev->nHeight + 1) % nPeriod)));

    const CBlockIndex* previousPeriodParent = pindexPrev->GetAncestor(pindexPrev->nHeight - nPeriod);

    while (previousPeriodParent != nullptr && GetStateFor(previousPeriodParent, cache) == initialState) {
        pindexPrev = previousPeriodParent;
        previousPeriodParent = pindexPrev->GetAncestor(pindexPrev->nHeight - nPeriod);
    }

    // Adjust the result because right now we point to the parent block.
    return pindexPrev->nHeight + 1;
}

BIP9Info VersionBitsCache::Info(const CBlockIndex& block_index, const Consensus::Params& params, Consensus::DeploymentPos id)
{
    LOCK(m_mutex);
    return VersionBitsConditionChecker(params, id).Info(block_index, m_caches[id]);
}

BIP9Info VersionBitsConditionChecker::Info(const CBlockIndex& block_index, ThresholdConditionCache& cache)
{
    BIP9Info result;

    const ThresholdState current_state = GetStateFor(block_index.pprev, cache);
    const ThresholdState next_state = GetStateFor(&block_index, cache);
    result.since = GetStateSinceHeightFor(block_index.pprev, cache);

    result.period = Period();
    result.current_state = StateName(current_state);
    result.next_state = StateName(next_state);

    switch (current_state) {
    case DEFINED:
    case ABANDONED:
        break;
    case STARTED:
        result.signal_activate = ActivateVersion();
        [[fallthrough]];
    case LOCKED_IN:
    case ACTIVE:
    case DEACTIVATING:
        if (BeginTime() != Consensus::HereticalDeployment::ALWAYS_ACTIVE) {
            result.signal_abandon = AbandonVersion();
        }
        break;
    }

    if (current_state == ACTIVE) {
        result.active_since = result.since;
    } else if (next_state == ACTIVE) {
        result.active_since = block_index.nHeight + 1;
    }

    return result;
}

BIP9GBTStatus VersionBitsCache::GBTStatus(const CBlockIndex& block_index, const Consensus::Params& params)
{
    BIP9GBTStatus result;

    LOCK(m_mutex);
    for (int i = 0; i < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; i++) {
        auto pos = static_cast<Consensus::DeploymentPos>(i);
        VersionBitsConditionChecker checker(params, pos);
        ThresholdState state = checker.GetStateFor(&block_index, m_caches[pos]);
        const VBDeploymentInfo& vbdepinfo = VersionBitsDeploymentInfo[pos];
        BIP9GBTStatus::Info gbtinfo{.bit=32, .mask=0, .gbt_force=vbdepinfo.gbt_force};

        switch (state) {
        case DEFINED:
        case STARTED:
        case ABANDONED:
        case LOCKED_IN:
            // Not exposed to GBT
            break;
        case ACTIVE:
        case DEACTIVATING:
            result.active.try_emplace(vbdepinfo.name, gbtinfo);
            break;
        }
    }
    return result;
}

bool VersionBitsCache::IsActiveAfter(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(m_mutex);
    const auto state = VersionBitsConditionChecker(params, pos).GetStateFor(pindexPrev, m_caches[pos]);
    return state == ThresholdState::ACTIVE || state == ThresholdState::DEACTIVATING;
}

static int32_t ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params, std::array<ThresholdConditionCache, Consensus::MAX_VERSION_BITS_DEPLOYMENTS>& caches)
{
    int32_t nVersion = VERSIONBITS_TOP_BITS;
    return nVersion;
}

int32_t VersionBitsCache::ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    LOCK(m_mutex);
    return ::ComputeBlockVersion(pindexPrev, params, m_caches);
}

void VersionBitsCache::Clear()
{
    LOCK(m_mutex);
    for (unsigned int d = 0; d < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; d++) {
        m_caches[d].clear();
    }
}

std::vector<std::pair<int, bool>> VersionBitsCache::CheckUnknownActivations(const CBlockIndex* pindex, const CChainParams& chainparams)
{
    return {};
}

bool VersionBitsCache::BINANA(int& year, int& number, int& revision, const Consensus::Params& params, Consensus::DeploymentPos pos) const
{
    return VersionBitsConditionChecker(params, pos).BINANA(year, number, revision);
}
