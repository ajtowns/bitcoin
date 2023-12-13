// Copyright (c) 2016-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/params.h>
#include <deploymentinfo.h>
#include <kernel/chainparams.h>
#include <util/check.h>
#include <util/overloaded.h>
#include <versionbits.h>
#include <versionbits_impl.h>

template <size_t I=0, typename Fn, typename Tup, typename... Tups>
void MapZip(Fn&& fn, Tup& t1, Tups&... ts)
{
    if constexpr (I < std::tuple_size_v<Tup>) {
        fn(std::get<I>(t1), std::get<I>(ts)...);
        MapZip<I+1>(fn, t1, ts...);
    }
}

std::string StateName(ThresholdState state)
{
    switch (state) {
    case ThresholdState::DEFINED: return "defined";
    case ThresholdState::STARTED: return "started";
    case ThresholdState::LOCKED_IN: return "locked_in";
    case ThresholdState::ACTIVE: return "active";
    case ThresholdState::FAILED: return "failed";
    }
    return "invalid";
}

ThresholdState AbstractThresholdConditionChecker::GetStateFor(const CBlockIndex* pindexPrev, ThresholdConditionCache& cache) const
{
    int nPeriod = Period();
    int nThreshold = Threshold();
    int min_activation_height = MinActivationHeight();
    int64_t nTimeStart = BeginTime();
    int64_t nTimeTimeout = EndTime();

    // Check if this deployment is always active.
    if (nTimeStart == Consensus::BIP9Deployment::ALWAYS_ACTIVE) {
        return ThresholdState::ACTIVE;
    }

    // Check if this deployment is never active.
    if (nTimeStart == Consensus::BIP9Deployment::NEVER_ACTIVE) {
        return ThresholdState::FAILED;
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
        if (pindexPrev->GetMedianTimePast() < nTimeStart) {
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

        switch (state) {
            case ThresholdState::DEFINED: {
                if (pindexPrev->GetMedianTimePast() >= nTimeStart) {
                    stateNext = ThresholdState::STARTED;
                }
                break;
            }
            case ThresholdState::STARTED: {
                // We need to count
                const CBlockIndex* pindexCount = pindexPrev;
                int count = 0;
                for (int i = 0; i < nPeriod; i++) {
                    if (Condition(pindexCount)) {
                        count++;
                    }
                    pindexCount = pindexCount->pprev;
                }
                if (count >= nThreshold) {
                    stateNext = ThresholdState::LOCKED_IN;
                } else if (pindexPrev->GetMedianTimePast() >= nTimeTimeout) {
                    stateNext = ThresholdState::FAILED;
                }
                break;
            }
            case ThresholdState::LOCKED_IN: {
                // Progresses into ACTIVE provided activation height will have been reached.
                if (pindexPrev->nHeight + 1 >= min_activation_height) {
                    stateNext = ThresholdState::ACTIVE;
                }
                break;
            }
            case ThresholdState::FAILED:
            case ThresholdState::ACTIVE: {
                // Nothing happens, these are terminal states.
                break;
            }
        }
        cache[pindexPrev] = state = stateNext;
    }

    return state;
}

BIP9Stats AbstractThresholdConditionChecker::GetStateStatisticsFor(const CBlockIndex* pindex, std::vector<bool>* signalling_blocks) const
{
    BIP9Stats stats = {};

    stats.period = Period();
    stats.threshold = Threshold();

    if (pindex == nullptr) return stats;

    // Find how many blocks are in the current period
    int blocks_in_period = 1 + (pindex->nHeight % stats.period);

    // Reset signalling_blocks
    if (signalling_blocks) {
        signalling_blocks->assign(blocks_in_period, false);
    }

    // Count from current block to beginning of period
    int elapsed = 0;
    int count = 0;
    const CBlockIndex* currentIndex = pindex;
    do {
        ++elapsed;
        --blocks_in_period;
        if (Condition(currentIndex)) {
            ++count;
            if (signalling_blocks) signalling_blocks->at(blocks_in_period) = true;
        }
        currentIndex = currentIndex->pprev;
    } while(blocks_in_period > 0);

    stats.elapsed = elapsed;
    stats.count = count;
    stats.possible = (stats.period - stats.threshold ) >= (stats.elapsed - count);

    return stats;
}

int AbstractThresholdConditionChecker::GetStateSinceHeightFor(const CBlockIndex* pindexPrev, ThresholdConditionCache& cache) const
{
    int64_t start_time = BeginTime();
    if (start_time == Consensus::BIP9Deployment::ALWAYS_ACTIVE || start_time == Consensus::BIP9Deployment::NEVER_ACTIVE) {
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

BIP9Info GetDepInfo(const CBlockIndex& block_index, DepParamsCache<Consensus::BIP9Deployment> depcache)
{
    BIP9Info result;

    VersionBitsConditionChecker checker(depcache.dep);

    const ThresholdState current_state = checker.GetStateFor(block_index.pprev, depcache.cache);
    const ThresholdState next_state = checker.GetStateFor(&block_index, depcache.cache);
    result.since = checker.GetStateSinceHeightFor(block_index.pprev, depcache.cache);

    result.current_state = StateName(current_state);
    result.next_state = StateName(next_state);

    const bool has_signal = (ThresholdState::STARTED == current_state || ThresholdState::LOCKED_IN == current_state);
    if (has_signal) {
        result.stats.emplace(checker.GetStateStatisticsFor(&block_index, &result.signalling_blocks));
        if (ThresholdState::LOCKED_IN == current_state) {
            result.stats->threshold = 0;
            result.stats->possible = false;
        }
    }

    if (current_state == ThresholdState::ACTIVE) {
        result.active_since = result.since;
    } else if (next_state == ThresholdState::ACTIVE) {
        result.active_since = block_index.nHeight + 1;
    }

    return result;
}

void BumpGBTStatus(const CBlockIndex& blockindex, GBTStatus& gbtstatus, DepInfoParamsCache<Consensus::BuriedDeploymentParams> depinfocache)
{
    if (IsActiveAfter(&blockindex, depinfocache)) {
        GBTStatus::Info gbtinfo{.bit=-1, .mask=0, .gbt_force=true};
        gbtstatus.active.try_emplace(depinfocache.info.name, gbtinfo);
    }
}

void BumpGBTStatus(const CBlockIndex& blockindex, GBTStatus& gbtstatus, DepInfoParamsCache<Consensus::BIP9Deployment> depinfocache)
{
    VersionBitsConditionChecker checker(depinfocache.dep);
    GBTStatus::Info gbtinfo{.bit=depinfocache.dep.bit, .mask=checker.Mask(), .gbt_force=depinfocache.info.gbt_force};

    ThresholdState state = checker.GetStateFor(&blockindex, depinfocache.cache);
    switch (state) {
    case ThresholdState::DEFINED:
    case ThresholdState::FAILED:
        // Not exposed to GBT
        break;
    case ThresholdState::STARTED:
        gbtstatus.signalling.try_emplace(depinfocache.info.name, gbtinfo);
        break;
    case ThresholdState::LOCKED_IN:
        gbtstatus.locked_in.try_emplace(depinfocache.info.name, gbtinfo);
        break;
    case ThresholdState::ACTIVE:
        gbtstatus.active.try_emplace(depinfocache.info.name, gbtinfo);
        break;
    }
}

GBTStatus VersionBitsCache::GetGBTStatus(const CBlockIndex& block_index, const Consensus::Params& params)
{
    GBTStatus result;

    LOCK(m_mutex);
    auto fn = [&](auto& dep, auto& info, auto& cache) {
        BumpGBTStatus(block_index, result, DepInfoParamsCache(info, dep, cache));
    };
    MapZip(fn, params.vDeployments, VersionBitsDeploymentInfo, m_caches);
    return result;
}

bool IsActiveAfter(const CBlockIndex* pindexPrev, DepParamsCache<Consensus::BIP9Deployment> depcache)
{
    return ThresholdState::ACTIVE == VersionBitsConditionChecker(depcache.dep).GetStateFor(pindexPrev, depcache.cache);
}

void ComputeBlockVersion(const CBlockIndex* pindexPrev, int32_t& nVersion, DepParamsCache<Consensus::BIP9Deployment> depcache)
{
    if ((nVersion & VERSIONBITS_TOP_BITS) != VERSIONBITS_TOP_BITS) return;

    VersionBitsConditionChecker checker(depcache.dep);
    ThresholdState state = checker.GetStateFor(pindexPrev, depcache.cache);
    if (state == ThresholdState::LOCKED_IN || state == ThresholdState::STARTED) {
        nVersion |= checker.Mask();
    }
}

static int32_t ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params, DeploymentCaches& caches)
{
    int32_t nVersion = VERSIONBITS_TOP_BITS;
    auto fn = [&](auto& dep, auto& cache) {
        ComputeBlockVersion(pindexPrev, nVersion, DepParamsCache(dep, cache));
    };
    MapZip(fn, params.vDeployments, caches);
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
    MapZip(util::Overloaded{
        [](ThresholdConditionCache& cache) { cache.clear(); },
        [](auto& cache) { }
    }, m_caches);
}

namespace {
/**
 * Threshold condition checker that triggers when unknown versionbits are seen on the network.
 */
class WarningBitsConditionChecker : public AbstractThresholdConditionChecker
{
private:
    const Consensus::Params& m_params;
    DeploymentCaches& m_caches;
    int m_bit;
    int period{2016};
    int threshold{0};

public:
    explicit WarningBitsConditionChecker(const CChainParams& chainparams, DeploymentCaches& caches, int bit) : m_params{chainparams.GetConsensus()}, m_caches{caches}, m_bit(bit)
    {
        if (chainparams.IsTestChain()) {
            period = 144;
            threshold = 108;
        } else {
            period = 2016;
            threshold = 1815;
        }
    }

    int64_t BeginTime() const override { return 0; }
    int64_t EndTime() const override { return std::numeric_limits<int64_t>::max(); }
    int Period() const override { return period; }
    int Threshold() const override { return threshold; }

    bool Condition(const CBlockIndex* pindex) const override
    {
        return pindex->nHeight >= m_params.MinBIP9WarningHeight &&
               ((pindex->nVersion & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS) &&
               ((pindex->nVersion >> m_bit) & 1) != 0 &&
               ((::ComputeBlockVersion(pindex->pprev, m_params, m_caches) >> m_bit) & 1) == 0;
    }
};
} // anonymous namespace

std::vector<std::pair<int, bool>> VersionBitsCache::CheckUnknownActivations(const CBlockIndex* pindex, const CChainParams& chainparams)
{
    LOCK(m_mutex);
    std::vector<std::pair<int, bool>> result;
    for (int bit = 0; bit < VERSIONBITS_NUM_BITS; ++bit) {
        WarningBitsConditionChecker checker(chainparams, m_caches, bit);
        ThresholdState state = checker.GetStateFor(pindex, m_warning_caches.at(bit));
        if (state == ThresholdState::ACTIVE || state == ThresholdState::LOCKED_IN) {
            result.emplace_back(bit, state == ThresholdState::ACTIVE);
        }
    }
    return result;
}
