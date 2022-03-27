// Copyright (c) 2016-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <versionbits.h>
#include <consensus/params.h>

ThresholdState VersionBitsConditionChecker::GetStateFor(const ConditionLogic& logic, const CBlockIndex* pindexPrev)
{
    const int nPeriod{logic.dep.period};
    const int nThreshold{logic.dep.threshold};
    const int min_activation_height{logic.dep.min_activation_height};
    const int64_t nTimeStart{logic.dep.nStartTime};
    const int64_t nTimeTimeout{logic.dep.nTimeout};

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
    while (m_cache.count(pindexPrev) == 0) {
        if (pindexPrev == nullptr) {
            // The genesis block is by definition defined.
            m_cache[pindexPrev] = ThresholdState::DEFINED;
            break;
        }
        if (pindexPrev->GetMedianTimePast() < nTimeStart) {
            // Optimization: don't recompute down further, as we know every earlier block will be before the start time
            m_cache[pindexPrev] = ThresholdState::DEFINED;
            break;
        }
        vToCompute.push_back(pindexPrev);
        pindexPrev = pindexPrev->GetAncestor(pindexPrev->nHeight - nPeriod);
    }

    // At this point, m_cache[pindexPrev] is known
    assert(m_cache.count(pindexPrev));
    ThresholdState state = m_cache[pindexPrev];

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
                    if (logic.Condition(pindexCount)) {
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
        m_cache[pindexPrev] = state = stateNext;
    }

    return state;
}

BIP9Stats ConditionLogic::GetStateStatisticsFor(const CBlockIndex* pindex, std::vector<bool>* signalling_blocks) const
{
    BIP9Stats stats = {};

    stats.period = dep.period;
    stats.threshold = dep.threshold;

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

int VersionBitsConditionChecker::GetStateSinceHeightFor(const ConditionLogic& logic, const CBlockIndex* pindexPrev)
{
    const int64_t start_time{logic.dep.nStartTime};
    if (start_time == Consensus::BIP9Deployment::ALWAYS_ACTIVE || start_time == Consensus::BIP9Deployment::NEVER_ACTIVE) {
        return 0;
    }

    const ThresholdState initialState = GetStateFor(logic, pindexPrev);

    // BIP 9 about state DEFINED: "The genesis block is by definition in this state for each deployment."
    if (initialState == ThresholdState::DEFINED) {
        return 0;
    }

    const int nPeriod{logic.dep.period};

    // A block's state is always the same as that of the first of its period, so it is computed based on a pindexPrev whose height equals a multiple of nPeriod - 1.
    // To ease understanding of the following height calculation, it helps to remember that
    // right now pindexPrev points to the block prior to the block that we are computing for, thus:
    // if we are computing for the last block of a period, then pindexPrev points to the second to last block of the period, and
    // if we are computing for the first block of a period, then pindexPrev points to the last block of the previous period.
    // The parent of the genesis block is represented by nullptr.
    pindexPrev = pindexPrev->GetAncestor(pindexPrev->nHeight - ((pindexPrev->nHeight + 1) % nPeriod));

    const CBlockIndex* previousPeriodParent = pindexPrev->GetAncestor(pindexPrev->nHeight - nPeriod);

    while (previousPeriodParent != nullptr && GetStateFor(logic, previousPeriodParent) == initialState) {
        pindexPrev = previousPeriodParent;
        previousPeriodParent = pindexPrev->GetAncestor(pindexPrev->nHeight - nPeriod);
    }

    // Adjust the result because right now we point to the parent block.
    return pindexPrev->nHeight + 1;
}

ThresholdState VersionBitsCache::State(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(m_mutex);
    return m_checker[pos].GetStateFor(ConditionLogic(params.vDeployments[pos]), pindexPrev);
}

BIP9Stats VersionBitsCache::Statistics(const CBlockIndex* pindex, const Consensus::Params& params, Consensus::DeploymentPos pos, std::vector<bool>* signalling_blocks)
{
    return ConditionLogic(params.vDeployments[pos]).GetStateStatisticsFor(pindex, signalling_blocks);
}

int VersionBitsCache::StateSinceHeight(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(m_mutex);
    return m_checker[pos].GetStateSinceHeightFor(ConditionLogic(params.vDeployments[pos]), pindexPrev);
}

uint32_t VersionBitsCache::Mask(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    return ConditionLogic(params.vDeployments[pos]).Mask();
}

int32_t VersionBitsCache::ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    LOCK(m_mutex);
    int32_t nVersion = VERSIONBITS_TOP_BITS;

    for (int i = 0; i < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; i++) {
        Consensus::DeploymentPos pos = static_cast<Consensus::DeploymentPos>(i);
        ConditionLogic logic(params.vDeployments[pos]);
        ThresholdState state = m_checker[pos].GetStateFor(logic, pindexPrev);
        if (state == ThresholdState::LOCKED_IN || state == ThresholdState::STARTED) {
            nVersion |= logic.Mask();
        }
    }

    return nVersion;
}

void VersionBitsCache::Clear()
{
    LOCK(m_mutex);
    for (unsigned int d = 0; d < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; d++) {
        m_checker[d].clear();
    }
}
