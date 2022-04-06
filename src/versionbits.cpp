// Copyright (c) 2016-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <versionbits.h>
#include <consensus/params.h>

using ThresholdState = BIP9DeploymentLogic::State;

std::optional<ThresholdState> BIP9DeploymentLogic::SpecialState() const
{
    // Check if this deployment is always active.
    if (dep.nStartTime == Consensus::BIP9Deployment::ALWAYS_ACTIVE) {
        return ThresholdState::ACTIVE;
    }

    // Check if this deployment is never active.
    if (dep.nStartTime == Consensus::BIP9Deployment::NEVER_ACTIVE) {
        return ThresholdState::FAILED;
    }

    return std::nullopt;
}

std::optional<ThresholdState> BIP9DeploymentLogic::TrivialState(const CBlockIndex* pindexPrev) const
{
    if (pindexPrev->GetMedianTimePast() < dep.nStartTime) {
        return ThresholdState::DEFINED;
    }

    return std::nullopt;
}

ThresholdState BIP9DeploymentLogic::NextState(const ThresholdState state, const CBlockIndex* pindexPrev) const
{
    const int nThreshold{dep.threshold};
    const int64_t nTimeStart{dep.nStartTime};
    const int64_t nTimeTimeout{dep.nTimeout};

    switch (state) {
        case ThresholdState::DEFINED: {
            if (pindexPrev->GetMedianTimePast() >= nTimeTimeout) {
                return ThresholdState::FAILED;
            } else if (pindexPrev->GetMedianTimePast() >= nTimeStart) {
                return ThresholdState::STARTED;
            }
            break;
        }
        case ThresholdState::STARTED: {
            // If after the timeout, automatic fail
            if (pindexPrev->GetMedianTimePast() >= nTimeTimeout) {
                return ThresholdState::FAILED;
            }
            // Otherwise, we need to count
            const int count = ThreshCheck::Count(*this, pindexPrev);
            if (count >= nThreshold) {
                return ThresholdState::LOCKED_IN;
            }
            break;
        }
        case ThresholdState::LOCKED_IN: {
            // Always progresses into ACTIVE
            return ThresholdState::ACTIVE;
        }
        case ThresholdState::FAILED:
        case ThresholdState::ACTIVE: {
            // Nothing happens, these are terminal states.
            break;
        }
    }
    return state;
}

std::optional<ThresholdState> BIP341DeploymentLogic::SpecialState() const
{
    // Check if this deployment is always active.
    if (dep.nStartTime == Consensus::BIP9Deployment::ALWAYS_ACTIVE) {
        return ThresholdState::ACTIVE;
    }

    // Check if this deployment is never active.
    if (dep.nStartTime == Consensus::BIP9Deployment::NEVER_ACTIVE) {
        return ThresholdState::FAILED;
    }

    return std::nullopt;
}

std::optional<ThresholdState> BIP341DeploymentLogic::TrivialState(const CBlockIndex* pindexPrev) const
{
    if (pindexPrev->GetMedianTimePast() < dep.nStartTime) {
        return ThresholdState::DEFINED;
    }

    return std::nullopt;
}

ThresholdState BIP341DeploymentLogic::NextState(const ThresholdState state, const CBlockIndex* pindexPrev) const
{
    const int nThreshold{dep.threshold};
    const int min_activation_height{dep.min_activation_height};
    const int64_t nTimeStart{dep.nStartTime};
    const int64_t nTimeTimeout{dep.nTimeout};

    switch (state) {
        case ThresholdState::DEFINED: {
            if (pindexPrev->GetMedianTimePast() >= nTimeStart) {
                return ThresholdState::STARTED;
            }
            break;
        }
        case ThresholdState::STARTED: {
            // We need to count
            const int count = ThreshCheck::Count(*this, pindexPrev);
            if (count >= nThreshold) {
                return ThresholdState::LOCKED_IN;
            } else if (pindexPrev->GetMedianTimePast() >= nTimeTimeout) {
                return ThresholdState::FAILED;
            }
            break;
        }
        case ThresholdState::LOCKED_IN: {
            // Progresses into ACTIVE provided activation height will have been reached.
            if (pindexPrev->nHeight + 1 >= min_activation_height) {
                return ThresholdState::ACTIVE;
            }
            break;
        }
        case ThresholdState::FAILED:
        case ThresholdState::ACTIVE: {
            // Nothing happens, these are terminal states.
            break;
        }
    }
    return state;
}

template<typename Logic>
typename Logic::State ThresholdConditionChecker<Logic>::GetStateFor(const Logic& logic, typename Logic::Cache& cache, const CBlockIndex* pindexPrev)
{
    if (auto maybe_state = logic.SpecialState()) return *maybe_state;

    const int nPeriod{logic.Period()};

    // A block's state is always the same as that of the first of its period, so it is computed based on a pindexPrev whose height equals a multiple of nPeriod - 1.
    if (pindexPrev != nullptr) {
        pindexPrev = pindexPrev->GetAncestor(pindexPrev->nHeight - ((pindexPrev->nHeight + 1) % nPeriod));
    }

    // Walk backwards in steps of nPeriod to find a pindexPrev whose information is known
    std::vector<const CBlockIndex*> vToCompute;
    while (cache.count(pindexPrev) == 0) {
        if (pindexPrev == nullptr) {
            cache[pindexPrev] = logic.GenesisState;
            break;
        }
        if (auto maybe_state = logic.TrivialState(pindexPrev)) {
            // Optimisation: don't recurse further, since earlier states are likely trivial too
            cache[pindexPrev] = *maybe_state;
            break;
        }
        vToCompute.push_back(pindexPrev);
        pindexPrev = pindexPrev->GetAncestor(pindexPrev->nHeight - nPeriod);
    }

    // At this point, cache[pindexPrev] is known
    assert(cache.count(pindexPrev));
    typename Logic::State state = cache[pindexPrev];

    // Now walk forward and compute the state of descendants of pindexPrev
    while (!vToCompute.empty()) {
        pindexPrev = vToCompute.back();
        vToCompute.pop_back();
        cache[pindexPrev] = state = logic.NextState(state, pindexPrev);
    }

    return state;
}

template<typename Logic>
typename Logic::Stats ThresholdConditionChecker<Logic>::GetStateStatisticsFor(const Logic& logic, const CBlockIndex* pindex, std::vector<bool>* signalling_blocks)
{
    typename Logic::Stats stats = {};
    if (pindex == nullptr) return stats;

    const int period = logic.Period();

    // Find how many blocks are in the current period
    int blocks_in_period = 1 + (pindex->nHeight % period);

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
        if (logic.Condition(currentIndex)) {
            ++count;
            if (signalling_blocks) signalling_blocks->at(blocks_in_period) = true;
        }
        currentIndex = currentIndex->pprev;
    } while(blocks_in_period > 0);

    stats.elapsed = elapsed;
    stats.count = count;

    return stats;
}

template<typename Logic>
int ThresholdConditionChecker<Logic>::GetStateSinceHeightFor(const Logic& logic, typename Logic::Cache& cache, const CBlockIndex* pindexPrev)
{
    if (logic.SpecialState()) return 0;

    const typename Logic::State initialState = GetStateFor(logic, cache, pindexPrev);

    // BIP 9 about state DEFINED: "The genesis block is by definition in this state for each deployment."
    if (initialState == logic.GenesisState) {
        return 0;
    }

    const int nPeriod{logic.Period()};

    // A block's state is always the same as that of the first of its period, so it is computed based on a pindexPrev whose height equals a multiple of nPeriod - 1.
    // To ease understanding of the following height calculation, it helps to remember that
    // right now pindexPrev points to the block prior to the block that we are computing for, thus:
    // if we are computing for the last block of a period, then pindexPrev points to the second to last block of the period, and
    // if we are computing for the first block of a period, then pindexPrev points to the last block of the previous period.
    // The parent of the genesis block is represented by nullptr.
    pindexPrev = pindexPrev->GetAncestor(pindexPrev->nHeight - ((pindexPrev->nHeight + 1) % nPeriod));

    const CBlockIndex* previousPeriodParent = pindexPrev->GetAncestor(pindexPrev->nHeight - nPeriod);

    while (previousPeriodParent != nullptr && GetStateFor(logic, cache, previousPeriodParent) == initialState) {
        pindexPrev = previousPeriodParent;
        previousPeriodParent = pindexPrev->GetAncestor(pindexPrev->nHeight - nPeriod);
    }

    // Adjust the result because right now we point to the parent block.
    return pindexPrev->nHeight + 1;
}

template class ThresholdConditionChecker<BIP9DeploymentLogic>;
template class ThresholdConditionChecker<BIP341DeploymentLogic>;
