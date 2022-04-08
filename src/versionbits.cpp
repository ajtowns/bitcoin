// Copyright (c) 2016-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <versionbits.h>
#include <consensus/params.h>

using ThresholdState = BIP9DeploymentLogic::State;

namespace {
template<typename Logic>
int Count(const Logic& logic, const CBlockIndex* blockindex)
{
    int count = 0;
    for (int i = logic.Period(); i > 0; --i) {
        if (logic.Condition(blockindex)) {
            ++count;
        }
        blockindex = blockindex->pprev;
    }
    return count;
}

/**
 * Class that implements BIP9-style threshold logic, and caches results.
 */
template<typename Logic>
class ThresholdConditionChecker
{
private:
    // Static checks to give cleaner errors if the "Logic" class is broken */

    // need to be able to determine the period
    static_assert(std::is_invocable_r_v<int, decltype(&Logic::Period), const Logic&>, "missing Logic::Period");

    // need to be told whether a block signals or not
    static_assert(std::is_invocable_r_v<bool, decltype(&Logic::Condition), const Logic&, const CBlockIndex*>, "missing Logic::Condition");

    // need to know the genesis state to kick things off
    static_assert(std::is_same_v<const typename Logic::State, decltype(Logic::GenesisState)>, "missing Logic::GenesisState");

    // state transition logic:
    // SpecialState (always the same), TrivialState (doesn't depend on earlier blocks) and NextState (conditional on earlier blocks)
    static_assert(std::is_invocable_r_v<std::optional<typename Logic::State>, decltype(&Logic::SpecialState), const Logic&>, "missing Logic::SpecialState");
    static_assert(std::is_invocable_r_v<std::optional<typename Logic::State>, decltype(&Logic::TrivialState), const Logic&, const CBlockIndex*>, "missing Logic::TrivialState");
    static_assert(std::is_invocable_r_v<typename Logic::State, decltype(&Logic::NextState), const Logic&, typename Logic::State, const CBlockIndex*>, "missing Logic::NextState");

public:
    /** Returns the state for pindex A based on parent pindexPrev B. Applies any state transition if conditions are present.
     *  Caches state from first block of period. */
    static typename Logic::State GetStateFor(const Logic& logic, typename Logic::Cache& cache, const CBlockIndex* pindexPrev);

    /** Returns the height since when the State has started for pindex A based on parent pindexPrev B, all blocks of a period share the same */
    static int GetStateSinceHeightFor(const Logic& logic, typename Logic::Cache& cache, const CBlockIndex* pindexPrev);
};

} // anonymous namespace

// BIP 9

BIP9DeploymentLogic::State BIP9DeploymentLogic::GetStateFor(Cache& cache, const CBlockIndex* pindexPrev) const
{
    return ThresholdConditionChecker<BIP9DeploymentLogic>::GetStateFor(*this, cache, pindexPrev);
}

int BIP9DeploymentLogic::GetStateSinceHeightFor(Cache& cache, const CBlockIndex* pindexPrev) const
{
    return ThresholdConditionChecker<BIP9DeploymentLogic>::GetStateSinceHeightFor(*this, cache, pindexPrev);
}

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
            const int count = Count(*this, pindexPrev);
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

// BIP 341

BIP341DeploymentLogic::State BIP341DeploymentLogic::GetStateFor(Cache& cache, const CBlockIndex* pindexPrev) const
{
    return ThresholdConditionChecker<BIP341DeploymentLogic>::GetStateFor(*this, cache, pindexPrev);
}

int BIP341DeploymentLogic::GetStateSinceHeightFor(Cache& cache, const CBlockIndex* pindexPrev) const
{
    return ThresholdConditionChecker<BIP341DeploymentLogic>::GetStateSinceHeightFor(*this, cache, pindexPrev);
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
            const int count = Count(*this, pindexPrev);
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

// BIP Blah

BIPBlahDeploymentLogic::State BIPBlahDeploymentLogic::GetStateFor(Cache& cache, const CBlockIndex* pindexPrev) const
{
    return ThresholdConditionChecker<BIPBlahDeploymentLogic>::GetStateFor(*this, cache, pindexPrev);
}

int BIPBlahDeploymentLogic::GetStateSinceHeightFor(Cache& cache, const CBlockIndex* pindexPrev) const
{
    return ThresholdConditionChecker<BIPBlahDeploymentLogic>::GetStateSinceHeightFor(*this, cache, pindexPrev);
}

std::optional<BIPBlahDeploymentLogic::State> BIPBlahDeploymentLogic::SpecialState() const
{
    // Check if this deployment is always active.
    if (dep.optin_start == Consensus::BIPBlahDeployment::ALWAYS_ACTIVE) {
        return {{StateCode::ACTIVE, 0}};
    }

    // Check if this deployment is never active.
    if (dep.optin_start == Consensus::BIPBlahDeployment::NEVER_ACTIVE) {
        return {{StateCode::FAILED, 0}};
    }

    return std::nullopt;
}

std::optional<BIPBlahDeploymentLogic::State> BIPBlahDeploymentLogic::TrivialState(const CBlockIndex* pindexPrev) const
{
    if (pindexPrev->GetMedianTimePast() < dep.optin_start) {
        return {{StateCode::DEFINED, 0}};
    }

    return std::nullopt;
}

BIPBlahDeploymentLogic::State BIPBlahDeploymentLogic::NextState(const BIPBlahDeploymentLogic::State state, const CBlockIndex* pindexPrev) const
{
    switch (state.code) {
        case StateCode::DEFINED: {
            if (pindexPrev->GetMedianTimePast() >= dep.optin_start) {
                return {StateCode::OPT_IN, 0};
            }
            break;
        }
        case StateCode::OPT_IN: {
            // We need to count
            const int count = Count(*this, pindexPrev);
            if (count >= dep.optin_threshold) {
                return {StateCode::LOCKED_IN, dep.optin_earliest_activation/60};
            } else if (pindexPrev->GetMedianTimePast() >= dep.optin_timeout) {
                if (pindexPrev->nHeight < dep.optout_block_height) {
                    return {StateCode::OPT_OUT_WAIT, 0};
                } else {
                    return {StateCode::FAILED, 0};
                }
            }
            break;
        }
        case StateCode::OPT_OUT_WAIT: {
           if (pindexPrev->nHeight + 1 == dep.optout_block_height + dep.period) {
               const CBlockIndex* pindexFlag = pindexPrev->GetAncestor(dep.optout_block_height);
               if (pindexFlag->GetBlockHash() != dep.optout_block_hash) {
                   return {StateCode::FAILED, 0};
               } else {
                   return {StateCode::OPT_OUT, pindexFlag->GetMedianTimePast()/60 + dep.optout_delay_mins};
               }
           }
           break;
        }
        case StateCode::OPT_OUT: {
            if (pindexPrev->GetMedianTimePast() < state.data * 60) break;
            const CBlockIndex* pindexStart = pindexPrev->GetAncestor(pindexPrev->nHeight - (dep.period - 1));
            const int64_t start_mtp = pindexStart->GetMedianTimePast();
            if (start_mtp < state.data * 60) break;

            // We need to count
            const int count = Count(*this, pindexPrev);
            if (count >= dep.optout_threshold) {
                return {StateCode::FAILED, 0};
            } else {
                return {StateCode::LOCKED_IN, start_mtp/60 + dep.optout_delay_activation_mins};
            }
            break;
        }
        case StateCode::LOCKED_IN: {
            // Progresses into ACTIVE provided activation height will have been reached.
            std::optional<int> act_height = ActivationHeight(state, pindexPrev);
            if (act_height) {
                return {StateCode::ACTIVE, *act_height};
            }
            break;
        }
        case StateCode::FAILED:
        case StateCode::ACTIVE: {
            // Nothing happens, these are terminal states.
            break;
        }
    }
    return state;
}

std::optional<int> BIPBlahDeploymentLogic::ActivationHeight(BIPBlahDeploymentLogic::State state, const CBlockIndex* pindexPrev) const
{
    if (state.code == StateCode::ACTIVE) return static_cast<int>(state.data);
    if (state.code == StateCode::LOCKED_IN) {
        if (pindexPrev->GetMedianTimePast() >= state.data * 60) {
            while (pindexPrev->pprev != nullptr && pindexPrev->pprev->GetMedianTimePast() >= state.data * 60) {
                pindexPrev = pindexPrev->pprev;
            }
            return pindexPrev->nHeight + dep.period;
        }
    }
    return std::nullopt;
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

VersionBits::Stats VersionBits::GetStateStatisticsFor(const CBlockIndex* pindex, int period, int threshold, const std::function<bool(const CBlockIndex*)>& condition, std::vector<bool>* signalling_blocks)
{
    if (pindex == nullptr) return VersionBits::Stats{};

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
        if (condition(currentIndex)) {
            ++count;
            if (signalling_blocks) signalling_blocks->at(blocks_in_period) = true;
        }
        currentIndex = currentIndex->pprev;
    } while(blocks_in_period > 0);

    VersionBits::Stats stats;
    stats.period = period;
    stats.threshold = threshold;
    stats.elapsed = elapsed;
    stats.count = count;
    stats.possible = (stats.period - stats.elapsed) >= (stats.threshold - stats.count);

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

