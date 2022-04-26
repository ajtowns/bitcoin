// Copyright (c) 2016-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <versionbits.h>
#include <consensus/params.h>

#include <functional>

namespace {
template<typename StateLogic>
int Count(const StateLogic& logic, const CBlockIndex* blockindex)
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

/** Returns the numerical statistics of an in-progress softfork in the period including pindex
 * If provided, signalling_blocks is set to true/false based on whether each block in the period signalled
 */
VersionBits::Stats GetStateStatisticsFor(const CBlockIndex* pindex, int period, int threshold, const std::function<bool(const CBlockIndex*)>& condition, std::vector<bool>* signalling_blocks)
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

/**
 * Class that implements BIP9-style threshold logic, and caches results.
 */
template<typename StateLogic>
class ThresholdConditionChecker
{
private:
    // Static checks to give cleaner errors if the "StateLogic" class is broken */

    // need to be able to determine the period
    static_assert(std::is_invocable_r_v<int, decltype(&StateLogic::Period), const StateLogic&>, "missing StateLogic::Period");

    // need to be told whether a block signals or not
    static_assert(std::is_invocable_r_v<bool, decltype(&StateLogic::Condition), const StateLogic&, const CBlockIndex*>, "missing StateLogic::Condition");

    // need to know the genesis state to kick things off
    static_assert(std::is_same_v<const typename StateLogic::State, decltype(StateLogic::GenesisState)>, "missing StateLogic::GenesisState");

    // state transition logic:
    // SpecialState (always the same), TrivialState (doesn't depend on earlier blocks) and NextState (conditional on earlier blocks)
    static_assert(std::is_invocable_r_v<std::optional<typename StateLogic::State>, decltype(&StateLogic::SpecialState), const StateLogic&>, "missing StateLogic::SpecialState");
    static_assert(std::is_invocable_r_v<std::optional<typename StateLogic::State>, decltype(&StateLogic::TrivialState), const StateLogic&, const CBlockIndex*>, "missing StateLogic::TrivialState");
    static_assert(std::is_invocable_r_v<typename StateLogic::State, decltype(&StateLogic::NextState), const StateLogic&, typename StateLogic::State, const CBlockIndex*>, "missing StateLogic::NextState");

public:
    /** Returns the state for pindex A based on parent pindexPrev B. Applies any state transition if conditions are present.
     *  Caches state from first block of period. */
    static typename StateLogic::State GetStateFor(const StateLogic& logic, typename StateLogic::Cache& cache, const CBlockIndex* pindexPrev);

    /** Returns the height since when the State has started for pindex A based on parent pindexPrev B, all blocks of a period share the same */
    static int GetStateSinceHeightFor(const StateLogic& logic, typename StateLogic::Cache& cache, const CBlockIndex* pindexPrev);
};
} // anonymous namespace

// BIP 9

namespace {
class BIP9StateLogic {
public:
    const BIP9DeploymentLogic& logic;

    /* implicit */ BIP9StateLogic(const BIP9DeploymentLogic& logic) : logic{logic} { }

    using State = BIP9DeploymentLogic::State;
    using Cache = BIP9DeploymentLogic::Cache;

    int Period() const { return logic.dep.period; }
    bool Condition(const CBlockIndex* block) const { return logic.Condition(block); }

    /** Configured to be always in the same state */
    std::optional<State> SpecialState() const
    {
        // Check if this deployment is always active.
        if (logic.dep.nStartTime == Consensus::BIP9Deployment::ALWAYS_ACTIVE) {
            return State::ACTIVE;
        }

        // Check if this deployment is never active.
        if (logic.dep.nStartTime == Consensus::BIP9Deployment::NEVER_ACTIVE) {
            return State::FAILED;
        }

        return std::nullopt;
    }

    /* Normal transitions */
    static constexpr State GenesisState = State::DEFINED;

    std::optional<State> TrivialState(const CBlockIndex* pindexPrev) const
    {
        if (pindexPrev->GetMedianTimePast() < logic.dep.nStartTime) {
            return GenesisState;
        }

        return std::nullopt;
    }

    State NextState(const State state, const CBlockIndex* pindexPrev) const
    {
        const int nThreshold{logic.dep.threshold};
        const int64_t nTimeStart{logic.dep.nStartTime};
        const int64_t nTimeTimeout{logic.dep.nTimeout};

        switch (state) {
            case State::DEFINED: {
                if (pindexPrev->GetMedianTimePast() >= nTimeTimeout) {
                    return State::FAILED;
                } else if (pindexPrev->GetMedianTimePast() >= nTimeStart) {
                    return State::STARTED;
                }
                break;
            }
            case State::STARTED: {
                // If after the timeout, automatic fail
                if (pindexPrev->GetMedianTimePast() >= nTimeTimeout) {
                    return State::FAILED;
                }
                // Otherwise, we need to count
                const int count = Count(*this, pindexPrev);
                if (count >= nThreshold) {
                    return State::LOCKED_IN;
                }
                break;
            }
            case State::LOCKED_IN: {
                // Always progresses into ACTIVE
                return State::ACTIVE;
            }
            case State::FAILED:
            case State::ACTIVE: {
                // Nothing happens, these are terminal states.
                break;
            }
        }
        return state;
    }
};
} // anonymous namespace

BIP9DeploymentLogic::State BIP9DeploymentLogic::GetStateFor(Cache& cache, const CBlockIndex* pindexPrev) const
{
    return ThresholdConditionChecker<BIP9StateLogic>::GetStateFor(*this, cache, pindexPrev);
}

int BIP9DeploymentLogic::GetStateSinceHeightFor(Cache& cache, const CBlockIndex* pindexPrev) const
{
    return ThresholdConditionChecker<BIP9StateLogic>::GetStateSinceHeightFor(*this, cache, pindexPrev);
}

VersionBits::Stats BIP9DeploymentLogic::GetStateStatisticsFor(const CBlockIndex* pindex, std::vector<bool>* signalling_blocks) const
{
    return ::GetStateStatisticsFor(pindex, dep.period, dep.threshold, [&](const CBlockIndex* p){return Condition(p);}, signalling_blocks);
}

// BIP 341

namespace {
class BIP341StateLogic {
public:
    const BIP341DeploymentLogic& logic;

    /* implicit */ BIP341StateLogic(const BIP341DeploymentLogic& logic) : logic{logic} { }

    using State = BIP341DeploymentLogic::State;
    using Cache = BIP341DeploymentLogic::Cache;

    int Period() const { return logic.dep.period; }
    bool Condition(const CBlockIndex* block) const { return logic.Condition(block); }

    std::optional<State> SpecialState() const
    {
        // Check if this deployment is always active.
        if (logic.dep.nStartTime == Consensus::BIP341Deployment::ALWAYS_ACTIVE) {
            return State::ACTIVE;
        }

        // Check if this deployment is never active.
        if (logic.dep.nStartTime == Consensus::BIP341Deployment::NEVER_ACTIVE) {
            return State::FAILED;
        }

        return std::nullopt;
    }

    static constexpr State GenesisState = State::DEFINED;

    std::optional<State> TrivialState(const CBlockIndex* pindexPrev) const
    {
        if (pindexPrev->GetMedianTimePast() < logic.dep.nStartTime) {
            return GenesisState;
        }

        return std::nullopt;
    }

    State NextState(const State state, const CBlockIndex* pindexPrev) const
    {
        const int nThreshold{logic.dep.threshold};
        const int min_activation_height{logic.dep.min_activation_height};
        const int64_t nTimeStart{logic.dep.nStartTime};
        const int64_t nTimeTimeout{logic.dep.nTimeout};

        switch (state) {
            case State::DEFINED: {
                if (pindexPrev->GetMedianTimePast() >= nTimeStart) {
                    return State::STARTED;
                }
                break;
            }
            case State::STARTED: {
                // We need to count
                const int count = Count(*this, pindexPrev);
                if (count >= nThreshold) {
                    return State::LOCKED_IN;
                } else if (pindexPrev->GetMedianTimePast() >= nTimeTimeout) {
                    return State::FAILED;
                }
                break;
            }
            case State::LOCKED_IN: {
                // Progresses into ACTIVE provided activation height will have been reached.
                if (pindexPrev->nHeight + 1 >= min_activation_height) {
                    return State::ACTIVE;
                }
                break;
            }
            case State::FAILED:
            case State::ACTIVE: {
                // Nothing happens, these are terminal states.
                break;
            }
        }
        return state;
    }
};
} // anonymous namespace

BIP341DeploymentLogic::State BIP341DeploymentLogic::GetStateFor(Cache& cache, const CBlockIndex* pindexPrev) const
{
    return ThresholdConditionChecker<BIP341StateLogic>::GetStateFor(*this, cache, pindexPrev);
}

int BIP341DeploymentLogic::GetStateSinceHeightFor(Cache& cache, const CBlockIndex* pindexPrev) const
{
    return ThresholdConditionChecker<BIP341StateLogic>::GetStateSinceHeightFor(*this, cache, pindexPrev);
}

VersionBits::Stats BIP341DeploymentLogic::GetStateStatisticsFor(const CBlockIndex* pindex, std::vector<bool>* signalling_blocks) const
{
    return ::GetStateStatisticsFor(pindex, dep.period, dep.threshold, [&](const CBlockIndex* p){return Condition(p);}, signalling_blocks);
}

// BIP Blah

namespace {
class BIPBlahStateLogic {
public:
    const BIPBlahDeploymentLogic& logic;

    /* implicit */ BIPBlahStateLogic(const BIPBlahDeploymentLogic& logic) : logic{logic} { }

    using State = BIPBlahDeploymentLogic::State;
    using Cache = BIPBlahDeploymentLogic::Cache;
    using StateCode = BIPBlahDeploymentLogic::StateCode;

    int Period() const { return logic.dep.period; }
    bool Condition(const CBlockIndex* block) const { return logic.Condition(block); }

    std::optional<State> SpecialState() const
    {
        // Check if this deployment is always active.
        if (logic.dep.optin_start == Consensus::BIPBlahDeployment::ALWAYS_ACTIVE) {
            return {{StateCode::ACTIVE, 0}};
        }

        // Check if this deployment is never active.
        if (logic.dep.optin_start == Consensus::BIPBlahDeployment::NEVER_ACTIVE) {
            return {{StateCode::FAILED, 0}};
        }

        return std::nullopt;
    }

    static constexpr State GenesisState = {StateCode::DEFINED, 0};

    std::optional<State> TrivialState(const CBlockIndex* pindexPrev) const
    {
        if (pindexPrev->GetMedianTimePast() < logic.dep.optin_start) {
            return GenesisState;
        }

        return std::nullopt;
    }

    State NextState(const State state, const CBlockIndex* pindexPrev) const
    {
        const auto& dep = logic.dep;

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
                    if (dep.optout_block_height == pindexPrev->nHeight
                        && pindexPrev->GetBlockHash() == dep.optout_block_hash)
                    {
                        return {StateCode::OPT_OUT_WAIT, 0};
                    } else {
                        return {StateCode::FAILED, 0};
                    }
                }
                break;
            }
            case StateCode::OPT_OUT_WAIT: {
               if (pindexPrev->GetMedianTimePast() >= dep.optout_start) {
                   return {StateCode::OPT_OUT, 0};
               }
               break;
            }
            case StateCode::OPT_OUT: {
                // We need to count
                const int count = Count(*this, pindexPrev);
                if (count >= dep.optout_threshold) {
                    return {StateCode::FAILED, 0};
                } else {
                    return {StateCode::LOCKED_IN, dep.optout_earliest_activation/60};
                }
                break;
            }
            case StateCode::LOCKED_IN: {
                // Progresses into ACTIVE provided activation height will have been reached.
                std::optional<int> act_height = logic.ActivationHeight(state, pindexPrev);
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
};
} // anonymous namespace

std::optional<int> BIPBlahDeploymentLogic::ActivationHeight(BIPBlahDeploymentLogic::State state, const CBlockIndex* pindexPrev) const
{
    if (state.code == StateCode::ACTIVE) return static_cast<int>(state.data);
    if (state.code == StateCode::LOCKED_IN) {
        if (pindexPrev->GetMedianTimePast() >= state.data * 60) {
            auto step{pindexPrev->nHeight % dep.period};
            while (step > 0 && pindexPrev->pprev != nullptr && pindexPrev->pprev->GetMedianTimePast() >= state.data * 60) {
                pindexPrev = pindexPrev->pprev;
                --step;
            }
            return pindexPrev->nHeight + dep.period;
        }
    }
    return std::nullopt;
}

BIPBlahDeploymentLogic::State BIPBlahDeploymentLogic::GetStateFor(Cache& cache, const CBlockIndex* pindexPrev) const
{
    return ThresholdConditionChecker<BIPBlahStateLogic>::GetStateFor(*this, cache, pindexPrev);
}

int BIPBlahDeploymentLogic::GetStateSinceHeightFor(Cache& cache, const CBlockIndex* pindexPrev) const
{
    return ThresholdConditionChecker<BIPBlahStateLogic>::GetStateSinceHeightFor(*this, cache, pindexPrev);
}

VersionBits::Stats BIPBlahDeploymentLogic::GetStateStatisticsFor(const CBlockIndex* pindex, const State& state, std::vector<bool>* signalling_blocks) const
{
    const int threshold = (state.code == StateCode::OPT_OUT || state.code == StateCode::OPT_OUT_WAIT) ? dep.optout_threshold : dep.optin_threshold;
    return ::GetStateStatisticsFor(pindex, dep.period, threshold, [&](const CBlockIndex* p){return Condition(p);}, signalling_blocks);
}

// generic state transition functions

template<typename StateLogic>
typename StateLogic::State ThresholdConditionChecker<StateLogic>::GetStateFor(const StateLogic& logic, typename StateLogic::Cache& cache, const CBlockIndex* pindexPrev)
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
    typename StateLogic::State state = cache[pindexPrev];

    // Now walk forward and compute the state of descendants of pindexPrev
    while (!vToCompute.empty()) {
        pindexPrev = vToCompute.back();
        vToCompute.pop_back();
        cache[pindexPrev] = state = logic.NextState(state, pindexPrev);
    }

    return state;
}

template<typename StateLogic>
int ThresholdConditionChecker<StateLogic>::GetStateSinceHeightFor(const StateLogic& logic, typename StateLogic::Cache& cache, const CBlockIndex* pindexPrev)
{
    if (logic.SpecialState()) return 0;

    const typename StateLogic::State initialState = GetStateFor(logic, cache, pindexPrev);

    if (initialState == logic.GenesisState) return 0;

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
