// Copyright (c) 2016-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <versionbits.h>
#include <consensus/params.h>

std::optional<ThresholdState> ConditionLogic::SpecialState() const
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

std::optional<ThresholdState> ConditionLogic::TrivialState(const CBlockIndex* pindexPrev) const
{
    if (pindexPrev->GetMedianTimePast() < dep.nStartTime) {
        return ThresholdState::DEFINED;
    }

    return std::nullopt;
}

ThresholdState ConditionLogic::NextState(const ThresholdState state, const CBlockIndex* pindexPrev) const
{
    const int nPeriod{dep.period};
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
            const CBlockIndex* pindexCount = pindexPrev;
            int count = 0;
            for (int i = 0; i < nPeriod; i++) {
                if (Condition(pindexCount)) {
                    count++;
                }
                pindexCount = pindexCount->pprev;
            }
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

ThresholdState VersionBitsConditionChecker::GetStateFor(const ConditionLogic& logic, const CBlockIndex* pindexPrev)
{
    if (auto maybe_state = logic.SpecialState()) return *maybe_state;

    const int nPeriod{logic.Period()};

    // A block's state is always the same as that of the first of its period, so it is computed based on a pindexPrev whose height equals a multiple of nPeriod - 1.
    if (pindexPrev != nullptr) {
        pindexPrev = pindexPrev->GetAncestor(pindexPrev->nHeight - ((pindexPrev->nHeight + 1) % nPeriod));
    }

    // Walk backwards in steps of nPeriod to find a pindexPrev whose information is known
    std::vector<const CBlockIndex*> vToCompute;
    while (m_cache.count(pindexPrev) == 0) {
        if (pindexPrev == nullptr) {
            m_cache[pindexPrev] = logic.GenesisState;
            break;
        }
        if (auto maybe_state = logic.TrivialState(pindexPrev)) {
            // Optimisation: don't recurse further, since earlier states are likely trivial too
            m_cache[pindexPrev] = *maybe_state;
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
        pindexPrev = vToCompute.back();
        vToCompute.pop_back();
        m_cache[pindexPrev] = state = logic.NextState(state, pindexPrev);
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
    if (logic.SpecialState()) return 0;

    const ThresholdState initialState = GetStateFor(logic, pindexPrev);

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

    while (previousPeriodParent != nullptr && GetStateFor(logic, previousPeriodParent) == initialState) {
        pindexPrev = previousPeriodParent;
        previousPeriodParent = pindexPrev->GetAncestor(pindexPrev->nHeight - nPeriod);
    }

    // Adjust the result because right now we point to the parent block.
    return pindexPrev->nHeight + 1;
}

ConditionLogic VersionBitsCache::GetLogic(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    return ConditionLogic{params.vDeployments[pos]};
}

using checker_array = std::array<VersionBitsConditionChecker,Consensus::MAX_VERSION_BITS_DEPLOYMENTS>;

template<size_t POS>
static inline std::pair<ConditionLogic, VersionBitsConditionChecker&> GetLogicChecker(checker_array& checkers, const Consensus::Params& params)
{
    return {ConditionLogic{params.vDeployments[POS]}, std::get<POS>(checkers)};
}

template<typename F, size_t... ints>
static auto AllDeployments_impl(checker_array& checkers, const Consensus::Params& params, F&& fn, std::index_sequence<ints...> int_seq)
{
    return fn(GetLogicChecker<ints>(checkers, params)...);
}

template<typename F>
static auto AllDeployments(checker_array& checkers, const Consensus::Params& params, F&& fn)
{
    constexpr size_t ts = std::tuple_size_v<checker_array>;
    return AllDeployments_impl(checkers, params, fn, std::make_index_sequence<ts>{});
}

template<size_t POS, typename F, typename P, typename C>
static auto ExactDeployment(checker_array& checkers, const Consensus::Params& params, F&& fn)
{
    auto [logic, checker] = GetLogicChecker<POS>(checkers, params);
    return fn(logic, checker);
}

template<size_t I, typename F, typename P, typename C, typename T>
static T OneDeployment_impl(checker_array& checkers, const Consensus::Params& params, T&& def, size_t pos, F&& fn)
{
    if constexpr (I < std::tuple_size_v<checker_array>) {
        if (pos == I) {
            auto [logic, checker] = GetLogicChecker<I>(checkers, params);
            return fn(logic, checker);
        } else {
            return OneDeployment_impl<I+1>(checkers, params, def, pos, fn);
        }
    } else {
        return def;
    }
}

bool VersionBitsCache::IsActive(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(m_mutex);
    ConditionLogic logic{GetLogic(params, pos)};
    return logic.IsActive(m_checker[pos].GetStateFor(logic, pindexPrev), pindexPrev);
}

ThresholdState VersionBitsCache::State(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(m_mutex);
    return m_checker[pos].GetStateFor(GetLogic(params, pos), pindexPrev);
}

BIP9Stats VersionBitsCache::Statistics(const CBlockIndex* pindex, const Consensus::Params& params, Consensus::DeploymentPos pos, std::vector<bool>* signalling_blocks)
{
    return GetLogic(params, pos).GetStateStatisticsFor(pindex, signalling_blocks);
}

int VersionBitsCache::StateSinceHeight(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(m_mutex);
    return m_checker[pos].GetStateSinceHeightFor(GetLogic(params, pos), pindexPrev);
}

std::optional<int> VersionBitsCache::ActivationHeight(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(m_mutex);
    ConditionLogic logic{GetLogic(params, pos)};
    return logic.ActivationHeight(m_checker[pos].GetStateFor(logic, pindexPrev), m_checker[pos].GetStateSinceHeightFor(logic, pindexPrev));
}

uint32_t VersionBitsCache::Mask(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    return GetLogic(params, pos).Mask();
}

bool VersionBitsCache::ShouldSetVersionBit(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(m_mutex);
    ConditionLogic logic{GetLogic(params, pos)};
    return logic.ShouldSetVersionBit(m_checker[pos].GetStateFor(logic, pindexPrev));
}

int32_t VersionBitsCache::ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    LOCK(m_mutex);

    auto get_mask = [&](auto p) -> int32_t {
        auto [logic, checker] = p;
        if (logic.ShouldSetVersionBit(checker.GetStateFor(logic, pindexPrev))) {
            return logic.Mask();
        } else {
            return 0;
        }
    };

    return AllDeployments(m_checker, params, [&](auto... p) -> int32_t {
        return (VERSIONBITS_TOP_BITS | ... | get_mask(p));
    });
}

void VersionBitsCache::Clear()
{
    LOCK(m_mutex);
    for (unsigned int d = 0; d < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; d++) {
        m_checker[d].clear();
    }
}
