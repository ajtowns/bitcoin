// Copyright (c) 2016-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VERSIONBITS_H
#define BITCOIN_VERSIONBITS_H

#include <chain.h>
#include <sync.h>

#include <map>
#include <optional>

/** What block version to use for new blocks (pre versionbits) */
static const int32_t VERSIONBITS_LAST_OLD_BLOCK_VERSION = 4;
/** What bits to set in version for versionbits blocks */
static const int32_t VERSIONBITS_TOP_BITS = 0x20000000UL;
/** What bitmask determines whether versionbits is in use */
static const int32_t VERSIONBITS_TOP_MASK = 0xE0000000UL;
/** Total bits available for versionbits */
static const int32_t VERSIONBITS_NUM_BITS = 29;

/**
 * Class that implements BIP9-style threshold logic, and caches results.
 */
template<typename Logic>
class ThresholdConditionChecker
{
private:
    /** Static checks to give cleaner errors if the "Logic" class is broken */
    static constexpr void static_checks(const Logic& logic)
    {
        // need to be able to determine the period
        static_assert(std::is_invocable_r_v<int, decltype(&Logic::Period), const Logic&>, "missing Logic::Period");

        // need to be told whether a block signals or not
        static_assert(std::is_invocable_r_v<bool, decltype(&Logic::Condition), const Logic&, const CBlockIndex*>, "missing Logic::Condition");

        // need to know the genesis state to kick things off
        static_assert(std::is_same_v<const typename Logic::State, decltype(logic.GenesisState)>, "missing Logic::GenesisState");

        // state transition logic:
        // SpecialState (always the same), TrivialState (doesn't depend on earlier blocks) and NextState (conditional on earlier blocks)
        static_assert(std::is_invocable_r_v<std::optional<typename Logic::State>, decltype(&Logic::SpecialState), const Logic&>, "missing Logic::SpecialState");
        static_assert(std::is_invocable_r_v<std::optional<typename Logic::State>, decltype(&Logic::TrivialState), const Logic&, const CBlockIndex*>, "missing Logic::TrivialState");
        static_assert(std::is_invocable_r_v<typename Logic::State, decltype(&Logic::NextState), const Logic&, typename Logic::State, const CBlockIndex*>, "missing Logic::NextState");

        // need to be able to return a Stats object with count and elapsed
        typename Logic::Stats stats;
        static_assert(std::is_same_v<int, decltype(stats.count)>, "missing Logic::Stats::count");
        static_assert(std::is_same_v<int, decltype(stats.elapsed)>, "missing Logic::Stats::elapsed");
    }

public:
    /** Returns the state for pindex A based on parent pindexPrev B. Applies any state transition if conditions are present.
     *  Caches state from first block of period. */
    static typename Logic::State GetStateFor(const Logic& logic, typename Logic::Cache& cache, const CBlockIndex* pindexPrev);

    /** Returns the height since when the State has started for pindex A based on parent pindexPrev B, all blocks of a period share the same */
    static int GetStateSinceHeightFor(const Logic& logic, typename Logic::Cache& cache, const CBlockIndex* pindexPrev);

    /** Returns the numerical statistics of an in-progress softfork in the period including pindex
     * If provided, signalling_blocks is set to true/false based on whether each block in the period signalled
     */
    static typename Logic::Stats GetStateStatisticsFor(const Logic& logic, const CBlockIndex* pindex, std::vector<bool>* signalling_blocks = nullptr);
};

class ConditionLogic
{
public:
    using Params = Consensus::BIP9Deployment;

private:
    const ConditionLogic::Params& dep;
    using ThreshCheck = ThresholdConditionChecker<ConditionLogic>;

public:
    /** BIP 9 defines a finite-state-machine to deploy a softfork in multiple stages.
     *  State transitions happen during retarget period if conditions are met
     *  In case of reorg, transitions can go backward. Without transition, state is
     *  inherited between periods. All blocks of a period share the same state.
     */
    enum class State {
        DEFINED,   // First state that each softfork starts out as. The genesis block is by definition in this state for each deployment.
        STARTED,   // For blocks past the starttime.
        LOCKED_IN, // For at least one retarget period after the first retarget period with STARTED blocks of which at least threshold have the associated bit set in nVersion, until min_activation_height is reached.
        ACTIVE,    // For all blocks after the LOCKED_IN retarget period (final state)
        FAILED,    // For all blocks once the first retarget period after the timeout time is hit, if LOCKED_IN wasn't already reached (final state)
    };

    /** Display status of an in-progress BIP9 softfork */
    struct Stats {
        /** Length of blocks of the BIP9 signalling period */
        int period;
        /** Number of blocks with the version bit set required to activate the softfork */
        int threshold;
        /** Number of blocks elapsed since the beginning of the current period */
        int elapsed;
        /** Number of blocks with the version bit set since the beginning of the current period */
        int count;
        /** False if there are not enough blocks left in this period to pass activation threshold */
        bool possible;
    };

    // A map that caches the state for blocks whose height is a multiple of Period().
    // The map is indexed by the block's parent, however, so all keys in the map
    // will either be nullptr or a block with (height + 1) % Period() == 0.
    using Cache = std::map<const CBlockIndex*, State>;

    explicit ConditionLogic(const Consensus::BIP9Deployment& dep) : dep{dep} {}

    const Consensus::BIP9Deployment& Dep() const { return dep; }
    int Period() const { return dep.period; }

    /* State logic */

    /** Is deployment enabled at all? */
    bool Enabled() const { return dep.nStartTime != Consensus::BIP9Deployment::NEVER_ACTIVE; }

    /** Configured to be always in the same state */
    std::optional<State> SpecialState() const;

    /* Normal transitions */
    static constexpr State GenesisState = State::DEFINED;
    std::optional<State> TrivialState(const CBlockIndex* pindexPrev) const;
    State NextState(const State state, const CBlockIndex* pindexPrev) const;

    State GetStateFor(Cache& cache, const CBlockIndex* pindexPrev) const { return ThreshCheck::GetStateFor(*this, cache, pindexPrev); }
    int GetStateSinceHeightFor(Cache& cache, const CBlockIndex* pindexPrev) const { return ThreshCheck::GetStateSinceHeightFor(*this, cache, pindexPrev); }

    /** Determine if deployment is active */
    bool IsActive(State state, const CBlockIndex* pindexPrev) const { return state == State::ACTIVE; }
    bool IsActive(Cache& cache, const CBlockIndex* pindexPrev) const { return GetStateFor(cache, pindexPrev) == State::ACTIVE; }

    /** Determine if deployment is certain */
    bool IsCertain(State state) const
    {
        return state == State::ACTIVE || state == State::LOCKED_IN;
    }

    /** Get bit mask */
    uint32_t Mask() const { return ((uint32_t)1) << dep.bit; }

    /** Given current state, should bit be set? */
    std::optional<int> VersionBitToSet(State state, const CBlockIndex* pindexPrev) const
    {
        if ((state == State::STARTED) || (state == State::LOCKED_IN)) {
            return dep.bit;
        } else {
            return std::nullopt;
        }
    }

    std::optional<int> VersionBitToSet(Cache& cache, const CBlockIndex* pindexPrev) const
    {
        return VersionBitToSet(GetStateFor(cache, pindexPrev), pindexPrev);
    }

    /** Is the bit set? */
    bool VersionBitIsSet(int32_t version) const
    {
        return (((version & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS) && (version & Mask()) != 0);
    }

    /** Does this block count towards the threshold? */
    virtual bool Condition(const CBlockIndex* pindex) const { return VersionBitIsSet(pindex->nVersion); }

    /** Returns the numerical statistics of an in-progress BIP9 softfork in the period including pindex
     * If provided, signalling_blocks is set to true/false based on whether each block in the period signalled
     */
    Stats GetStateStatisticsFor(const CBlockIndex* pindex, std::vector<bool>* signalling_blocks = nullptr) const
    {
        Stats stats{ThreshCheck::GetStateStatisticsFor(*this, pindex, signalling_blocks)};
        stats.period = Period();
        stats.threshold = dep.threshold;
        stats.possible = (stats.period - stats.threshold ) >= (stats.elapsed - stats.count);
        return stats;
    }

    /** Activation height if known */
    std::optional<int> ActivationHeight(Cache& cache, const CBlockIndex* pindexPrev) const
    {
        const State state{ThresholdConditionChecker<ConditionLogic>::GetStateFor(*this, cache, pindexPrev)};
        if (IsCertain(state)) {
            const int since{ThresholdConditionChecker<ConditionLogic>::GetStateSinceHeightFor(*this, cache, pindexPrev)};
            if (state == ConditionLogic::State::ACTIVE) return since;
            if (state == ConditionLogic::State::LOCKED_IN) {
                return std::max(since + Period(), dep.min_activation_height);
            }
        }
        return std::nullopt;
    }

    static void ClearCache(Cache& cache) { cache.clear(); }
};

#endif // BITCOIN_VERSIONBITS_H
