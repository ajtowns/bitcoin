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

/** BIP 9 defines a finite-state-machine to deploy a softfork in multiple stages.
 *  State transitions happen during retarget period if conditions are met
 *  In case of reorg, transitions can go backward. Without transition, state is
 *  inherited between periods. All blocks of a period share the same state.
 */
enum class ThresholdState {
    DEFINED,   // First state that each softfork starts out as. The genesis block is by definition in this state for each deployment.
    STARTED,   // For blocks past the starttime.
    LOCKED_IN, // For at least one retarget period after the first retarget period with STARTED blocks of which at least threshold have the associated bit set in nVersion, until min_activation_height is reached.
    ACTIVE,    // For all blocks after the LOCKED_IN retarget period (final state)
    FAILED,    // For all blocks once the first retarget period after the timeout time is hit, if LOCKED_IN wasn't already reached (final state)
};

/** Display status of an in-progress BIP9 softfork */
struct BIP9Stats {
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

class ConditionLogic
{
private:
    const Consensus::BIP9Deployment& dep;

public:
    explicit ConditionLogic(const Consensus::BIP9Deployment& dep) : dep{dep} {}

    const Consensus::BIP9Deployment& Dep() const { return dep; }
    int Period() const { return dep.period; }

    /* State logic */

    /** Is deployment enabled at all? */
    bool Enabled() const { return dep.nStartTime != Consensus::BIP9Deployment::NEVER_ACTIVE; }

    /** Configured to be always in the same state */
    std::optional<ThresholdState> SpecialState() const;

    /* Normal transitions */
    static constexpr ThresholdState GenesisState = ThresholdState::DEFINED;
    std::optional<ThresholdState> TrivialState(const CBlockIndex* pindexPrev) const;
    ThresholdState NextState(const ThresholdState state, const CBlockIndex* pindexPrev) const;

    /** Determine if deployment is active */
    bool IsActive(ThresholdState state, const CBlockIndex* pindexPrev) const { return state == ThresholdState::ACTIVE; }

    /** Determine if deployment is certain */
    bool IsCertain(ThresholdState state) const
    {
        return state == ThresholdState::ACTIVE || state == ThresholdState::LOCKED_IN;
    }

    /** Get bit mask */
    uint32_t Mask() const { return ((uint32_t)1) << dep.bit; }

    /** Given current state, should bit be set? */
    bool ShouldSetVersionBit(ThresholdState state, const CBlockIndex* pindexPrev) const
    {
        return (state == ThresholdState::STARTED) || (state == ThresholdState::LOCKED_IN);
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
    BIP9Stats GetStateStatisticsFor(const CBlockIndex* pindex, std::vector<bool>* signalling_blocks = nullptr) const;
};

/**
 * Class that implements BIP9-style threshold logic, and caches results.
 */
class VersionBitsConditionChecker
{
protected:
    // A map that caches the state for blocks whose height is a multiple of Period().
    // The map is indexed by the block's parent, however, so all keys in the map
    // will either be nullptr or a block with (height + 1) % Period() == 0.
    std::map<const CBlockIndex*, ThresholdState> m_cache;

public:
    VersionBitsConditionChecker() = default;
    VersionBitsConditionChecker(const VersionBitsConditionChecker&) = delete;
    VersionBitsConditionChecker(VersionBitsConditionChecker&&) = delete;
    VersionBitsConditionChecker& operator=(const VersionBitsConditionChecker&) = delete;
    VersionBitsConditionChecker& operator=(VersionBitsConditionChecker&&) = delete;

    /** Returns the state for pindex A based on parent pindexPrev B. Applies any state transition if conditions are present.
     *  Caches state from first block of period. */
    ThresholdState GetStateFor(const ConditionLogic& logic, const CBlockIndex* pindexPrev);
    /** Returns the height since when the ThresholdState has started for pindex A based on parent pindexPrev B, all blocks of a period share the same */
    int GetStateSinceHeightFor(const ConditionLogic& logic, const CBlockIndex* pindexPrev);

    /** Activation height if known */
    std::optional<int> ActivationHeight(const ConditionLogic& logic, const CBlockIndex* pindexPrev)
    {
        const ThresholdState state{GetStateFor(logic, pindexPrev)};
        if (logic.IsCertain(state)) {
            const int since = GetStateSinceHeightFor(logic, pindexPrev);
            if (state == ThresholdState::ACTIVE) return since;
            if (state == ThresholdState::LOCKED_IN) {
                return std::max(since + logic.Period(), logic.Dep().min_activation_height);
            }
        }
        return std::nullopt;
    }

    void clear() { m_cache.clear(); }
};

class BuriedDeploymentLogic
{
public:
    const int m_height;
    BuriedDeploymentLogic(int height) : m_height{height} { }
    bool ShouldSetVersionBit(bool state, const CBlockIndex* pindexPrev) const { return false; }
    uint32_t Mask() const { return 0; }
    bool Enabled() const { return m_height != std::numeric_limits<int>::max(); }
    bool IsActive(bool state, const CBlockIndex* pindexPrev) const { return state; }
};

struct BuriedDeploymentChecker
{
    bool GetStateFor(const BuriedDeploymentLogic& logic, const CBlockIndex* pindexPrev) { return (pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1) >= logic.m_height; }
    std::optional<int> ActivationHeight(const BuriedDeploymentLogic& logic, const CBlockIndex* pindexPrev)
    {
        return logic.m_height;
    }
};

/** BIP 9 allows multiple softforks to be deployed in parallel. We cache
 *  per-period state for every one of them. */
class VersionBitsCache
{
private:
    Mutex m_mutex;
    using checker_array = std::array<VersionBitsConditionChecker,Consensus::MAX_VERSION_BITS_DEPLOYMENTS>;
    mutable checker_array m_checker GUARDED_BY(m_mutex);

    static ConditionLogic GetLogic(const Consensus::Params& params, Consensus::DeploymentPos pos);

    template<size_t I=0, typename Fn>
    static void ForEachDeployment_impl(checker_array& checkers, const Consensus::Params& params, Fn&& fn)
    {
        if constexpr (I < std::tuple_size_v<checker_array>) {
            constexpr Consensus::DeploymentPos pos = static_cast<Consensus::DeploymentPos>(I);
            static_assert(Consensus::ValidDeployment(pos), "invalid deployment");
            fn(pos, GetLogic(params, pos), std::get<I>(checkers));
            ForEachDeployment_impl<I+1>(checkers, params, fn);
        }
    }

    template<Consensus::BuriedDeployment POS=Consensus::DEPLOYMENT_HEIGHTINCB, typename Fn>
    static void ForEachBuriedDeployment(const Consensus::Params& params, Fn&& fn)
    {
        if constexpr (ValidDeployment(POS)) {
            BuriedDeploymentLogic logic{params.DeploymentHeight(POS)};
            BuriedDeploymentChecker checker;
            fn(POS, logic, checker);
            ForEachBuriedDeployment<static_cast<Consensus::BuriedDeployment>(POS+1)>(params, fn);
        }
    }

public:
    /** Check if the deployment is active */
    bool IsActive(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos pos);

    /** Determine what nVersion a new block should use */
    int32_t ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params);

    /** Get the bitmask for a given deployment */
    static uint32_t Mask(const Consensus::Params& params, Consensus::DeploymentPos pos);

    /** Iterate over all deployments, and do something
     * Fn should be [](auto pos, const auto& logic, auto& checker) { ... }
     */
    template<typename Fn>
    void ForEachDeployment(const Consensus::Params& params, Fn&& fn)
    {
        LOCK(m_mutex);
        ForEachDeployment_impl(m_checker, params, fn);
        ForEachBuriedDeployment(params, fn);
    }

    /** Clear the cache */
    void Clear();
};

#endif // BITCOIN_VERSIONBITS_H
