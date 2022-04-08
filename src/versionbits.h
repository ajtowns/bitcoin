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
static constexpr int32_t VERSIONBITS_LAST_OLD_BLOCK_VERSION = 4;
/** What bits to set in version for versionbits blocks */
static constexpr int32_t VERSIONBITS_TOP_BITS = 0x20000000UL;
/** What bitmask determines whether versionbits is in use */
static constexpr int32_t VERSIONBITS_TOP_MASK = 0xE0000000UL;
/** Total bits available for versionbits */
static constexpr int32_t VERSIONBITS_NUM_BITS = 29;

namespace VersionBits {
/** Display status of an in-progress softfork */
struct Stats {
    /** Length of blocks of the signalling period */
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

inline bool IsBitSet(int bit, int32_t version)
{
    return (bit >= 0) && (bit < VERSIONBITS_NUM_BITS)
           && (((version & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS) && (version & (1 << bit)) != 0);
}

} // namespace VersionBits

class BIP9DeploymentLogic
{
public:
    using Params = Consensus::BIP9Deployment;

private:
    const Params& dep;

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

    // A map that caches the state for blocks whose height is a multiple of Period().
    // The map is indexed by the block's parent, however, so all keys in the map
    // will either be nullptr or a block with (height + 1) % Period() == 0.
    using Cache = std::map<const CBlockIndex*, State>;

    explicit BIP9DeploymentLogic(const Consensus::BIP9Deployment& dep) : dep{dep} {}

    const Consensus::BIP9Deployment& Dep() const { return dep; }
    int Period() const { return dep.period; }

    /* State logic */

    /* Get state! */
    State GetStateFor(Cache& cache, const CBlockIndex* pindexPrev) const;
    int GetStateSinceHeightFor(Cache& cache, const CBlockIndex* pindexPrev) const;

    /** Is deployment enabled at all? */
    bool Enabled() const { return dep.nStartTime != Consensus::BIP9Deployment::NEVER_ACTIVE; }

    /** Determine if deployment is active */
    bool IsActive(State state, const CBlockIndex* pindexPrev) const { return state == State::ACTIVE; }

    /** Determine if deployment is certain */
    bool IsCertain(State state) const { return state == State::ACTIVE || state == State::LOCKED_IN; }

    /** Get bit mask */
    uint32_t Mask() const { return ((uint32_t)1) << dep.bit; }

    /** Given current state, should bit be set? */
    std::optional<int> VersionBitToSet(State state, const CBlockIndex* pindexPrev) const
    {
        if ((state == State::STARTED) || (state == State::LOCKED_IN)) return dep.bit;
        return std::nullopt;
    }

    std::optional<int> VersionBitToSet(Cache& cache, const CBlockIndex* pindexPrev) const
    {
        return VersionBitToSet(GetStateFor(cache, pindexPrev), pindexPrev);
    }

    /** Does this block count towards the threshold? */
    virtual bool Condition(const CBlockIndex* pindex) const { return VersionBits::IsBitSet(dep.bit, pindex->nVersion); }

    /** Returns the numerical statistics of an in-progress BIP9 softfork in the period including pindex
     * If provided, signalling_blocks is set to true/false based on whether each block in the period signalled
     */
    VersionBits::Stats GetStateStatisticsFor(const CBlockIndex* pindex, std::vector<bool>* signalling_blocks = nullptr) const;

    /** Activation height if known */
    std::optional<int> ActivationHeight(Cache& cache, const CBlockIndex* pindexPrev) const
    {
        const State state{GetStateFor(cache, pindexPrev)};
        if (IsCertain(state)) {
            const int since{GetStateSinceHeightFor(cache, pindexPrev)};
            if (state == BIP9DeploymentLogic::State::ACTIVE) return since;
            if (state == BIP9DeploymentLogic::State::LOCKED_IN) return since + Period();
        }
        return std::nullopt;
    }

    static void ClearCache(Cache& cache) { cache.clear(); }
};


class BIP341DeploymentLogic
{
public:
    using Params = Consensus::BIP341Deployment;

private:
    const Params& dep;

public:
    using State = BIP9DeploymentLogic::State;
    using Cache = std::map<const CBlockIndex*, State>;

    explicit BIP341DeploymentLogic(const Consensus::BIP341Deployment& dep) : dep{dep} {}

    const Consensus::BIP341Deployment& Dep() const { return dep; }
    int Period() const { return dep.period; }

    /* State logic */

    State GetStateFor(Cache& cache, const CBlockIndex* pindexPrev) const;
    int GetStateSinceHeightFor(Cache& cache, const CBlockIndex* pindexPrev) const;

    /** Is deployment enabled at all? */
    bool Enabled() const { return dep.nStartTime != Consensus::BIP341Deployment::NEVER_ACTIVE; }

    /** Determine if deployment is active */
    bool IsActive(State state, const CBlockIndex* pindexPrev) const { return state == State::ACTIVE; }

    /** Determine if deployment is certain */
    bool IsCertain(State state) const { return state == State::ACTIVE || state == State::LOCKED_IN; }

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

    /** Does this block count towards the threshold? */
    virtual bool Condition(const CBlockIndex* pindex) const { return VersionBits::IsBitSet(dep.bit, pindex->nVersion); }

    /** Returns the numerical statistics of an in-progress BIP9 softfork in the period including pindex
     * If provided, signalling_blocks is set to true/false based on whether each block in the period signalled
     */
    VersionBits::Stats GetStateStatisticsFor(const CBlockIndex* pindex, std::vector<bool>* signalling_blocks = nullptr) const;

    /** Activation height if known */
    std::optional<int> ActivationHeight(Cache& cache, const CBlockIndex* pindexPrev) const
    {
        const State state{GetStateFor(cache, pindexPrev)};
        if (IsCertain(state)) {
            const int since{GetStateSinceHeightFor(cache, pindexPrev)};
            if (state == BIP9DeploymentLogic::State::ACTIVE) return since;
            if (state == BIP9DeploymentLogic::State::LOCKED_IN) {
                return std::max(since + Period(), dep.min_activation_height);
            }
        }
        return std::nullopt;
    }

    static void ClearCache(Cache& cache) { cache.clear(); }
};

class BIPBlahDeploymentLogic
{
public:
    using Params = Consensus::BIPBlahDeployment;

private:
    const Params& dep;

    static int height(const CBlockIndex* pindexPrev) { return pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1; }

public:
    enum class StateCode : int64_t {
        DEFINED,
        OPT_IN,
        OPT_OUT_WAIT,
        OPT_OUT,      // count if first block in period has MTP greater than data
        LOCKED_IN,    // switch to ACTIVE when MTP greater than data
        ACTIVE,       // data = period + (height of first block greater than LOCKED_IN data)
        FAILED,
    };
    struct State {
        StateCode code :  4;
        int64_t data   : 58; // allows timestamp in minutes instead of seconds

        bool operator==(const State& other) const { return code == other.code && data == other.data; }
    };
    static_assert(sizeof(State) == sizeof(int64_t));
    using Cache = std::map<const CBlockIndex*, State>;

    explicit BIPBlahDeploymentLogic(const Consensus::BIPBlahDeployment& dep) : dep{dep} {}

    const Consensus::BIPBlahDeployment& Dep() const { return dep; }
    int Period() const { return dep.period; }

    /* State logic */

    /** Is deployment enabled at all? */
    bool Enabled() const { return dep.optin_start != Consensus::BIPBlahDeployment::NEVER_ACTIVE; }

    State GetStateFor(Cache& cache, const CBlockIndex* pindexPrev) const;
    int GetStateSinceHeightFor(Cache& cache, const CBlockIndex* pindexPrev) const;

    /** Determine if deployment is active */
    bool IsActive(State state, const CBlockIndex* pindexPrev) const { return state.code == StateCode::ACTIVE && state.data <= height(pindexPrev); }

    /** Determine if deployment is certain */
    bool IsCertain(State state) const { return state.code == StateCode::ACTIVE || state.code == StateCode::LOCKED_IN; }

    /** Get bit mask */
    uint32_t Mask() const { return ((uint32_t)1) << dep.bit; }

    /** Given current state, should bit be set? */
    std::optional<int> VersionBitToSet(State state, const CBlockIndex* pindexPrev) const
    {
        if ((state.code == StateCode::OPT_IN) || (state.code == StateCode::LOCKED_IN)) {
            return dep.bit;
        } else {
            return std::nullopt;
        }
    }

    std::optional<int> VersionBitToSet(Cache& cache, const CBlockIndex* pindexPrev) const
    {
        return VersionBitToSet(GetStateFor(cache, pindexPrev), pindexPrev);
    }

    /** Does this block count towards the threshold? */
    virtual bool Condition(const CBlockIndex* pindex) const { return VersionBits::IsBitSet(dep.bit, pindex->nVersion); }

    /** Returns the numerical statistics of an in-progress BIP9 softfork in the period including pindex
     * If provided, signalling_blocks is set to true/false based on whether each block in the period signalled
     */
    VersionBits::Stats GetStateStatisticsFor(const CBlockIndex* pindex, const State& state, std::vector<bool>* signalling_blocks = nullptr) const;

    /** Activation height if known */
    std::optional<int> ActivationHeight(State state, const CBlockIndex* pindexPrev) const;
    std::optional<int> ActivationHeight(Cache& cache, const CBlockIndex* pindexPrev) const
    {
        return ActivationHeight(GetStateFor(cache, pindexPrev), pindexPrev);
    }

    static void ClearCache(Cache& cache) { cache.clear(); }
};

#endif // BITCOIN_VERSIONBITS_H
