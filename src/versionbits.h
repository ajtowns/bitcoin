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

    int Period() const { return dep.period; }

    /* State logic */

    /** Configured to be always in the same state */
    std::optional<ThresholdState> SpecialState() const;

    /* Normal transitions */
    static constexpr ThresholdState GenesisState = ThresholdState::DEFINED;
    std::optional<ThresholdState> TrivialState(const CBlockIndex* pindexPrev) const;
    ThresholdState NextState(const ThresholdState state, const CBlockIndex* pindexPrev) const;

    /** Determine if deployment is active */
    inline bool IsActive(ThresholdState state, const CBlockIndex* pindexPrev) const { return state == ThresholdState::ACTIVE; }

    /** Get bit mask */
    inline uint32_t Mask() const { return ((uint32_t)1) << dep.bit; }

    /** Given current state, should bit be set? */
    inline bool ShouldSetVersionBit(ThresholdState state)
    {
        return (state == ThresholdState::STARTED) || (state == ThresholdState::LOCKED_IN);
    }

    /** Is the bit set? */
    inline bool VersionBitIsSet(int32_t version) const
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
    /** Returns the state for pindex A based on parent pindexPrev B. Applies any state transition if conditions are present.
     *  Caches state from first block of period. */
    ThresholdState GetStateFor(const ConditionLogic& logic, const CBlockIndex* pindexPrev);
    /** Returns the height since when the ThresholdState has started for pindex A based on parent pindexPrev B, all blocks of a period share the same */
    int GetStateSinceHeightFor(const ConditionLogic& logic, const CBlockIndex* pindexPrev);

    void clear() { m_cache.clear(); }
};

/** BIP 9 allows multiple softforks to be deployed in parallel. We cache
 *  per-period state for every one of them. */
class VersionBitsCache
{
private:
    Mutex m_mutex;
    mutable VersionBitsConditionChecker m_checker[Consensus::MAX_VERSION_BITS_DEPLOYMENTS] GUARDED_BY(m_mutex);

public:
    /** Get the numerical statistics for a given deployment for the signalling period that includes pindex.
     * If provided, signalling_blocks is set to true/false based on whether each block in the period signalled
     */
    static BIP9Stats Statistics(const CBlockIndex* pindex, const Consensus::Params& params, Consensus::DeploymentPos pos, std::vector<bool>* signalling_blocks = nullptr);

    static uint32_t Mask(const Consensus::Params& params, Consensus::DeploymentPos pos);

    /** Check if the deployment is active */
    bool IsActive(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos pos);

    /** Get the BIP9 state for a given deployment for the block after pindexPrev. */
    ThresholdState State(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos pos);

    /** Get the block height at which the BIP9 deployment switched into the state for the block after pindexPrev. */
    int StateSinceHeight(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos pos);

    /** Determine what nVersion a new block should use
     */
    int32_t ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params);

    void Clear();
};

#endif // BITCOIN_VERSIONBITS_H
