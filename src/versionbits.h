// Copyright (c) 2016-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VERSIONBITS_H
#define BITCOIN_VERSIONBITS_H

#include <chain.h>
#include <sync.h>

#include <array>
#include <map>
#include <optional>
#include <vector>

class CChainParams;

/** What block version to use for new blocks (pre versionbits) */
static const int32_t VERSIONBITS_LAST_OLD_BLOCK_VERSION = 4;
/** What bits to set in version for versionbits blocks */
static const int32_t VERSIONBITS_TOP_BITS = 0x20000000UL;
/** What bitmask determines whether versionbits is in use */
static const int32_t VERSIONBITS_TOP_MASK = 0xE0000000UL;
/** Total bits available for versionbits */
static const int32_t VERSIONBITS_NUM_BITS = 29;

/** Opaque type for BIP9 state. See versionbits_impl.h for details. */
enum class ThresholdState : uint8_t;

// A map that gives the state for blocks whose height is a multiple of Period().
// The map is indexed by the block's parent, however, so all keys in the map
// will either be nullptr or a block with (height + 1) % Period() == 0.
typedef std::map<const CBlockIndex*, ThresholdState> ThresholdConditionCache;

/** Detailed status of an enabled BIP9 deployment */
struct BIP9Info {
    /** Height at which current_state started */
    int since{0};
    /** String representing the current state */
    std::string current_state{};
    /** String representing the next block's state */
    std::string next_state{};
    /** State period */
    uint32_t period;
    /** Signal for activation */
    std::optional<int32_t> signal_activate;
    /** Signal for abandonment */
    std::optional<int32_t> signal_abandon;
    /** Height at which the deployment is active, if known. May be in the future. */
    std::optional<int> active_since;
};

struct BIP9GBTStatus {
    struct Info {
        int bit;
        uint32_t mask;
        bool gbt_force;
    };
    std::map<std::string, const Info, std::less<>> signalling, locked_in, active;
};

/** BIP 9 allows multiple softforks to be deployed in parallel. We cache
 *  per-period state for every one of them. */
class VersionBitsCache
{
private:
    Mutex m_mutex;
    std::array<ThresholdConditionCache,VERSIONBITS_NUM_BITS> m_warning_caches GUARDED_BY(m_mutex);
    std::array<ThresholdConditionCache,Consensus::MAX_VERSION_BITS_DEPLOYMENTS> m_caches GUARDED_BY(m_mutex);

public:
    BIP9Info Info(const CBlockIndex& block_index, const Consensus::Params& params, Consensus::DeploymentPos id) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    BIP9GBTStatus GBTStatus(const CBlockIndex& block_index, const Consensus::Params& params) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Get the BIP9 state for a given deployment for the block after pindexPrev. */
    bool IsActiveAfter(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos pos) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Determine what nVersion a new block should use */
    int32_t ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Check for unknown activations
     *  Returns a vector containing the bit number used for signalling and a bool
     *  indicating the deployment is likely to be ACTIVE, rather than merely LOCKED_IN. */
    std::vector<std::pair<int,bool>> CheckUnknownActivations(const CBlockIndex* pindex, const CChainParams& chainparams) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Report BINANA details, based on nVersion signalling standard */
    bool BINANA(int& year, int& number, int& revision, const Consensus::Params& params, Consensus::DeploymentPos pos) const;

    void Clear() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
};

#endif // BITCOIN_VERSIONBITS_H
