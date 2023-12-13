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
struct VBDeploymentInfo;

template<typename T> struct DeploymentParamsCache;
template<Consensus::DeploymentPos D> using DeploymentCache = DeploymentParamsCache<typename Consensus::DeploymentParams<D>::type>;

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
using ThresholdConditionCache = std::map<const CBlockIndex*, ThresholdState>;
template<> struct DeploymentParamsCache<Consensus::BIP9Deployment> { using type = ThresholdConditionCache; };

/** Display status of an in-progress BIP9 softfork */
struct BIP9Stats {
    /** Length of blocks of the BIP9 signalling period */
    int period{0};
    /** Number of blocks with the version bit set required to activate the softfork */
    int threshold{0};
    /** Number of blocks elapsed since the beginning of the current period */
    int elapsed{0};
    /** Number of blocks with the version bit set since the beginning of the current period */
    int count{0};
    /** False if there are not enough blocks left in this period to pass activation threshold */
    bool possible{false};
};

/** Detailed status of an enabled BIP9 deployment */
struct BIP9Info {
    int since{0};
    std::string current_state{};
    std::string next_state{};
    std::optional<BIP9Stats> stats;
    std::vector<bool> signalling_blocks;
    std::optional<int> active_since;
};

struct GBTStatus {
    struct Info {
        int bit;
        uint32_t mask;
        bool gbt_force;
    };
    std::map<std::string, const Info> signalling, locked_in, active;
};

template<typename P>
struct DepParamsCache {
    using Cache = typename DeploymentParamsCache<P>::type;
    const P& dep;
    Cache& cache;
    explicit DepParamsCache(const P& dep, Cache& cache) : dep{dep}, cache{cache} { };
};

template<typename P>
struct DepInfoParamsCache {
    using Cache = typename DeploymentParamsCache<P>::type;
    const VBDeploymentInfo& info;
    const P& dep;
    Cache& cache;
    explicit DepInfoParamsCache(const VBDeploymentInfo& info, const P& dep, Cache& cache) : info{info}, dep{dep}, cache{cache} {};
};

inline bool DepEnabled(const Consensus::BIP9Deployment& dep) { return dep.nStartTime != Consensus::BIP9Deployment::NEVER_ACTIVE; }
bool IsActiveAfter(const CBlockIndex* pindexPrev, DepParamsCache<Consensus::BIP9Deployment> depcache);
int StateSinceHeight(const CBlockIndex* pindexPrev, DepParamsCache<Consensus::BIP9Deployment> depcache);
BIP9Info GetDepInfo(const CBlockIndex& block_index, DepParamsCache<Consensus::BIP9Deployment> depcache);

void ComputeBlockVersion(const CBlockIndex* pindexPrev, int32_t& nVersion, DepParamsCache<Consensus::BIP9Deployment> depcache);
void BumpGBTStatus(const CBlockIndex& blockindex, GBTStatus& gbtstatus, DepInfoParamsCache<Consensus::BIP9Deployment> depinfocache);

template <typename P>
concept DeploymentConcept = requires(const P& dep) {
    DepEnabled(dep);
} && requires(DepParamsCache<P> depcache, const CBlockIndex& blockindex, int32_t& nVersion) {
    IsActiveAfter(&blockindex, depcache);
    StateSinceHeight(&blockindex, depcache);
    GetDepInfo(blockindex, depcache);
    ComputeBlockVersion(&blockindex, nVersion, depcache);
} && requires(DepInfoParamsCache<P> depinfocache, const CBlockIndex& blockindex, GBTStatus& gbtstatus) {
    BumpGBTStatus(blockindex, gbtstatus, depinfocache);
};

/** BIP 9 allows multiple softforks to be deployed in parallel. We cache
 *  per-period state for every one of them. */
class VersionBitsCache
{
private:
    static_assert(DeploymentConcept<Consensus::BIP9Deployment>);

    Mutex m_mutex;
    std::array<ThresholdConditionCache,VERSIONBITS_NUM_BITS> m_warning_caches GUARDED_BY(m_mutex);

    auto GetDPC(const Consensus::Params& params, Consensus::DeploymentPos id) EXCLUSIVE_LOCKS_REQUIRED(m_mutex) { return DepParamsCache(params.vDeployments[id], m_caches[id]); }

    std::array<ThresholdConditionCache,Consensus::MAX_VERSION_BITS_DEPLOYMENTS> m_caches GUARDED_BY(m_mutex);

public:
    auto GetDepInfo(const CBlockIndex& block_index, const Consensus::Params& params, Consensus::DeploymentPos id) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return ::GetDepInfo(block_index, GetDPC(params, id));
    }

    /** Get the BIP9 state for a given deployment for the block after pindexPrev. */
    bool Enabled(const Consensus::Params& params, Consensus::DeploymentPos id)
    {
        return ::DepEnabled(params.vDeployments[id]);
    }

    /** Get the BIP9 state for a given deployment for the block after pindexPrev. */
    bool IsActiveAfter(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos id) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return ::IsActiveAfter(pindexPrev, GetDPC(params, id));
    }

    /** Determine what nVersion a new block should use */
    int32_t ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    GBTStatus GetGBTStatus(const CBlockIndex& block_index, const Consensus::Params& params) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    std::vector<std::pair<int,bool>> CheckUnknownActivations(const CBlockIndex* pindex, const CChainParams& chainparams) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void Clear() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
};

#endif // BITCOIN_VERSIONBITS_H
