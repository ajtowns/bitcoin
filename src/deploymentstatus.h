// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DEPLOYMENTSTATUS_H
#define BITCOIN_DEPLOYMENTSTATUS_H

#include <chain.h>
#include <versionbits.h>

#include <limits>

/** Logic for height based deployments */

class BuriedDeploymentLogic
{
public:
    using Params = int;

    const int m_height;
    using State = bool;
    using Cache = std::true_type;

    static void ClearCache(const Cache& cache) { }

    BuriedDeploymentLogic(int height) : m_height{height} { }

    uint32_t Mask() const { return 0; }
    std::optional<int> VersionBitToSet(State state, const CBlockIndex* pindexPrev) const { return std::nullopt; }
    bool Enabled() const { return m_height != std::numeric_limits<int>::max(); }
    bool IsActive(bool state, const CBlockIndex* pindexPrev) const { return state; }
    State GetStateFor(const Cache& cache, const CBlockIndex* pindexPrev) const { return (pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1) >= m_height; }
    std::optional<int> ActivationHeight(Cache& cache, const CBlockIndex* pindexPrev) const { return m_height; }
};

/** Caching for deployments */

template<typename P>
struct LogicType { using Type = void; };

template<>
struct LogicType<Consensus::BIP9Deployment> { using Type = ConditionLogic; };

template<>
struct LogicType<int> { using Type = BuriedDeploymentLogic; };

template<typename P>
static typename LogicType<P>::Type xGetLogic(const P& params) { return typename LogicType<P>::Type{params}; }

/** BIP 9 allows multiple softforks to be deployed in parallel. We cache
 *  per-period state for every one of them. */
class VersionBitsCache
{
private:
    Mutex m_mutex;
    using cache_array = std::array<ConditionLogic::Cache,Consensus::MAX_VERSION_BITS_DEPLOYMENTS>;
    mutable cache_array m_cache GUARDED_BY(m_mutex);
    BuriedDeploymentLogic::Cache dummy_cache GUARDED_BY(m_mutex){};

    template<size_t I=0, typename Fn>
    static void ForEachDeployment_impl(cache_array& caches, const Consensus::Params& params, Fn&& fn)
    {
        if constexpr (I < std::tuple_size_v<cache_array>) {
            constexpr Consensus::DeploymentPos POS = static_cast<Consensus::DeploymentPos>(I);
            static_assert(Consensus::ValidDeployment(POS), "invalid deployment");
            fn(POS, zGetLogic<POS>(params), std::get<I>(caches));

            ForEachDeployment_impl<I+1>(caches, params, fn);
        }
    }

    template<size_t I=0, typename Fn>
    static void ForEachDeployment_impl(const Consensus::Params& params, Fn&& fn)
    {
        if constexpr (I < std::tuple_size_v<cache_array>) {
            constexpr Consensus::DeploymentPos POS = static_cast<Consensus::DeploymentPos>(I);
            static_assert(Consensus::ValidDeployment(POS), "invalid deployment");

            fn(POS, zGetLogic<POS>(params));

            ForEachDeployment_impl<I+1>(params, fn);
        }
    }

    template<Consensus::BuriedDeployment POS=Consensus::DEPLOYMENT_HEIGHTINCB, typename Fn>
    static void ForEachBuriedDeployment(const Consensus::Params& params, Fn&& fn)
    {
        if constexpr (ValidDeployment(POS)) {
            const auto logic = zGetLogic<POS>(params);
            BuriedDeploymentLogic::Cache cache; // dummy
            fn(POS, logic, cache);

            ForEachBuriedDeployment<static_cast<Consensus::BuriedDeployment>(POS+1)>(params, fn);
        }
    }

    template<Consensus::BuriedDeployment pos>
    static BuriedDeploymentLogic zGetLogic(const Consensus::Params& params)
    {
        return xGetLogic(params.DeploymentHeight(pos));
    }

    template<Consensus::DeploymentPos pos>
    static ConditionLogic zGetLogic(const Consensus::Params& params)
    {
        return xGetLogic(std::get<pos>(params.vDeployments));
    }

    template<Consensus::DeploymentPos pos>
    ConditionLogic::Cache& GetCache(const Consensus::Params& params) EXCLUSIVE_LOCKS_REQUIRED(m_mutex)
    {
        return std::get<pos>(m_cache);
    }

    template<Consensus::BuriedDeployment pos>
    BuriedDeploymentLogic::Cache& GetCache(const Consensus::Params& params)
    {
        return dummy_cache;
    }

public:
    /** Check if the deployment is enabled */
    template<auto dep>
    static bool IsEnabled(const Consensus::Params& params)
    {
        return zGetLogic<dep>(params).Enabled();
    }

    /** Check if the deployment is active */
    template<auto dep>
    bool IsActive(const CBlockIndex* pindexPrev, const Consensus::Params& params) LOCKS_EXCLUDED(m_mutex)
    {
        const auto logic{zGetLogic<dep>(params)};
        if constexpr(std::is_same_v<decltype(GetCache<dep>(params)), std::true_type>) {
            std::true_type dummy_cache{};
            return logic.IsActive(dummy_cache, pindexPrev);
        } else {
            LOCK(m_mutex);
            return logic.IsActive(GetCache<dep>(params), pindexPrev);
        }
    }

    /** Determine what nVersion a new block should use */
    int32_t ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params);

    /** Iterate over all deployments, and do something
     * Fn should be [](auto pos, const auto& logic, auto& cache) { ... }
     */
    template<typename Fn>
    void ForEachDeployment(const Consensus::Params& params, Fn&& fn)
    {
        LOCK(m_mutex);
        ForEachBuriedDeployment(params, fn);
        ForEachDeployment_impl(m_cache, params, fn);
    }

    /** Iterate over all deployments, and do something
     * Fn should be [](auto pos, const auto& logic, auto& cache) { ... }
     */
    template<typename Fn>
    static void ForEachDeployment_nocache(const Consensus::Params& params, Fn&& fn)
    {
        ForEachDeployment_impl(params, fn);
    }

    /** Clear the cache */
    void Clear();
};

#endif // BITCOIN_DEPLOYMENTSTATUS_H
