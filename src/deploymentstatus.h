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
    using Params = Consensus::BuriedDeployment;
    using State = bool;
    using Cache = std::true_type;

    const Params& m_params;

    BuriedDeploymentLogic(const Params& params) : m_params{params} { }

    int Bit() const { return -1; }
    bool ShouldSetVersionBit(State state) const { return false; }
    bool Enabled() const { return m_params.height != std::numeric_limits<int>::max(); }
    bool IsActive(bool state, const CBlockIndex* pindexPrev) const { return state; }
    State GetStateFor(const Cache& cache, const CBlockIndex* pindexPrev) const { return (pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1) >= m_params.height; }
    std::optional<int> ActivationHeight(Cache& cache, const CBlockIndex* pindexPrev) const { return m_params.height; }
};

/** BIP 9 allows multiple softforks to be deployed in parallel. We cache
 *  per-period state for every one of them. */
class VersionBitsCache
{
private:
    /** Caching for deployments */

    template<typename P>
    struct LogicType;

    template<> struct LogicType<Consensus::BIP9Deployment> { using T = BIP9DeploymentLogic; };
    template<> struct LogicType<Consensus::BIP341Deployment> { using T = BIP341DeploymentLogic; };
    template<> struct LogicType<Consensus::BuriedDeployment> { using T = BuriedDeploymentLogic; };

    template<typename T> struct DepCache_impl;
    template<size_t... I>
    struct DepCache_impl<std::index_sequence<I...>>
    {
        using T = std::tuple<typename LogicType<std::tuple_element_t<I, Consensus::DeploymentParams>>::T::Cache...>;
    };

    /** Tuple type for the parameters for each deployment */
    using DeploymentCache = DepCache_impl<std::make_index_sequence<std::tuple_size_v<Consensus::DeploymentParams>>>::T;

    Mutex m_mutex;
    mutable DeploymentCache m_cache GUARDED_BY(m_mutex);

    template<size_t pos>
    static auto GetLogic(const Consensus::Params& params)
    {
        return (typename LogicType<std::tuple_element_t<pos, Consensus::DeploymentParams>>::T){std::get<pos>(params.vDeployments)};
    }

    template<size_t I=0, typename Fn>
    static void ForEachDeployment_impl(DeploymentCache& caches, const Consensus::Params& params, Fn&& fn)
    {
        if constexpr (I < std::tuple_size_v<DeploymentCache>) {
            fn(static_cast<Consensus::DeploymentPos>(I), GetLogic<I>(params), std::get<I>(caches));
            ForEachDeployment_impl<I+1>(caches, params, fn);
        }
    }

    template<size_t I=0, typename Fn>
    static void ForEachDeployment_impl(const Consensus::Params& params, Fn&& fn)
    {
        if constexpr (I < std::tuple_size_v<DeploymentCache>) {
            fn(static_cast<Consensus::DeploymentPos>(I), GetLogic<I>(params));
            ForEachDeployment_impl<I+1>(params, fn);
        }
    }

public:
    /** Check if the deployment is enabled */
    template<auto dep>
    static bool IsEnabled(const Consensus::Params& params)
    {
        return GetLogic<dep>(params).Enabled();
    }

    /** Check if the deployment is active */
    template<auto dep>
    bool IsActive(const CBlockIndex* pindexPrev, const Consensus::Params& params) LOCKS_EXCLUDED(m_mutex)
    {
        const auto logic{GetLogic<dep>(params)};
        auto is_active = [&](auto& cache) {
            return logic.IsActive(logic.GetStateFor(cache, pindexPrev), pindexPrev);
        };
        if constexpr(std::is_same_v<typename decltype(logic)::Cache, std::true_type>) {
            // cache is a dummy, so avoid locking
            std::true_type dummy_cache{};
            return is_active(dummy_cache);
        } else {
            LOCK(m_mutex);
            return is_active(std::get<dep>(m_cache));
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
