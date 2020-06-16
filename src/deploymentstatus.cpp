// Copyright (c) 2016-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/deployment.h>
#include <deploymentstatus.h>

#include <consensus/params.h>

using State = BIP8DeploymentStatus::State;
using StateHeight = BIP8DeploymentStatus::StateHeight;
using Stats = BIP8DeploymentStatus::Stats;
using Condition = BIP8DeploymentStatus::Condition;

static StateHeight GetStateHeightIncremental(const CBlockIndex* pindexPrev, StateHeight prev_state, const Consensus::BIP8DeploymentParams& dep, const Condition& condition)
{
    int height = (pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1);

    if (height % dep.period != 0) return prev_state;

    switch (prev_state.state) {
    case State::ACTIVE:
    case State::FAILED:
        // Final state
        return prev_state;

    case State::LOCKED_IN:
        // LOCKED_IN transitions to ACTIVE at next period boundary
        return {State::ACTIVE, height};

    case State::SIGNAL:
        // SIGNAL transitions to LOCKED_IN at next period boundary
        return {State::LOCKED_IN, height};

    case State::LAST_CHANCE:
        // Check for signalling in previous period
        {
            Stats stats = BIP8DeploymentStatus::GetStateStatisticsFor(pindexPrev, dep, condition);
            if (stats.count >= dep.period) {
                return {State::LOCKED_IN, height};
            } else {
                return {State::FAILED, height};
            }
        }

    case State::STARTED:
        // Check for signalling in previous period
        {
            Stats stats = BIP8DeploymentStatus::GetStateStatisticsFor(pindexPrev, dep, condition);
            if (stats.count >= dep.threshold) return {State::LOCKED_IN, height};
            // otherwise, transition based on height
        }
        break;

    case State::DEFINED:
        // Transition on height
        break;
    }

    if (height < dep.start_height) {
        return {State::DEFINED, 0};
    }

    const int periods = (height - dep.start_height) / dep.period - dep.signal_periods;
    State next;
    if (periods < 0) {
        next = State::STARTED;
    } else if (periods == 0) {
        next = (dep.guaranteed ? State::SIGNAL : State::LAST_CHANCE);
    } else { // periods > 0
        next = (dep.guaranteed ? State::ACTIVE : State::FAILED);
    }

    if (next != prev_state.state) return {next, height};
    return prev_state;
}

State BIP8DeploymentStatus::GetStateFor(const CBlockIndex* pindexPrev, const Consensus::BIP8DeploymentParams& dep, const Condition& condition)
{
    int height = (pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1);
    if (dep.guaranteed && (height > dep.start_height + dep.period * ((int)dep.signal_periods+2))) return State::ACTIVE;
    return GetStateHeightFor(pindexPrev, dep, condition).state;
}

StateHeight BIP8DeploymentStatus::GetStateHeightFor(const CBlockIndex* pindexPrev, const Consensus::BIP8DeploymentParams& dep, const Condition& condition)
{
    if (AlwaysDisabled(dep)) return {State::DEFINED, 0};

    if (dep.guaranteed && dep.signal_periods == 0 && dep.start_height % dep.period == 0) {
        int height = (pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1);
        if (height >= dep.start_height + 2*dep.period) {
            return {State::ACTIVE, dep.start_height + 2*dep.period};
        } else if (height >= dep.start_height + dep.period) {
            return {State::LOCKED_IN, dep.start_height + dep.period};
        } else if (height >= dep.start_height) {
            return {State::SIGNAL, dep.start_height};
        } else {
            return {State::DEFINED, 0};
        }
    }

    // A block's state is always the same as that of the first of its period, so it is computed based on a pindexPrev whose height equals a multiple of nPeriod - 1.
    if (pindexPrev != nullptr) {
        int height = pindexPrev->nHeight;
        height = height - ((height + 1) % dep.period);
        pindexPrev = pindexPrev->GetAncestor(height);
        assert(pindexPrev == nullptr || pindexPrev->nHeight % dep.period == dep.period - 1);
    }

    // walk backwards until a known state

    std::vector<const CBlockIndex*> to_compute;
    while (m_cache.count(pindexPrev) == 0) {
        if (pindexPrev == nullptr || pindexPrev->nHeight + 1 < dep.start_height) {
            m_cache.insert({pindexPrev, {State::DEFINED, 0}});
            break;
        }

        to_compute.push_back(pindexPrev);
        pindexPrev = pindexPrev->GetAncestor(pindexPrev->nHeight - dep.period);
    }

    // can pull from cache
    assert(m_cache.count(pindexPrev));
    StateHeight stateheight = m_cache.at(pindexPrev);

    // Now walk forward and compute the state of descendants of pindexPrev
    while (!to_compute.empty()) {
        pindexPrev = to_compute.back();
        to_compute.pop_back();

        stateheight = GetStateHeightIncremental(pindexPrev, stateheight, dep, condition);
        m_cache.insert({pindexPrev, stateheight});
    }

    return stateheight;
}

Stats BIP8DeploymentStatus::GetStateStatisticsFor(const CBlockIndex* pindex, const Consensus::BIP8DeploymentParams& dep, const Condition& condition)
{
    if (pindex == nullptr) return {0,0,false};

    Stats stats;

    // Find beginning of period
    int blocks_to_check = (pindex->nHeight % dep.period) + 1;
    stats.elapsed = blocks_to_check;

    // Count from current block to beginning of period
    int count = 0;
    const CBlockIndex* currentIndex = pindex;
    while (blocks_to_check > 0) {
        if (condition(currentIndex, dep)) count++;
        currentIndex = currentIndex->pprev;
        --blocks_to_check;
    }

    stats.count = count;
    stats.possible = (dep.period - dep.threshold) >= (stats.elapsed - count);

    return stats;
}

bool BIP8DeploymentStatus::AlwaysDisabled(const Consensus::BIP8DeploymentParams& dep)
{
    return !dep.guaranteed && dep.signal_periods == 0;
}

bool DeploymentStatus::Condition::operator()(const CBlockIndex* pindex, const Consensus::BIP8DeploymentParams& dep) const
{
    return ((pindex->nVersion & Consensus::VERSIONBITS_TOP_MASK) == Consensus::VERSIONBITS_TOP_BITS) && (pindex->nVersion & (1L << dep.bit)) != 0;
}

State DeploymentStatus::GetStateFor(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::BIP8Deployment pos)
{
    return m_mds[pos].GetStateFor(pindexPrev, params.vDeployments[pos], g_condition);
}

StateHeight DeploymentStatus::GetStateHeightFor(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::BIP8Deployment pos)
{
    return m_mds[pos].GetStateHeightFor(pindexPrev, params.vDeployments[pos], g_condition);
}

Stats DeploymentStatus::GetStateStatisticsFor(const CBlockIndex* pindex, const Consensus::Params& params, Consensus::BIP8Deployment pos)
{
    return BIP8DeploymentStatus::GetStateStatisticsFor(pindex, params.vDeployments[pos], g_condition);
}

uint32_t DeploymentStatus::Mask(const Consensus::Params& params, Consensus::BIP8Deployment pos)
{
     return 1L << params.vDeployments[pos].bit;
}

void DeploymentStatus::Clear()
{
    for (unsigned int d = 0; d < Consensus::MAX_BIP8_DEPLOYMENTS; d++) {
        m_mds[d].clear();
    }
}

int32_t DeploymentStatus::ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    int32_t nVersion = Consensus::VERSIONBITS_TOP_BITS;

    for (int i = 0; i < (int)Consensus::MAX_BIP8_DEPLOYMENTS; ++i) {
        const Consensus::BIP8Deployment pos = static_cast<Consensus::BIP8Deployment>(i);
        State state = GetStateFor(pindexPrev, params, pos);
        switch (state) {
        case State::STARTED:
        case State::SIGNAL:
        case State::LAST_CHANCE:
        case State::LOCKED_IN:
            nVersion |= Mask(params, pos);
            break;
        default:
            break;
        }
    }

    return nVersion;
}

bool DeploymentActiveAt(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::BIP8Deployment pos)
{
    return DeploymentActiveAfter(pindexPrev->pprev, params, pos);
}

bool DeploymentActiveAfter(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::BIP8Deployment pos)
{
    return State::ACTIVE == g_deploymentstatus.GetStateFor(pindexPrev, params, pos);
}

bool DeploymentDisabled(const Consensus::Params& params, Consensus::BIP8Deployment pos)
{
    return BIP8DeploymentStatus::AlwaysDisabled(params.vDeployments[pos]);
}

const DeploymentStatus::Condition DeploymentStatus::g_condition;
DeploymentStatus g_deploymentstatus;
