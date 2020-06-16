// Copyright (c) 2016-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/deployment.h>
#include <deploymentstatus.h>

#include <consensus/params.h>

using State = SignalledDeploymentStatus::State;
using StateHeight = SignalledDeploymentStatus::StateHeight;
using Stats = SignalledDeploymentStatus::Stats;
using Condition = SignalledDeploymentStatus::Condition;

static StateHeight GetStateHeightIncremental(const CBlockIndex* pindexPrev, StateHeight prev_state, const Consensus::SignalledDeploymentParams& dep, const Condition& condition)
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

    case State::PRIMARY:
    case State::SECONDARY:
        // Check for signalling in previous period
        {
            Stats stats = SignalledDeploymentStatus::GetStateStatisticsFor(pindexPrev, dep, condition);
            if (stats.count >= dep.threshold) return {State::LOCKED_IN, height};
            // otherwise, transition based on height
        }
        break;

    case State::QUIET:
    case State::DEFINED:
        // Remaining cases only transition on height
        break;
    }

    if (height < dep.start_height) {
        return {State::DEFINED, 0};
    }

    const int periods = (height - dep.start_height) / dep.period;
    State next;
    if (periods < dep.primary_periods) {
        next = State::PRIMARY;
    } else if (!dep.guaranteed) {
        next = State::FAILED;
    } else if (periods < dep.primary_periods + dep.quiet_periods) {
        next = State::QUIET;
    } else if (periods < dep.primary_periods + dep.quiet_periods + dep.secondary_periods) {
        next = State::SECONDARY;
    } else {
        next = State::LOCKED_IN;
    }

    if (next != prev_state.state) return {next, height};
    return prev_state;
}

State SignalledDeploymentStatus::GetStateFor(const CBlockIndex* pindexPrev, const Consensus::SignalledDeploymentParams& dep, const Condition& condition)
{
    return GetStateHeightFor(pindexPrev, dep, condition).state;
}

StateHeight SignalledDeploymentStatus::GetStateHeightFor(const CBlockIndex* pindexPrev, const Consensus::SignalledDeploymentParams& dep, const Condition& condition)
{
    if (dep.guaranteed && dep.primary_periods == 0 && dep.secondary_periods == 0 && dep.quiet_periods == 0 && dep.start_height % dep.period == 0) {
        int height = (pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1);
        if (height >= dep.start_height + dep.period) {
            return {State::ACTIVE, dep.start_height + dep.period};
        } else if (height >= dep.start_height) {
            return {State::LOCKED_IN, dep.start_height};
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

Stats SignalledDeploymentStatus::GetStateStatisticsFor(const CBlockIndex* pindex, const Consensus::SignalledDeploymentParams& dep, const Condition& condition)
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

bool SignalledDeploymentStatus::AlwaysDisabled(const Consensus::SignalledDeploymentParams& dep)
{
    return !dep.guaranteed && dep.primary_periods == 0;
}

bool DeploymentStatus::Condition::operator()(const CBlockIndex* pindex, const Consensus::SignalledDeploymentParams& dep) const
{
    return ((pindex->nVersion & Consensus::VERSIONBITS_TOP_MASK) == Consensus::VERSIONBITS_TOP_BITS) && (pindex->nVersion & (1L << dep.bit)) != 0;
}

State DeploymentStatus::GetStateFor(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::SignalledDeployment pos)
{
    return m_mds[pos].GetStateFor(pindexPrev, params.vDeployments[pos], g_condition);
}

StateHeight DeploymentStatus::GetStateHeightFor(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::SignalledDeployment pos)
{
    return m_mds[pos].GetStateHeightFor(pindexPrev, params.vDeployments[pos], g_condition);
}

Stats DeploymentStatus::GetStateStatisticsFor(const CBlockIndex* pindex, const Consensus::Params& params, Consensus::SignalledDeployment pos)
{
    return SignalledDeploymentStatus::GetStateStatisticsFor(pindex, params.vDeployments[pos], g_condition);
}

uint32_t DeploymentStatus::Mask(const Consensus::Params& params, Consensus::SignalledDeployment pos)
{
     return 1L << params.vDeployments[pos].bit;
}

void DeploymentStatus::Clear()
{
    for (unsigned int d = 0; d < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; d++) {
        m_mds[d].clear();
    }
}

int32_t DeploymentStatus::ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    int32_t nVersion = Consensus::VERSIONBITS_TOP_BITS;

    for (int i = 0; i < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++i) {
        const Consensus::SignalledDeployment pos = static_cast<Consensus::SignalledDeployment>(i);
        State state = GetStateFor(pindexPrev, params, pos);
        switch (state) {
        case State::PRIMARY:
        case State::QUIET:
        case State::SECONDARY:
        case State::LOCKED_IN:
            nVersion |= Mask(params, pos);
            break;
        default:
            break;
        }
    }

    return nVersion;
}

bool DeploymentActiveAt(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::SignalledDeployment pos)
{
    return DeploymentActiveAfter(pindexPrev->pprev, params, pos);
}

bool DeploymentActiveAfter(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::SignalledDeployment pos)
{
    return State::ACTIVE == g_deploymentstatus.GetStateFor(pindexPrev, params, pos);
}

bool DeploymentDisabled(const Consensus::Params& params, Consensus::SignalledDeployment pos)
{
    return SignalledDeploymentStatus::AlwaysDisabled(params.vDeployments[pos]);
}

const DeploymentStatus::Condition DeploymentStatus::g_condition;
DeploymentStatus g_deploymentstatus;
