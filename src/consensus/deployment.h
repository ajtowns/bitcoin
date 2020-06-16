// Copyright (c) 2016-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VERSIONBITSINFO_H
#define BITCOIN_VERSIONBITSINFO_H

#include <consensus/params.h>

namespace Consensus {

/** Minimum block version to use for new blocks (pre BIP 9) */
static const int32_t VERSIONBITS_LAST_OLD_BLOCK_VERSION = 4;
/** What bits to set in version for signalling blocks */
static const int32_t VERSIONBITS_TOP_BITS = 0x20000000UL;
/** What bitmask determines whether signalling is in use */
static const int32_t VERSIONBITS_TOP_MASK = 0xE0000000UL;
/** What bitmask is ignorable */
static const int32_t VERSIONBITS_IGNORE_BITS = 0x1FFFE000;
/** Total bits available for signalling */
static const uint8_t VERSIONBITS_NUM_BITS = 13;

/** Helper functions for initialising SignalledDeploymentParams struct */

/** Initialise arbitrary SignalledDeploymentParams, checking parameters are reasonable */
template<uint8_t bit, int start_height, uint16_t signal_periods, uint16_t quiet_periods, uint16_t secondary_periods, uint16_t period, uint16_t threshold>
inline constexpr SignalledDeploymentParams Deployment(bool guaranteed) {
    static_assert(0 <= bit && bit < VERSIONBITS_NUM_BITS, "Invalid version bit");
    static_assert(0 < period && period <= 52416, "Period out of range");
    static_assert(period < 2*(int)threshold && threshold <= period, "Threshold out of range");
    static_assert(start_height >= 0 || start_height + period == 0, "Deployment start_height cannot be negative unless using DeploymentAlwaysActive");
    static_assert(start_height % period == 0, "Deployment start_height must be divisible by period");

    return SignalledDeploymentParams{start_height, signal_periods, quiet_periods, secondary_periods, period, threshold, bit, guaranteed};
}

/** Initialise a Deployment as disabled */
template<int bit>
inline constexpr SignalledDeploymentParams DeploymentDisabled() {
    return Deployment<bit,std::numeric_limits<int>::max(),0,0,0,1,1>(false);
}

/** Initialise a Deployment as buried */
template<int bit,int height>
inline constexpr SignalledDeploymentParams DeploymentBuried() {
    return Deployment<bit,height-1,0,0,0,1,1>(true);
}

/** Initialise a Deployment as always ative */
template<int bit>
inline constexpr SignalledDeploymentParams DeploymentAlwaysActive() {
    return Deployment<bit,-1,0,0,0,1,1>(true);
}

/** Initialise a Deployment as able to be activated at any time */
template<int bit, uint16_t period=2016, uint16_t threshold=1916>
inline constexpr SignalledDeploymentParams DeploymentAlwaysSignal() {
    // actually DEFINED for a period, then signal
    return Deployment<bit,period,std::numeric_limits<uint16_t>::max(),0,0,period,threshold>(false);
}

/** Information about signalled Deployments that isn't chain specific */
struct SignalledDeploymentInfo {
    /** Deployment name */
    const char *name;
    /** Whether GBT clients can safely ignore this rule in simplified usage */
    bool gbt_force;
};

extern const struct SignalledDeploymentInfo DeploymentInfo[];

} // Consensus namespace

#endif // BITCOIN_VERSIONBITSINFO_H
