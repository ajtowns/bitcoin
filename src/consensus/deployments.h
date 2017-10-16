// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_DEPLOYMENTS_H
#define BITCOIN_CONSENSUS_DEPLOYMENTS_H

#include <stdint.h>

namespace Consensus {

enum DeploymentPos
{
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_CSV, // Deployment of BIP68, BIP112, and BIP113.
    DEPLOYMENT_SEGWIT, // Deployment of BIP141, BIP143, and BIP147.
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in versionbits.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int Xbit;
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t XnStartTime;
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t XnTimeout;

    inline bool Defined() const {
        return XnTimeout > 0;
    }
};

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_DEPLOYMENTS_H
