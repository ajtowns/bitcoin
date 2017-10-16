// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_VERSIONBITS
#define BITCOIN_CONSENSUS_VERSIONBITS

#include "chain.h"
#include "chainparams.h"
#include <map>

/** What block version to use for new blocks (pre versionbits) */
static const int32_t VERSIONBITS_LAST_OLD_BLOCK_VERSION = 4;
/** What bits to set in version for versionbits blocks */
static const int32_t VERSIONBITS_TOP_BITS = 0x20000000UL;
/** What bitmask determines whether versionbits is in use */
static const int32_t VERSIONBITS_TOP_MASK = 0xE0000000UL;
/** Total bits available for versionbits */
static const int32_t VERSIONBITS_NUM_BITS = 29;

enum ThresholdState {
    THRESHOLD_DEFINED,
    THRESHOLD_STARTED,
    THRESHOLD_LOCKED_IN,
    THRESHOLD_ACTIVE,
    THRESHOLD_FAILED,
};

// A map that gives the state for blocks whose height is a multiple of Period().
// The map is indexed by the block's parent, however, so all keys in the map
// will either be nullptr or a block with (height + 1) % Period() == 0.
typedef std::map<const CBlockIndex*, ThresholdState> ThresholdConditionCache;

struct VBDeploymentInfo {
    /** Deployment name */
    const char *name;
    /** Whether GBT clients can safely ignore this rule in simplified usage */
    bool gbt_force;
};

struct BIP9Stats {
    int period;
    int threshold;
    int elapsed;
    int count;
    bool possible;
};

extern const struct VBDeploymentInfo VersionBitsDeploymentInfo[];

/**
 * Abstract class that implements BIP9-style threshold logic, and caches results.
 */
class AbstractThresholdConditionChecker {
protected:
    virtual bool Condition(const CBlockIndex* pindex, const Consensus::Params& params) const =0;
    virtual int64_t BeginTime(const Consensus::Params& params) const =0;
    virtual int64_t EndTime(const Consensus::Params& params) const =0;
    virtual int Period(const Consensus::Params& params) const =0;
    virtual int Threshold(const Consensus::Params& params) const =0;

public:
    BIP9Stats GetStateStatisticsFor(const CBlockIndex* pindex, const Consensus::Params& params) const;
    // Note that the functions below take a pindexPrev as input: they compute information for block B based on its parent.
    ThresholdState GetStateFor(const CBlockIndex* pindexPrev, const Consensus::Params& params, ThresholdConditionCache& cache) const;
    int GetStateSinceHeightFor(const CBlockIndex* pindexPrev, const Consensus::Params& params, ThresholdConditionCache& cache) const;
};


/** Get the BIP9 state for a given deployment at the current tip.
 * LOCKs cs_main */
ThresholdState VersionBitsTipState(const Consensus::Params& params, Consensus::DeploymentPos pos);

/** Get the numerical statistics for the BIP9 state for a given deployment at the current tip.
 * LOCKs cs_main */
BIP9Stats VersionBitsTipStatistics(const Consensus::Params& params, Consensus::DeploymentPos pos);

/** Get the block height at which the BIP9 deployment switched into the state for the block building on the current tip.
 * LOCKs cs_main */
int VersionBitsTipStateSinceHeight(const Consensus::Params& params, Consensus::DeploymentPos pos);


/** Get the BIP9 state for a given deployment at the given block.
 * Expects cs_main to be already locked */
ThresholdState VersionBitsState(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos pos);
uint32_t VersionBitsMask(const Consensus::Params& params, Consensus::DeploymentPos pos);

/** Clear Caches used for calculating BIP9 states
 * Expects cs_main to be already locked */
void VersionBitsCachesClear();


inline bool Consensus::Params::DeploymentActive(Consensus::DeploymentPos pos, const CBlockIndex* pindex) const { assert(pindex != nullptr); return DeploymentActivePrev(pos, pindex->pprev); }

inline bool Consensus::Params::DeploymentActivePrev(Consensus::DeploymentPos pos, const CBlockIndex* pindexPrev) const
{
    // AssertLockHeld(cs_main);

    const int nHeight = (pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1);

    switch (pos) {
    case DEPLOYMENT_COINBASEHEIGHT:
        return nHeight >= BIP34Height;
    case DEPLOYMENT_CLTV:
        return nHeight >= BIP65Height;
    case DEPLOYMENT_STRICTDER:
        return nHeight >= BIP66Height;
    case DEPLOYMENT_BIP30FAST:
        if (pindexPrev != nullptr) {
            const CBlockIndex *pindexBIP34height = pindexPrev->GetAncestor(BIP34Height);
            if (pindexBIP34height != nullptr && pindexBIP34height->GetBlockHash() == BIP34Hash) {
                return true;
            }
        }
        return false;
    default:
         assert(pos < MAX_VERSION_BITS_DEPLOYMENTS);
         return VersionBitsState(pindexPrev, *this, pos) == THRESHOLD_ACTIVE;
    }
    assert(0);
}

#endif
