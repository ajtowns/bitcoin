// Copyright (c) 2016-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/deployment.h>

#include <consensus/params.h>

namespace Consensus {

const struct BIP8DeploymentInfo DeploymentInfo[Consensus::MAX_BIP8_DEPLOYMENTS] = {
    {
        /*.name =*/ "testdummy",
        /*.gbt_force =*/ true,
    },
};


static_assert((((1L<<VERSIONBITS_NUM_BITS) - 1) & VERSIONBITS_IGNORE_BITS) == 0, "Overlap between VERSIONBITS_NUM_BITS and VERSIONBITS_IGNORE_BITS");
static_assert((VERSIONBITS_TOP_MASK & VERSIONBITS_IGNORE_BITS) == 0, "Overlap between VERSIONBITS_TOP_MASK and VERSIONBITS_IGNORE_BITS");
static_assert((VERSIONBITS_TOP_MASK & VERSIONBITS_TOP_BITS) == VERSIONBITS_TOP_BITS, "VERSIONBITS_TOP_BITS not a subset of VERSIONBITS_TOP_MASK");

} // Consensus namespace
