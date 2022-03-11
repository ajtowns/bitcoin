// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHAINPARAMS_H
#define BITCOIN_CHAINPARAMS_H

#include <kernel/chainparams.h>

#include <chainparamsbase.h>
#include <consensus/params.h>
#include <cstdint>
#include <netaddress.h>
#include <primitives/block.h>
#include <protocol.h>
#include <unordered_map>
#include <util/hash_type.h>

#include <memory>
#include <string>
#include <vector>

/**
 * Creates and returns a std::unique_ptr<CChainParams> for signet.
 * @returns std::unique_ptr<const CChainParams>.
 * @throws a std::runtime_error if multiple signet challenges are passed in through the args.
 */
std::unique_ptr<const CChainParams> CreateSignetChainParams(const ArgsManager& args);

/**
 * Creates and returns a std::unique_ptr<CChainParams> for regtest.
 * @return std::unique_ptr<const CChainParams>
 * @throws a std::runtime_error if the -testactivationheight or -vbparams is set, but malformed.
 */
std::unique_ptr<const CChainParams> CreateRegTestChainParams(const ArgsManager& args);

/**
 * Creates and returns a std::unique_ptr<CChainParams> of the chosen chain.
 * @returns a CChainParams* of the chosen chain.
 * @throws a std::runtime_error if the chain is not supported.
 */
std::unique_ptr<const CChainParams> CreateChainParams(const ArgsManager& args, const std::string& chain);

/**
 * Return the currently selected parameters. This won't change after app
 * startup, except for unit tests.
 */
const CChainParams &Params();

/**
 * Sets the params returned by Params() to those for the given chain name.
 * @throws std::runtime_error when the chain is not supported.
 */
void SelectParams(const std::string& chain);

#endif // BITCOIN_CHAINPARAMS_H
