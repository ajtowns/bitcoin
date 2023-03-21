// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_CHAINNAME_H
#define BITCOIN_KERNEL_CHAINNAME_H

#include <chainparamsbase.h>

#include <string>

namespace kernel {
namespace chainname {
static const std::string& MAIN = CBaseChainParams::MAIN;
static const std::string& TESTNET = CBaseChainParams::TESTNET;
static const std::string& SIGNET = CBaseChainParams::SIGNET;
static const std::string& REGTEST = CBaseChainParams::REGTEST;
} // namespace chainname
} // namespace kernel

#endif // BITCOIN_KERNEL_CHAINNAME_H
