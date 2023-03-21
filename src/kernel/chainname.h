// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_CHAINNAME_H
#define BITCOIN_KERNEL_CHAINNAME_H

#include <string>

namespace kernel {
namespace chainname {
static const std::string MAIN{"main"};
static const std::string TESTNET{"test"};
static const std::string SIGNET{"signet"};
static const std::string REGTEST{"regtest"};
} // namespace chainname
} // namespace kernel

#endif // BITCOIN_KERNEL_CHAINNAME_H
