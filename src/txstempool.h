// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXSTEMPOOL_H
#define BITCOIN_TXSTEMPOOL_H

#include <primitives/transaction.h>
#include <net.h> // For NodeId
#include <uint256.h>
#include <util/time.h>

#include <memory>

class TxStemPool
{
private:
    class Impl;
    std::unique_ptr<Impl> m_impl;

public:
    explicit TxStemPool();
    ~TxStemPool();

    void Limit(size_t max_size);
};

#endif // BITCOIN_TXSTEMPOOL_H
