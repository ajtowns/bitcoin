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

constexpr NodeId STEMPOOL_FLOOD_NODEID{-1};

class TxStemPool
{
private:
    class Impl;
    const std::unique_ptr<Impl> m_impl;

public:
    explicit TxStemPool();
    ~TxStemPool();

    bool HaveTx(const uint256& txid, const uint256& wtxid, NodeId peer);
    void AddTx(CTransactionRef&& ptx, uint64_t spaminess, const std::vector<std::tuple<NodeClock::time_point, NodeId>>& outbounds);

    void DropWtx(const uint256& wtxid);
    void DropTx(const uint256& txid);

    std::tuple<NodeId, CTransactionRef> ExtractTrickleTx(NodeClock::time_point now);
    std::vector<CTransactionRef> ExtractFloodTxs(NodeClock::time_point now, size_t maxdmu);

    size_t size() const;
    size_t DynamicMemoryUsage() const;
};

#endif // BITCOIN_TXSTEMPOOL_H
