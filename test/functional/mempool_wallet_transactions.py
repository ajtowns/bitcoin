#!/usr/bin/env python3
# Copyright (c) 2009-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Ensure that wallet transactions get successfully broadcast to at least one peer.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
        assert_greater_than,
        wait_until,
        create_confirmed_utxos,
        disconnect_nodes
)
from test_framework.mininode import P2PTxInvStore
import time

# Constant from txmempool.h
MAX_REBROADCAST_WEIGHT = 3000000

class MempoolWalletTransactionsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [[
            "-whitelist=127.0.0.1",
            "-blockmaxweight=3000000"
            ]] * self.num_nodes

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.log.info("test that mempool will ensure initial broadcast of wallet txns")

        node = self.nodes[0]
        min_relay_fee = node.getnetworkinfo()["relayfee"]

        self.log.info("create high fee rate transactions")

        node.settxfee(min_relay_fee * 3)
        utxos = create_confirmed_utxos(min_relay_fee, node, 2000)

        addresses = []
        for i in range(50):
            addresses.append(self.nodes[1].getnewaddress())

        # create large txns by sending to all the addresses
        outputs = {}
        for addr in addresses:
            outputs[addr] = 0.0001

        # create lots of txns with that large output
        for i in range(len(utxos) - 1):
            utxo = utxos.pop()
            inputs = [{'txid': utxo['txid'], 'vout': utxo['vout']}]
            raw_tx_hex = node.createrawtransaction(inputs, outputs)
            signed_tx = node.signrawtransactionwithwallet(raw_tx_hex)
            node.sendrawtransaction(hexstring=signed_tx['hex'], maxfeerate=0)

        # confirm txns are more than max rebroadcast amount
        assert_greater_than(node.getmempoolinfo()['bytes'], MAX_REBROADCAST_WEIGHT)
        node.add_p2p_connection(P2PTxInvStore())
        disconnect_nodes(node, 1)

        self.log.info("generate a wallet txn that won't be marked as broadcast")

        us0 = utxos.pop()
        inputs = [{ "txid" : us0["txid"], "vout" : us0["vout"]}]
        outputs = {node.getnewaddress() : 0.0001}
        tx = node.createrawtransaction(inputs, outputs)
        node.settxfee(min_relay_fee) # specifically fund this tx with low fee
        txF = node.fundrawtransaction(tx)
        txFS = node.signrawtransactionwithwallet(txF['hex'])
        wallettxid = node.sendrawtransaction(txFS['hex'])  # txhsh in hex

        # ensure the txn won't be rebroadcast due to top-of-mempool rule
        tx_hshs = []
        tmpl = node.getblocktemplate({'rules': ['segwit']})

        for tx in tmpl['transactions']:
            tx_hshs.append(tx['hash'])

        assert(wallettxid not in tx_hshs)

        # add p2p connection
        conn = node.add_p2p_connection(P2PTxInvStore())

        # bump mocktime of node1 so rebroadcast is triggered
        mocktime = int(time.time()) + 300 * 60 # hit rebroadcast interval
        node.setmocktime(mocktime)

        # verify the wallet txn inv was sent due to mempool tracking
        wallettxinv = int(wallettxid, 16)
        wait_until(lambda: wallettxinv in conn.get_invs())

if __name__ == '__main__':
    MempoolWalletTransactionsTest().main()

