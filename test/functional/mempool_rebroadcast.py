#!/usr/bin/env python3
# Copyright (c) 2009-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test mempool rebroadcast logic.

la de da de rebroadcasts are so much fun!!
"""

from collections import defaultdict
from decimal import Decimal
from test_framework.mininode import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.messages import (
        msg_mempool,
        msg_getdata,
        CInv
)
from test_framework.util import (
        assert_equal,
        assert_greater_than,
        assert_greater_than_or_equal,
        wait_until,
        disconnect_nodes,
        connect_nodes,
        random_transaction,
        gen_return_txouts,
        create_confirmed_utxos,
        create_lots_of_big_transactions,
)
import pdb
import time
import random

"""
* populate mempool with transactions
* calculate min of max fee rate -> assert correct
* block comes in
* check that the correct transactions are rebroadcasted
"""

# Constant from net_processing
MAX_REBROADCAST_WEIGHT = 3000000

class P2PStoreTxInvs(P2PInterface):
    def __init__(self):
        super().__init__()
        self.tx_invs_received = defaultdict(int)

    def on_inv(self, message):
        # Store how many times invs have been received for each tx.
        for i in message.inv:
            if i.type == 1:
                # save txid
                self.tx_invs_received[i.hash] += 1

class MempoolRebroadcastTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [[
            "-acceptnonstdtxn=1"
            ]] * self.num_nodes

    def run_test(self):
        self.test_simple_rebroadcast()

        # self.test_rebroadcast_top_txns()

        #self.wip_test_rebroadcast_top_txns()


    def test_simple_rebroadcast(self):
        self.log.info("Testing rebroadcast works")

        node1 = self.nodes[0]
        node2 = self.nodes[1]

        # generate mempool transactions that both nodes know about
        for i in range(3):
            node1.sendtoaddress(node2.getnewaddress(), 4)

        self.sync_all()
        disconnect_nodes(node1, 1)

        # generate mempool transactions that only node1 knows about
        for i in range(3):
            node1.sendtoaddress(node2.getnewaddress(), 5)

        # check that mempools are different
        assert_equal(len(node1.getrawmempool()), 6)
        assert_equal(len(node2.getrawmempool()), 3)

        # reconnect the bitcoin nodes
        connect_nodes(node1, 1)
        time.sleep(1)
        start_time = int(time.time())
        delta_time = 60 * 60 # seconds
        node1.setmocktime(start_time + delta_time)
        node2.setmocktime(start_time + delta_time)
        self.log.info("Should be time to rebroadcast")
        time.sleep(1)

        # check that node2 got txns bc rebroadcasting
        # assert_equal(len(node2.getrawmempool()), 6)

        # bump by GETDATA interval
        node1.setmocktime(start_time + delta_time + 60)
        node2.setmocktime(start_time + delta_time + 60)
        self.log.info("Should be time to get tx")
        wait_until(lambda: len(node2.getrawmempool()) == 6)

    # def test_correct_invs(self):
        # add p2p connection to check invs
        # node1_conn = node1.add_p2p_connection(P2PStoreTxInvs())
        # node2_conn = node2.add_p2p_connection(P2PStoreTxInvs())

        # self.compare_txns_to_invs(node1.getrawmempool(), node1_conn.tx_invs_received)
        # self.compare_txns_to_invs(node2.getrawmempool(), node2_conn.tx_invs_received)

    # txn_hshs -> output from find_top_txns (list of hashes)
    # invs -> tx_invs_received
    def compare_txns_to_invs(self, txn_hshs, invs):
        # WHAT IS WRONG WITH ALL_INVS?
        all_invs = list(invs.keys())
        tx_ids = [int(txhsh, 16) for txhsh in txn_hshs]
        assert_equal(all_invs, tx_ids)

    def test_rebroadcast_top_txns(self):
        self.log.info("Testing that only txns with top fee rate get rebroadcast")

        node = self.nodes[0]

        node.add_p2p_connection(P2PStoreTxInvs())

        # create txns
        min_relay_fee = node.getnetworkinfo()["relayfee"]
        txouts = gen_return_txouts()
        utxo_count = 90
        utxos = create_confirmed_utxos(min_relay_fee, node, utxo_count)
        base_fee = min_relay_fee*100 # our transactions are smaller than 100kb
        txids = []

        # Create 3 batches of transactions at 3 different fee rate levels
        range_size = utxo_count // 3

        for i in range(3):
            txids.append([])
            start_range = i * range_size
            end_range = start_range + range_size
            txids[i] = create_lots_of_big_transactions(node, txouts, utxos[start_range:end_range], end_range - start_range, (i+1)*base_fee)

        # confirm the invs were sent (initial broadcast)
        # 90 transactions should be created
        wait_until(lambda: len(node.p2p.tx_invs_received) == 90)

        # confirm txns are more than max rebroadcast amount
        assert_greater_than(node.getmempoolinfo()['bytes'], MAX_REBROADCAST_WEIGHT)

        # add another p2p connection since txns aren't rebroadcast to the same peer (see filterInventoryKnown)
        second_conn = node.add_p2p_connection(P2PStoreTxInvs())

        # trigger rebroadcast to occur, but how??
        second_conn.sync_with_ping()
        time.sleep(60)
        print("invs after sleep: ", len(node.p2ps[1].tx_invs_received))

        # confirm that the correct txns were rebroadcast
        calculated_top_tx_hshs = self.find_top_txns(node.getrawmempool(True))
        print("num top txns identified: ", len(calculated_top_tx_hshs))

        # compare calculated top txs to invs received
        invs = node.p2ps[1].tx_invs_received

        all_invs = list(invs.keys())
        top_tx_ids = [int(txhsh, 16) for txhsh in calculated_top_tx_hshs]

        print("top_tx_ids: ", len(top_tx_ids))
        print("all_invs: ", len(all_invs))
        print("delta: ", len(set(top_tx_ids) - set(all_invs)))

    def find_top_txns(self, mempool_txs):
        txns_by_fee_rate = defaultdict(list)

        # iterate through mempool txs & populate dictionary
        # with feerate, size & tx hsh
        for tx_hsh in mempool_txs:
            tx = mempool_txs[tx_hsh]
            fee = tx['fees']['ancestor'] # in btc
            size = tx['ancestorsize'] # vsize
            fee_rate = fee / size
            txns_by_fee_rate[fee_rate].append([tx_hsh, size])

        # iterate through sorted list & extract top txns
        # not knapsack - stop when next txn doesn't fit
        top_tx_hshs = []
        weight_remaining = MAX_REBROADCAST_WEIGHT

        for fee_rate in sorted(txns_by_fee_rate, reverse=True):
            for vals in txns_by_fee_rate[fee_rate]:
                hsh = vals[0]
                size = vals[1]
                if weight_remaining > size:
                    top_tx_hshs.append(hsh)
                    weight_remaining -= size

        return top_tx_hshs

    def wip_test_rebroadcast_top_txns(self):
        self.log.info("Testing that all txns with top fee rate get rebroadcast")

        node1 = self.nodes[0]
        node2 = self.nodes[1]

        # populate the mempool with transactions
        # two methods - `random_transaction` & `create_lots_of_big_transactions`
        min_relay_fee = self.nodes[0].getnetworkinfo()["relayfee"]
        for i in range (10):
            (txid, txhex, fee) = random_transaction(self.nodes, Decimal(random.randrange(100)), min_relay_fee, Decimal(random.randrange(1)), 20)

        txouts = gen_return_txouts()
        utxo_count = 90
        utxos = create_confirmed_utxos(min_relay_fee, node1, utxo_count)
        base_fee = min_relay_fee*100 # our transactions are smaller than 100kb
        txids = []

        # Create 3 batches of transactions at 3 different fee rate levels
        range_size = utxo_count // 3

        for i in range(3):
            txids.append([])
            start_range = i * range_size
            end_range = start_range + range_size
            txids[i] = create_lots_of_big_transactions(node1, txouts, utxos[start_range:end_range], end_range - start_range, (i+1)*base_fee)

        self.sync_all()

        # check that the transactions have all been broadcast
        # assert_equal(len(node1.getrawmempool()), len(node2.getrawmempool()))

        # check that theres more in the mempool than the max rebroadcast definition
        assert_greater_than(node1.getmempoolinfo()['bytes'], MAX_REBROADCAST_WEIGHT)

        # Add a p2p connection
        node1.add_p2p_connection(P2PStoreTxInvs())

        # TODO: trigger rebroadcast conditions. But How?

        mempool = node1.getrawmempool(True)
        count = len(mempool)
        self.log.info("tx count: %s", count)

        top_tx_hshs = self.find_top_txns(mempool)

        time.sleep(60)

        # verify that these are the ones that get rebroadcasted
        invs = node1.p2p.tx_invs_received

        all_invs = list(invs.keys())
        top_tx_ids = [int(txhsh, 16) for txhsh in top_tx_hshs]
        delta = set(top_tx_ids) - set(all_invs)

        self.log.info("invs: %s", len(invs))
        self.log.info("all_invs: %s", len(all_invs))
        self.log.info("top txns: %s", len(top_tx_hshs))
        self.log.info("top tx_ids: %s", len(top_tx_ids))
        self.log.info("delta: %s", len(delta))

        # assert_equal(len(invs), len(top_tx_hshs))

# -----------------------------

        # question: when I inspect that txn using getrawmempool(true),
        # what does it mean that ancestorsize and descendantsize are 198?
        # oh, vsize is also 198, so maybe its just the package size in
        # different ways?

if __name__ == '__main__':
    MempoolRebroadcastTest().main()

