#!/usr/bin/env python3
# Copyright (c) 2009-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test mempool rebroadcast logic.

"""

from test_framework.mininode import P2PTxInvStore
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
        assert_approx,
        assert_equal,
        assert_greater_than,
        wait_until,
        disconnect_nodes,
        connect_nodes,
        create_confirmed_utxos,
)
import time
from decimal import Decimal

# Constant from txmempool.h
MAX_REBROADCAST_WEIGHT = 3000000

# Constant from consensus.h
MAX_BLOCK_WEIGHT = 4000000

global_mocktime = 0

class MempoolRebroadcastTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [[
            "-acceptnonstdtxn=1",
            "-blockmaxweight=3000000",
            "-whitelist=127.0.0.1",
            "-txindex=1"
            ]] * self.num_nodes

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.test_simple_rebroadcast()
        self.test_recency_filter()
        self.test_fee_rate_cache()

    def compare_txns_to_invs(self, txn_hshs, invs):
        tx_ids = [int(txhsh, 16) for txhsh in txn_hshs]

        assert_equal(len(tx_ids), len(invs))
        assert_equal(tx_ids.sort(), invs.sort())

    def make_txn_at_fee_rate(self, input_utxo, outputs, outputs_sum, desired_fee_rate, change_address):
        self.timer(0)

        node = self.nodes[0]
        inputs = [{'txid': input_utxo['txid'], 'vout': input_utxo['vout']}]

        self.timer(1)

        # calculate how much input values add up to
        input_tx_hsh = input_utxo['txid']
        raw_tx = node.decoderawtransaction(node.getrawtransaction(input_tx_hsh))
        inputs_list = raw_tx['vout']
        if 'coinbase' in raw_tx['vin'][0].keys():
            return
        index = raw_tx['vin'][0]['vout']
        inputs_sum = inputs_list[index]['value']

        self.timer(2)

        # vsize is in bytes, cache fee rate is BTC / kB. Thus divide by 1000
        tx_vsize_with_change = 1660
        desired_fee_btc = desired_fee_rate * tx_vsize_with_change / 1000
        current_fee_btc = inputs_sum - Decimal(str(outputs_sum))

        # add another output with change
        outputs[change_address] = float(current_fee_btc - desired_fee_btc)
        outputs_sum += outputs[change_address]

        self.timer(3)

        # form txn & submit to mempool
        raw_tx_hex = node.createrawtransaction(inputs, outputs)
        signed_tx = node.signrawtransactionwithwallet(raw_tx_hex)
        tx_hsh = node.sendrawtransaction(hexstring=signed_tx['hex'], maxfeerate=0)
        self.timer(4)

        # retrieve mempool txn to calculate fee rate
        mempool_entry = node.getmempoolentry(tx_hsh)

        # check absolute fee matches up to expectations
        fee_calculated = inputs_sum - Decimal(str(outputs_sum))
        fee_got = mempool_entry['fee']
        assert_approx(float(fee_calculated), float(fee_got))

        # mempool_entry['fee'] is in BTC, fee rate should be BTC / kb
        fee_rate = mempool_entry['fee']*1000/mempool_entry['vsize']
        assert_approx(float(fee_rate), float(desired_fee_rate))

        self.timer('xxx')

        return tx_hsh

    _c_timer = None
    _c_start = None
    _c_cum = {}
    def timer(self, n):
        t = time.time()
        if self._c_timer is not None:
            self._c_cum[self._c_timer] = (t - self._c_start) + self._c_cum.get(self._c_timer,0)
        self._c_timer = n
        self._c_start = t

    def test_simple_rebroadcast(self):
        self.log.info("Test simplest rebroadcast case")

        node0 = self.nodes[0]
        node1 = self.nodes[1]

        # generate mempool transactions that both nodes know about
        for _ in range(3):
            node0.sendtoaddress(node1.getnewaddress(), 4)

        self.sync_all()

        # generate mempool transactions that only node0 knows about
        disconnect_nodes(node0, 1)

        for _ in range(3):
            node0.sendtoaddress(node1.getnewaddress(), 5)

        # check that mempools are different
        assert_equal(len(node0.getrawmempool()), 6)
        assert_equal(len(node1.getrawmempool()), 3)

        # reconnect the nodes
        connect_nodes(node0, 1)

        # rebroadcast will only occur if there has been a block since the
        # last run of CacheMinRebroadcastFee. when we connect a new peer, rebroadcast
        # will be skipped on the first run, but caching will trigger.
        # have node1 generate so there are still mempool txns that need to be synched.
        node1.generate(1)

        assert_equal(len(node1.getrawmempool()), 0)
        wait_until(lambda: len(node0.getrawmempool()) == 3)

        # bump time to hit rebroadcast interval
        mocktime = int(time.time()) + 300 * 60
        node0.setmocktime(mocktime)
        node1.setmocktime(mocktime)

        # check that node1 got txns bc rebroadcasting
        wait_until(lambda: len(node1.getrawmempool()) == 3, timeout=30)

        global global_mocktime
        global_mocktime = mocktime

    def test_recency_filter(self):
        self.log.info("Test recent txns don't get rebroadcast")

        node = self.nodes[0]
        node1 = self.nodes[1]

        global global_mocktime
        mocktime = global_mocktime

        node.setmocktime(global_mocktime)
        node1.setmocktime(global_mocktime)

        # mine blocks to clear out the mempool
        node.generate(4)
        assert_equal(len(node.getrawmempool()), 0)

        # add p2p connection
        conn = node.add_p2p_connection(P2PTxInvStore())

        # create old txn
        node.sendtoaddress(node.getnewaddress(), 2)
        assert_equal(len(node.getrawmempool()), 1)
        wait_until(lambda: conn.get_invs(), timeout=30)

        # bump mocktime to ensure the txn is old
        mocktime += 31 * 60 # seconds
        node.setmocktime(mocktime)

        delta_time = 28 * 60 # seconds
        while True:
            # create a recent transaction
            new_tx = node1.sendtoaddress(node1.getnewaddress(), 2)
            new_tx_id = int(new_tx, 16)

            # ensure node0 has the transaction
            wait_until(lambda: new_tx in node.getrawmempool())

            # add another p2p connection since txns aren't rebroadcast
            # to the same peer (see filterInventoryKnown)
            new_conn = node.add_p2p_connection(P2PTxInvStore())
            self.log.info("Added another p2p connection, whee!")

            # bump mocktime to try to get rebroadcast,
            # but not so much that the txn would be old
            mocktime += delta_time
            node.setmocktime(mocktime)

            time.sleep(1.1)

            # once we get any rebroadcasts, ensure the most recent txn is not included
            if new_conn.get_invs():
                assert(new_tx_id not in new_conn.get_invs())
                break

        global_mocktime = mocktime
        node.disconnect_p2ps()

    def test_fee_rate_cache(self):
        self.log.info("test min fee rate cache limits rebroadcast set")
        node = self.nodes[0]
        mocktime = global_mocktime
        node.setmocktime(mocktime)
        self.nodes[1].setmocktime(mocktime)

        min_relay_fee = node.getnetworkinfo()["relayfee"]

        print(node.getpeerinfo())

        self.log.info("ABCD create confirmed utxos now")
        utxos = create_confirmed_utxos(min_relay_fee, node, 3000)

        self.log.info("ABCD get new addresses")
        addresses = []
        for i in range(50):
            addresses.append(node.getnewaddress())

        # create large txns by sending to all the addresses
        outputs = { addr: 0.0001 for addr in addresses }
        change_address = node.getnewaddress()
        outputs_sum = 0.0001 * 50

        # --------------------------

        initial_tx_hshs = []
        cache_fee_rate = min_relay_fee * 3
        node.settxfee(cache_fee_rate) # unsure if these are necessary / relevant at all

        self.log.info("node 0 has %d peers", len(node.getpeerinfo()))
        self.log.info("expected num of nodes: %d", len(self.nodes))
        self.log.info("ABCD fill mempool with txns with fee at cache_fee_rate: %s", cache_fee_rate)

        self.sync_mempools()
        start_time = time.time()
        # create lots of txns with that large output
        for i in range(len(utxos) - 500):
            self.timer('zzz')
            tx_hsh = self.make_txn_at_fee_rate(utxos.pop(), outputs, outputs_sum, cache_fee_rate, change_address)
            self.timer('yyy')
            if tx_hsh is None:
                continue

            initial_tx_hshs.append(tx_hsh)
            if i%250 == 0:
                print("%d " % i)
                print("timers:", self._c_cum)
                self.timer('www')
                self.sync_mempools()
                self.timer('vvv')


        print("making the txns took %r" % (time.time()-start_time))
        self.sync_mempools()
        assert_greater_than(node.getmempoolinfo()['bytes'], MAX_BLOCK_WEIGHT)

        self.log.info("ABCD trigger cache job to run")
        # this is needed to hit the send messages loop? huh??
        node.add_p2p_connection(P2PTxInvStore())

        time.sleep(1)

        node.getnewaddress()

        self.log.info("ABCD cache job should have run by now")

        # make a block. it will leave behind some txns > fee rate R
        self.log.info("ABCD make a block")
        node.generate(1)

        # make 10 high fee rate txns
        high_fee_rate_tx_hshs = []
        high_fee_rate = min_relay_fee * 4
        node.settxfee(high_fee_rate)

        self.log.info("ABCD make high fee rate txns at: %s", high_fee_rate)

        for i in range(10):
            tx_hsh = self.make_txn_at_fee_rate(utxos.pop(), outputs, outputs_sum, high_fee_rate, change_address)

            # unsure if this is necessary here
            if tx_hsh is None:
                continue

            high_fee_rate_tx_hshs.append(tx_hsh)

        # self.sync_mempools()

        # --------------

        # make 10 low fee rate txns
        low_fee_rate_tx_hshs = []
        low_fee_rate = min_relay_fee * 2
        node.settxfee(low_fee_rate)

        self.log.info("ABCD make low fee rate txns at: %s", low_fee_rate)

        for i in range(10):
            tx_hsh = self.make_txn_at_fee_rate(utxos.pop(), outputs, outputs_sum, low_fee_rate, change_address)

            # unsure if this is necessary here
            if tx_hsh is None:
                continue

            low_fee_rate_tx_hshs.append(tx_hsh)

        # ensure removed from unbroadcast set
        # aka that all the GETDATAs have been received before its time to rebroadcast
        self.sync_mempools()

        # -----------------

        # trigger rebroadcast by bumping mocktime
        # also need to bump mocktime so txns aren't filtered bc recency
        self.log.info("ABCD bump time, trigger rebroadcast")
        conn = node.add_p2p_connection(P2PTxInvStore())

        time.sleep(1)

        # mocktime = int(time.time())
        mocktime += 300 * 60
        node.setmocktime(mocktime)

        time.sleep(1) # ensure send message thread runs so invs get sent

        mocktime += 60
        node.setmocktime(mocktime)

        # `nNextInvSend` delay on `setInventoryTxToSend
        wait_until(lambda: conn.get_invs(), timeout=30)

        # confirm that txns made below fee rate aren't rebroadcast
        # confirm that < 3M weight of txns are rebroadcast
        rebroadcasted_invs = conn.get_invs()

        self.log.info("ABCD from tests, {} transactions have been rebroadcast".format(len(rebroadcasted_invs)))

        # check that top fee rate txns are rebroadcast
        # check that low fee rate txns are not rebroadcast
        high_fee_rate_tx_ids = [int(txhsh, 16) for txhsh in high_fee_rate_tx_hshs]
        low_fee_rate_tx_ids = [int(txhsh, 16) for txhsh in low_fee_rate_tx_hshs]

        self.log.info("ABCD test high fee rate txns")
        self.log.info("ABCD from tests, {} transactions have been rebroadcast".format(len(rebroadcasted_invs)))

        for high_tx_id in high_fee_rate_tx_ids:
            assert(high_tx_id in rebroadcasted_invs)

        self.log.info("ABCD test low fee rate txns")
        for low_tx_id in low_fee_rate_tx_ids:
            assert(low_tx_id not in rebroadcasted_invs)

if __name__ == '__main__':
    MempoolRebroadcastTest().main()

