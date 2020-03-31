#!/usr/bin/env python3
# Copyright (c) 2017-2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that we don't leak txs to inbound peers that we haven't yet announced to"""

import time
from test_framework.messages import msg_notfound, msg_inv, CInv
from test_framework.mininode import P2PDataStore
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)


class P2PNode(P2PDataStore):
    def on_inv(self, msg):
        pass

    def on_getdata(self, msg):
        t = time.time()
        self.notfound_queue.extend(msg.inv)
        for inv in msg.inv:
            self.getdata[inv] = t
        while len(self.notfound_queue) >= 100:
            self.send_message(msg_notfound(vec=self.notfound_queue[:100]))
            self.notfound_queue = self.notfound_queue[100:]

    def summary(self):
        return len(self.getdata), len(self.notfound_queue)

class P2PNotFoundPerf(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        PEERS = 11
        TRANSACTIONS = 99000

        gen_node = self.nodes[0]  # The block and tx generating node
        gen_node.generate(1)

        inbound_peers = [ self.nodes[0].add_p2p_connection(P2PNode()) for _ in range(PEERS) ]
        for inbound in inbound_peers:
            inbound.getdata = {}
            inbound.notfound_queue = []

        for txbatch in range(TRANSACTIONS//100):
            self.log.info("Doing batch %d" % (txbatch+1))
            ann = [CInv(t=1, h=(txbatch*1000+i)) for i in range(100)]
            for inbound in inbound_peers:
                inbound.send_message(msg_inv(inv=ann))

        #gen_node.logging(exclude=['net'])


        for i in range(60):
            self.log.info("State: " + " ".join("%d:%d" % inbound.summary() for inbound in inbound_peers))
            time.sleep(15)


if __name__ == '__main__':
    P2PNotFoundPerf().main()
