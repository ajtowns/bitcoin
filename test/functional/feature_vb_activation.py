#!/usr/bin/env python3
# Copyright (c) 2015-2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test version bits logic

...
"""

from decimal import Decimal
from itertools import product
from io import BytesIO
import time

from test_framework.blocktools import create_coinbase, create_block, create_transaction
from test_framework.messages import ToHex, CTransaction
from test_framework.mininode import P2PDataStore
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    connect_nodes_bi,
    get_bip9_status,
)

BASE_RELATIVE_LOCKTIME = 10
SEQ_DISABLE_FLAG = 1 << 31
SEQ_RANDOM_HIGH_BIT = 1 << 25
SEQ_TYPE_FLAG = 1 << 22
SEQ_RANDOM_LOW_BIT = 1 << 18

class VersionBitTest(BitcoinTestFramework):
    def set_test_params(self):
        self.start = int(time.time()) + 3600
        self.flag = self.start + 7200
        self.end = self.flag + 7200

        self.flag_day_tip = None
        self.height_base = 0

        self.num_nodes = 3
        self.setup_clean_chain = True

        # soft-fork only, flag day aware, not aware of soft-fork
        vbparams="-vbparams=csv:%d:%d" % (self.start,self.end)
        self.extra_args = [
            [vbparams], [vbparams, "-vbflagtime=csv:%d" % (self.flag)], ["-vbparams=csv:0:0"]
        ]

    def connect_nodes(self):
        # Connect all nodes to each other
        for i in range(1, self.num_nodes):
            for j in range(i):
                connect_nodes_bi(self.nodes, i, j)

    def setup_network(self):
        """Override this method to customize test network topology"""
        self.setup_nodes()
        self.connect_nodes()
        self.sync_all()

    def bump_mocktime(self, t):
        for n in range(3):
            self.nodes[n].setmocktime(t)

    def generate_blocks(self, who, num):
        self.nodes[who].generate(num)

    def reorg_to_flag_time(self):
        if self.flag_day_tip is not None:
            target_height = self.nodes[2].getblockchaininfo()["blocks"]
            blk = self.nodes[2].getblockheader(self.flag_day_tip)
            for node in self.nodes:
                node.invalidateblock(self.flag_day_tip)
            self.sync_all()
            base_time = blk["time"] + 60
            my_height = blk["height"]
            self.bump_mocktime(base_time)
            self.generate_blocks(2, 1)
            self.flag_day_tip = self.nodes[2].getbestblockhash()
            extra_blocks = target_height - my_height
            if extra_blocks % 144 != 0:
                extra_blocks += 144 - (extra_blocks % 144)
            self.generate_blocks(2, extra_blocks)
        else:
            self.sync_all()
            self.flag_day_tip = self.nodes[2].getbestblockhash()

        self.bump_mocktime(self.flag)
        self.generate_blocks(2, 6)
        self.height_base = self.nodes[2].getblockchaininfo()["blocks"]
        self.height_base -= self.height_base % 144
        self.sync_all()

    def assert_state_is(self, state):
        assert "csv" not in self.nodes[2].getblockchaininfo()["bip9_softforks"]
        assert_equal(get_bip9_status(self.nodes[0], 'csv')['status'], state)
        assert_equal(get_bip9_status(self.nodes[1], 'csv')['status'], state)

    def assert_heights(self, height1, height2, height3):
        assert_equal(self.nodes[0].getblockchaininfo()["blocks"] - self.height_base, height1)
        assert_equal(self.nodes[1].getblockchaininfo()["blocks"] - self.height_base, height2)
        assert_equal(self.nodes[2].getblockchaininfo()["blocks"] - self.height_base, height3)

    def run_test(self):
        self.nodes[0].add_p2p_connection(P2PDataStore())

        self.assert_heights(0, 0, 0)
        self.assert_state_is('defined')

        self.log.info("Generate blocks pre-fork.")
        self.generate_blocks(2, 200)
        self.sync_all()
        self.assert_state_is('defined')

        self.log.info("Generate blocks past start time.")
        self.bump_mocktime(self.start)
        self.generate_blocks(0, 11) # median time past start time
        # soft-fork still isn't started, because it needs a retarget boundary
        self.assert_state_is('defined')

        # does become started at retarget boundary
        self.generate_blocks(0, 75)
        self.assert_state_is('defined')
        self.generate_blocks(0, 1)
        self.sync_all()
        self.assert_heights(287, 287, 287)
        self.assert_state_is('started')

        # generate 107 of 144 signalling blocks to almost-but-not-quite
        # lock change in
        self.generate_blocks(1, 50)
        self.sync_all()
        self.generate_blocks(2, 37) # not signalling
        self.sync_all()
        self.generate_blocks(0, 57)
        self.sync_all()
        self.assert_heights(431, 431, 431)
        self.assert_state_is('started')

        self.generate_blocks(2, 100)
        self.log.info("Generate blocks past flag day time.")
        self.reorg_to_flag_time()
        self.assert_heights(105, 105, 105)

        self.log.info("Testing flag day node getting left behind.")
        self.generate_blocks(2, 5) # blocks past flag time
        self.sync_all([self.nodes[0], self.nodes[2]])
        # node 1 should not continue from here
        self.assert_heights(110, 105, 110)

        self.generate_blocks(0, 33)
        self.sync_all([self.nodes[0], self.nodes[2]])
        self.assert_heights(143, 105, 143)
        self.assert_state_is('started')
        self.generate_blocks(0, 144)
        self.sync_all([self.nodes[0], self.nodes[2]])
        self.assert_heights(287, 105, 287)
        assert_equal(get_bip9_status(self.nodes[0], 'csv')['status'], 'locked_in')
        self.generate_blocks(2, 143)
        self.sync_all([self.nodes[0], self.nodes[2]])
        assert_equal(get_bip9_status(self.nodes[0], 'csv')['status'], 'locked_in')
        self.generate_blocks(2, 1)
        self.sync_all([self.nodes[0], self.nodes[2]])
        assert_equal(get_bip9_status(self.nodes[0], 'csv')['status'], 'active')
        self.assert_heights(431, 105, 431)

        self.log.info("Reorging, testing non-signalling node gets dropped")
        self.reorg_to_flag_time()
        self.assert_heights(105, 105, 105)

        stats = get_bip9_status(self.nodes[1], 'csv')['statistics']
        assert_equal(stats["possible"], False)

        self.generate_blocks(1, 38)

        stats = get_bip9_status(self.nodes[1], 'csv')['statistics']
        assert_equal(stats["period"], 144)
        assert_equal(stats["threshold"], 108)
        assert_equal(stats["elapsed"], 0)
        assert_equal(stats["count"], 0)
        assert_equal(stats["possible"], True)
        self.sync_all()
        self.assert_heights(143, 143, 143)

        self.generate_blocks(0, 50)
        self.sync_all()
        self.assert_heights(193, 193, 193)

        self.generate_blocks(1, 50)
        self.sync_all()
        self.assert_heights(243, 243, 243)

        self.generate_blocks(2, 35)
        self.sync_all([self.nodes[0], self.nodes[2]])
        self.generate_blocks(0, 5)
        self.sync_all([self.nodes[0], self.nodes[2]])
        self.assert_heights(283, 243, 283)

        self.generate_blocks(1, 43)
        self.sync_all()
        self.assert_heights(286, 286, 286)
        self.assert_state_is('started')

        self.generate_blocks(0, 1)
        self.sync_all()
        self.assert_state_is('locked_in')
        self.assert_heights(287, 287, 287)

        # no longer need to signal
        self.generate_blocks(2, 144)
        self.sync_all()
        self.assert_heights(431, 431, 431)
        self.assert_state_is('active')

        self.log.info("Reorging, testing timeout scenario")
        self.reorg_to_flag_time()
        self.assert_heights(105, 105, 105)
        self.generate_blocks(0, 38)
        self.sync_all()
        self.assert_heights(143, 143, 143)
        stats = get_bip9_status(self.nodes[0], 'csv')['statistics']
        assert_equal(stats["elapsed"], 0)

        self.generate_blocks(0, 101)
        self.sync_all()
        self.assert_heights(244, 244, 244)
        stats = get_bip9_status(self.nodes[1], 'csv')['statistics']
        assert_equal(stats["threshold"], 108)
        assert_equal(stats["count"], 101)

        self.bump_mocktime(self.end)
        self.generate_blocks(0, 6)
        self.sync_all()

        # should accept non-signalling blocks now
        self.generate_blocks(2, 1)
        self.sync_all()
        self.assert_heights(251, 251, 251)

        # even if rest of blocks are from supporting nodes,
        # activation will fail at this point
        self.generate_blocks(0, 35)
        self.sync_all()
        self.assert_heights(286, 286, 286)
        self.assert_state_is("started")
        self.generate_blocks(0, 1)
        self.sync_all()
        self.assert_state_is("failed")

        self.log.info("Finished")

if __name__ == '__main__':
    VersionBitTest().main()
