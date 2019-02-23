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

    def assert_state_is(self, state):
        assert "csv" not in self.nodes[2].getblockchaininfo()["bip9_softforks"]
        assert_equal(get_bip9_status(self.nodes[0], 'csv')['status'], state)
        assert_equal(get_bip9_status(self.nodes[1], 'csv')['status'], state)

    def assert_heights(self, height1, height2, height3):
        assert_equal(self.nodes[0].getblockchaininfo()["blocks"], height1)
        assert_equal(self.nodes[1].getblockchaininfo()["blocks"], height2)
        assert_equal(self.nodes[2].getblockchaininfo()["blocks"], height3)

    def run_test(self):
        self.nodes[0].add_p2p_connection(P2PDataStore())

        self.assert_heights(0, 0, 0)
        self.assert_state_is('defined')

        print(get_bip9_status(self.nodes[0], 'csv'))
        print(get_bip9_status(self.nodes[1], 'csv'))

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
        self.bump_mocktime(self.flag)
        self.generate_blocks(2, 6)
        self.sync_all()

        self.assert_heights(537, 537, 537)
        flag_day_tip = self.nodes[0].getbestblockhash()

        self.log.info("Testing flag day node getting left behind.")
        self.generate_blocks(2, 5) # blocks past flag time
        self.sync_all([self.nodes[0], self.nodes[2]])
        # node 1 should not continue from here
        assert_equal(self.nodes[1].getbestblockhash(), flag_day_tip)

        self.generate_blocks(0, 33)
        self.sync_all([self.nodes[0], self.nodes[2]])
        self.assert_state_is('started')
        self.assert_heights(575, 537, 575)
        self.generate_blocks(0, 144)
        self.sync_all([self.nodes[0], self.nodes[2]])
        self.assert_heights(719, 537, 719)
        assert_equal(get_bip9_status(self.nodes[0], 'csv')['status'], 'locked_in')
        self.generate_blocks(2, 143)
        self.sync_all([self.nodes[0], self.nodes[2]])
        assert_equal(get_bip9_status(self.nodes[0], 'csv')['status'], 'locked_in')
        self.generate_blocks(2, 1)
        self.sync_all([self.nodes[0], self.nodes[2]])
        assert_equal(get_bip9_status(self.nodes[0], 'csv')['status'], 'active')
        self.assert_heights(863, 537, 863)

        self.log.info("Reorging, testing non-signalling node gets dropped")
        self.bump_mocktime(self.flag + 60) # make the blocks different
        for node in self.nodes:
            node.invalidateblock(flag_day_tip)
        self.generate_blocks(2, 1)
        self.sync_all()
        self.assert_heights(537, 537, 537)
        flag_day_tip = self.nodes[2].getbestblockhash()
        self.generate_blocks(0, 38)
        self.sync_all()
        self.assert_heights(575, 575, 575)

        stats = get_bip9_status(self.nodes[1], 'csv')['statistics']
        assert_equal(stats["period"], 144)
        assert_equal(stats["threshold"], 108)
        assert_equal(stats["elapsed"], 0)
        assert_equal(stats["count"], 0)
        assert_equal(stats["possible"], True)

        self.generate_blocks(0, 50)
        self.sync_all()
        self.assert_heights(625, 625, 625)

        self.generate_blocks(1, 50)
        self.sync_all()
        self.assert_heights(675, 675, 675)

        self.generate_blocks(2, 35)
        self.sync_all([self.nodes[0], self.nodes[2]])
        self.generate_blocks(0, 5)
        self.sync_all([self.nodes[0], self.nodes[2]])
        self.assert_heights(715, 675, 715)

        self.generate_blocks(1, 43)
        self.sync_all()
        self.assert_heights(718, 718, 718)
        self.assert_state_is('started')

        self.generate_blocks(0, 1)
        self.sync_all()
        self.assert_state_is('locked_in')

        # no longer need to signal
        self.generate_blocks(2, 144)
        self.sync_all()
        self.assert_heights(863, 863, 863)
        self.assert_state_is('active')

        self.log.info("Finished")
        return

        self.nodes[0].setmocktime(0)  # set time back to present so yielded blocks aren't in the future as we advance last_block_time
        self.tipheight = 82  # height of the next block to build
        self.last_block_time = long_past_time
        self.tip = int(self.nodes[0].getbestblockhash(), 16)
        self.nodeaddress = self.nodes[0].getnewaddress()

        self.log.info("Test that the csv softfork is DEFINED")
        assert_equal(get_bip9_status(self.nodes[0], 'csv')['status'], 'defined')
        test_blocks = self.generate_blocks(61, 4)
        self.sync_blocks(test_blocks)

        self.log.info("Advance from DEFINED to STARTED, height = 143")
        assert_equal(get_bip9_status(self.nodes[0], 'csv')['status'], 'started')

        self.log.info("Fail to achieve LOCKED_IN")
        # 100 out of 144 signal bit 0. Use a variety of bits to simulate multiple parallel softforks

        test_blocks = self.generate_blocks(50, 536870913)  # 0x20000001 (signalling ready)
        test_blocks = self.generate_blocks(20, 4, test_blocks)  # 0x00000004 (signalling not)
        test_blocks = self.generate_blocks(50, 536871169, test_blocks)  # 0x20000101 (signalling ready)
        test_blocks = self.generate_blocks(24, 536936448, test_blocks)  # 0x20010000 (signalling not)
        self.sync_blocks(test_blocks)

        self.log.info("Failed to advance past STARTED, height = 287")
        assert_equal(get_bip9_status(self.nodes[0], 'csv')['status'], 'started')

        self.log.info("Generate blocks to achieve LOCK-IN")
        # 108 out of 144 signal bit 0 to achieve lock-in
        # using a variety of bits to simulate multiple parallel softforks
        test_blocks = self.generate_blocks(58, 536870913)  # 0x20000001 (signalling ready)
        test_blocks = self.generate_blocks(26, 4, test_blocks)  # 0x00000004 (signalling not)
        test_blocks = self.generate_blocks(50, 536871169, test_blocks)  # 0x20000101 (signalling ready)
        test_blocks = self.generate_blocks(10, 536936448, test_blocks)  # 0x20010000 (signalling not)
        self.sync_blocks(test_blocks)

        self.log.info("Advanced from STARTED to LOCKED_IN, height = 431")
        assert_equal(get_bip9_status(self.nodes[0], 'csv')['status'], 'locked_in')

        # Generate 140 more version 4 blocks
        test_blocks = self.generate_blocks(140, 4)
        self.sync_blocks(test_blocks)

        # Inputs at height = 572
        #
        # Put inputs for all tests in the chain at height 572 (tip now = 571) (time increases by 600s per block)
        # Note we reuse inputs for v1 and v2 txs so must test these separately
        # 16 normal inputs
        bip68inputs = []
        for i in range(16):
            bip68inputs.append(send_generic_input_tx(self.nodes[0], self.coinbase_blocks, self.nodeaddress))

        # 2 sets of 16 inputs with 10 OP_CSV OP_DROP (actually will be prepended to spending scriptSig)
        bip112basicinputs = []
        for j in range(2):
            inputs = []
            for i in range(16):
                inputs.append(send_generic_input_tx(self.nodes[0], self.coinbase_blocks, self.nodeaddress))
            bip112basicinputs.append(inputs)

        # 2 sets of 16 varied inputs with (relative_lock_time) OP_CSV OP_DROP (actually will be prepended to spending scriptSig)
        bip112diverseinputs = []
        for j in range(2):
            inputs = []
            for i in range(16):
                inputs.append(send_generic_input_tx(self.nodes[0], self.coinbase_blocks, self.nodeaddress))
            bip112diverseinputs.append(inputs)

        # 1 special input with -1 OP_CSV OP_DROP (actually will be prepended to spending scriptSig)
        bip112specialinput = send_generic_input_tx(self.nodes[0], self.coinbase_blocks, self.nodeaddress)

        # 1 normal input
        bip113input = send_generic_input_tx(self.nodes[0], self.coinbase_blocks, self.nodeaddress)

        self.nodes[0].setmocktime(self.last_block_time + 600)
        inputblockhash = self.nodes[0].generate(1)[0]  # 1 block generated for inputs to be in chain at height 572
        self.nodes[0].setmocktime(0)
        self.tip = int(inputblockhash, 16)
        self.tipheight += 1
        self.last_block_time += 600
        assert_equal(len(self.nodes[0].getblock(inputblockhash, True)["tx"]), 82 + 1)

        # 2 more version 4 blocks
        test_blocks = self.generate_blocks(2, 4)
        self.sync_blocks(test_blocks)

        self.log.info("Not yet advanced to ACTIVE, height = 574 (will activate for block 576, not 575)")
        assert_equal(get_bip9_status(self.nodes[0], 'csv')['status'], 'locked_in')

        # Test both version 1 and version 2 transactions for all tests
        # BIP113 test transaction will be modified before each use to put in appropriate block time
        bip113tx_v1 = create_transaction(self.nodes[0], bip113input, self.nodeaddress, amount=Decimal("49.98"))
        bip113tx_v1.vin[0].nSequence = 0xFFFFFFFE
        bip113tx_v1.nVersion = 1
        bip113tx_v2 = create_transaction(self.nodes[0], bip113input, self.nodeaddress, amount=Decimal("49.98"))
        bip113tx_v2.vin[0].nSequence = 0xFFFFFFFE
        bip113tx_v2.nVersion = 2

        # For BIP68 test all 16 relative sequence locktimes
        bip68txs_v1 = create_bip68txs(self.nodes[0], bip68inputs, 1, self.nodeaddress)
        bip68txs_v2 = create_bip68txs(self.nodes[0], bip68inputs, 2, self.nodeaddress)

        # For BIP112 test:
        # 16 relative sequence locktimes of 10 against 10 OP_CSV OP_DROP inputs
        bip112txs_vary_nSequence_v1 = create_bip112txs(self.nodes[0], bip112basicinputs[0], False, 1, self.nodeaddress)
        bip112txs_vary_nSequence_v2 = create_bip112txs(self.nodes[0], bip112basicinputs[0], False, 2, self.nodeaddress)
        # 16 relative sequence locktimes of 9 against 10 OP_CSV OP_DROP inputs
        bip112txs_vary_nSequence_9_v1 = create_bip112txs(self.nodes[0], bip112basicinputs[1], False, 1, self.nodeaddress, -1)
        bip112txs_vary_nSequence_9_v2 = create_bip112txs(self.nodes[0], bip112basicinputs[1], False, 2, self.nodeaddress, -1)
        # sequence lock time of 10 against 16 (relative_lock_time) OP_CSV OP_DROP inputs
        bip112txs_vary_OP_CSV_v1 = create_bip112txs(self.nodes[0], bip112diverseinputs[0], True, 1, self.nodeaddress)
        bip112txs_vary_OP_CSV_v2 = create_bip112txs(self.nodes[0], bip112diverseinputs[0], True, 2, self.nodeaddress)
        # sequence lock time of 9 against 16 (relative_lock_time) OP_CSV OP_DROP inputs
        bip112txs_vary_OP_CSV_9_v1 = create_bip112txs(self.nodes[0], bip112diverseinputs[1], True, 1, self.nodeaddress, -1)
        bip112txs_vary_OP_CSV_9_v2 = create_bip112txs(self.nodes[0], bip112diverseinputs[1], True, 2, self.nodeaddress, -1)
        # -1 OP_CSV OP_DROP input
        bip112tx_special_v1 = create_bip112special(self.nodes[0], bip112specialinput, 1, self.nodeaddress)
        bip112tx_special_v2 = create_bip112special(self.nodes[0], bip112specialinput, 2, self.nodeaddress)

        self.log.info("TESTING")

        self.log.info("Pre-Soft Fork Tests. All txs should pass.")
        self.log.info("Test version 1 txs")

        success_txs = []
        # add BIP113 tx and -1 CSV tx
        bip113tx_v1.nLockTime = self.last_block_time - 600 * 5  # = MTP of prior block (not <) but < time put on current block
        bip113signed1 = sign_transaction(self.nodes[0], bip113tx_v1)
        success_txs.append(bip113signed1)
        success_txs.append(bip112tx_special_v1)
        # add BIP 68 txs
        success_txs.extend(all_rlt_txs(bip68txs_v1))
        # add BIP 112 with seq=10 txs
        success_txs.extend(all_rlt_txs(bip112txs_vary_nSequence_v1))
        success_txs.extend(all_rlt_txs(bip112txs_vary_OP_CSV_v1))
        # try BIP 112 with seq=9 txs
        success_txs.extend(all_rlt_txs(bip112txs_vary_nSequence_9_v1))
        success_txs.extend(all_rlt_txs(bip112txs_vary_OP_CSV_9_v1))
        self.sync_blocks([self.create_test_block(success_txs)])
        self.nodes[0].invalidateblock(self.nodes[0].getbestblockhash())

        self.log.info("Test version 2 txs")

        success_txs = []
        # add BIP113 tx and -1 CSV tx
        bip113tx_v2.nLockTime = self.last_block_time - 600 * 5  # = MTP of prior block (not <) but < time put on current block
        bip113signed2 = sign_transaction(self.nodes[0], bip113tx_v2)
        success_txs.append(bip113signed2)
        success_txs.append(bip112tx_special_v2)
        # add BIP 68 txs
        success_txs.extend(all_rlt_txs(bip68txs_v2))
        # add BIP 112 with seq=10 txs
        success_txs.extend(all_rlt_txs(bip112txs_vary_nSequence_v2))
        success_txs.extend(all_rlt_txs(bip112txs_vary_OP_CSV_v2))
        # try BIP 112 with seq=9 txs
        success_txs.extend(all_rlt_txs(bip112txs_vary_nSequence_9_v2))
        success_txs.extend(all_rlt_txs(bip112txs_vary_OP_CSV_9_v2))
        self.sync_blocks([self.create_test_block(success_txs)])
        self.nodes[0].invalidateblock(self.nodes[0].getbestblockhash())

        # 1 more version 4 block to get us to height 575 so the fork should now be active for the next block
        test_blocks = self.generate_blocks(1, 4)
        self.sync_blocks(test_blocks)
        assert_equal(get_bip9_status(self.nodes[0], 'csv')['status'], 'active')

        self.log.info("Post-Soft Fork Tests.")

        self.log.info("BIP 113 tests")
        # BIP 113 tests should now fail regardless of version number if nLockTime isn't satisfied by new rules
        bip113tx_v1.nLockTime = self.last_block_time - 600 * 5  # = MTP of prior block (not <) but < time put on current block
        bip113signed1 = sign_transaction(self.nodes[0], bip113tx_v1)
        bip113tx_v2.nLockTime = self.last_block_time - 600 * 5  # = MTP of prior block (not <) but < time put on current block
        bip113signed2 = sign_transaction(self.nodes[0], bip113tx_v2)
        for bip113tx in [bip113signed1, bip113signed2]:
            self.sync_blocks([self.create_test_block([bip113tx])], success=False)
        # BIP 113 tests should now pass if the locktime is < MTP
        bip113tx_v1.nLockTime = self.last_block_time - 600 * 5 - 1  # < MTP of prior block
        bip113signed1 = sign_transaction(self.nodes[0], bip113tx_v1)
        bip113tx_v2.nLockTime = self.last_block_time - 600 * 5 - 1  # < MTP of prior block
        bip113signed2 = sign_transaction(self.nodes[0], bip113tx_v2)
        for bip113tx in [bip113signed1, bip113signed2]:
            self.sync_blocks([self.create_test_block([bip113tx])])
            self.nodes[0].invalidateblock(self.nodes[0].getbestblockhash())

        # Next block height = 580 after 4 blocks of random version
        test_blocks = self.generate_blocks(4, 1234)
        self.sync_blocks(test_blocks)

        self.log.info("BIP 68 tests")
        self.log.info("Test version 1 txs - all should still pass")

        success_txs = []
        success_txs.extend(all_rlt_txs(bip68txs_v1))
        self.sync_blocks([self.create_test_block(success_txs)])
        self.nodes[0].invalidateblock(self.nodes[0].getbestblockhash())

        self.log.info("Test version 2 txs")

        # All txs with SEQUENCE_LOCKTIME_DISABLE_FLAG set pass
        bip68success_txs = [tx['tx'] for tx in bip68txs_v2 if tx['sdf']]
        self.sync_blocks([self.create_test_block(bip68success_txs)])
        self.nodes[0].invalidateblock(self.nodes[0].getbestblockhash())

        # All txs without flag fail as we are at delta height = 8 < 10 and delta time = 8 * 600 < 10 * 512
        bip68timetxs = [tx['tx'] for tx in bip68txs_v2 if not tx['sdf'] and tx['stf']]
        for tx in bip68timetxs:
            self.sync_blocks([self.create_test_block([tx])], success=False)

        bip68heighttxs = [tx['tx'] for tx in bip68txs_v2 if not tx['sdf'] and not tx['stf']]
        for tx in bip68heighttxs:
            self.sync_blocks([self.create_test_block([tx])], success=False)

        # Advance one block to 581
        test_blocks = self.generate_blocks(1, 1234)
        self.sync_blocks(test_blocks)

        # Height txs should fail and time txs should now pass 9 * 600 > 10 * 512
        bip68success_txs.extend(bip68timetxs)
        self.sync_blocks([self.create_test_block(bip68success_txs)])
        self.nodes[0].invalidateblock(self.nodes[0].getbestblockhash())
        for tx in bip68heighttxs:
            self.sync_blocks([self.create_test_block([tx])], success=False)

        # Advance one block to 582
        test_blocks = self.generate_blocks(1, 1234)
        self.sync_blocks(test_blocks)

        # All BIP 68 txs should pass
        bip68success_txs.extend(bip68heighttxs)
        self.sync_blocks([self.create_test_block(bip68success_txs)])
        self.nodes[0].invalidateblock(self.nodes[0].getbestblockhash())

        self.log.info("BIP 112 tests")
        self.log.info("Test version 1 txs")

        # -1 OP_CSV tx should fail
        self.sync_blocks([self.create_test_block([bip112tx_special_v1])], success=False)
        # If SEQUENCE_LOCKTIME_DISABLE_FLAG is set in argument to OP_CSV, version 1 txs should still pass

        success_txs = [tx['tx'] for tx in bip112txs_vary_OP_CSV_v1 if tx['sdf']]
        success_txs += [tx['tx'] for tx in bip112txs_vary_OP_CSV_9_v1 if tx['sdf']]
        self.sync_blocks([self.create_test_block(success_txs)])
        self.nodes[0].invalidateblock(self.nodes[0].getbestblockhash())

        # If SEQUENCE_LOCKTIME_DISABLE_FLAG is unset in argument to OP_CSV, version 1 txs should now fail
        fail_txs = all_rlt_txs(bip112txs_vary_nSequence_v1)
        fail_txs += all_rlt_txs(bip112txs_vary_nSequence_9_v1)
        fail_txs += [tx['tx'] for tx in bip112txs_vary_OP_CSV_9_v1 if not tx['sdf']]
        fail_txs += [tx['tx'] for tx in bip112txs_vary_OP_CSV_9_v1 if not tx['sdf']]
        for tx in fail_txs:
            self.sync_blocks([self.create_test_block([tx])], success=False)

        self.log.info("Test version 2 txs")

        # -1 OP_CSV tx should fail
        self.sync_blocks([self.create_test_block([bip112tx_special_v2])], success=False)

        # If SEQUENCE_LOCKTIME_DISABLE_FLAG is set in argument to OP_CSV, version 2 txs should pass (all sequence locks are met)
        success_txs = [tx['tx'] for tx in bip112txs_vary_OP_CSV_v2 if tx['sdf']]
        success_txs += [tx['tx'] for tx in bip112txs_vary_OP_CSV_9_v2 if tx['sdf']]

        self.sync_blocks([self.create_test_block(success_txs)])
        self.nodes[0].invalidateblock(self.nodes[0].getbestblockhash())

        # SEQUENCE_LOCKTIME_DISABLE_FLAG is unset in argument to OP_CSV for all remaining txs ##

        # All txs with nSequence 9 should fail either due to earlier mismatch or failing the CSV check
        fail_txs = all_rlt_txs(bip112txs_vary_nSequence_9_v2)
        fail_txs += [tx['tx'] for tx in bip112txs_vary_OP_CSV_9_v2 if not tx['sdf']]
        for tx in fail_txs:
            self.sync_blocks([self.create_test_block([tx])], success=False)

        # If SEQUENCE_LOCKTIME_DISABLE_FLAG is set in nSequence, tx should fail
        fail_txs = [tx['tx'] for tx in bip112txs_vary_nSequence_v2 if tx['sdf']]
        for tx in fail_txs:
            self.sync_blocks([self.create_test_block([tx])], success=False)

        # If sequencelock types mismatch, tx should fail
        fail_txs = [tx['tx'] for tx in bip112txs_vary_nSequence_v2 if not tx['sdf'] and tx['stf']]
        fail_txs += [tx['tx'] for tx in bip112txs_vary_OP_CSV_v2 if not tx['sdf'] and tx['stf']]
        for tx in fail_txs:
            self.sync_blocks([self.create_test_block([tx])], success=False)

        # Remaining txs should pass, just test masking works properly
        success_txs = [tx['tx'] for tx in bip112txs_vary_nSequence_v2 if not tx['sdf'] and not tx['stf']]
        success_txs += [tx['tx'] for tx in bip112txs_vary_OP_CSV_v2 if not tx['sdf'] and not tx['stf']]
        self.sync_blocks([self.create_test_block(success_txs)])
        self.nodes[0].invalidateblock(self.nodes[0].getbestblockhash())

        # Additional test, of checking that comparison of two time types works properly
        time_txs = []
        for tx in [tx['tx'] for tx in bip112txs_vary_OP_CSV_v2 if not tx['sdf'] and tx['stf']]:
            tx.vin[0].nSequence = BASE_RELATIVE_LOCKTIME | SEQ_TYPE_FLAG
            signtx = sign_transaction(self.nodes[0], tx)
            time_txs.append(signtx)

        self.sync_blocks([self.create_test_block(time_txs)])
        self.nodes[0].invalidateblock(self.nodes[0].getbestblockhash())

        # TODO: Test empty stack fails

if __name__ == '__main__':
    VersionBitTest().main()
