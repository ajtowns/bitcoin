#!/usr/bin/env python3
# Copyright (c) 2017-2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test getblockstats rpc call
#
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
import json
import os

TESTSDIR = os.path.dirname(os.path.realpath(__file__))

def assert_contains(data, values, check_cointains=True):
    for val in values:
        if check_cointains:
            assert val in data
        else:
            assert val not in data

class GetblockstatsTest(BitcoinTestFramework):
    EXPECTED_STATS = [
        "height",
        "time",
        "mediantime",
        "txs",
        "swtxs",
        "ins",
        "outs",
        "subsidy",
        "totalfee",
        "utxo_increase",
        "utxo_size_inc",
        "total_size",
        "total_weight",
        "swtotal_size",
        "swtotal_weight",
        "total_out",
        "minfee",
        "maxfee",
        "medianfee",
        "avgfee",
        "minfeerate",
        "maxfeerate",
        "medianfeerate",
        "avgfeerate",
        "mintxsize",
        "maxtxsize",
        "mediantxsize",
        "avgtxsize",
    ]

    start_height = 101
    max_stat_pos = 2

    def add_options(self, parser):
        parser.add_option("--gen-test-data", dest="gen_test_data",
                          default=False, action="store_true",
                          help="Generate test data")
        parser.add_option("--test-data", dest="test_data", 
                          default="data/rpc_getblockstats.json",
                          action="store", metavar="FILE",
                          help="Test data file")

    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [['-txindex'], ['-paytxfee=0.003']]
        self.setup_clean_chain = True

    def generate_test_data(self, filename):
        node = self.nodes[0]
        node.generate(101)

        node.sendtoaddress(address=self.nodes[1].getnewaddress(), amount=10, subtractfeefromamount=True)
        node.generate(1)
        self.sync_all()

        node.sendtoaddress(address=node.getnewaddress(), amount=10, subtractfeefromamount=True)
        node.sendtoaddress(address=node.getnewaddress(), amount=10, subtractfeefromamount=True)
        self.nodes[1].sendtoaddress(address=node.getnewaddress(), amount=1, subtractfeefromamount=True)
        self.sync_all()
        node.generate(1)

        self.expected_stats = self.get_stats()

        blocks = []
        tip = node.getbestblockhash()
        blkhash = None
        height = 0
        while tip != blkhash:
            blkhash = node.getblockhash(height)
            blocks.append(node.getblock(blkhash, 0))
            height += 1

        with open(filename, "w") as f:
            f.write("""{\n  "stats": """)
            json.dump(self.expected_stats, f, indent=4)
            f.write(""",\n  "blocks": """)
            json.dump(blocks, f)
            f.write("""\n}\n""")

    def load_test_data(self, filename):
        node = self.nodes[0]

        with open(filename, "r") as f:
            d = json.load(f)
            blocks = d["blocks"]
            self.expected_stats = d["stats"]
            del d

        for b in blocks:
            node.submitblock(b)

    def get_stats(self):
        node = self.nodes[0]
        return [node.getblockstats(height=self.start_height + i) for i in range(self.max_stat_pos+1)]

    def run_test(self):
        test_data = os.path.join(TESTSDIR, self.options.test_data)
        if self.options.gen_test_data:
            self.generate_test_data(test_data)
        else:
            self.load_test_data(test_data)

        node = self.nodes[0]
        stats = self.get_stats()

        # Make sure all valid statistics are included but nothing else is
        assert_equal(set(stats[0].keys()), set(self.EXPECTED_STATS))

        assert_equal(stats[0]['height'], self.start_height)
        assert_equal(stats[self.max_stat_pos]['height'], self.start_height + self.max_stat_pos)

        for i in range(self.max_stat_pos+1):
            self.log.info("Checking block %d\n" % (i))
            for stat in self.EXPECTED_STATS:
                assert_equal(stats[i][stat], self.expected_stats[i][stat])

        # Test invalid parameters raise the proper json exceptions
        tip = self.start_height + self.max_stat_pos
        assert_raises_rpc_error(-8, 'Target block height %d after current tip %d' % (tip+1, tip), node.getblockstats, height=tip+1)
        assert_raises_rpc_error(-8, 'Target block height %d is negative' % (-1), node.getblockstats, height=-tip-2)

        # Make sure not valid stats aren't allowed
        inv_sel_stat = 'asdfghjkl'
        inv_stats = [
            [inv_sel_stat],
            ['minfee' , inv_sel_stat],
            [inv_sel_stat, 'minfee'],
            ['minfee', inv_sel_stat, 'maxfee'],
        ]
        for inv_stat in inv_stats:
            assert_raises_rpc_error(-8, 'Invalid requested statistic %s' % inv_sel_stat, node.getblockstats, height=1, stats=inv_stat)
        # Make sure we aren't always returning inv_sel_stat as the culprit stat
        assert_raises_rpc_error(-8, 'Invalid requested statistic aaa%s' % inv_sel_stat, node.getblockstats, height=1, stats=['minfee' , 'aaa%s' % inv_sel_stat])

        # Make sure only the selected statistics are included
        some_stats = {'minfee', 'maxfee'}
        stats = node.getblockstats(height=1, stats=list(some_stats))
        # Make sure only valid stats that have been requested appear
        assert_equal(set(stats.keys()), some_stats)

if __name__ == '__main__':
    GetblockstatsTest().main()
