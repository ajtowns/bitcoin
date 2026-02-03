#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test stale tip relay (STALETIP message).

Currently implemented:
- test_basic_relay: Create stale tip, verify STALETIP sent to supporting peer

Future test cases to implement:

FEATURE Negotiation:
- test_no_feature_no_relay: Peer doesn't send FEATURE -> node doesn't send STALETIP
- test_prefer_blocks_mode: Peer sends prefer_blocks=true -> node only sends tips with block data
- test_prefer_headers_mode: Peer sends prefer_blocks=false -> node sends tips when headers known
- test_staletips_none: Node with -staletips=none doesn't send STALETIP

Receiving STALETIP:
- test_receive_staletip_new_tip: Receive STALETIP -> headers processed, tip tracked, blocks requested
- test_receive_staletip_unknown_fork_point: Unknown fork point -> message ignored
- test_receive_staletip_too_old: Fork point too deep (>MAX_HEIGHT_DELTA) -> ignored
- test_receive_staletip_known_tip_missing_blocks: Know tip but missing data -> request blocks
- test_receive_staletip_relay: Receive from peer A -> relay to peer B

Cache Behavior:
- test_multiple_stale_tips: Create multiple forks, verify all tracked (up to 10)
- test_extending_tip_replaces: New tip extends existing stale tip -> old entry replaced
- test_ancestor_not_added: Tip that's ancestor of existing tip -> not added
- test_cache_eviction: Cache full, new higher tip -> lowest tip evicted
- test_tip_becomes_ineligible: Active chain advances -> old stale tips removed

Eligibility Criteria:
- test_max_fork_length: Fork with >20 blocks -> not eligible
- test_max_height_delta: Tip >1000 blocks behind active tip -> not eligible

Reorg Scenarios:
- test_reorg_creates_stale_tip: Reorg via invalidateblock -> orphaned block becomes stale tip
- test_stale_tip_becomes_active: Reorg makes stale tip active chain -> removed from cache
- test_deep_reorg: Large reorg -> some stale tips now too old, removed

Node Integration:
- test_two_nodes_exchange: Two nodes connected, both create stale tips -> exchange
- test_new_peer_receives_tips: Node has stale tips, new peer connects -> receives existing tips
- test_submitblock_creates_tip: submitblock with competing block -> tracked as stale tip

Mode Combinations:
- test_blocks_mode_waits_for_data: -staletips=blocks -> only announces after block data received
- test_headers_mode_immediate: -staletips=headers -> announces as soon as headers known
"""

from io import BytesIO
import struct

from test_framework.messages import (
    CBlockHeader,
    msg_feature,
    msg_headers,
    uint256_from_str,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

# Feature ID for stale tip announcements
STALETIP_FEATURE = "https://github.com/ajtowns/bitcoin/tree/202601-staletips"


class StaleTipP2P(P2PInterface):
    """P2P interface that handles stale tip messages."""

    def __init__(self):
        super().__init__()
        self.staletips_received = []

    def on_version(self, message):
        # Send FEATURE message to indicate we support stale tips
        # prefer_blocks = False (we accept headers-only announcements)
        feature_data = struct.pack("<?", False)
        self.send_without_ping(msg_feature(STALETIP_FEATURE, feature_data))
        super().on_version(message)

    def on_staletip(self, message):
        self.staletips_received.append(message)

    def wait_for_staletip(self, timeout=60):
        def check():
            return len(self.staletips_received) > 0
        self.wait_until(check, timeout=timeout)


class StaleTipTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-staletips=headers"]]

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Mine initial blocks to get past coinbase maturity")
        self.generate(node, 101)

        self.log.info("Connect P2P peer that supports stale tips")
        peer = node.add_p2p_connection(StaleTipP2P())

        self.log.info("Sync peer's headers with node")
        # Send a headers message with the current tip so the node knows where we are
        tip_hash = node.getbestblockhash()
        tip_header = CBlockHeader()
        tip_header_hex = node.getblockheader(tip_hash, False)
        tip_header.deserialize(BytesIO(bytes.fromhex(tip_header_hex)))
        peer.send_and_ping(msg_headers([tip_header]))

        self.log.info("Check that getnetworkinfo shows no stale tips initially")
        netinfo = node.getnetworkinfo()
        assert_equal(netinfo["staletips"], [])

        self.log.info("Create a stale tip via invalidateblock/reconsiderblock")
        # Mine a block, then invalidate it and mine a longer chain
        tip_before = node.getbestblockhash()
        stale_hash = self.generate(node, 1)[0]
        node.invalidateblock(stale_hash)
        assert_equal(node.getbestblockhash(), tip_before)

        # Advance time to ensure the new blocks are different
        node.setmocktime(node.getblock(tip_before)['time'] + 100)
        # Mine 2 blocks on the new chain so it has more work than the stale one
        new_blocks = self.generate(node, 2)
        new_tip = new_blocks[-1]

        # Reconsider the stale block - it should now be tracked as a stale tip
        # but the current chain (with more work) should remain best
        node.reconsiderblock(stale_hash)
        assert_equal(node.getbestblockhash(), new_tip)  # Still on the new chain (more work)

        self.log.info("Check that getnetworkinfo shows the stale tip")
        netinfo = node.getnetworkinfo()
        assert_equal(len(netinfo["staletips"]), 1)
        assert_equal(netinfo["staletips"][0]["hash"], stale_hash)
        assert_equal(netinfo["staletips"][0]["have_block"], True)

        self.log.info("Wait for STALETIP message to be sent to peer")
        peer.wait_for_staletip()

        assert_equal(len(peer.staletips_received), 1)
        staletip = peer.staletips_received[0]
        self.log.info(f"Received: {staletip}")

        # Verify the message content
        assert_equal(staletip.have_block, True)
        assert_equal(len(staletip.headers), 1)

        # Reconstruct the tip hash from the compressed headers
        # The tip hash should match the stale_hash we created
        prev_hash = uint256_from_str(bytes.fromhex(tip_before)[::-1])
        assert_equal(staletip.hash_fork_point, prev_hash)

        self.log.info("Test passed!")


if __name__ == '__main__':
    StaleTipTest(__file__).main()
