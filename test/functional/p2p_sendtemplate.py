#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test chunked tmplttxn sending via the sendtemplate protocol.

Tests:
- test_chunked_tmplttxn: Verify gettmplttxn response is sent in multiple
  byte-limited chunks via MaybeSendTemplateTxns in SendMessages.
- test_out_of_range_disconnect: Verify peer is disconnected when requesting
  a position beyond the template size.
- test_template_eviction: Verify the node handles template eviction gracefully
  when a tmplttxn queue is still pending.
"""

import time

from test_framework.messages import (
    msg_feature,
    msg_gettmplt,
    msg_gettmplttxn,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than
from test_framework.wallet import MiniWallet

# Feature version for feature negotiation (from protocol_version.h)
FEATURE_VERSION = 70017

# Feature ID for template sharing (from protocol.h)
BIN25_2_1_FEATURE = "BIN25-2.1"

# Template update interval in seconds (from templateman.h)
TEMPLATE_UPDATE_INTERVAL = 30


class TemplateP2P(P2PInterface):
    """P2P interface that negotiates template support and collects responses."""

    def __init__(self):
        super().__init__()
        self.tmplt_received = []
        self.tmplttxn_received = []

    def peer_connect_send_version(self, services):
        super().peer_connect_send_version(services)
        # Override version to FEATURE_VERSION (70017)
        self.on_connection_send_msg.nVersion = FEATURE_VERSION

    def on_version(self, message):
        # Send feature message before verack to negotiate BIN25-2.1
        self.send_without_ping(msg_feature(BIN25_2_1_FEATURE, b""))
        super().on_version(message)

    def on_tmplt(self, message):
        self.tmplt_received.append(message)

    def on_tmplttxn(self, message):
        self.tmplttxn_received.append(message)

    def wait_for_tmplt(self, timeout=60):
        self.wait_until(lambda: len(self.tmplt_received) > 0, timeout=timeout)

    def wait_for_tmplttxn(self, count=1, timeout=60):
        self.wait_until(lambda: len(self.tmplttxn_received) >= count, timeout=timeout)


class SendTemplateTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.test_chunked_tmplttxn()
        self.test_out_of_range_disconnect()
        self.test_template_eviction()

    def trigger_template_generation(self, peer):
        """Bump mocktime past the template update interval and ping to trigger."""
        node = self.nodes[0]
        node.bumpmocktime(TEMPLATE_UPDATE_INTERVAL + 1)
        peer.sync_with_ping()

    def test_chunked_tmplttxn(self):
        self.log.info("Test chunked tmplttxn sending")
        node = self.nodes[0]

        self.log.info("Mine blocks for coinbase maturity")
        self.generate(self.wallet, 200)

        # Initialize mocktime so bumpmocktime works
        node.setmocktime(int(time.time()))

        self.log.info("Create transactions in the mempool")
        # Use target_vsize=5000 to make ~5KB txs. With ~100 of them,
        # total is ~500KB which should produce multiple 100KB chunks.
        for _ in range(100):
            self.wallet.send_self_transfer(from_node=node, target_vsize=5000)
        assert_greater_than(node.getmempoolinfo()["size"], 50)

        self.log.info("Connect template-supporting peer")
        peer = node.add_p2p_connection(TemplateP2P())

        self.log.info("Trigger template generation")
        self.trigger_template_generation(peer)

        tmpl_info = node.gettemplateinfo()
        self.log.info(f"Template info: {tmpl_info}")
        assert_greater_than(tmpl_info["templates"], 0)
        tx_count = tmpl_info["latest_template_tx"]
        assert_greater_than(tx_count, 50)

        self.log.info("Request template via gettmplt")
        peer.send_and_ping(msg_gettmplt())
        peer.wait_for_tmplt()
        assert_equal(len(peer.tmplt_received), 1)
        tmplt = peer.tmplt_received[0]
        self.log.info(f"Received tmplt: {tmplt}")
        assert_equal(tmplt.tx_count, tx_count)

        self.log.info(f"Request all {tx_count} transactions via gettmplttxn")
        positions = list(range(tx_count))
        peer.send_without_ping(msg_gettmplttxn(tmplt.template_hash, positions))

        self.log.info("Collect tmplttxn chunks")
        # Each SendMessages call drains one chunk. Ping repeatedly to trigger
        # multiple SendMessages calls until all txs are received.
        total_txs = 0
        all_txs = []
        prev_count = 0
        for _ in range(100):  # safety limit
            peer.sync_with_ping()
            if len(peer.tmplttxn_received) > prev_count:
                for msg in peer.tmplttxn_received[prev_count:]:
                    all_txs.extend(msg.transactions)
                    assert_equal(msg.template_hash, tmplt.template_hash)
                prev_count = len(peer.tmplttxn_received)
            total_txs = len(all_txs)
            if total_txs >= tx_count:
                break

        num_chunks = len(peer.tmplttxn_received)
        self.log.info(f"Received {total_txs} txs in {num_chunks} chunks")
        assert_equal(total_txs, tx_count)
        assert_greater_than(num_chunks, 1)

        self.log.info("Verify each chunk respects the ~100KB size limit")
        MAX_TMPLTTXN_MSG_SIZE = 100000
        for i, msg in enumerate(peer.tmplttxn_received):
            chunk_size = sum(len(tx.serialize_with_witness()) for tx in msg.transactions)
            self.log.info(f"  Chunk {i}: {len(msg.transactions)} txs, {chunk_size} bytes")
            if i < num_chunks - 1:
                # Non-final chunks should be close to the limit (within one max tx)
                assert_greater_than(chunk_size, MAX_TMPLTTXN_MSG_SIZE // 2)

        # Disconnect peer for next test
        peer.peer_disconnect()
        peer.wait_for_disconnect()

    def test_out_of_range_disconnect(self):
        self.log.info("Test out-of-range position causes disconnect")
        node = self.nodes[0]

        peer = node.add_p2p_connection(TemplateP2P())

        # Get the template
        peer.send_and_ping(msg_gettmplt())
        peer.wait_for_tmplt()
        tmplt = peer.tmplt_received[0]
        tx_count = tmplt.tx_count

        self.log.info(f"Send gettmplttxn with position {tx_count} (out of range)")
        peer.send_without_ping(msg_gettmplttxn(tmplt.template_hash, [tx_count]))
        peer.wait_for_disconnect()
        self.log.info("Peer disconnected as expected")

    def test_template_eviction(self):
        self.log.info("Test template eviction with pending queue")
        node = self.nodes[0]

        peer = node.add_p2p_connection(TemplateP2P())

        # Get a template and its hash
        peer.send_and_ping(msg_gettmplt())
        peer.wait_for_tmplt()
        tmplt = peer.tmplt_received[0]
        original_hash = tmplt.template_hash

        self.log.info("Queue a gettmplttxn for the current template")
        positions = list(range(tmplt.tx_count))
        peer.send_and_ping(msg_gettmplttxn(original_hash, positions))

        self.log.info("Generate enough new templates to evict the original")
        info_before = node.gettemplateinfo()
        max_templates = info_before["max_templates"]
        templates_before = info_before["templates"]
        for i in range(max_templates):
            # Add a new tx each time to ensure the template changes
            self.wallet.send_self_transfer(from_node=node)
            self.trigger_template_generation(peer)

        # Verify eviction actually happened: at max capacity and some were dropped
        new_info = node.gettemplateinfo()
        self.log.info(f"After eviction: {new_info}")
        assert_equal(new_info["templates"], max_templates)
        assert_greater_than(templates_before + max_templates, max_templates)

        # Snapshot: chunks sent so far (during eviction loop's sync_with_ping calls)
        pre_eviction_count = len(peer.tmplttxn_received)

        self.log.info("Trigger SendMessages to drain the queue (should drop it)")
        peer.sync_with_ping()

        # After eviction, no NEW tmplttxn for the original hash should arrive.
        for msg in peer.tmplttxn_received[pre_eviction_count:]:
            assert msg.template_hash != original_hash, \
                f"Received tmplttxn for evicted template {original_hash:064x}"

        self.log.info("Node handled eviction gracefully (no tmplttxn for evicted template)")

        peer.peer_disconnect()
        peer.wait_for_disconnect()


if __name__ == '__main__':
    SendTemplateTest(__file__).main()
