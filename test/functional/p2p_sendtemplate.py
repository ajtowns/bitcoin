#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the sendtemplate protocol (provide and receive sides).

Provide-side tests (node sends templates to test peer):
- test_chunked_tmplttxn: Verify gettmplttxn response is sent in multiple
  byte-limited chunks via MaybeSendTemplateTxns in SendMessages.
- test_out_of_range_disconnect: Verify peer is disconnected when requesting
  a position beyond the template size.
- test_template_eviction: Verify the node handles template eviction gracefully
  when a tmplttxn queue is still pending.

Receive-side tests (test peer sends templates to node):
- test_receive_template_mempool: Test peer provides a template to the node;
  node reconstructs it, populates mempool via ConsiderTemplateTransactions.
- test_receive_template_partial_match: Some txs already in node's mempool;
  node matches them via short IDs, requests only the missing ones.
"""

import time

from test_framework.messages import (
    calculate_shortid,
    msg_feature,
    msg_gettmplt,
    msg_gettmplttxn,
    msg_tmplt,
    msg_tmplttxn,
    ser_uint256,
    sha256,
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

# Local template expiry in seconds (from templateman.h)
LOCAL_TEMPLATE_EXPIRY = 300

# Template request interval in seconds (from templateman.h)
TEMPLATE_REQUEST_INTERVAL = 120

# Max inbound peers to actively request templates from (from templateman.h)
MAX_INBOUND_TEMPLATE_PEERS = 10


def build_tmplt(txs, nonce=0):
    """Build a msg_tmplt from a list of CTransaction objects (flat encoding).

    Computes template_hash = SHA256(concatenated wtxids), derives SipHash
    keys from SHA256(template_hash || nonce), and produces 6-byte short IDs.
    Returns a msg_tmplt with basis_hash=0 (full/flat template).
    """
    # Compute template hash: SHA256 of concatenated wtxids (as 32-byte LE)
    wtxid_data = b""
    for tx in txs:
        wtxid_data += ser_uint256(tx.wtxid_int)
    template_hash_bytes = sha256(wtxid_data)
    template_hash = int.from_bytes(template_hash_bytes, 'little')

    # Derive SipHash keys: SHA256(template_hash_bytes || nonce_le)
    key_input = template_hash_bytes + nonce.to_bytes(8, 'little')
    key_hash = sha256(key_input)
    k0 = int.from_bytes(key_hash[0:8], 'little')
    k1 = int.from_bytes(key_hash[8:16], 'little')

    # Compute 6-byte short IDs
    raw_payload = b""
    for tx in txs:
        shortid = calculate_shortid(k0, k1, tx.wtxid_int)
        raw_payload += shortid.to_bytes(6, 'little')

    msg = msg_tmplt()
    msg.template_hash = template_hash
    msg.nonce = nonce
    msg.basis_hash = 0
    msg.tx_count = len(txs)
    msg.raw_payload = raw_payload
    return msg


class FeatureProbeP2P(P2PInterface):
    """P2P interface that records received feature messages."""

    def __init__(self):
        super().__init__()
        self.features_received = []

    def peer_connect_send_version(self, services):
        super().peer_connect_send_version(services)
        self.on_connection_send_msg.nVersion = FEATURE_VERSION

    def on_feature(self, message):
        self.features_received.append(message)


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


class TemplateProviderP2P(TemplateP2P):
    """P2P interface that acts as a template provider.

    Responds to the node's gettmplt with a pre-built tmplt message, and
    to gettmplttxn with the requested transactions.
    """

    def __init__(self):
        super().__init__()
        self.template_txs = []      # list of CTransaction in template order
        self.template_msg = None     # msg_tmplt to send
        self.gettmplt_received = []
        self.gettmplttxn_received = []

    def set_template(self, txs, tmplt_msg):
        """Arm the provider with a template."""
        self.template_txs = txs
        self.template_msg = tmplt_msg

    def on_gettmplt(self, message):
        self.gettmplt_received.append(message)
        if self.template_msg:
            self.send_without_ping(self.template_msg)

    def on_gettmplttxn(self, message):
        self.gettmplttxn_received.append(message)
        # Respond with the requested transactions
        resp = msg_tmplttxn()
        resp.template_hash = message.template_hash
        resp.transactions = [self.template_txs[i] for i in message.positions]
        self.send_without_ping(resp)

    def wait_for_gettmplt(self, count=1, timeout=60):
        self.wait_until(lambda: len(self.gettmplt_received) >= count, timeout=timeout)

    def wait_for_gettmplttxn(self, count=1, timeout=60):
        self.wait_until(lambda: len(self.gettmplttxn_received) >= count, timeout=timeout)


class SendTemplateTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.test_disabled()
        self.test_chunked_tmplttxn()
        self.test_out_of_range_disconnect()
        self.test_template_eviction()
        self.test_receive_template_mempool()
        self.test_receive_template_partial_match()
        self.test_inbound_rotation()

    def test_disabled(self):
        """Test that BIN25-2.1 is not announced when templates are disabled."""
        node = self.nodes[0]

        self.log.info("Test -sendtemplate=0 disables feature announcement")
        self.restart_node(0, extra_args=["-sendtemplate=0"])
        node.setmocktime(int(time.time()))
        peer = node.add_p2p_connection(FeatureProbeP2P())
        peer.sync_with_ping()
        has_bin25 = any(f.feature_id == BIN25_2_1_FEATURE for f in peer.features_received)
        assert not has_bin25, "BIN25-2.1 should not be announced with -sendtemplate=0"
        peer.peer_disconnect()
        peer.wait_for_disconnect()

        self.log.info("Test -blocksonly disables feature announcement")
        self.restart_node(0, extra_args=["-blocksonly"])
        node.setmocktime(int(time.time()))
        peer = node.add_p2p_connection(FeatureProbeP2P())
        peer.sync_with_ping()
        has_bin25 = any(f.feature_id == BIN25_2_1_FEATURE for f in peer.features_received)
        assert not has_bin25, "BIN25-2.1 should not be announced in -blocksonly mode"
        peer.peer_disconnect()
        peer.wait_for_disconnect()

        self.log.info("Test normal mode announces BIN25-2.1")
        self.restart_node(0)
        node.setmocktime(int(time.time()))
        peer = node.add_p2p_connection(FeatureProbeP2P())
        peer.sync_with_ping()
        has_bin25 = any(f.feature_id == BIN25_2_1_FEATURE for f in peer.features_received)
        assert has_bin25, "BIN25-2.1 should be announced in normal mode"
        peer.peer_disconnect()
        peer.wait_for_disconnect()

    def trigger_template_generation(self, peer):
        """Bump mocktime past the template update interval (with jitter headroom) and ping."""
        node = self.nodes[0]
        # Jittered interval is in [INTERVAL/2, INTERVAL*3/2), so bump past the max.
        node.bumpmocktime(TEMPLATE_UPDATE_INTERVAL * 3 // 2 + 1)
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

        self.log.info("Request template via gettmplt (deferred)")
        peer.send_without_ping(msg_gettmplt())

        self.log.info("Trigger template generation (sends deferred response)")
        self.trigger_template_generation(peer)

        tmpl_info = node.gettemplateinfo()
        self.log.info(f"Template info: {tmpl_info}")
        assert_greater_than(tmpl_info["templates"], 0)
        tx_count = tmpl_info["latest_template_tx"]
        assert_greater_than(tx_count, 50)

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

        # Get the template (deferred: request, then trigger generation)
        peer.send_without_ping(msg_gettmplt())
        self.trigger_template_generation(peer)
        peer.wait_for_tmplt()
        tmplt = peer.tmplt_received[0]
        tx_count = tmplt.tx_count

        self.log.info(f"Send gettmplttxn with position {tx_count} (out of range)")
        peer.send_without_ping(msg_gettmplttxn(tmplt.template_hash, [tx_count]))
        peer.wait_for_disconnect()
        self.log.info("Peer disconnected as expected")

    def test_template_eviction(self):
        self.log.info("Test template eviction with pending queue (time-based)")
        node = self.nodes[0]

        peer = node.add_p2p_connection(TemplateP2P())

        # Get a template and its hash (deferred)
        peer.send_without_ping(msg_gettmplt())
        self.trigger_template_generation(peer)
        peer.wait_for_tmplt()
        tmplt = peer.tmplt_received[0]
        original_hash = tmplt.template_hash

        self.log.info("Queue a gettmplttxn for the current template")
        positions = list(range(tmplt.tx_count))
        peer.send_and_ping(msg_gettmplttxn(original_hash, positions))

        # Snapshot: chunks sent so far (send_and_ping may have drained some)
        pre_eviction_count = len(peer.tmplttxn_received)

        self.log.info("Advance time past LOCAL_TEMPLATE_EXPIRY to expire the template")
        # Bump past 300s expiry. The cleanup sweep runs every ~30s in
        # ProcessMessages and trims templates older than LOCAL_TEMPLATE_EXPIRY.
        node.bumpmocktime(LOCAL_TEMPLATE_EXPIRY + TEMPLATE_UPDATE_INTERVAL + 1)
        peer.sync_with_ping()

        new_info = node.gettemplateinfo()
        self.log.info(f"After expiry: {new_info}")
        assert_equal(new_info["templates"], 0)

        # After eviction, no NEW tmplttxn for the original hash should arrive.
        for msg in peer.tmplttxn_received[pre_eviction_count:]:
            assert msg.template_hash != original_hash, \
                f"Received tmplttxn for evicted template {original_hash:064x}"

        self.log.info("Node handled eviction gracefully (no tmplttxn for evicted template)")

        peer.peer_disconnect()
        peer.wait_for_disconnect()


    def test_receive_template_mempool(self):
        """Test receiving a template from a peer and populating the mempool."""
        self.log.info("Test receive-side: peer provides template, node populates mempool")
        node = self.nodes[0]

        # Clear the mempool so we start fresh
        self.generate(node, 1)
        assert_equal(node.getmempoolinfo()["size"], 0)

        self.log.info("Create transactions (don't submit to node)")
        num_txs = 20
        txs = []
        for _ in range(num_txs):
            tx_info = self.wallet.create_self_transfer()
            txs.append(tx_info["tx"])

        self.log.info("Build template message from the transactions")
        tmplt_msg = build_tmplt(txs)
        self.log.info(f"Template: {num_txs} txs, hash={tmplt_msg.template_hash:064x}")

        self.log.info("Connect provider peer with BIN25-2.1 negotiation")
        provider = node.add_p2p_connection(TemplateProviderP2P())
        provider.set_template(txs, tmplt_msg)

        self.log.info("Wait for node to send gettmplt")
        # BIN25-2.1 sets m_next_gettmplt = now(). MaybeRequestTemplate fires
        # when now > m_next_gettmplt, so bump mocktime past it.
        node.bumpmocktime(1)
        provider.sync_with_ping()
        provider.wait_for_gettmplt()
        self.log.info(f"Received gettmplt: {provider.gettmplt_received[0]}")

        self.log.info("Wait for node to request missing transactions")
        # After receiving tmplt, node can't match any short IDs (empty mempool),
        # so it sends gettmplttxn for all positions. The provider auto-responds.
        node.bumpmocktime(1)
        provider.sync_with_ping()
        provider.wait_for_gettmplttxn()
        gettmplttxn = provider.gettmplttxn_received[0]
        self.log.info(f"Node requested {len(gettmplttxn.positions)} txs")
        assert_equal(len(gettmplttxn.positions), num_txs)
        assert_equal(gettmplttxn.template_hash, tmplt_msg.template_hash)

        self.log.info("Verify peer template is registered")
        # Need another ping to process the tmplttxn response and finalize
        node.bumpmocktime(1)
        provider.sync_with_ping()
        tmpl_info = node.gettemplateinfo()
        self.log.info(f"Template info: {tmpl_info}")
        assert_greater_than(tmpl_info["peer_templates"], 0)

        self.log.info("Drive mempool population via ConsiderTemplateTransactions")
        # Each ProcessMessages call submits one tx. Bump mocktime each
        # iteration to ensure time-gated checks pass.
        def mempool_populated():
            node.bumpmocktime(1)
            return node.getmempoolinfo()["size"] >= num_txs
        provider.wait_until(mempool_populated, timeout=60)

        mempool_size = node.getmempoolinfo()["size"]
        self.log.info(f"Mempool populated: {mempool_size} txs")
        assert_equal(mempool_size, num_txs)

        # Verify the right txids ended up in the mempool
        mempool_txids = set(node.getrawmempool())
        expected_txids = {tx.txid_hex for tx in txs}
        assert_equal(mempool_txids, expected_txids)

        provider.peer_disconnect()
        provider.wait_for_disconnect()

    def test_receive_template_partial_match(self):
        """Test that short ID matching works for txs already in the mempool."""
        self.log.info("Test receive-side: partial match via short IDs")
        node = self.nodes[0]

        # Clear the mempool
        self.generate(node, 1)
        assert_equal(node.getmempoolinfo()["size"], 0)

        self.log.info("Create transactions")
        num_txs = 10
        txs = []
        for _ in range(num_txs):
            tx_info = self.wallet.create_self_transfer()
            txs.append(tx_info["tx"])

        self.log.info("Submit first half to node's mempool")
        num_presubmit = num_txs // 2
        for tx in txs[:num_presubmit]:
            node.sendrawtransaction(tx.serialize_with_witness().hex())
        assert_equal(node.getmempoolinfo()["size"], num_presubmit)

        self.log.info("Build template from all transactions")
        tmplt_msg = build_tmplt(txs)

        self.log.info("Connect provider peer")
        provider = node.add_p2p_connection(TemplateProviderP2P())
        provider.set_template(txs, tmplt_msg)

        self.log.info("Wait for gettmplt and gettmplttxn")
        node.bumpmocktime(1)
        provider.sync_with_ping()
        provider.wait_for_gettmplt()

        # Node processes tmplt, matches pre-submitted txs by short ID,
        # requests only the missing ones.
        node.bumpmocktime(1)
        provider.sync_with_ping()
        provider.wait_for_gettmplttxn()
        gettmplttxn = provider.gettmplttxn_received[0]
        num_requested = len(gettmplttxn.positions)
        self.log.info(f"Node requested {num_requested} txs (had {num_presubmit} already)")
        # Should only request the txs not already in the mempool
        assert_equal(num_requested, num_txs - num_presubmit)

        self.log.info("Drive mempool population for remaining txs")
        node.bumpmocktime(1)
        provider.sync_with_ping()  # finalize the peer template
        def mempool_populated():
            node.bumpmocktime(1)
            return node.getmempoolinfo()["size"] >= num_txs
        provider.wait_until(mempool_populated, timeout=60)

        mempool_size = node.getmempoolinfo()["size"]
        self.log.info(f"Mempool populated: {mempool_size} txs")
        assert_equal(mempool_size, num_txs)

        mempool_txids = set(node.getrawmempool())
        expected_txids = {tx.txid_hex for tx in txs}
        assert_equal(mempool_txids, expected_txids)

        provider.peer_disconnect()
        provider.wait_for_disconnect()

    def get_active_template_peers(self, node):
        """Return set of peer IDs with template_status == 'active' from getpeerinfo."""
        return {p["id"] for p in node.getpeerinfo() if p.get("template_status") == "active"}

    def test_inbound_rotation(self):
        """Test that inbound peer selection rotates among eligible peers."""
        self.log.info("Test inbound template peer rotation")
        node = self.nodes[0]

        # Restart to get a clean peer state
        self.restart_node(0)
        node.setmocktime(int(time.time()))

        # Ensure we have a template for the node to request
        self.generate(self.wallet, 1)
        self.wallet.send_self_transfer(from_node=node)

        self.log.info("Connect 15 inbound peers with BIN25-2.1 support")
        num_peers = 15
        peers = []
        for _ in range(num_peers):
            peer = node.add_p2p_connection(TemplateProviderP2P())
            peer.sync_with_ping()
            peers.append(peer)

        # Trigger template generation so the node has something to request
        node.bumpmocktime(TEMPLATE_UPDATE_INTERVAL * 2)
        peers[0].sync_with_ping()

        # All peers have m_next_gettmplt = now() from feature negotiation,
        # so the first bump should activate exactly MAX_INBOUND_TEMPLATE_PEERS.
        self.log.info("Bump mocktime to trigger initial activation")
        node.bumpmocktime(1)
        for peer in peers:
            peer.sync_with_ping()

        active = self.get_active_template_peers(node)
        self.log.info(f"Initially active: {len(active)} peers {active}")
        assert_equal(len(active), MAX_INBOUND_TEMPLATE_PEERS)

        # Advance time in 30s increments. Each bump may trigger request cycles
        # for peers whose jittered timer has expired. With 1/8 deactivation
        # probability per cycle and 10 active peers, we expect ~1.25 rotations
        # per cycle. Track which peer IDs have ever been active.
        self.log.info("Run cycles with 30s increments to observe rotation")
        ever_active = set(active)
        for cycle in range(80):
            node.bumpmocktime(30)
            for peer in peers:
                peer.sync_with_ping()

            active = self.get_active_template_peers(node)
            ever_active |= active

            # Active count should never exceed MAX_INBOUND_TEMPLATE_PEERS
            assert_greater_than(MAX_INBOUND_TEMPLATE_PEERS + 1, len(active))

            if len(ever_active) == num_peers:
                self.log.info(f"All {num_peers} peers activated after {cycle + 1} cycles")
                break

        self.log.info(f"Ever active: {len(ever_active)} peers")
        assert_equal(len(ever_active), num_peers)

        for peer in peers:
            peer.peer_disconnect()
            peer.wait_for_disconnect()


if __name__ == '__main__':
    SendTemplateTest(__file__).main()
