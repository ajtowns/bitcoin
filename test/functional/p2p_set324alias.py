#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test BIP324 one-byte message type id reassignment via SET324ALIAS."""

from test_framework.messages import (
    BIP324Alias,
    msg_feature,
    msg_getaddr,
    msg_ping,
    msg_sendaddrv2,
    msg_set324alias,
    msg_verack,
    msg_wtxidrelay,
)
from test_framework.p2p import (
    MIN_P2P_VERSION_SUPPORTED,
    P2PInterface,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

# The SET324ALIAS feature id bitcoind advertises (NetMsgFeature::SET324ALIAS).
SET324ALIAS_FEATURE_ID = "https://github.com/ajtowns/bitcoin/tree/202605-bip324-id"

# One-byte message types to reassign ping/pong to. Deliberately distinct from the
# BIP324 default table, where ping=18 and pong=19.
PING_ID = 128
PONG_ID = 129


class Set324AliasPeer(P2PInterface):
    """A v2 peer that advertises the feature, reassigns ping/pong, and records
    the feature advertisement, peer's set324alias and pong it receives."""

    def __init__(self):
        super().__init__()
        self.feature = None
        self.set324alias = None
        self.pong = None

    def on_version(self, message):
        # Mirror the base on_version, but advertise willingness to accept
        # SET324ALIAS-based messages within the version..verack window (the
        # advertisement must precede our verack).
        assert message.nVersion >= MIN_P2P_VERSION_SUPPORTED, "Version {} received. Test framework only supports versions greater than {}".format(message.nVersion, MIN_P2P_VERSION_SUPPORTED)
        if not self.p2p_connected_to_node:
            self.send_version()
            self.reconnect = False
        if message.nVersion >= 70016 and self.wtxidrelay:
            self.send_without_ping(msg_wtxidrelay())
        if self.support_addrv2:
            self.send_without_ping(msg_sendaddrv2())
        self.send_without_ping(msg_feature(SET324ALIAS_FEATURE_ID, b""))
        self.send_without_ping(msg_verack())
        self.nServices = message.nServices
        self.relay = message.relay
        if self.p2p_connected_to_node:
            self.send_without_ping(msg_getaddr())

    def on_feature(self, message):
        self.feature = message

    def on_verack(self, message):
        # BIP 434: the feature advertisement must be sent between version and
        # verack, so by the time bitcoind's verack arrives we must already have
        # received its SET324ALIAS feature advertisement.
        assert self.feature is not None, "received verack before the SET324ALIAS feature advertisement"

    def on_set324alias(self, message):
        self.set324alias = message

    def on_pong(self, message):
        self.pong = message


class P2PSet324AliasTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        # set324alias only applies to v2-transport peers, so force v2.
        self.extra_args = [["-v2transport=1", "-debug=net"]]

    def run_test(self):
        peer = self.nodes[0].add_p2p_connection(Set324AliasPeer(), supports_v2_p2p=True)
        # add_p2p_connection runs sync_with_ping(), whose pongs our on_pong
        # records; clear those so we only assert on the reply to our own ping.
        peer.pong = None

        # The on_verack assertion above guarantees bitcoind's feature was
        # received before its verack; check it is the SET324ALIAS feature.
        assert_equal(peer.feature.feature_id, SET324ALIAS_FEATURE_ID)

        # Declare the mapping we will use for our outbound messages.
        peer.send_without_ping(msg_set324alias(vec=[
            BIP324Alias(PING_ID, b"ping"),
            BIP324Alias(PONG_ID, b"pong"),
        ]))

        # Send a ping encoded as a single-byte message type 128, bypassing
        # build_message (which would use the default table id 18). build_message
        # would also handle the v2 packet framing, so replicate it here.
        nonce = 0x1122334455667788
        tmsg = bytes([PING_ID]) + msg_ping(nonce=nonce).serialize()
        peer.send_raw_message(peer.v2_state.v2_enc_packet(tmsg))

        # bitcoind must have decoded id 128 as a ping and replied with a pong
        # echoing the nonce. If it did not apply the set324alias mapping, id 128 is
        # unknown and no pong is sent, so wait_until times out.
        self.wait_until(lambda: peer.pong is not None)
        assert_equal(peer.pong.nonce, nonce)


if __name__ == "__main__":
    P2PSet324AliasTest(__file__).main()
