#!/usr/bin/env python3
# Copyright (c) 2019-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
# Test Taproot softfork (BIPs 340-342)

from test_framework.blocktools import (
    COINBASE_MATURITY,
    create_coinbase,
    create_block,
    add_witness_commitment,
    MAX_BLOCK_SIGOPS_WEIGHT,
    NORMAL_GBT_REQUEST_PARAMS,
    WITNESS_SCALE_FACTOR,
)
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.script import (
    ANNEX_TAG,
    CScript,
    CScriptNum,
    CScriptOp,
    LEAF_VERSION_TAPSCRIPT,
    LegacySignatureHash,
    LOCKTIME_THRESHOLD,
    MAX_SCRIPT_ELEMENT_SIZE,
    OP_0,
    OP_1,
    OP_2DROP,
    OP_2DUP,
    OP_CHECKMULTISIG,
    OP_CHECKMULTISIGVERIFY,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_CHECKSIGADD,
    OP_CHECKSIGVERIFY,
    OP_CODESEPARATOR,
    OP_DROP,
    OP_DUP,
    OP_ELSE,
    OP_ENDIF,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_IF,
    OP_NOP,
    OP_NOT,
    OP_NOTIF,
    OP_PUSHDATA1,
    OP_RETURN,
    OP_SWAP,
    OP_VERIFY,
    SIGHASH_DEFAULT,
    SIGHASH_ALL,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SIGHASH_ANYONECANPAY,
    SegwitV0SignatureHash,
    TaprootSignatureHash,
    is_op_success,
    taproot_construct,
)
from test_framework.script_util import (
    key_to_p2wpkh_script,
    keyhash_to_p2pkh_script,
    script_to_p2sh_script,
    script_to_p2wsh_script,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error, assert_equal
from test_framework.key import generate_privkey, compute_xonly_pubkey, sign_schnorr, tweak_add_privkey, ECKey, ECPubKey, SECP256K1_ORDER, SECP256K1_G, SECP256K1, TaggedHash, verify_schnorr
from test_framework.bip32 import BIP32, bip32_tests
from test_framework.musig import MuSigBase, MuSig2, MakeECKey
from test_framework.address import (
    hash160,
)
from collections import OrderedDict, namedtuple
from io import BytesIO
import json
import hashlib
import os
import random
from binascii import hexlify, unhexlify
from typing import Tuple, Optional, List
from dataclasses import dataclass, field
import struct

###### stuff

@dataclass
class SecretPair:
    r1: bytes
    r2: bytes

    def __init__(self, seed):
        h = hashlib.sha256(seed).digest()
        self.r1 = hashlib.sha256(h + bytes([0])).digest()
        self.r2 = hashlib.sha256(h + bytes([1])).digest()

    def sec(self):
        return self.r1, self.r2

    def nonce(self):
        return MakeECKey(self.r1).get_pubkey(), MakeECKey(self.r2).get_pubkey()

@dataclass
class ChannelParams:
    musigbase: MuSigBase
    delay: int
    obscured_cn: int = 0xC011EC7AB1E5
    fees: int = 1000
    # secrets? my secrets, their secrets?
    # maybe keep that separate and deal with updating?
    # this is so complicated

@dataclass
class FundingTx:
    params: ChannelParams
    f: int  # funding version
    op: COutPoint # funding tx outpoint (txid, vout)
    value: int  # value (satoshis)

    def address(self):
        fk = self.params.musigbase.derive(0, self.f).pubkey.get_bytes()
        return taproot_construct(fk[1:], None)

    def txout(self):
        return CTxOut(self.value, self.address().scriptPubKey)

    def pubkeytweak(self):
        addr = self.address()
        return (addr.negflag, int.from_bytes(addr.tweak, 'big'))

@dataclass
class BalanceTx:
    params: ChannelParams
    funding: FundingTx
    n: int  # balance version
    bal: Tuple[int, int]

    def __post_init__(self):
        assert self.funding.value == sum(self.bal)

    def balance_output(self, who):
        assert who == 0 or who == 1
        k = self.params.musigbase.keys[who].neuter().derive(1, self.n)[0].key.get_bytes()
        assert len(k) == 33
        scr = CScript([k[1:], OP_CHECKSIGVERIFY, self.params.delay, OP_CHECKSEQUENCEVERIFY])
        ipk = self.params.musigbase.derive(1,self.n,who).pubkey.get_bytes()
        assert len(ipk) == 33
        return taproot_construct(ipk[1:], [("csv", scr)])

    def build_tx(self):
        obs_n = (self.n ^ (self.params.obscured_cn)) & 0xFFFFFFFFFFFF
        nseq = 0x80000000 | ((obs_n & 0xFFFFFF000000) >> 24)
        nlck = 0x20000000 | (obs_n & 0x000000FFFFFF)

        tx = CTransaction()
        tx.nLockTime = nlck
        tx.vin = [CTxIn(self.funding.op, nSequence=nseq)]
        tx.vout = [
            CTxOut(self.bal[0] - self.params.fees//2, self.balance_output(0).scriptPubKey),
            CTxOut(self.bal[1] - self.params.fees//2, self.balance_output(1).scriptPubKey),
        ]
        tx.wit.vtxinwit = [CTxInWitness()]
        return tx

    def build_msg(self):
        return TaprootSignatureHash(self.build_tx(), [self.funding.txout()], 0, input_index = 0, scriptpath = False, annex = None)

    def half_sign(self, index, secret, nonce):
        musig = self.params.musigbase.derive(0, self.funding.f)
        m2 = MuSig2(musig, self.build_msg(), pubkeytweak=self.funding.pubkeytweak())
        m2.set_secret(index, *secret)
        m2.set_nonce(1-index, *nonce)
        m2.calc_b_r()
        m2.calc_partial(index)
        return m2.partial[1]

    def complete_sign(self, index, secret, nonce, partial_sig):
        musig = self.params.musigbase.derive(0, self.funding.f)
        m2 = MuSig2(musig, self.build_msg(), pubkeytweak=self.funding.pubkeytweak())
        m2.set_secret(index, *secret)
        m2.set_nonce(1-index, *nonce)
        m2.calc_b_r()
        m2.set_partial(1-index, partial_sig)
        m2.calc_partial(index)
        sig = m2.calc_sig()
        tx = self.build_tx()
        tx.wit.vtxinwit[0].scriptWitness.stack = [sig]
        return tx

@dataclass
class InflightTx:
    params: ChannelParams
    balance: BalanceTx
    side: int
    bal: Tuple[int, int]


# make it work with just balance updates first, then add the p/htlcs
# should be SIMPLE DIMPLE

# channel
#    funding_tx  (pending_funding_tx for establishment, splicing)
#    balance_tx  (pending_balance_tx?)
#    update_tx
#    secret generation
#    signatures
#    bump balance/update
#    mutual close (special case of splicing? :)
#    unilateral close
#    punish

###### test

class LNPTLCTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        bip32_tests()

        alice = BIP32(b"alice2", public=False)
        bob = BIP32(b"bob", public=False)

        alice_pub = alice.neuter()
        bob_pub = bob.neuter()

        alice_sec = SecretPair(b"alicehorsebatterystaple")
        bob_sec = SecretPair(b"bobhorsebatterystaple")

        cp_pub = ChannelParams(MuSigBase(alice_pub, bob_pub), delay=144)
        fund = FundingTx(params=cp_pub,
                         f=0,
                         op=COutPoint(int("2821b06cc43229974f833c9eb0e4c85a586cee5c645eb8507e51ea7f5caf4547", 16), 0),
                         value=5000)

        # half sign balance by B
        cp_b = ChannelParams(MuSigBase(alice_pub, bob), delay=144)
        bal_b =  BalanceTx(params=cp_b, funding=fund, n=1, bal=(2500, 2500))
        bob_partial = bal_b.half_sign(1, bob_sec.sec(), alice_sec.nonce())

        # complete balance by A
        cp_a = ChannelParams(MuSigBase(alice, bob_pub), delay=144)
        bal_a =  BalanceTx(params=cp_a, funding=fund, n=1, bal=(2500, 2500))
        tx = bal_a.complete_sign(0, alice_sec.sec(), bob_sec.nonce(), bob_partial)

        self.log.info("Balance tx: %s" % (tx.serialize().hex()))

        # make these functions?
        #   - funding address
        #   - generate balance(params, fundinginfo, n, [bal, bal], fees)
        #     - recover secret from revoked balance sig [via det]
        #     - sign via csv delay
        #   - generate inflight
        #     - with ptlcs/htlcs
        #     - claim via revocation of 1st secret (old balance)
        #     - claim via revocation of 2nd secret (old inflight)
        #     - claim via timeout
        #     - claim via hash/point preimage
        #     - recover hash/point preimage

if __name__ == '__main__':
    LNPTLCTest().main()
