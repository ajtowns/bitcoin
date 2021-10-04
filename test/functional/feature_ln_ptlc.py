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
from test_framework.key import generate_privkey, compute_xonly_pubkey, sign_schnorr, tweak_add_privkey, ECKey, ECPubKey, SECP256K1_ORDER, SECP256K1_G, SECP256K1
from test_framework.bip32 import BIP32, bip32_tests
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
from typing import Tuple
from dataclasses import dataclass
import struct

###### key functions

def MakeECKey(secret):
    k = ECKey()
    k.set(secret, compressed=True)
    return k

def MakeECPubKey(b):
    k = ECPubKey()
    k.set(b)
    return k

def keystr(k):
    if isinstance(k, ECKey):
        k = k.get_pubkey()
    return hexlify(k.get_bytes()).decode('utf8')

###### stuff

def partial_schnorr_sign(partialkey, pubkey, msg, partialnonce, pubnonce):
    assert len(partialkey) == 32
    assert len(pubkey) == 32
    assert len(msg) == 32
    assert len(partialnonce) == 32
    assert len(pubnonce) == 32

    # note that these points may not have even y
    sec = int.from_bytes(partialkey, 'big')
    if sec == 0 or sec >= SECP256K1_ORDER:
        return None
    nonce = int.from_bytes(privnonce, 'big')
    if nonce == 0 or nonce >= SECP256K1_ORDER:
        return None

    # these points do have even y though
    P = SECP256K1.lift_x(pubkey)
    if P is None:
        return None
    R = SECP256K1.lift_x(pubnonce)
    if R is None:
        return None

    e = int.from_bytes(TaggedHash("BIP0340/challenge", pubnonce + pubkey + msg), 'big') % SECP256K1_ORDER
    return ((nonce + e * sec) % SECP256K1_ORDER).to_bytes(32, 'big')

def partial_schnorr_verify(partialkey, pubkey, msg, partialnonce, pubnonce, sig_s):
    assert len(partialkey) == 33
    assert len(pubkey) == 32
    assert len(msg) == 32
    assert len(partialnonce) == 33
    assert len(sig_s) == 32

    # these points are fully specified
    Pa = ECPubKey()
    Pa.set(partialkey)
    assert Pa.is_valid and Pa.compressed
    Ra = ECPubKey()
    Ra.set(partialnonce)
    assert Ra.is_valid and Ra.compressed

    # these points must have even y
    P = SECP256K1.lift_x(pubkey)
    if P is None:
        return None
    R = SECP256K1.lift_x(pubnonce)
    if R is None:
        return None

    s = int.from_bytes(sig_s, 'big')
    if s >= SECP256K1_ORDER:
        return False

    e = int.from_bytes(TaggedHash("BIP0340/challenge", pubnonce + pubkey + msg), 'big') % SECP256K1_ORDER
    Ra_calc = SECP256K1.mul([(SECP256K1_G, s), (Pa, SECP256K1_ORDER - e)])
    return SECP256K1.affine(Ra.key) == SECP256K1.affine(Ra_calc)

class RevocableSecret:
    max_ceiling = 10000
    def __init__(self, seed, ceiling=None):
        if ceiling is None:
            ceiling = self.max_ceiling
        assert 0 <= ceiling <= self.max_ceiling
        assert isinstance(seed, bytes) and len(seed) == 32
        self.seed = seed
        self.ceiling = ceiling

    def get(self, level):
        assert level < self.ceiling
        d = self.seed
        for _ in range(self.ceiling - self.level):
            d = hashlib.sha256(d).digest()
        return d

    def __eq__(self, other):
        m = min(self.ceiling, other.ceiling)
        return self.get(m) == other.get(m)

class RevocableSecret2:
    def __init__(self, i, j, seed1, seed2):
        self.top = RevocableSecret(seed1, i)
        self.sec = RevocableSecret(seed2, j)

    def _secseeder(self, i):
        return RevocableSecret(self.top.get(i))

    def get(self, i, j=None):
        if j is None:
            return self.top.get(i)
        elif i == self.top.ceiling:
            return self.sec.get(j)
        else:
            return _secseeder(i).get(j)

    def __eq__(self, other):
        if self.top != other.top:
            return False

        if self.top.ceiling == other.top.ceiling:
            return self.sec == other.sec
        elif self.top.ceiling < other.top.ceiling:
            return self.sec == other._secseeder(self.top.ceiling)
        else:
            return self._secseeder(other.top.ceiling) == other.sec

class DeterministicNonce:
    def __init__(self, seed):
        self.seed = hashlib.sha256(d).digest()

    def nonce(self, *path):
        d = self.seed
        for p in path:
            d = hashlib.sha256(d + struct.patck("<L", p)).digest()
        return d

class MuSig:
    def __init__(self, keys, mul, tweak):
        self.keys = keys
        self.mul = mul
        self.tweak = tweak

        # P = sum(mul*(key + tweak*G))
        #   = sum(mul*key) + sum(mul*tweak)*G
        pts = [k.neuter().key.p for k in keys]
        mt = sum(m*t for m, t in zip(mul, tweak))
        p = SECP256K1.mul([(p, m) for m, p in zip(mul, pts)] + [(SECP256K1_G, mt)])

        if not SECP256K1.has_even_y(p):
            # negate everything
            p = SECP256K1.negate(p)
            self.mul = [(SECP256K1_ORDER - n) for n in self.mul]

        k = ECPubKey()
        k.p = p
        k.valid = True
        k.compressed = True
        self.pubkey = k

class MuSigBase:
    def __init__(self, *keys):
        assert len(keys) >= 1
        assert all(isinstance(k, BIP32) for k in keys)
        self.keys = keys

    def derive(self, *path):
        d_tweak = []
        d_keys = []
        for k in self.keys:
            tweak = 0
            for p in path:
                k, t = k.derive(p)
                tweak = (tweak + t) % SECP256K1_ORDER
            d_tweak.append(tweak)
            d_keys.append(k)

        basehash = hashlib.sha256(b"".join([k.neuter().key.get_bytes() for k in d_keys]))
        d_mul = []
        for i, k in enumerate(d_keys):
            h = basehash.copy()
            h.update(struct.pack("<L", i))
            n = int.from_bytes(h.digest(), 'big') % SECP256K1_ORDER
            d_mul.append(n)

        return MuSig(d_keys, d_mul, d_tweak)

@dataclass
class ChannelSecrets:
    def __init__(self, seed):
        self.deterministic_secret = DeterministicNonce(seed + b"det")
        self.balance_secret = RevocableSecret(hashlib.sha256(seed + b"rec"))

@dataclass
class ChannelParams:
    musigbase: MuSigBase
    delay: int
    # secrets? my secrets, their secrets?
    # maybe keep that separate and deal with updating?
    # this is so complicated

@dataclass
class ChannelBalance:
    params: ChannelParams
    f: int  # funding version
    n: int  # balance version
    bal: Tuple[int, int]
    funding: COutPoint

    # these should probably be post_init?
    def balance_output(self, who):
        assert who == 0 or who == 1
        k = self.params.musigbase.keys[who].neuter().derive(1, self.n)[0].key.get_bytes()
        assert len(k) == 33
        scr = CScript([k[1:], OP_CHECKSIGVERIFY, self.params.delay, OP_CHECKSEQUENCEVERIFY])
        ipk = self.params.musigbase.derive(1,self.n,who).pubkey.get_bytes()
        assert len(ipk) == 33
        return taproot_construct(ipk[1:], [("csv", scr)])

    def build_tx(self):
        tx = CTransaction()
        tx.vin = [CTxIn(self.funding, nSequence=0)]
        tx.vout = [
            CTxOut(self.bal[0], self.balance_output(0).scriptPubKey),
            CTxOut(self.bal[1], self.balance_output(1).scriptPubKey),
        ]
        tx.nLockTime = 0
        return tx

class Channel:
    def __init__(self, mykey, theirkey):
        if mykey.neuter().key.get_bytes()[1:] < theirkey.neuter().key.get_bytes()[1:]:
            i, keys = 0, [mykey, theirkey]
        else:
            i, keys = 1, [theirkey, mykey]
        self.musigbase = MuSigBase(*keys)
        self.idx = i

        self.secrets = ChannelSecrets(b"channel" + bytes(i))
        self.state = ChannelState(0, [0,0])


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

# musig2signing:
#     `-- calculates the musig2 nonce
#     `-- accepts nonce offsets for adaptor sigs
#     `-- does partial sigs
#     `-- recovers privatekey given known nonce secret
#     `-- validates partial sigs
# (maybe musig2 nonce calc gets split out too)

# taproot
#     `-- take a musig and a path for ipk
#     `-- be able to get back to the musig for "tweaking" the privkey
#     `-- also add script paths
#     `-- sign for the script paths, basically specifying the path and
#         the key and the various flags manually?

###### test

alice = MakeECKey(b'a'*32)
bob = MakeECKey(b'b'*32)

alice = BIP32(b"alice", public=False)
bob = BIP32(b"bob", public=False)

class LNPTLCTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        bip32_tests()

        self.log.info("Hello... %s %s" % (keystr(alice.key), keystr(bob.key)))

        bxonly = bob.neuter().key.get_bytes()[1:]
        assert len(bxonly) == 32
        msg = b"m" * 32
        sig = sign_schnorr(bxonly, msg)
        self.log.info("sig %s" % (hexlify(sig).decode('utf8')))

        cp = ChannelParams(MuSigBase(alice, bob), delay=144)
        f1 = COutPoint(100000, 3)
        bal =  ChannelBalance(cp, 0, 1, (5000, 5000), f1)

        tx = bal.build_tx()
        print(tx)
        print(tx.serialize().hex())

if __name__ == '__main__':
    LNPTLCTest().main()
