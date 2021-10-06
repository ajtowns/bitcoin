#!/usr/bin/env python3
# Copyright (c) 2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test-only musig/musig2 implementation"""

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

###### key functions

def MakeECKey(secret):
    k = ECKey()
    k.set(secret, compressed=True)
    return k

def MakeECPubKey(b):
    k = ECPubKey()
    k.set(b)
    return k

###### stuff

def partial_schnorr_sign(pubnonce : bytes, pubkey : bytes, msg : bytes, partialkey : int, partialnonce : int):
    assert len(pubnonce) == 32
    assert len(pubkey) == 32
    assert len(msg) == 32

    # note that these points may not have even y
    if partialkey <= 0 or partialkey >= SECP256K1_ORDER:
        return None
    if partialnonce is None:
        # used for adding the taproot tweak to a signature
        partialnonce = 0
    elif partialnonce <= 0 or partialnonce >= SECP256K1_ORDER:
        return None

    # these points do have even y though
    if SECP256K1.lift_x(int.from_bytes(pubkey, 'big')) is None:
        return None
    if SECP256K1.lift_x(int.from_bytes(pubnonce, 'big')) is None:
        return None

    e = int.from_bytes(TaggedHash("BIP0340/challenge", pubnonce + pubkey + msg), 'big') % SECP256K1_ORDER
    return ((partialnonce + e * partialkey) % SECP256K1_ORDER).to_bytes(32, 'big')

def partial_schnorr_verify(pubnonce : bytes, pubkey : bytes, msg : bytes, partialkey : ECPubKey, partialnonce : ECPubKey, sig_s : bytes):
    assert len(pubnonce) == 32
    assert len(pubkey) == 32
    assert len(msg) == 32
    assert len(sig_s) == 32

    # these points are fully specified
    assert partialkey.is_valid and partialkey.compressed
    assert partialnonce.is_valid and partialnonce.compressed

    # these points must have even y
    if SECP256K1.lift_x(pubkey) is None:
        return False
    if SECP256K1.lift_x(pubnonce) is None:
        return False

    s = int.from_bytes(sig_s, 'big')
    if s >= SECP256K1_ORDER:
        return False

    e = int.from_bytes(TaggedHash("BIP0340/challenge", pubnonce + pubkey + msg), 'big') % SECP256K1_ORDER
    pnonce_calc = SECP256K1.mul([(SECP256K1_G, s), (partialkey.p, SECP256K1_ORDER - e)])
    return SECP256K1.affine(partialnonce.p) == SECP256K1.affine(pnonce_calc)

class MuSig:
    def __init__(self, keys, tweak):
        # tweak can be used to recover the master key
        self.keys = keys
        self.tweak = tweak

        # calculate the musig multipliers
        basehash = hashlib.sha256(b"".join([k.neuter().key.get_bytes() for k in keys]))
        mul = []
        for i, k in enumerate(keys):
            h = basehash.copy()
            h.update(struct.pack("<L", i))
            mul.append(int.from_bytes(h.digest(), 'big') % SECP256K1_ORDER)

        p = SECP256K1.mul([(k.neuter().key.p, m) for k, m in zip(keys, mul)])
        p = SECP256K1.affine(p)
        if not SECP256K1.has_even_y(p):
            # negate result by negating all the multipliers
            p = SECP256K1.negate(p)
            self.mul = [(SECP256K1_ORDER - n) for n in mul]
            self.negated = True
        else:
            self.negated = False
            self.mul = mul
        del mul

        k = ECPubKey()
        k.p = p
        k.valid = True
        k.compressed = True
        self.pubkey = k

        # multiply the keys
        self.pts = []
        for i, (k, m) in enumerate(zip(keys, self.mul)):
            if isinstance(k.key, ECPubKey):
                p = SECP256K1.mul([(k.key.p, m)])
            else:
                p = (k.key.secret * m) % SECP256K1_ORDER
            self.pts.append(p)

    def xonly(self):
        assert self.pubkey.get_bytes()[0] == 0x02
        return self.pubkey.get_bytes()[1:]

class MuSigBase:
    def __init__(self, *keys):
        assert len(keys) >= 1
        assert all(isinstance(k, BIP32) for k in keys)
        self.keys = keys

    def derive(self, *path):
        d_tweak = []
        d_keys = []
        for k in self.keys:
            c, t = k.derive(*path)
            d_keys.append(c)
            d_tweak.append(t)
        return MuSig(d_keys, d_tweak)

@dataclass
class MuSig2:
    musig: MuSig
    msg: Optional[bytes] = None
    pubkeytweak: Optional[Tuple[bool, int]] = None
    secretpairs: List[Optional[Tuple[bytes, bytes]]] = field(default_factory=list)
    noncepairs: List[Optional[Tuple[ECPubKey, ECPubKey]]] = field(default_factory=list)
    b: Optional[int] = None
    r: Optional[int] = None
    h: Optional[bytes] = None
    partial: List[Optional[bytes]] = field(default_factory=list)
    extra: Optional[bytes] = None
    sig: Optional[bytes] = None

    def __post_init__(self):
        n = len(self.musig.keys)
        self.secretpairs += [None] * (n - len(self.secretpairs))
        self.noncepairs += [None] * (n - len(self.noncepairs))
        self.partial += [None] * (n - len(self.partial))

    def set_secret(self, i, r1, r2):
        assert 0 <= i < len(self.musig.keys)
        self.secretpairs[i] = (r1, r2)
        self.set_nonce(i, MakeECKey(r1).get_pubkey(), MakeECKey(r2).get_pubkey())

    def set_nonce(self, i, r1g : ECPubKey, r2g : ECPubKey):
        self.noncepairs[i] = (r1g, r2g)
        self.b = None
        self.partial = [None]*len(self.musig.keys)
        self.sig = None

    def set_msg(self, msg):
        self.msg = msg
        self.partial = [None]*len(self.musig.keys)
        self.sig = None

    def calc_b_r(self):
        assert all(i is not None for i in self.noncepairs)
        assert self.msg is not None
        assert len(self.msg) == 32
        pk = self.musig.pubkey.get_bytes()
        assert len(pk) == 33

        hasher = hashlib.sha256()
        hasher.update(pk)
        for r1, r2 in self.noncepairs:
            hasher.update(r1.get_bytes())
            hasher.update(r2.get_bytes())
        hasher.update(self.msg)
        self.b = int.from_bytes(hasher.digest(), 'big') % SECP256K1_ORDER
        pt_r = ECPubKey()
        pt_r.p = SECP256K1.mul(
                     [(r1.p, 1) for r1, _ in self.noncepairs] +
                     [(r2.p, self.b) for _, r2 in self.noncepairs]
                 )
        pt_r.compressed = True
        pt_r.valid = SECP256K1.on_curve(pt_r.p)
        assert pt_r.valid
        self.r = pt_r.get_bytes()

    def calc_pubkey(self):
        p = self.musig.pubkey.get_bytes()
        assert p[0] == 0x02 and len(p) == 33
        if self.pubkeytweak is not None:
            neg = -1 if self.pubkeytweak[0] else +1
            p = SECP256K1.lift_x(int.from_bytes(p[1:], 'big'))
            t = (SECP256K1_ORDER + neg*self.pubkeytweak[1]) % SECP256K1_ORDER
            p = SECP256K1.mul([(p, neg), (SECP256K1_G, t)])
            p = SECP256K1.affine(p)
            p = bytes([0x02]) + p[0].to_bytes(32, 'big')
        return p

    def calc_sig(self):
        assert all(p is not None for p in self.partial)

        s = sum(int.from_bytes(p, 'big') for p in self.partial) % SECP256K1_ORDER
        if self.pubkeytweak is not None:
             key = self.pubkeytweak[1]
             p = self.calc_pubkey()
             extra_s = partial_schnorr_sign(self.r[1:], p[1:], self.msg, key, None)
             s = (s + int.from_bytes(extra_s, 'big')) % SECP256K1_ORDER
             if self.pubkeytweak[0]:
                 s = SECP256K1_ORDER - s

        return self.r[1:] + s.to_bytes(32, 'big')

    def calc_partial(self, i):
        assert isinstance(self.musig.pts[i], int)
        assert self.secretpairs[i] is not None
        assert self.b is not None and self.r is not None

        r1, r2 = self.secretpairs[i]
        r1 = int.from_bytes(r1, 'big')
        r2 = int.from_bytes(r2, 'big')

        key = self.musig.pts[i]

        my_r = (r1 + self.b * r2) % SECP256K1_ORDER
        assert len(self.r) == 33
        if self.r[0] == 0x03:
            my_r = SECP256K1_ORER - my_r

        p = self.calc_pubkey()
        self.partial[i] = partial_schnorr_sign(self.r[1:], p[1:], self.msg, key, my_r)

    def set_partial(self, i, partial):
        assert self.b is not None and self.r is not None
        self.partial[i] = partial
        #if isinstance(self.musig.pts[i], int):
        #p = self.calc_pubkey()
        #if partial_schnorr_verify(self.r[1:], p[1:], self.msg, 
