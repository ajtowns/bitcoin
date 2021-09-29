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
from test_framework.key import generate_privkey, compute_xonly_pubkey, sign_schnorr, tweak_add_privkey, ECKey, ECPubKey
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

    sec = int.from_bytes(partialkey, 'big')
    if sec == 0 or sec >= SECP256K1_ORDER:
        return None

    nonce = int.from_bytes(privnonce, 'big')
    if nonce == 0 or nonce >= SECP256K1_ORDER:
        return None

    P = SECP256K1.lift_x(pubkey)
    if P is None or not SECP256K1.has_even_y(P):
        return None
    R = SECP256K1.lift_x(pubnonce)
    if R is None or not SECP256K1.has_even_y(R):
        return None

    e = int.from_bytes(TaggedHash("BIP0340/challenge", pubnonce + pubkey + msg), 'big') % SECP256K1_ORDER
    return R[0].to_bytes(32, 'big') + ((nonce + e * sec) % SECP256K1_ORDER).to_bytes(32, 'big')

def partial_schnorr_verify(partialkey, pubkey, msg, partialnonce, pubnonce):
    assert len(partialkey) == 32
    assert len(pubkey) == 32
    assert len(msg) == 32
    assert len(partialnonce) == 32

# pubkeys: musig(alice, bob)
#     `-- accepts 1+ pubkeys
#     `-- does musig calcs if >1 pubkey
#     `-- does bip32 paths
#     `-- spits out the multiplier to sign with
#     `-- spits out addresses

# musig2signing:
#     `-- calculates the musig2 nonce
#     `-- accepts nonce offsets for adaptor sigs
#     `-- does partial sigs
#     `-- recovers privatekey given known nonce secret
#     `-- validates partial sigs
# (maybe musig2 nonce calc gets split out too)

# revocable secrets
#     `-- generate at two levels
#     `-- validate consistency at both levels
#     `-- generated deterministic secrets for own nonces as well

# taproot
#     `-- take a musig and a path for ipk
#     `-- be able to get back to the musig for "tweaking" the privkey
#     `-- also add script paths
#     `-- sign for the script paths, basically specifying the path and
#         the key and the various flags manually?

# create funding tx
#   - set i=funding round, pay to P/0/i
#   - whatever

# create balance tx
#   - spens funding tx, two balances

# create inflight tx
#   - whose balance is it spending
#   - their balance, counterparty balance
#   - htlcs, ptlcs

###### test

alice = MakeECKey(b'a'*32)
bob = MakeECKey(b'b'*32)

alice = MakeECPubKey(unhexlify('023e4740d0ba639e28963f3476157b7cf2fb7c6fdf4254f97099cf8670b505ea59'))

bip32 = BIP32(unhexlify(b"000102030405060708090a0b0c0d0e0f"), public=True)



class LNPTLCTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        self.log.info("Hello... %s %s" % (keystr(alice), keystr(bob)))

        self.log.info("b32: %s" % (bip32))
        self.log.info("want: %s" % ("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"))

        bip32_tests()

if __name__ == '__main__':
    LNPTLCTest().main()
