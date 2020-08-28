#!/usr/bin/env python3
# Copyright (c) 2010 ArtForz -- public domain half-a-node
# Copyright (c) 2012 Jeff Garzik
# Copyright (c) 2010-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import base64
import json
import struct
import sys
import time
import subprocess

from binascii import unhexlify
from io import BytesIO

sys.path.insert(0, "../test/functional/")

from test_framework.blocktools import WITNESS_COMMITMENT_HEADER, script_BIP34_coinbase_height # noqa: E402
from test_framework.messages import CBlock, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, FromHex, ToHex, deser_string, hash256, ser_compact_size, ser_string, ser_uint256, uint256_from_str # noqa: E402
from test_framework.script import CScriptOp

SIGNET_HEADER = b"\xec\xc7\xda\xa2"
PSBT_SIGNET_BLOCK = b'\xfc\x06signetb'    # proprietary use PSBT golbal field holding the block being signed

# like FromHex, but without the hex part
def FromBinary(cls, stream):
    '''deserialize a binary stream (or bytes object) into an object'''
    # handle bytes object by turning it into a stream
    was_bytes = isinstance(stream, bytes)
    if was_bytes:
        stream = BytesIO(stream)
    obj = cls()
    obj.deserialize(stream)
    if was_bytes:
        assert len(stream.read()) == 0
    return obj

class PSBTMap:
    """Class for serializing and deserializing PSBT maps"""

    def __init__(self, map=None):
        self.map = map if map is not None else {}

    def deserialize(self, f):
        m = {}
        while True:
            k = deser_string(f)
            if len(k) == 0:
                break
            v = deser_string(f)
            if len(k) == 1:
                k = k[0]
            assert k not in m
            m[k] = v
        self.map = m

    def serialize(self):
        m = b''
        for k,v in self.map.items():
            if isinstance(k, int) and 0 <= k and k <= 255:
                k = bytes([k])
            m += ser_compact_size(len(k)) + k
            m += ser_compact_size(len(v)) + v
        m += b'\x00'
        return m

class PSBT:
    """Class for serializing and deserializing PSBTs"""

    def __init__(self):
        self.g = PSBTMap()
        self.i = []
        self.o = []
        self.tx = None

    def deserialize(self, f):
        assert f.read(5) == b'psbt\xff'
        self.g = FromBinary(PSBTMap, f)
        assert 0 in self.g.map
        self.tx = FromBinary(CTransaction, self.g.map[0])
        self.i = [FromBinary(PSBTMap, f) for _ in self.tx.vin]
        self.o = [FromBinary(PSBTMap, f) for _ in self.tx.vout]
        return self

    def serialize(self):
        assert isinstance(self.g, PSBTMap)
        assert isinstance(self.i, list) and all(isinstance(x, PSBTMap) for x in self.i)
        assert isinstance(self.o, list) and all(isinstance(x, PSBTMap) for x in self.o)
        assert 0 in self.g.map
        tx = FromBinary(CTransaction, self.g.map[0])
        assert len(tx.vin) == len(self.i)
        assert len(tx.vout) == len(self.o)

        psbt = [x.serialize() for x in [self.g] + self.i + self.o]
        return b'psbt\xff' + b''.join(psbt)

    def to_base64(self):
        return base64.b64encode(self.serialize()).decode('utf8')

    @classmethod
    def from_base64(cls, b64psbt):
        return FromBinary(cls, base64.b64decode(b64psbt))

def gbt_height1(challenge):
    return {
        "version": 0x20000000,
        "previousblockhash": "0000032d7f67af9ec7b7152aea0fe7c95b9804ff973265e252f245e0ae61799d",
        "transactions": [],
        "coinbasevalue": 5000000000,
        "target": "00002adc28000000000000000000000000000000000000000000000000000000",
        "mintime": 1534313276,
        "noncerange": "00000000ffffffff",
        "sigoplimit": 80000,
        "sizelimit": 4000000,
        "weightlimit": 4000000,
        "curtime": time.time(),
        "bits": "1e2adc28",
        "height": 1,
        "signet_challenge": challenge,
        "default_witness_commitment": "6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9",
    }

def create_coinbase(height, value, spk):
    cb = CTransaction()
    cb.vin = [CTxIn(COutPoint(0, 0xffffffff), script_BIP34_coinbase_height(height), 0xffffffff)]
    cb.vout = [CTxOut(value, spk)]
    return cb

def pushdata(data):
    assert 1 < len(data) < 65536
    l = len(data)
    if l <= 75:
        push = bytes([l])
    elif l <= 255:
        push = bytes([76,l])
    elif l <= 65535:
        push = bytes([77,l%256,l//256])
    else:
        assert False
    return push + data

def get_witness_script(witness_root, witness_nonce):
    commitment = uint256_from_str(hash256(ser_uint256(witness_root) + ser_uint256(witness_nonce)))
    return b"\x6a" + pushdata(WITNESS_COMMITMENT_HEADER + ser_uint256(commitment))

def signet_txs(block, challenge):
    # assumes signet solution has not been added yet so does not need
    # to be removed

    txs = block.vtx[:]
    txs[0] = CTransaction(txs[0])
    txs[0].vout[-1].scriptPubKey += pushdata(SIGNET_HEADER)
    hashes = []
    for tx in txs:
        tx.rehash()
        hashes.append(ser_uint256(tx.sha256))
    mroot = block.get_merkle_root(hashes)

    sd = b""
    sd += struct.pack("<i", block.nVersion)
    sd += ser_uint256(block.hashPrevBlock)
    sd += ser_uint256(mroot)
    sd += struct.pack("<I", block.nTime)

    to_spend = CTransaction()
    to_spend.nVersion = 0
    to_spend.nLockTime = 0
    to_spend.vin = [CTxIn(COutPoint(0, 0xFFFFFFFF), b"\x00" + pushdata(sd), 0)]
    to_spend.vout = [CTxOut(0, challenge)]
    to_spend.rehash()

    spend = CTransaction()
    spend.nVersion = 0
    spend.nLockTime = 0
    spend.vin = [CTxIn(COutPoint(to_spend.sha256, 0), b"", 0)]
    spend.vout = [CTxOut(0, b"\x6a")]

    return spend, to_spend

def do_createpsbt(block, signme, spendme):
    psbt = PSBT()
    psbt.g = PSBTMap( {0: signme.serialize(),
                       PSBT_SIGNET_BLOCK: block.serialize()
                     } )
    psbt.i = [ PSBTMap( {0: spendme.serialize(),
                         3: bytes([1,0,0,0])})
             ]
    psbt.o = [ PSBTMap() ]
    return psbt.to_base64()

def do_decode_psbt(b64psbt):
    psbt = PSBT.from_base64(b64psbt)

    assert len(psbt.tx.vin) == 1
    assert len(psbt.tx.vout) == 1
    assert PSBT_SIGNET_BLOCK in psbt.g.map

    scriptSig = psbt.i[0].map.get(7, b'')
    scriptWitness = psbt.i[0].map.get(8, b'')

    return FromBinary(CBlock, psbt.g.map[PSBT_SIGNET_BLOCK]), ser_string(scriptSig) + scriptWitness

def signet_txs_from_template(cb_payout_address):
    tmpl = json.load(sys.stdin)
    signet_spk = tmpl["signet_challenge"]
    signet_spk_bin = unhexlify(signet_spk)

    if cb_payout_address is None:
        cb_payout_address = signet_spk_bin

    cbtx = create_coinbase(height=tmpl["height"], value=tmpl["coinbasevalue"], spk=cb_payout_address)
    cbtx.vin[0].nSequence = 2**32-2
    cbtx.rehash()

    block = CBlock()
    block.nVersion = tmpl["version"]
    block.hashPrevBlock = int(tmpl["previousblockhash"], 16)
    block.nTime = tmpl["curtime"]
    block.nBits = int(tmpl["bits"], 16)
    block.nNonce = 0
    block.vtx = [cbtx] + [FromHex(CTransaction(), t["data"]) for t in tmpl["transactions"]]

    witnonce = 0
    witroot = block.calc_witness_merkle_root()
    cbwit = CTxInWitness()
    cbwit.scriptWitness.stack = [ser_uint256(witnonce)]
    block.vtx[0].wit.vtxinwit = [cbwit]
    block.vtx[0].vout.append(CTxOut(0, get_witness_script(witroot, witnonce)))

    signme, spendme = signet_txs(block, signet_spk_bin)

    return block, signme, spendme

def solve_block(block, signet_solution):
    block.vtx[0].vout[-1].scriptPubKey += pushdata(SIGNET_HEADER + signet_solution)
    block.vtx[0].rehash()
    block.hashMerkleRoot = block.calc_merkle_root()
    block.solve()
    return block

def do_genpsbt(args):
    if len(args) > 1:
        print("Only specify scriptPubKey (hex) for block reward")
        return
    elif len(args) == 1:
        cb_payout_address = unhexlify(args[0])
    else:
        cb_payout_address = None

    block, signme, spendme = signet_txs_from_template(cb_payout_address)
    print(do_createpsbt(block, signme, spendme))

def do_solvepsbt(args):
    if len(args) > 0:
        print("No args accepted for solvepsbt")
        return
    block, signet_solution = do_decode_psbt(sys.stdin.read())
    block = solve_block(block, signet_solution)

    #print("Sol: %r\nBlock: %r\n" % (signet_solution.hex(), block))
    print(ToHex(block))

def main():
    if len(sys.argv) >= 2 and sys.argv[1] in ["genpsbt", "solvepsbt"]:
        cmd = sys.argv[1]
        args = sys.argv[2:]
    else:
        sys.stderr.write("Must specify genpsbt or solvepsbt")
        return

    if cmd == "genpsbt":
        return do_genpsbt(args)
    elif cmd == "solvepsbt":
        return do_solvepsbt(args)
    else:
        sys.stderr.write("Bad cmd %r %r %r\n" % (len(sys.argv), cmd, args))
        return

if __name__ == "__main__":
    main()


