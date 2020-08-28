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

SIGNET_HEADER = b"\xec\xc7\xda\xa2"
PSBT_SIGNET_BLOCK = b'\xfc\x06signetb'

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

class PSBTMap:
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

def DeserBinaryStream(cls, f):
    obj = cls()
    obj.deserialize(f)
    return obj

def DeserBinary(cls, b):
    return DeserBinaryStream(cls, BytesIO(b))

def do_createpsbt(block, signme, spendme):
    psbt = b'psbt\xff'
    # global
    psbt += PSBTMap( {0: signme.serialize(),
                      PSBT_SIGNET_BLOCK: block.serialize()
                     } ).serialize()
    # inputs
    psbt += PSBTMap( {0: spendme.serialize(),
                      3: bytes([1,0,0,0])}).serialize()
    # outputs
    psbt += PSBTMap().serialize()
    return base64.b64encode(psbt).decode('utf8')


def do_decode_psbt(b64psbt):
    psbtf = BytesIO(base64.b64decode(b64psbt))
    assert psbtf.read(5) == b'psbt\xff'

    # global
    g = DeserBinaryStream(PSBTMap, psbtf)
    assert 0 in g.map
    tx = DeserBinary(CTransaction, g.map[0])
    assert len(tx.vin) == 1
    assert len(tx.vout) == 1
    assert PSBT_SIGNET_BLOCK in g.map

    # inputs
    inp = [DeserBinaryStream(PSBTMap, psbtf) for _ in tx.vin]

    # outputs
    _ = [DeserBinaryStream(PSBTMap, psbtf) for _ in tx.vout]

    assert len(psbtf.read()) == 0
    scriptSig = inp[0].map.get(7, b'')
    scriptWitness = inp[0].map.get(8, b'')

    return DeserBinary(CBlock, g.map[PSBT_SIGNET_BLOCK]), ser_string(scriptSig) + scriptWitness

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


