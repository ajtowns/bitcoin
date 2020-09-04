#!/usr/bin/env python3
# Copyright (c) 2010 ArtForz -- public domain half-a-node
# Copyright (c) 2012 Jeff Garzik
# Copyright (c) 2010-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import argparse
import base64
import json
import logging
import struct
import sys
import time
import subprocess

from binascii import unhexlify
from io import BytesIO

sys.path.insert(0, "../test/functional/")

from test_framework.blocktools import WITNESS_COMMITMENT_HEADER, script_BIP34_coinbase_height # noqa: E402
from test_framework.messages import CBlock, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, FromHex, ToHex, deser_string, hash256, ser_compact_size, ser_string, ser_uint256, uint256_from_str # noqa: E402
from test_framework.script import CScriptOp # noqa: E402

logging.basicConfig(
    format='%(asctime)s %(levelname)s %(message)s',
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S')

SIGNET_HEADER = b"\xec\xc7\xda\xa2"
PSBT_SIGNET_BLOCK = b"\xfc\x06signetb"    # proprietary PSBT global field holding the block being signed

##### some helpers that could go into test_framework

# like FromHex, but without the hex part
def FromBinary(cls, stream):
    """deserialize a binary stream (or bytes object) into an object"""
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
        m = b""
        for k,v in self.map.items():
            if isinstance(k, int) and 0 <= k and k <= 255:
                k = bytes([k])
            m += ser_compact_size(len(k)) + k
            m += ser_compact_size(len(v)) + v
        m += b"\x00"
        return m

class PSBT:
    """Class for serializing and deserializing PSBTs"""

    def __init__(self):
        self.g = PSBTMap()
        self.i = []
        self.o = []
        self.tx = None

    def deserialize(self, f):
        assert f.read(5) == b"psbt\xff"
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
        return b"psbt\xff" + b"".join(psbt)

    def to_base64(self):
        return base64.b64encode(self.serialize()).decode("utf8")

    @classmethod
    def from_base64(cls, b64psbt):
        return FromBinary(cls, base64.b64decode(b64psbt))

######

def gbt_first_block(challenge, gbci=None):
    if gbci is None:
        gbci = {"blocks": 0, "bestblockhash": "0000032d7f67af9ec7b7152aea0fe7c95b9804ff973265e252f245e0ae61799d",}
    assert gbci["blocks"] < 210000
    return {
        "height": gbci["blocks"]+1
        "previousblockhash": gbci["bestblockhash",
        "mintime": 1534313276,
        "coinbasevalue": 5000000000,
        "curtime": time.time(),
        "bits": "1e2adc28",
        "target": "00002adc28000000000000000000000000000000000000000000000000000000",

        "signet_challenge": challenge,

        "transactions": [],
        "default_witness_commitment": "6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9",
        "version": 0x20000000,
        "noncerange": "00000000ffffffff",
        "sigoplimit": 80000,
        "sizelimit": 4000000,
        "weightlimit": 4000000,
    }

def create_coinbase(height, value, spk):
    cb = CTransaction()
    cb.vin = [CTxIn(COutPoint(0, 0xffffffff), script_BIP34_coinbase_height(height), 0xffffffff)]
    cb.vout = [CTxOut(value, spk)]
    return cb

def get_witness_script(witness_root, witness_nonce):
    commitment = uint256_from_str(hash256(ser_uint256(witness_root) + ser_uint256(witness_nonce)))
    return b"\x6a" + CScriptOp.encode_op_pushdata(WITNESS_COMMITMENT_HEADER + ser_uint256(commitment))

def signet_txs(block, challenge):
    # assumes signet solution has not been added yet so does not need
    # to be removed

    txs = block.vtx[:]
    txs[0] = CTransaction(txs[0])
    txs[0].vout[-1].scriptPubKey += CScriptOp.encode_op_pushdata(SIGNET_HEADER)
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
    to_spend.vin = [CTxIn(COutPoint(0, 0xFFFFFFFF), b"\x00" + CScriptOp.encode_op_pushdata(sd), 0)]
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

    scriptSig = psbt.i[0].map.get(7, b"")
    scriptWitness = psbt.i[0].map.get(8, b"")

    return FromBinary(CBlock, psbt.g.map[PSBT_SIGNET_BLOCK]), ser_string(scriptSig) + scriptWitness

def solve_block(block, signet_solution):
    block.vtx[0].vout[-1].scriptPubKey += CScriptOp.encode_op_pushdata(SIGNET_HEADER + signet_solution)
    block.vtx[0].rehash()
    block.hashMerkleRoot = block.calc_merkle_root()
    block.solve()
    return block

def generate_psbt(tmpl, reward_spk, *, blocktime=None):
    signet_spk = tmpl["signet_challenge"]
    signet_spk_bin = unhexlify(signet_spk)

    cbtx = create_coinbase(height=tmpl["height"], value=tmpl["coinbasevalue"], spk=reward_spk)
    cbtx.vin[0].nSequence = 2**32-2
    cbtx.rehash()

    block = CBlock()
    block.nVersion = tmpl["version"]
    block.hashPrevBlock = int(tmpl["previousblockhash"], 16)
    block.nTime = tmpl["curtime"] if blocktime is None else blocktime
    if block.nTime < tmpl["mintime"]:
        block.nTime = tmpl["mintime"]
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

    return do_createpsbt(block, signme, spendme)

def get_reward_address(args, height):
    if args.address is not None:
        return args.address

    if '*' not in args.descriptor:
        addr = json.loads(args.bcli("deriveaddresses", args.descriptor))[0]
        args.address = addr
        return addr

    remove = [k for k in args.derived_addresses.keys() if k+20 <= height]
    for k in remove:
        del args.derived_addresses[k]

    addr = args.derived_addresses.get(height, None)
    if addr is None:
        addrs = json.loads(args.bcli("deriveaddresses", args.descriptor, "[%d,%d]" % (height, height+20)))
        addr = addrs[0]
        for k, a in enumerate(addrs):
            args.derived_addresses[height+k] = a

    return addr

def get_reward_addr_spk(args, height):
    assert args.address is not None or args.descriptor is not None

    if hasattr(args, "reward_spk"):
        return args.address, args.reward_spk

    reward_addr = get_reward_address(args, height)
    reward_spk = unhexlify(json.loads(args.bcli("getaddressinfo", reward_addr))["scriptPubKey"])
    if args.address is not None:
        # will always be the same, so cache
        args.reward_spk = reward_spk

    return reward_addr, reward_spk

def do_genpsbt(args):
    if args.firstblock:
        bci = json.loads(args.bcli("getblockchaininfo"))
        tmpl = gbt_first_block(bci["signet_challenge"])
    else:
        tmpl = json.load(sys.stdin)
    _, reward_spk = get_reward_spk(args, tmpl["height"])
    psbt = generate_psbt(tmpl, reward_spk)
    print(psbt)

def do_solvepsbt(args):
    block, signet_solution = do_decode_psbt(sys.stdin.read())
    block = solve_block(block, signet_solution)
    print(ToHex(block))

def do_generate(args):
    if args.N != int(args.N) or args.N < -1:
       logging.error("N must be an integer, and at least -1")
       return 1

    if args.target_mining_time is not None:
        if args.target_mining_time <= 0 or args.target_mining_time > 600:
            logging.error("Target mining time must be between 1 and 600")
            return 1

    bci = json.loads(args.bcli("getblockchaininfo"))
    nextblock = bci["blocks"] + 1
    mined_blocks = 0
    last_mine_time = 600

    if args.backdate:
        start = min(args.backdate, bci["mediantime"] + 1)
    else:
        start = time.time()

    while args.N <= 0 or mined_blocks < args.N:
        # sleep
        if args.block_time > 0:
            block_time = args.block_time
        else:
            block_time = (600.0*2016/2015) * (last_mine_time / args.target_mining_time)
            block_time = max(150, min(block_time, 2400)) # don't be too fast or too slow

        if block_time > 0:
            next_time = start + block_time
            sleep_for = next_time - time.time()
            if sleep_for > 0:
                time.sleep(sleep_for)
            start = next_time

        # gbt
        if nextblock == 1:
            tmpl = gbt_first_block(bci["signet_challenge"])
        else:
            tmpl = json.loads(args.bcli("getblocktemplate", '{"rules":["signet","segwit"]}'))
        logging.debug("GBT template: %s", tmpl)

        # work out if we should actually mine
        if args.secondary and tmpl["height"] > nextblock:
            if nextblock is not None:
                logging.info("Chain height increased (%d to %d), waiting", nextblock, tmpl["height"]-1)
            nextblock = tmpl["height"]
            continue
        else:
            nextblock = tmpl["height"] + 1

        # address for reward
        reward_addr, reward_spk = get_reward_addr_spk(args, tmpl["height"])

        # mine block
        mined_blocks += 1
        psbt = generate_psbt(tmpl, reward_spk, blocktime=start)
        psbt_signed = json.loads(args.bcli("-stdin", "walletprocesspsbt", input=psbt.encode('utf8')))
        if not psbt_signed.get("complete",False):
            sys.stderr.write("PSBT signing failed")
            return 1
        block, signet_solution = do_decode_psbt(psbt_signed["psbt"])
        block = solve_block(block, signet_solution)
        r = args.bcli("-stdin", "submitblock", input=ToHex(block).encode('utf8'))
        if r == "":
            logging.info("Mined block height %d hash %s payout to %s", tmpl["height"], block.hash, reward_addr)
        else:
            logging.info("Mined block at height %d hash %s payout to %s; submitblock returned %s", tmpl["height"], block.hash, reward_addr, r)

def bitcoin_cli(basecmd, args, **kwargs):
    cmd = basecmd + ["-signet"] + args
    logging.debug("Calling bitcoin-cli: %r", cmd)
    return subprocess.run(cmd, stdout=subprocess.PIPE, **kwargs, check=True).stdout.strip()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli", default="bitcoin-cli", type=str, help="bitcoin-cli command")
    parser.add_argument("--debug", action="store_true", help="Print debugging info")
    parser.add_argument("--quiet", action="store_true", help="Only print warnings/errors")

    cmds = parser.add_subparsers(help="sub-commands")
    genpsbt = cmds.add_parser("genpsbt", help="Generate a block PSBT for signing")
    genpsbt.set_defaults(fn=do_genpsbt)
    genpsbt.add_argument("--firstblock", action="store_true", help="Generate PSBT for first block of chain")

    solvepsbt = cmds.add_parser("solvepsbt", help="Solve a signed block PSBT")
    solvepsbt.set_defaults(fn=do_solvepsbt)

    generate = cmds.add_parser("generate", help="Mine blocks")
    generate.set_defaults(fn=do_generate)
    generate.add_argument("N", default=None, type=int, help="How many blocks to generate (0 or -1 for no limit)")
    generate.add_argument("--block-time", default=600, type=int, help="How long between blocks")
    generate.add_argument("--target-mining-time", default=20, type=int, help="How long to spend mining before finding a block")
    generate.add_argument("--backdate", default=None, type=int, help="Backdate mining to date (unix timestamp)")
    generate.add_argument("--secondary", action="store_true", help="Only mine a block if no new blocks were found in block-time")
    generate.add_argument("--signcmd", default=None, type=str, help="Alternative signing command")

    for sp in [genpsbt, generate]:
        sp.add_argument("--address", default=None, type=str, help="Address for block reward payment")
        sp.add_argument("--descriptor", default=None, type=str, help="Descriptor for block reward payment")

    args = parser.parse_args(sys.argv[1:])

    args.bcli = lambda *a, input=b"", **kwargs: bitcoin_cli(args.cli.split(" "), list(a), input=input, **kwargs)

    if hasattr(args, "address") and hasattr(args, "descriptor"):
        if args.address is None and args.descriptor is None:
            sys.stderr.write("Must specify --address or --descriptor\n")
            return 1
        elif args.address is not None and args.descriptor is not None:
            sys.stderr.write("Only specify one of --address or --descriptor\n")
            return 1
        args.derived_addresses = {}

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    else:
        logging.getLogger().setLevel(logging.INFO)

    return args.fn(args)

if __name__ == "__main__":
    main()


