#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Cut a serialized UTXO set snapshot into leaves, and reassemble one from
leaves fetched a few at a time.

The snapshot to cut is the file written by the `dumptxoutset` RPC:

$ bitcoin-cli dumptxoutset ~/utxo.dat rollback=900000

The snapshot is cut into leaves of LEAF_SIZE bytes (65,536: one message per
leaf, a page-aligned size, and the granularity a bittorrent-style transfer
already works at), and the leaves are grouped into files of LEAVES_PER_FILE
leaves (`txout0000.dat`, `txout0001.dat`, ...) in a directory of its own, whose
name is the producer's to choose, alongside a `meta.dat` index. Neither number
is an option: the leaf size is part of the format, and one file holds one branch,
so a store has one shape. A downloader picks its own grouping when it
initialises one. Concatenating the files in order reproduces the input byte for
byte:

$ cat txout*.dat > utxo.dat

so the reassembled file can be passed straight to `loadtxoutset`, and the leaves
can be fed to `bitcoin-util txoutsetsummary -` for a content check without ever
joining them.

The words used here:

  leaf     LEAF_SIZE bytes of the serialized snapshot. The unit of transfer:
           one leaf is one message. A leaf boundary can fall inside a txid
           group or a coin, so a leaf is a byte range, not a set of coins, and
           cannot be hashed on its own as if it were.
  txout    a `txout<NNNN>.dat` file, holding LEAVES_PER_FILE leaves.
  hashes   one hash per leaf, 32 bytes each, the same list a torrent carries for
           its pieces, sent in branches of BRANCH_LEAVES leaves. 2048 hashes is
           65,536 bytes, so a message carrying a branch is about the size of a
           message carrying a leaf, and a peer doing either can be given the
           same slice of attention. A branch whose hashes have not arrived yet
           reads as a hash of zero, which no leaf can hash to.
  payload  either one branch of the hash list, its path to the root and its leaf
           hashes, or one leaf on its own, its index and its bytes. getleaf
           writes a leaf as hex on stdout and addleaf reads one as hex on stdin,
           so `getleaf a 5 | addleaf b` moves a leaf between two stores; the
           message of leaf hashes travels the same way, so one call a message
           does the whole exchange:
             for x in $(seq 0 71); do getleafhash a $x | addleafhash b; done
             for x in $(seq 0 999); do getleaf a $x | addleaf b; done
           A thousand leaves at a time is a reasonable size for a run: `getleaf a 0
           999 | addleaf b`, then the next thousand, until the store is in. The last
           run of a store is short, and a run that would go past its end is refused
           rather than clamped.
           Each message is checked as it arrives, so a store fills in a branch at
           a time and a leaf at a time, with nothing out of turn. A run of payloads can travel in one call too, since
           each carries its own index and the store knows how long that leaf is:
           `getleaf a 5 9 | addleaf b` takes five leaves, and `getleafhash a 3 5 |
           addleafhash b` three messages.

A leaf is not sent with anything to prove where it belongs: it is checked by
hashing it and comparing against its entry in the hash list. A branch of the
list is, because a branch is what a message carries and what has to be checked
against the root: it goes with the path from the branch's root up to the
snapshot root, so a message can be checked as soon as it arrives rather than
after all of them are in, and the leaves of that branch can be checked as soon as
their hashes are. Branch paths cost almost nothing next to that list, and the
list costs less than proving every leaf against the root would: 32 bytes per
leaf once, against a path of one hash per tree level for every leaf served, which
is eighteen times as much at these sizes.

The Merkle tree is built over the leaf hashes with tagged hashes (single SHA256,
as in BIP340/BIP341), so that leaves and branches cannot be confused:

  leaf_hash   = SHA256(SHA256("BIP452Leaf")   || SHA256("BIP452Leaf")   || leaf)
  branch_hash = SHA256(SHA256("BIP452Branch") || SHA256("BIP452Branch") || lhs || rhs)

A node left without a sibling at a level is carried up to the next level
unchanged; nodes are never duplicated. The snapshot root is the tree over the
branch roots, not over the leaves themselves: a branch root is what a message
proves, and since BRANCH_LEAVES is a power of two a full branch always folds the
same way, so the branch roots are all a message needs.

`verify` recomputes what it can from the leaves on disk: every leaf present is
hashed and checked against the hash list, the branch roots are folded to the
root, and `--root` can require that root to equal the one committed in
chainparams. With `--bitcoin-util` the muhash is recomputed from the leaves on
disk, by streaming them through `bitcoin-util txoutsetsummary -`, and compared
against `--muhash` if one is given.

The muhash is deliberately not stored anywhere: it is a statement about the data
rather than part of it, so the only copy is the one a reader computes for itself
and there is no recorded value that can be wrong. Nothing in the store depends
on it; the root commits to the leaves, and hence to every coin in them.
"""
import argparse
from concurrent import futures
import hashlib
import json
import os
import re
import shlex
import signal
import struct
import subprocess
import sys
from decimal import Decimal


UTXO_DUMP_MAGIC = b'utxo\xff'
UTXO_DUMP_VERSION = 2
UTXO_DUMP_HEADER_SIZE = 5 + 2 + 4 + 32 + 8
# Core's own chain names, as ChainTypeToString() gives them and as
# getblockchaininfo reports them, so a value from here can be compared with the
# RPC and passed to -chain=.
NET_MAGIC_BYTES = {
    b"\xf9\xbe\xb4\xd9": "main",
    b"\x0a\x03\xcf\x40": "signet",
    b"\x0b\x11\x09\x07": "test",
    b"\x1c\x16\x3f\x28": "testnet4",
    b"\xfa\xbf\xb5\xda": "regtest",
}
NET_MAGIC_BY_NAME = {name: magic for magic, name in NET_MAGIC_BYTES.items()}

# A leaf is the unit of transfer, one message per leaf, so its size trades the
# serving node's time slice per message against the number of messages a
# download takes. 64 KiB is a page-aligned size, small enough to interleave with
# other peers freely and to spread a download across them in small pieces, and
# the granularity bittorrent-style transfers use.
LEAF_SIZE = 65_536

# The hash list goes over the wire in branches of this many leaves, one message
# each. A branch is a power of two so that a full one folds as a perfect tree,
# and 2048 hashes is 65,536 bytes, the size of a leaf, so the two kinds of
# message are the same size.
BRANCH_LEAVES = 2048

# A file holds exactly one branch, so the file boundaries are the boundaries the
# hash messages are built on and a branch is a contiguous run of bytes on disk.
# That is 2048 * 65,536 = 128 MiB a file. A downloader picks its own grouping
# when it initialises a store, but a producer writes this one.
LEAVES_PER_FILE = BRANCH_LEAVES

META_MAGIC = b'utxometa'
META_VERSION = 10
# magic, version, net magic, blockhash, data length, coin count: the snapshot
# header's fields, in its order, then one hash per leaf and a bitmap of which
# leaves have arrived. Nothing derivable is recorded -- not the height (a
# chainparams fact), the leaf size (the format), the leaves per file (which
# follow from it), the leaf count or the branch count (which follow from the
# data length). The root is not derivable from an incomplete list and does not
# come from the list at all: it is the anchor the snapshot is checked against,
# from chainparams by init and computed by split. A branch whose
# hashes have not arrived is written as ZERO_HASH, which is not a hash any leaf
# can produce, so a store can hold some of the list and say which.
META_FMT = '<8sH4s32sQQ32s'
META_FIXED_SIZE = struct.calcsize(META_FMT)

SUMMARY_MAGIC = b'utxsum'
SUMMARY_VERSION = 7
# magic, version, net magic, blockhash, data length, coin count, branch index,
# path count, then the path from the branch root up to the snapshot root, then
# the branch's leaf hashes. A message describes the whole snapshot and proves one
# branch of it, so any message can be checked against the committed root by
# itself.
SUMMARY_FMT = '<6sH4s32sQQII'
SUMMARY_FIXED_SIZE = struct.calcsize(SUMMARY_FMT)

# leaf index, then the leaf bytes
LEAF_PAYLOAD_PREFIX_FMT = '<I'
LEAF_PAYLOAD_PREFIX_SIZE = struct.calcsize(LEAF_PAYLOAD_PREFIX_FMT)

LEAF_TAG = b'BIP452Leaf'
BRANCH_TAG = b'BIP452Branch'

# Not a hash the tree can produce: stands for a branch whose hashes have not
# arrived, in a store built one message at a time.
ZERO_HASH = b'\x00' * 32


# --- Merkle tree -----------------------------------------------------------

def tagged_hash(tag, data):
    """Single SHA256 with the BIP340/BIP341 tag prefix."""
    taghash = hashlib.sha256(tag).digest()
    return hashlib.sha256(taghash + taghash + data).digest()


def leaf_hash(data):
    return tagged_hash(LEAF_TAG, data)


def branch_hash(lhs, rhs):
    return tagged_hash(BRANCH_TAG, lhs + rhs)


def levels(nodes):
    """All levels of a tree over `nodes`, node level first, root last."""
    all_levels = [list(nodes)]
    while len(all_levels[-1]) > 1:
        level = all_levels[-1]
        nxt = [branch_hash(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        all_levels.append(nxt)
    return all_levels


def merkle_root(nodes):
    """Root over the nodes, carrying unpaired ones up unchanged."""
    if not nodes:
        raise ValueError("no nodes")
    return levels(nodes)[-1][0]


def merkle_path(nodes, index):
    """Path for the node at `index`, as a list of sibling hashes.

    Shorter than the number of levels when a node on the way up was carried,
    since a carried node has no sibling to name.
    """
    if not 0 <= index < len(nodes):
        raise ValueError(f"node index {index} out of range")
    path = []
    i = index
    for level in levels(nodes)[:-1]:
        if i % 2 == 0:
            if i + 1 < len(level):
                path.append(level[i + 1])
        else:
            path.append(level[i - 1])
        i //= 2
    return path


def root_from_path(node, path, index, total):
    """The root a path leads to, checking the path is exactly the right length.

    A node with no sibling at its level is carried, so which side a path hash is
    combined on has to be read off the position at that level, not off the index
    it started at.
    """
    computed = node
    i = index
    level_size = total
    used = 0
    while level_size > 1:
        if i % 2 == 0 and i + 1 < level_size:
            if used == len(path):
                raise ValueError("path is too short")
            computed = branch_hash(computed, path[used])
            used += 1
        elif i % 2 == 1:
            if used == len(path):
                raise ValueError("path is too short")
            computed = branch_hash(path[used], computed)
            used += 1
        i //= 2
        level_size = (level_size + 1) // 2
    if used != len(path):
        raise ValueError(f"path has {len(path) - used} hashes too many")
    return computed


def verify_merkle_path(node, path, index, total, root):
    """Whether a path produced by merkle_path() leads to `root`."""
    try:
        return root_from_path(node, path, index, total) == root
    except ValueError:
        return False


def branch_count(leaf_count):
    """How many messages the hash list takes: one branch of BRANCH_LEAVES."""
    return -(-leaf_count // BRANCH_LEAVES)


def branch_leaf_count(leaf_count, branch):
    """How many leaves branch `branch` holds: every branch but the last is full."""
    return min(BRANCH_LEAVES, leaf_count - branch * BRANCH_LEAVES)


def branch_hashes(hashes, branch):
    """The leaf hashes of branch `branch`."""
    return hashes[branch * BRANCH_LEAVES:(branch + 1) * BRANCH_LEAVES]


def branch_roots(hashes):
    """The root of each branch: the nodes the snapshot root is built over."""
    return [merkle_root(branch_hashes(hashes, branch))
            for branch in range(branch_count(len(hashes)))]


def hashes_root(hashes):
    """The snapshot root: the tree over the branch roots."""
    return merkle_root(branch_roots(hashes))


def display_hex(data):
    """Hex as it is shown for a uint256 in Bitcoin Core (bytes reversed)."""
    return data[::-1].hex()


def from_display_hex(hexstr):
    return bytes.fromhex(hexstr)[::-1]



def payload_to_hex(payload):
    """A payload as getleaf writes it: hex and a newline, one to a pipe."""
    return payload.hex() + "\n"


def parse_btc(text):
    """Parse a BTC figure as text, with or without a decimal point, into
    satoshis. Text rather than a float, so the value is exact and a figure with
    more precision than satoshis can hold is refused rather than rounded."""
    if not re.fullmatch(r"\d+(\.\d+)?", text):
        raise ValueError(f"{text!r} is not a BTC amount")
    whole, _, frac = text.partition(".")
    if len(frac) > 8:
        raise ValueError(f"{text!r} has more than eight decimal places")
    return int(whole) * 100_000_000 + int(frac.ljust(8, "0"))


def payload_from_hex(text):
    """A payload as addleaf reads it. bytes.fromhex ignores whitespace."""
    try:
        return bytes.fromhex(text)
    except ValueError as e:
        raise ValueError(f"payload is not hex: {e}")


def parse_snapshot_header(data):
    """Validate the 51 bytes of serialized UTXO set header and describe them."""
    if len(data) < UTXO_DUMP_HEADER_SIZE:
        raise ValueError("data too short to hold a UTXO set header")
    magic = data[0:5]
    version = int.from_bytes(data[5:7], "little")
    net_magic = data[7:11]
    if magic != UTXO_DUMP_MAGIC:
        raise ValueError(f"bad snapshot magic {magic!r}")
    if version != UTXO_DUMP_VERSION:
        raise ValueError(f"unsupported snapshot version {version}, expected {UTXO_DUMP_VERSION}")
    return {
        "version": version,
        "network": NET_MAGIC_BYTES.get(net_magic, f"unknown ({net_magic.hex()})"),
        "net_magic": net_magic,
        "blockhash": data[11:43],
        "coins_count": int.from_bytes(data[43:51], "little"),
    }


# --- The meta.dat index -------------------------------------------------

def parse_meta(path):
    with open(path, "rb") as f:
        raw = f.read()
    if len(raw) < META_FIXED_SIZE:
        raise ValueError("meta file is too short")
    (magic, version, net_magic, blockhash, data_length,
     coins_count, root) = struct.unpack(META_FMT, raw[:META_FIXED_SIZE])
    if magic != META_MAGIC:
        raise ValueError(f"bad meta magic {magic!r}")
    if version != META_VERSION:
        raise ValueError(f"unsupported meta version {version}, expected {META_VERSION}")
    leaf_count = (data_length + LEAF_SIZE - 1) // LEAF_SIZE
    if leaf_count == 0:
        raise ValueError("meta file reports no coin data")
    off = META_FIXED_SIZE
    hashes = [raw[off + 32 * i:off + 32 * (i + 1)] for i in range(leaf_count)]
    off += 32 * leaf_count
    bits_size = (leaf_count + 7) // 8
    bits = bytearray(raw[off:off + bits_size])
    off += bits_size
    if len(raw) != off:
        raise ValueError(f"meta file has {len(raw) - off} bytes of trailing data")
    return {
        "leaf_size": LEAF_SIZE,
        "leaves_per_file": LEAVES_PER_FILE,
        "leaf_count": leaf_count,
        "data_length": data_length,
        "coins_count": coins_count,
        "network": NET_MAGIC_BYTES.get(net_magic, f"unknown ({net_magic.hex()})"),
        "net_magic": net_magic,
        "blockhash": blockhash,
        "root": root,
        "hashes": hashes,
        "bits": bits,
    }


def serialize_meta(meta):
    """Write the index: the header, the hash list, the bitmap."""
    return b"".join([
        struct.pack(META_FMT, META_MAGIC, META_VERSION, meta["net_magic"],
                    meta["blockhash"], meta["data_length"], meta["coins_count"],
                    meta["root"]),
        b"".join(meta["hashes"]),
        meta["bits"],
    ])


def write_meta(snapshot_dir, meta):
    path = os.path.join(snapshot_dir, "meta.dat")
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(serialize_meta(meta))
    os.replace(tmp, path)


def is_present(meta, index):
    return bool(meta["bits"][index // 8] & (1 << (index % 8)))


def mark_present(bits, index):
    bits[index // 8] |= 1 << (index % 8)


def leaf_length(meta, index):
    """Length of leaf `index`: every leaf but the last is a full leaf."""
    if index < meta["leaf_count"] - 1:
        return meta["leaf_size"]
    return meta["data_length"] - (meta["leaf_count"] - 1) * meta["leaf_size"]


def chunk_name(index, leaves_per_file):
    return f"txout{index // leaves_per_file:04d}.dat"


def chunk_path(snapshot_dir, index, leaves_per_file):
    return os.path.join(snapshot_dir, chunk_name(index, leaves_per_file))


def chunk_sizes(meta):
    """Size of each chunk file, in order."""
    sizes = []
    for index in range(meta["leaf_count"]):
        if index % meta["leaves_per_file"] == 0:
            sizes.append(0)
        sizes[-1] += leaf_length(meta, index)
    return sizes


def create_chunks(snapshot_dir, meta):
    """Create the chunk files, sized but empty, so leaves can be filled in."""
    sizes = chunk_sizes(meta)
    paths = []
    for index, size in enumerate(sizes):
        path = os.path.join(snapshot_dir, f"txout{index:04d}.dat")
        with open(path, "wb") as f:
            if size:
                f.truncate(size)
        paths.append(path)
    return paths


def write_leaf(snapshot_dir, meta, index, data):
    if len(data) != leaf_length(meta, index):
        raise ValueError(f"leaf {index} is {len(data)} bytes, expected "
                         f"{leaf_length(meta, index)}")
    path = chunk_path(snapshot_dir, index, meta["leaves_per_file"])
    with open(path, "r+b") as f:
        f.seek((index % meta["leaves_per_file"]) * meta["leaf_size"])
        f.write(data)


def read_leaf(snapshot_dir, meta, index):
    path = chunk_path(snapshot_dir, index, meta["leaves_per_file"])
    with open(path, "rb") as f:
        f.seek((index % meta["leaves_per_file"]) * meta["leaf_size"])
        data = f.read(leaf_length(meta, index))
    if len(data) != leaf_length(meta, index):
        raise ValueError(f"leaf {index} is short on disk, {len(data)} bytes not "
                         f"{leaf_length(meta, index)}")
    return data


def read_leaves(snapshot_dir, meta):
    """Yield (index, leaf bytes) for every leaf on disk, in order."""
    for index in range(meta["leaf_count"]):
        yield index, read_leaf(snapshot_dir, meta, index)


# --- Summary and leaf payloads --------------------------------------------

def summary_bytes(meta, branch, roots=None):
    """One branch of the hash list, with the path that proves it to the root."""
    hashes = meta["hashes"]
    if not 0 <= branch < branch_count(meta["leaf_count"]):
        raise ValueError(f"branch {branch} out of range")
    if roots is None:
        roots = branch_roots(hashes)
    leaves = branch_hashes(hashes, branch)
    path = merkle_path(roots, branch)
    return b"".join([
        struct.pack(SUMMARY_FMT, SUMMARY_MAGIC, SUMMARY_VERSION, meta["net_magic"],
                    meta["blockhash"], meta["data_length"], meta["coins_count"],
                    branch, len(path)),
        b"".join(path),
        b"".join(leaves),
    ])


def parse_summary(raw):
    """Read one branch message, and the root its path leads to."""
    if len(raw) < SUMMARY_FIXED_SIZE:
        raise ValueError("summary message is too short")
    (magic, version, net_magic, blockhash, data_length, coins_count, branch,
     path_count) = struct.unpack(SUMMARY_FMT, raw[:SUMMARY_FIXED_SIZE])
    if magic != SUMMARY_MAGIC:
        raise ValueError(f"bad summary magic {magic!r}")
    if version != SUMMARY_VERSION:
        raise ValueError(f"unsupported summary version {version}, expected {SUMMARY_VERSION}")
    if data_length <= UTXO_DUMP_HEADER_SIZE:
        raise ValueError("summary describes an impossible snapshot size")
    leaf_count = (data_length + LEAF_SIZE - 1) // LEAF_SIZE
    branches = branch_count(leaf_count)
    if not 0 <= branch < branches:
        raise ValueError(f"branch {branch} out of range for {branches} branches")
    want = branch_leaf_count(leaf_count, branch)
    off = SUMMARY_FIXED_SIZE + 32 * path_count
    if len(raw) != off + 32 * want:
        raise ValueError(f"summary message carries {len(raw) - off} bytes of hashes, "
                         f"expected {32 * want} for {want} leaves")
    path = [raw[SUMMARY_FIXED_SIZE + 32 * i:SUMMARY_FIXED_SIZE + 32 * (i + 1)]
            for i in range(path_count)]
    hashes = [raw[off + 32 * i:off + 32 * (i + 1)] for i in range(want)]
    return {
        "leaf_size": LEAF_SIZE,
        "leaf_count": leaf_count,
        "data_length": data_length,
        "coins_count": coins_count,
        "net_magic": net_magic,
        "network": NET_MAGIC_BYTES.get(net_magic, f"unknown ({net_magic.hex()})"),
        "blockhash": blockhash,
        "branch": branch,
        "branches": branches,
        "path": path,
        "hashes": hashes,
        "root": root_from_path(merkle_root(hashes), path, branch, branches),
    }


def leaf_payload(index, data):
    return struct.pack(LEAF_PAYLOAD_PREFIX_FMT, index) + data



# --- Which branches have arrived -------------------------------------------

def branch_known(meta, branch):
    """Whether a branch's hashes are here: the first of them is not zero."""
    return meta["hashes"][branch * BRANCH_LEAVES] != ZERO_HASH


def known_branches(meta):
    """The branches whose hashes are here, in order."""
    return [branch for branch in range(branch_count(meta["leaf_count"]))
            if branch_known(meta, branch)]


# --- Commands --------------------------------------------------------------

def cmd_split(args):
    data_length = os.path.getsize(args.infile)
    with open(args.infile, "rb") as f:
        header = parse_snapshot_header(f.read(UTXO_DUMP_HEADER_SIZE))
    if data_length <= UTXO_DUMP_HEADER_SIZE:
        raise ValueError("snapshot has no coin data")

    snapshot_dir = args.snapshot_dir
    if os.path.exists(os.path.join(snapshot_dir, "meta.dat")):
        raise ValueError(f"{snapshot_dir} already holds a snapshot")

    leaf_count = (data_length + LEAF_SIZE - 1) // LEAF_SIZE
    num_files = (leaf_count + LEAVES_PER_FILE - 1) // LEAVES_PER_FILE
    os.makedirs(snapshot_dir, exist_ok=True)

    hashes = []
    with open(args.infile, "rb") as f:
        for file_index in range(num_files):
            path = os.path.join(snapshot_dir, f"txout{file_index:04d}.dat")
            with open(path, "wb") as out:
                for _ in range(LEAVES_PER_FILE):
                    leaf = f.read(LEAF_SIZE)
                    if not leaf:
                        break
                    out.write(leaf)
                    hashes.append(leaf_hash(leaf))
    if len(hashes) != leaf_count:
        raise ValueError(f"read {len(hashes)} leaves, expected {leaf_count}")

    bits = bytearray((leaf_count + 7) // 8)
    for i in range(leaf_count):
        mark_present(bits, i)
    root = hashes_root(hashes)
    meta = {
        "leaf_size": LEAF_SIZE,
        "leaves_per_file": LEAVES_PER_FILE,
        "leaf_count": leaf_count,
        "data_length": data_length,
        "coins_count": header["coins_count"],
        "net_magic": header["net_magic"],
        "blockhash": header["blockhash"],
        "root": root,
        "hashes": hashes,
        "bits": bits,
    }
    write_meta(snapshot_dir, meta)

    print(f"network      {header['network']}")
    print(f"base block   {display_hex(header['blockhash'])}")
    print(f"coins        {header['coins_count']}")
    print(f"bytes        {data_length}")
    print(f"leaves       {leaf_count} x {LEAF_SIZE}")
    print(f"files        {num_files} in {snapshot_dir}")
    print(f"branches     {branch_count(leaf_count)} of {BRANCH_LEAVES} leaves")
    print(f"merkle root  {display_hex(root)}")


def cmd_init(args):
    """Create an empty store from the values a chainparams entry carries.

    The identity and the root come from the chain's parameters rather than from a
    peer, so a store can be set up before anything has been fetched, and every
    message is then checked against that root as it arrives.
    """
    magic = NET_MAGIC_BY_NAME.get(args.chain)
    if magic is None:
        raise ValueError(f"unknown chain {args.chain!r}, expected one of "
                         f"{', '.join(sorted(NET_MAGIC_BY_NAME))}")
    blockhash = from_display_hex(args.blockhash)
    if len(blockhash) != 32:
        raise ValueError("the base block hash should be 32 bytes of hex")
    root = from_display_hex(args.root)
    if len(root) != 32:
        raise ValueError("the root should be 32 bytes of hex")
    if args.data_length <= UTXO_DUMP_HEADER_SIZE:
        raise ValueError("a snapshot that small has no coins")
    leaf_count = (args.data_length + LEAF_SIZE - 1) // LEAF_SIZE

    if os.path.exists(os.path.join(args.snapshot_dir, "meta.dat")):
        raise ValueError(f"{args.snapshot_dir} already holds a snapshot")
    os.makedirs(args.snapshot_dir, exist_ok=True)
    meta = {
        "leaf_size": LEAF_SIZE,
        "leaves_per_file": LEAVES_PER_FILE,
        "leaf_count": leaf_count,
        "data_length": args.data_length,
        "coins_count": args.coins,
        "net_magic": magic,
        "blockhash": blockhash,
        "root": root,
        "hashes": [ZERO_HASH] * leaf_count,
        "bits": bytearray((leaf_count + 7) // 8),
    }
    create_chunks(args.snapshot_dir, meta)
    write_meta(args.snapshot_dir, meta)

    print(f"initialised  {args.snapshot_dir}")
    print(f"network      {args.chain}")
    print(f"base block   {display_hex(blockhash)}")
    print(f"coins        {args.coins}")
    print(f"bytes        {args.data_length}")
    print(f"leaves       {leaf_count} x {LEAF_SIZE}")
    print(f"branches     {branch_count(leaf_count)} of {BRANCH_LEAVES} leaves")
    print(f"merkle root  {args.root}")


def cmd_summary(args):
    """Print what a store holds, as the reader sees it: one JSON document.

    The root is only there once every branch of the hash list has arrived, since
    it folds from all of them; until then the branch counts say how much of the
    list is here.
    """
    meta = parse_meta(os.path.join(args.snapshot_dir, "meta.dat"))
    branches = branch_count(meta["leaf_count"])
    known = known_branches(meta)
    print(json.dumps({
        "network": meta["network"],
        "base_blockhash": display_hex(meta["blockhash"]),
        "coins_count": meta["coins_count"],
        "data_length": meta["data_length"],
        "leaf_count": meta["leaf_count"],
        "branch_count": branches,
        "branch_leaves": BRANCH_LEAVES,
        "branches_known": len(known),
        "leaves_present": sum(1 for index in range(meta["leaf_count"])
                              if is_present(meta, index)),
        "merkle_root": display_hex(meta["root"]),
    }, indent=2))


def cmd_getleafhash(args):
    """Write branches of the hash list as hex on stdout: each path, then its hashes.

    A run of branches can be asked for at once, and the tree above them is folded
    once rather than once a message.
    """
    meta = parse_meta(os.path.join(args.snapshot_dir, "meta.dat"))
    branches = branch_count(meta["leaf_count"])
    first = args.first
    last = args.last if args.last is not None else first
    if not 0 <= first <= last < branches:
        raise ValueError(f"branches {first}..{last} are not inside a store with "
                         f"{branches} branches")
    for branch in range(first, last + 1):
        if not branch_known(meta, branch):
            raise ValueError(f"branch {branch}'s hashes are not here to be sent")

    roots = branch_roots(meta["hashes"])
    size = 0
    for branch in range(first, last + 1):
        raw = summary_bytes(meta, branch, roots)
        sys.stdout.write(payload_to_hex(raw))
        size += len(raw)
    # The payload is the output, so the description of it goes to stderr.
    if first == last:
        print(f"branch {first}: {size} bytes", file=sys.stderr)
    else:
        print(f"branches {first}..{last}: {last - first + 1} messages, {size} bytes",
              file=sys.stderr)


def cmd_addleafhash(args):
    """Read messages of leaf hashes on stdin, check each, add its branch.

    Any number of messages may be given one after another. Each carries its own
    branch index, the number of hashes in its path, and the snapshot length its
    branch count follows from, so the stream parses itself.

    The first message creates the store unless one is already there: it describes
    the whole snapshot and proves one branch of the list, so there is nothing to
    initialise first and nothing to add out of turn.
    """
    path = os.path.join(args.snapshot_dir, "meta.dat")
    meta = parse_meta(path) if os.path.exists(path) else None
    raw = payload_from_hex(sys.stdin.read())
    off = 0
    added = 0
    while off < len(raw):
        if len(raw) - off < SUMMARY_FIXED_SIZE:
            raise ValueError(f"{len(raw) - off} bytes left, too few for a message header")
        (magic, version, _net_magic, _blockhash, data_length, _coins,
         branch, path_count) = struct.unpack(SUMMARY_FMT, raw[off:off + SUMMARY_FIXED_SIZE])
        if magic != SUMMARY_MAGIC or version != SUMMARY_VERSION:
            raise ValueError(f"bad summary message {off} bytes into the stream")
        size = (SUMMARY_FIXED_SIZE + 32 * path_count
                + 32 * branch_leaf_count((data_length + LEAF_SIZE - 1) // LEAF_SIZE, branch))
        if len(raw) - off < size:
            raise ValueError(f"branch {branch} is short: {len(raw) - off} bytes, expected {size}")
        message = parse_summary(raw[off:off + size])
        off += size

        if meta is None:
            os.makedirs(args.snapshot_dir, exist_ok=True)
            meta = {
                "leaf_size": LEAF_SIZE,
                "leaves_per_file": LEAVES_PER_FILE,
                "leaf_count": message["leaf_count"],
                "data_length": message["data_length"],
                "coins_count": message["coins_count"],
                "net_magic": message["net_magic"],
                "blockhash": message["blockhash"],
                "root": message["root"],
                "hashes": [ZERO_HASH] * message["leaf_count"],
                "bits": bytearray((message["leaf_count"] + 7) // 8),
            }
            create_chunks(args.snapshot_dir, meta)
        elif (meta["net_magic"], meta["blockhash"], meta["data_length"]) != \
                (message["net_magic"], message["blockhash"], message["data_length"]):
            raise ValueError(f"branch {message['branch']} describes another snapshot")

        # A branch's path proves where it belongs, so the root the store was set up
        # with is all it takes to know the message is the right one. The message's
        # own word is not enough, which is why init takes the root from chainparams.
        if message["root"] != meta["root"]:
            raise ValueError(f"branch {message['branch']} folds to "
                             f"{display_hex(message['root'])}, but this store's root is "
                             f"{display_hex(meta['root'])}")

        start = message["branch"] * BRANCH_LEAVES
        meta["hashes"][start:start + len(message["hashes"])] = message["hashes"]
        added += 1

    if added == 0:
        raise ValueError("no hash message payloads on stdin")
    write_meta(args.snapshot_dir, meta)

    known = known_branches(meta)
    print(f"{added} {'branch' if added == 1 else 'branches'} added, "
          f"{len(known)} of {branch_count(meta['leaf_count'])} branches of hashes here")


def cmd_addleaf(args):
    """Add the leaves a payload stream holds, until stdin ends.

    One payload is what one message of the exchange carries, its index and its
    bytes; a run of them is what a loop of messages would have sent, so a run can
    be taken in one call when the messages themselves are not the point. The index
    in each payload says which leaf it is and the store says how long that leaf
    is, so nothing is needed between them to tell where one ends.
    """
    dirname = args.snapshot_dir
    meta = parse_meta(os.path.join(dirname, "meta.dat"))
    raw = payload_from_hex(sys.stdin.read())
    off = 0
    added = 0
    while off < len(raw):
        if len(raw) - off < LEAF_PAYLOAD_PREFIX_SIZE:
            raise ValueError(f"{len(raw) - off} bytes left, too few for a leaf index")
        index, = struct.unpack(LEAF_PAYLOAD_PREFIX_FMT,
                               raw[off:off + LEAF_PAYLOAD_PREFIX_SIZE])
        off += LEAF_PAYLOAD_PREFIX_SIZE
        if not 0 <= index < meta["leaf_count"]:
            raise ValueError(f"leaf index {index} out of range")
        length = leaf_length(meta, index)
        if len(raw) - off < length:
            raise ValueError(f"leaf {index} is short: {len(raw) - off} bytes, expected "
                             f"{length}")
        data = raw[off:off + length]
        off += length
        if not branch_known(meta, index // BRANCH_LEAVES):
            raise ValueError(f"branch {index // BRANCH_LEAVES}'s hashes have not arrived, "
                             f"so leaf {index} cannot be checked yet")
        if leaf_hash(data) != meta["hashes"][index]:
            raise ValueError(f"leaf {index} does not hash to the hash the summary "
                             f"gives for it")
        write_leaf(dirname, meta, index, data)
        mark_present(meta["bits"], index)
        added += 1

    if added == 0:
        raise ValueError("no leaf payloads on stdin")
    # The hash list is authoritative and already known; only the bitmap changes,
    # so the index is written once however many leaves arrived.
    write_meta(dirname, meta)

    present = sum(bin(b).count("1") for b in meta["bits"])
    print(f"{added} {'leaf' if added == 1 else 'leaves'} added, "
          f"{present} of {meta['leaf_count']} leaves present")


def cmd_getleaf(args):
    """Write one leaf's payload as hex on stdout, or a run of them.

    The payloads are written one after another, each its own index and bytes, so a
    run of leaves can be moved in one call as easily as a single one.
    """
    meta = parse_meta(os.path.join(args.snapshot_dir, "meta.dat"))
    first = args.first
    last = args.last if args.last is not None else first
    if not 0 <= first <= last < meta["leaf_count"]:
        raise ValueError(f"leaves {first}..{last} are not inside a store of "
                         f"{meta['leaf_count']} leaves")
    for index in range(first, last + 1):
        if not is_present(meta, index):
            raise ValueError(f"leaf {index} is not here")

    total = 0
    for index in range(first, last + 1):
        data = read_leaf(args.snapshot_dir, meta, index)
        sys.stdout.write(payload_to_hex(leaf_payload(index, data)))
        total += len(data)
    # The payload is the output, so the description of it goes to stderr.
    if first == last:
        print(f"leaf {first}: {total} bytes", file=sys.stderr)
    else:
        print(f"leaves {first}..{last}: {last - first + 1} payloads, {total} bytes of leaves",
              file=sys.stderr)


def cmd_verify(args):
    expected_total = None
    meta = parse_meta(os.path.join(args.snapshot_dir, "meta.dat"))
    leaf_count = meta["leaf_count"]

    present = [index for index in range(leaf_count) if is_present(meta, index)]

    # Refuse a muhash check that cannot be done before spending a pass over
    # every leaf on the checks that can.
    branches = branch_count(leaf_count)
    known = known_branches(meta)
    if args.root and len(known) != branches:
        raise ValueError(f"checking the root needs every branch of the hash list, only "
                         f"{len(known)} of {branches} are here")
    if args.muhash and not args.bitcoin_util:
        raise ValueError("checking a muhash needs --bitcoin-util to compute one: "
                         "the store does not record one")
    if args.total_amount and not args.bitcoin_util:
        raise ValueError("checking the total needs --bitcoin-util to add the coins up: "
                         "the store does not record one")
    if args.total_amount is not None:
        expected_total = parse_btc(args.total_amount)
    if args.bitcoin_util and len(present) != leaf_count:
        raise ValueError("recomputing the muhash needs every leaf, only "
                         f"{len(present)} of {leaf_count} are here")

    # The leaves are the whole snapshot in order, so they can be streamed to
    # bitcoin-util as they are read without joining them first. It writes
    # progress to stderr and the hash to stdout only once it has read
    # everything, so writing all the input before reading the output cannot
    # deadlock.
    proc = None
    argv = []
    if args.bitcoin_util:
        argv = shlex.split(args.bitcoin_util) + ["txoutsetsummary", "-"]
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        except FileNotFoundError:
            raise ValueError(f"could not run {argv[0]}")

    muhash = ZERO_HASH
    total = "total not checked"
    got = b""

    def check_leaf(index, digest):
        if digest != meta["hashes"][index]:
            raise ValueError(f"leaf {index} on disk does not hash to the hash list")

    # One pass: each leaf is fed to bitcoin-util as it is read, and hashed in a
    # worker thread while the next leaf is being read, so hashing a leaf and
    # feeding the snapshot overlap instead of adding up. hashlib releases the
    # GIL for buffers this size, so the worker really does run alongside this
    # thread rather than taking turns with it.
    pending = None
    with futures.ThreadPoolExecutor(max_workers=1) as pool:
        try:
            for index in present:
                data = read_leaf(args.snapshot_dir, meta, index)
                if proc is not None:
                    assert proc.stdin is not None
                    proc.stdin.write(data)
                future = pool.submit(leaf_hash, data)
                if pending is not None:
                    check_leaf(pending[0], pending[1].result())
                pending = (index, future)
            if pending is not None:
                check_leaf(pending[0], pending[1].result())
            if proc is not None:
                assert proc.stdin is not None and proc.stdout is not None
                proc.stdin.close()
                got = proc.stdout.read()
        except Exception:
            if proc is not None:
                proc.kill()
            raise
    if proc is not None:
        proc.wait()
        if proc.returncode:
            raise ValueError(f"{' '.join(argv)} failed with status {proc.returncode}")
        report = json.loads(got.decode(), parse_float=Decimal)
        if "muhash" not in report:
            raise ValueError(f"{' '.join(argv)} reported no muhash: was it run with -nomuhash?")
        if expected_total is not None and Decimal(expected_total) != report["total_amount"] * 100_000_000:
            raise ValueError(f"total mismatch: the leaves total {report['total_amount']} BTC, "
                             f"expected {args.total_amount}")
        recomputed = from_display_hex(report["muhash"])
        if args.muhash and recomputed != from_display_hex(args.muhash):
            raise ValueError(f"muhash mismatch: the leaves give {display_hex(recomputed)}, "
                             f"expected {args.muhash}")
        muhash = recomputed
        total = f"total {report['total_amount']} BTC"

    computed = "muhash not checked" if muhash == ZERO_HASH else "muhash " + display_hex(muhash)
    if len(known) != branches:
        # The root folds from every branch, so a store holding some of the list
        # is reported as it stands rather than against a root it cannot have.
        print(f"ok  {len(present)} of {leaf_count} leaves checked, "
              f"{len(known)} of {branches} branches of hashes here, no root yet, {computed}, {total}")
        return
    root = hashes_root(meta["hashes"])
    if root != meta["root"]:
        raise ValueError(f"the hash list folds to {display_hex(root)}, but the root this "
                         f"store was set up with is {display_hex(meta['root'])}")
    if args.root and from_display_hex(args.root) != root:
        raise ValueError(f"root mismatch: the branch roots fold to {display_hex(root)}, "
                         f"expected {args.root}")
    print(f"ok  {len(present)} of {leaf_count} leaves checked, "
          f"root {display_hex(root)}, {computed}, {total}")


def main():
    # Piping the summary JSON into head or jq is ordinary use, so die quietly on
    # a closed pipe as any other command line tool does, rather than printing a
    # BrokenPipeError while flushing at exit. SIGPIPE does not exist on Windows.
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    split = sub.add_parser("split", help="cut a snapshot file into leaves plus a meta.dat index")
    split.add_argument("infile", help="snapshot file written by dumptxoutset")
    split.add_argument("snapshot_dir", help="snapshot directory to create")
    split.set_defaults(func=cmd_split)

    summary = sub.add_parser("summary", help="print what a store holds, as JSON")
    summary.add_argument("snapshot_dir", help="snapshot directory")
    summary.set_defaults(func=cmd_summary)

    init = sub.add_parser("init", help="create an empty store from the values a chainparams entry "
                                       "carries: chain, base block hash, coins, data length, root")
    init.add_argument("snapshot_dir", help="directory to create")
    init.add_argument("chain", help="chain name, as chainparams and -chain use it")
    init.add_argument("blockhash", help="base block hash, as hex in Bitcoin Core display order")
    init.add_argument("coins", type=int, help="coin count")
    init.add_argument("data_length", type=int, help="serialized snapshot size in bytes")
    init.add_argument("root", help="the root the snapshot folds to, as hex in Bitcoin Core display "
                                   "order, from the chainparams entry")
    init.set_defaults(func=cmd_init)

    getleafhash = sub.add_parser("getleafhash", help="write messages of leaf hashes as hex on "
                                                     "stdout: each path, then the hashes of one "
                                                     "branch")
    getleafhash.add_argument("snapshot_dir", help="snapshot directory")
    getleafhash.add_argument("first", type=int, help="first branch index")
    getleafhash.add_argument("last", type=int, nargs="?",
                             help="last branch of the run, inclusive; just the first if "
                                  "absent")
    getleafhash.set_defaults(func=cmd_getleafhash)

    addleafhash = sub.add_parser("addleafhash", help="read messages of leaf hashes as hex on stdin "
                                                     "until it ends and add their branches, creating "
                                                     "the store if it is not there")
    addleafhash.add_argument("snapshot_dir", help="snapshot directory")
    addleafhash.set_defaults(func=cmd_addleafhash)

    addleaf = sub.add_parser("addleaf",
                             help="add leaves to a snapshot, reading their payloads as hex on "
                                  "stdin until it ends")
    addleaf.add_argument("snapshot_dir", help="snapshot directory")
    addleaf.set_defaults(func=cmd_addleaf)

    getleaf = sub.add_parser("getleaf",
                             help="write a leaf's payload as hex on stdout, or a run of them: "
                                  "each index and bytes")
    getleaf.add_argument("snapshot_dir", help="snapshot directory")
    getleaf.add_argument("first", type=int, help="first leaf index")
    getleaf.add_argument("last", type=int, nargs="?",
                         help="last leaf of the range, inclusive; just the first if absent")
    getleaf.set_defaults(func=cmd_getleaf)

    verify = sub.add_parser("verify", help="check the leaves, the hash list and the root of a snapshot")
    verify.add_argument("snapshot_dir", help="snapshot directory")
    verify.add_argument("--root", help="also require the root to equal this, as hex in Bitcoin Core "
                                       "display order; pass the value committed in chainparams to check "
                                       "the snapshot against it")
    verify.add_argument("--muhash", help="also require the recomputed muhash to equal this, as hex "
                                         "in Bitcoin Core display order; needs --bitcoin-util, since "
                                         "no muhash is stored")
    verify.add_argument("--total-amount", help="also require the leaves to total this many BTC, as "
                                               "a decimal, the way gettxoutsetinfo reports it; needs "
                                               "--bitcoin-util, since no total is stored")
    verify.add_argument("--bitcoin-util", help="bitcoin-util to run to recompute the muhash from the "
                                               "leaves on disk, with any arguments")
    verify.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    try:
        args.func(args)
    except (ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
