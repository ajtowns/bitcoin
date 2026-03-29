# BIN25-2.2 Wire Protocol

Implemented wire messages for the gettmplt template sharing protocol.

## Negotiation

Announced via BIP-434 FEATURE message.

    feature_id:   "BIN25-2.2"
    feature_data: empty

## Messages

### `gettmplt` — request template data

**Round 0** (initial request, sent by receiver):

    round:      uint8_t = 0
    basis_hash: uint256          optional; omitted or zero if no basis

Sent every ~2 min to peers that advertised BIN25-2.2. `basis_hash`
is the hash of the most recent completed peer template from this peer,
enabling delta encoding.

**Rounds 1-4** (follow-up, sent by receiver after processing tmplt responses):

    round:         uint8_t      1, 2, 3, or 4
    hash:          uint256      template hash
    shortidmask:   uint32_t     groups to send shortids for (resolved)
    sketchmask:    uint32_t     groups to send sketches for (unresolved)

Both masks are always present on the wire (round 4 sends sketchmask=0).

### `tmplt` — template response

**Round 0** (initial response, sent by provider):

    hash:          uint256
    round:         uint8_t = 0
    tip_hash:      uint256      chain tip (or zero)
    nonce:         uint64_t     template-level nonce for shortid computation
    basis_hash:    uint256      basis template hash (or zero)
    basis_delta:   vector<uint8_t>  GR-encoded retained positions from basis
    sketches:      vector<Sketch>   4 stride-4 group sketches (round 0)

Sent from `MaybeSendTemplateMessages` when a pending `Req` is ready and
a local template exists.

**Rounds 1–4** (incremental response, sent by provider):

    hash:          uint256
    round:         uint8_t      1, 2, 3, or 4
    shortidmask:   uint32_t     echoed from gettmplt request
    sketchmask:    uint32_t     echoed from gettmplt request
    shortid_bytes: vector<uint8_t>  GR-encoded shortids for shortidmask groups
    sketches:      vector<Sketch>   sketches for sketchmask groups

Provider echoes the masks so the receiver can interpret the data without
storing what it sent. `shortid_bytes` skips the first `SKETCH_CAPACITY`
(64) shortids per group (covered by the sketch).

### `gettmplttxn` — request missing transactions

    hash:  uint256              template hash
    grenc: vector<uint8_t>      GR-encoded missing positions

Sent after sketch reconciliation resolves all buckets but some positions
have no local transaction. Positions are over a 16-bit range; encoding
is `compact_size(n) + P_byte + GR-encoded gaps`.

### `tmplttxn` — transaction data response

    hash: uint256               template hash
    txs:  vector<CTransaction>  transactions with witness (TX_WITH_WITNESS)

Provider drains queued positions in ~100 KB chunks per `SendMessages`
cycle. Multiple `tmplttxn` messages may be sent for one template.

## Serialization Types

    Sketch:  { uint32_t elements, vector<uint8_t> ser }
    uint256: 32 bytes, little-endian
    uint32_t: 4 bytes, little-endian
    uint64_t: 8 bytes, little-endian
    vector<T>: CompactSize length + serialized elements

## Protocol Flow

    Receiver                          Provider
    --------                          --------
    FEATURE "BIN25-2.2"  ---------->
                          <----------  FEATURE "BIN25-2.2"

    gettmplt n=0 [basis]  --------->
                          <---------  tmplt hash n=0 tip nonce basis delta sketches[4]

    (decode round-0 sketches; resolve some groups)

    gettmplt n=1 hash
      shortidmask sketchmask ------->
                          <---------  tmplt hash n=1 sidmask skmask sids sketches

    ... (rounds 2-4 as needed) ...

    (all groups resolved; some txs missing)

    gettmplttxn hash positions ----->
                          <---------  tmplttxn hash txs...
                          <---------  tmplttxn hash txs...  (chunked)

    (hash verified; template complete)

## Reconciliation Structure

32 sub-buckets; low 5 bits of shortid select bucket. 64-cap sketches.

Sketch tree (flat array, 32 slots):

    slots  0..3:  round 0 — 4 stride-4 groups (each covers 8 buckets)
    slots  4..7:  round 1 — 4 stride-8 groups
    slots  8..15: round 2 — 8 stride-16 groups
    slots 16..31: round 3 — 16 individual buckets

At each round, the receiver XORs received sketches into earlier slots to
split groups. `TryDecodeGroups` attempts `(basis+local)^provider` then
`basis^provider` per unresolved group.

Rounds 1–3: receiver requests sketches for unresolved groups and/or
shortids for resolved groups. Round 4: pure shortid fallback (no more
sketches).

## TemplateManager Interface (receiver side)

```
WaitingForPeerSketch(nodeid)
    — mark gettmplt n=0 sent; releases prior reconciliation state

InitPeerSketch(nodeid, tip, hash, nonce, basis_hash, basis_delta, sketches)
    → TmpltResult {UNRESOLVED|NEEDS_TXS|DONE|ERROR}

UpdatePeerSketch(nodeid, hash, round, shortidmask, sketchmask, shortid_bytes, sketches)
    → TmpltResult {UNRESOLVED|NEEDS_TXS|DONE|ERROR}

FillPeerPartial(nodeid, hash, txs)
    → pair<TmpltState, uint32_t>  {ERROR|NEEDS_TXS|DONE, ntxs}

GetLastPeerTemplateHash(nodeid)
    → uint256  (for basis hint in next gettmplt n=0)

ForgetPeer(nodeid)
    — cleanup on disconnect
```

net_processing switches on `TmpltState`:
- `ERROR` → log, disable future requests (m_next_gettmplt = max)
- `UNRESOLVED` → send gettmplt n=round+1 with masks from result
- `NEEDS_TXS` → send gettmplttxn with GR-encoded missing positions
- `DONE` → log completion
