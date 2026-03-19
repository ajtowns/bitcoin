# Receiver-side plan for BIN25-2.2 gettmplt

## `PeerTemplatePartial` (templateman.h)

Post-reconciliation reconstruction state. No shortids needed — positions are
determined during the sketch→partial transition and encoded in the bitset.

Fields:
```
// m_txs from Template base: ordered by position (= shortid-sorted order),
//   pool.end() entries = missing positions
// m_hash, m_tip from Template base
TemplateTxnsSelection m_missing   // bitset of unfilled positions
size_t m_filled{0}
```

Created from `PeerTemplateSketch` when all buckets resolved:
1. Build peer's full sorted shortid list:
   - Start with our shortids
   - Remove diff shortids we have (in our set, not peer's)
   - Add diff shortids we don't have (in peer's set, not ours)
   - Sort
2. For each peer shortid: binary search our sorted shortids → tx ref or pool.end()
3. Release refs for our shortids not in peer's template (RemoveTxs)
4. Build m_missing bitset for pool.end() positions

Fill (called from net_processing on tmplttxn):
- Iterate m_missing in order, fill next missing position with next incoming tx
- Increment m_filled

TryFinalize: ComputeHash(), compare to m_hash → on match promote to PeerTemplate

## TemplateManager additions

New maps (under m_template_mutex):
```cpp
std::unordered_map<NodeId, PeerTemplateSketch>  m_peer_sketches;
std::unordered_map<NodeId, PeerTemplatePartial> m_peer_partials;
std::unordered_map<NodeId, PeerTemplate>        m_peer_templates;  // completed
```

New methods (all called from net_processing with m_template_mutex held):
- `InitPeerSketch(nodeid, hash, tip_index, nonce, basis_hash, basis_delta, combined_sketch)`
  → scans mempool+pool, calls PeerTemplateSketch::Init; returns decode status
- `UpdatePeerSketch(nodeid, hash, round, shortid_bytes, sketches)`
  → adds data, attempts decode; returns {fully_resolved, shortidmask, sketchmask}
- `FinalizePeerSketch(nodeid)`
  → sketch→partial transition; returns GR-encoded missing positions (empty = nothing to request)
- `FillPeerPartial(nodeid, hash, txns)` → handle tmplttxn chunk
- `TryFinalizePeerPartial(nodeid)` → hash validate, promote to PeerTemplate
- `GetPeerTemplate(nodeid)` → for basis hint in next gettmplt
- `ForgetPeer(nodeid)` → cleanup on disconnect

## net_processing changes

### Per-peer state additions (Peer struct)

```cpp
std::atomic<NodeClock::time_point> m_next_gettmplt{NodeClock::time_point::max()};
std::atomic<bool> m_gettmplt_active{false};
uint256 m_pending_gettmplt_hash GUARDED_BY(g_msgproc_mutex);  // zero until round>=1
int m_pending_gettmplt_round{-1} GUARDED_BY(g_msgproc_mutex);
```

### PeerManagerImpl additions

```cpp
std::atomic<int> m_active_inbound_template_peers{0};
```

### MaybeRequestTemplate(node, peer)

- Check m_next_gettmplt timer
- Inbound rotation: cap at MAX_INBOUND_TEMPLATE_PEERS (~12), rotate randomly every ~30 min
- Send gettmplt n=0 with optional basis hash (from GetPeerTemplate)
- Set m_pending_gettmplt_hash = ZERO, m_pending_gettmplt_round = 0
- Schedule m_next_gettmplt ~2 min out (with jitter)
- Block-relay-only one-shot: deferred to polish

### TMPLT handler

Round 0:
- Parse hash, n, tip_hash, nonce, basis_hash, basis_delta, combined_sketch
- Validate peer supports templates (m_next_gettmplt != max())
- Look up tip_index under cs_main
- Call InitPeerSketch(...)
- If fully resolved: FinalizePeerSketch → send gettmplttxn if missing, else done
- Else: set m_pending_gettmplt_hash = hash, round = 1; send gettmplt n=1 (sketchmask only, no shortidmask)

Rounds 1-3:
- Validate hash == m_pending_gettmplt_hash, round matches
- Call UpdatePeerSketch(...)
- If fully resolved: FinalizePeerSketch → gettmplttxn or done
- Else: advance round, send gettmplt n=round (sketchmask for unresolved, no shortidmask yet)

Round 4 (shortid fallback):
- All remaining buckets get direct shortids
- Call UpdatePeerSketch with shortids → FinalizePeerSketch

### TMPLTTXN handler (receiver side)

- Validate this was requested (m_pending_gettmplt_hash not null, or track separately)
- Parse hash, txns
- Call FillPeerPartial(nodeid, hash, txns)
- Call TryFinalizePeerPartial(nodeid) → logs completion

### Wire into SendMessages

Add `MaybeRequestTemplate(node, *peer)` call alongside existing
`MaybeSendTemplateMessages`.

## Implementation order

1. ~~templateman: PeerTemplateSketch~~ (done)
2. templateman: PeerTemplatePartial (post-reconciliation reconstruction)
3. templateman: TemplateManager receiver methods
4. net_processing: Peer state + MaybeRequestTemplate + TMPLT/TMPLTTXN handlers
5. RPC: peer_templates in gettemplateinfo; template_status in getpeerinfo
