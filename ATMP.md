
Feeding template txs into ATMP

 - We want to do this on a per-peer basis, processing about one tx at a time.
 - We want to order the txs topologically, or we get too many rejections.
 - We want to package txs together so 1p1c works.


## Data structures (on PeerTemplate)

```c++
// Built by TopoSort() on template completion, in reverse topo order
// so pop_back() yields the next tx to validate.
struct TxPendingATMP {
    uint32_t pos;
    uint32_t nchildren;
};
std::vector<TxPendingATMP> m_pending;

// Built during validation
struct PackageCandidate {
    CTransactionRef tx;
    uint32_t remaining_children;
};
std::unordered_map<Txid, PackageCandidate, SaltedTxidHasher> m_package_candidates;
```

## ATMP result classification

```c++
// Returned by ConsiderTemplateTx to net_processing,
// passed to TemplateManager::ReportATMPResult
enum class TemplateATMPResult {
    ACCEPTED,             // VALID
    ALREADY_IN_MEMPOOL,   // MEMPOOL_ENTRY or DIFFERENT_WITNESS
    CONFLICT,             // TX_CONFLICT
    MISSING_INPUTS,       // TX_MISSING_INPUTS
    RECONSIDERABLE,       // TX_RECONSIDERABLE -- 1p1c candidate
    PREMATURE_SPEND,      // TX_PREMATURE_SPEND
    UNACCEPTABLE,         // consensus/policy failures -- permanent reject
};
```

## Return type from GetNextTemplateTx

```c++
struct NextTemplateTx {
    CTransactionRef tx;
    CTransactionRef package_parent;  // non-null if 1p1c opportunity
    size_t pos{0};
    size_t total{0};
    uint32_t nchildren{0};           // passed back to ReportATMPResult
    explicit operator bool() const { return tx != nullptr; }
};
```

When `package_parent` is set, net_processing uses `ProcessNewPackage({parent, child})`
instead of individual `ProcessTransaction`.

## Topological sort (called once on template completion)

Reverse Kahn's: start from leaves (out-degree 0), work toward roots.
Output is reverse-topo order so `pop_back()` gives topo order.
Parent lookup uses `tx->vin + txid_pos` — no children adjacency list needed.

```c++
void PeerTemplate::TopoSort()
{
    const uint32_t n = m_txs.size();

    std::unordered_map<Txid, uint32_t, SaltedTxidHasher> txid_pos;
    txid_pos.reserve(n);

    std::vector<uint32_t> out_degree(n, 0);

    std::vector<uint32_t> ready;

    // 1. Build txid -> position map
    for (uint32_t i = 0; i < n; ++i) {
        txid_pos.emplace(m_txs[i]->tx->GetHash(), i);
    }

    // 2. Count out-degree (number of in-template children) per tx
    for (uint32_t i = 0; i < n; ++i) {
        for (const auto& txin : m_txs[i]->tx->vin) {
            auto it = txid_pos.find(txin.prevout.hash);
            if (it != txid_pos.end()) {
                ++out_degree[it->second];
            }
        }
    }

    // 3. Reverse Kahn's: seed with leaves (out_degree == 0)
    for (uint32_t i = 0; i < n; ++i) {
        if (out_degree[i] == 0) ready.push_back(i);
    }

    // Save nchildren before Kahn's mutates out_degree
    std::vector<uint32_t> nchildren{out_degree};

    m_pending.clear();
    m_pending.reserve(n);
    while (!ready.empty()) {
        uint32_t pos = ready.back();
        ready.pop_back();

        m_pending.push_back({.pos=pos, .nchildren=nchildren[pos]});

        // Decrement out_degree of this tx's parents
        for (const auto& txin : m_txs[pos]->tx->vin) {
            auto it = txid_pos.find(txin.prevout.hash);
            if (it != txid_pos.end()) {
                if (--out_degree[it->second] == 0) {
                    ready.push_back(it->second);
                }
            }
        }
    }

    // m_pending is now in reverse topo order: pop_back() yields topo order
}
```

## GetNextTemplateTx (one tx per ProcessMessages call)

Pops from m_pending, skips already-handled txs, checks package candidates
for 1p1c opportunity before returning.

```c++
// In TemplateManager::GetNextTemplateTx

while (!pt.m_pending.empty()) {
    auto [pos, nchildren] = pt.m_pending.back();
    pt.m_pending.pop_back();

    auto& ttx = *pt.m_txs[pos];

    // Always decrement package candidates for this tx's parents, even if skipping.
    // No dedupe: nchildren counted with duplicates, so decrement with duplicates.
    for (const auto& txin : ttx.tx->vin) {
        auto it = pt.m_package_candidates.find(txin.prevout.hash);
        if (it != pt.m_package_candidates.end()) {
            if (--it->second.remaining_children == 0) {
                pt.m_package_candidates.erase(it);
            }
        }
    }

    // Skip if not yet ready for retry
    if (now < ttx.next_mempool_check) continue;

    // Skip if already in mempool
    if (mempool.exists(ttx.tx->GetWitnessHash())) {
        ttx.next_mempool_check = now + 120s;
        continue;
    }

    // Skip if confirmed in recent block (stale template)
    if (check_recent_block) {
        auto wit = recent_block_txs->find(GenTxid{ttx.tx->GetWitnessHash()});
        if (wit != recent_block_txs->end()) {
            ttx.next_mempool_check = now + 120s;
            continue;
        }
    }

    // Check package candidates for 1p1c opportunity
    // Dedupe to handle txs spending multiple outputs of the same parent
    CTransactionRef package_parent{nullptr};
    bool found_multiple{false};
    for (const auto& txin : ttx.tx->vin) {
        if (package_parent && txin.prevout.hash == package_parent.GetHash()) continue;
        auto it = pt.m_package_candidates.find(txin.prevout.hash);
        if (it != pt.m_package_candidates.end()) {
            if (package_parent) {
                found_multiple = true;
                break;
            } else {
                package_parent = it->second.tx;
            }
        }
    }
    // If multiple low-fee parents, 1p1c won't apply, so skip
    if (found_multiple) {
        ttx.next_mempool_check = now + 120s;
        continue;
    }

    return NextTemplateTx{ttx.tx, package_parent, pos, total, nchildren};
}
```

## ReportATMPResult (on TemplateManager)

Called after ATMP/ProcessNewPackage. Handles retry timing and adding to
package candidates on RECONSIDERABLE. Candidate decrement already happened
in GetNextTemplateTx.

```c++
void TemplateManager::ReportATMPResult(NodeId nodeid, const CTransactionRef& tx,
                                       uint32_t nchildren,
                                       NodeClock::time_point now,
                                       TemplateATMPResult result)
{
    // 1. Update next_mempool_check based on result
    // (inlines BumpMempoolCheck, which can be removed)
    auto it = m_pool.find(tx->GetWitnessHash());
    if (it != m_pool.end()) {
        switch (result) {
        case TemplateATMPResult::ACCEPTED:
        case TemplateATMPResult::ALREADY_IN_MEMPOOL:
        case TemplateATMPResult::CONFLICT:
        case TemplateATMPResult::RECONSIDERABLE:
        case TemplateATMPResult::MISSING_INPUTS:
            it->next_mempool_check = now + 120s;
            break;
        case TemplateATMPResult::PREMATURE_SPEND:
            it->next_mempool_check = now + 1200s;
            break;
        case TemplateATMPResult::UNACCEPTABLE:
            it->next_mempool_check = NodeClock::time_point::max();
            break;
        }
    }

    // 2. On RECONSIDERABLE with children: stash for potential 1p1c attempts
    // note: we we have a chain of grandparent A, parent B, child C, and B
    // fails as reconsiderable, we still add B here, as there may be another
    // child of A which is tried before C and gets A accepted into the mempool
    if (result == TemplateATMPResult::RECONSIDERABLE && nchildren > 0) {
        auto cache_it = m_peer_template_cache.find(nodeid);
        if (cache_it != m_peer_template_cache.end()) {
            cache_it->second->m_package_candidates.emplace(tx->GetHash(),
                PackageCandidate{tx, nchildren});
        }
    }
}
```

## ConsiderTemplateTx (net_processing)

Thin wrapper: calls ATMP or ProcessNewPackage, classifies result.

```c++
TemplateATMPResult PeerManagerImpl::ConsiderTemplateTx(
    Peer& peer, const NextTemplateTx& next, NodeClock::time_point now)
{
    auto process_next = [&]() -> MempoolAcceptResult {
        LOCK(cs_main);
        if (next.package_parent) {
            Package package{next.package_parent, next.tx};
            auto result = ProcessNewPackage(m_chainman.ActiveChainstate(), m_mempool,
                package, /*test_accept=*/false, /*client_maxfeerate=*/std::nullopt);
            auto it = result.m_tx_results.find(next.tx.GetWitnessHash());
            if (it == result.m_tx_results.end()) {
                // parent must have failed, and is no longer reconsiderable
                return MempoolAcceptResult::Failure(TxValidationResult::TX_MISSING_INPUTS);
            }
            return it->second;
        } else {
            return m_chainman.ProcessTransaction(next.tx);
        }
    };
    auto result = process_next();

    if (result.m_result_type == MempoolAcceptResult::ResultType::VALID) {
        LOCK(m_tx_download_mutex);
        ProcessValidTx(peer.m_id, next.tx, result.m_replaced_transactions);
        return TemplateATMPResult::ACCEPTED;
    }

    if (result.m_result_type == MempoolAcceptResult::ResultType::MEMPOOL_ENTRY ||
        result.m_result_type == MempoolAcceptResult::ResultType::DIFFERENT_WITNESS) {
        return TemplateATMPResult::ALREADY_IN_MEMPOOL;
    }

    switch (result.m_state.GetResult()) {
    case TxValidationResult::TX_RECONSIDERABLE:
        return TemplateATMPResult::RECONSIDERABLE;
    case TxValidationResult::TX_CONFLICT:
        return TemplateATMPResult::CONFLICT;
    case TxValidationResult::TX_MISSING_INPUTS:
        return TemplateATMPResult::MISSING_INPUTS;
    case TxValidationResult::TX_PREMATURE_SPEND:
        return TemplateATMPResult::PREMATURE_SPEND;
    default:
        return TemplateATMPResult::FAILED;
    }
}
```

## ConsiderTemplateTransactions (net_processing, top-level)

```c++
bool PeerManagerImpl::ConsiderTemplateTransactions(Peer& peer)
{
    AssertLockHeld(g_msgproc_mutex);
    AssertLockNotHeld(m_template_mutex);

    if (m_opts.ignore_incoming_txs) return false;
    if (m_chainman.IsInitialBlockDownload() || !m_mempool.GetLoadTried()) return false;

    auto now = NodeClock::now();
    NextTemplateTx next;
    {
        LOCK(m_template_mutex);
        LOCK(m_most_recent_block_mutex);
        next = m_templateman.GetNextTemplateTx(peer.m_id, now, m_mempool,
                                               m_most_recent_block_hash,
                                               m_most_recent_block_txs.get());
    }
    if (!next) return false;

    auto result = ConsiderTemplateTx(peer, next, now);

    WITH_LOCK(m_template_mutex,
              m_templateman.ReportATMPResult(peer.m_id, next.tx, now, result, next.nchildren));

    LogDebug(BCLog::GETTMPLT, "%s template tx %d/%d children=%d wtxid=%s peer=%d",
             (result == TemplateATMPResult::ACCEPTED ? "Accepted" : "Rejected"),
             next.pos + 1, next.total, next.nchildren,
             next.tx->GetWitnessHash().ToString(), peer.m_id);
    return true;
}
```

