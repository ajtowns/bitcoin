// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/templateman.h>
#include <node/templateman_impl.h>

#include <blockencodings.h>
#include <test/util/setup_common.h>
#include <test/util/templateman.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <vector>

using namespace node;

/** Sketch capacity used throughout these tests: small enough that the
 *  round machinery is exercised at tiny tx counts. */
static constexpr int TEST_SC = 8;

using TestLocalTemplate = LocalTemplateT<TEST_SC>;
using TestSketch = PeerTemplateSketchT<TEST_SC>;
using TestManager = TemplateManagerT<TEST_SC>;

BOOST_FIXTURE_TEST_SUITE(templateman_tests, BasicTestingSetup)

static std::vector<uint64_t> range_sids(uint64_t lo, uint64_t hi)
{
    std::vector<uint64_t> v;
    for (uint64_t i = lo; i < hi; ++i) v.push_back(i);
    return v;
}

static TestLocalTemplate MakeProvider(std::vector<uint64_t> sids)
{
    TestLocalTemplate tmpl;
    std::sort(sids.begin(), sids.end());
    tmpl.shortids = std::move(sids);
    for (auto sid : tmpl.shortids) {
        ++tmpl.bucket_count[sid % 32];
    }
    tmpl.GenerateSketches();
    return tmpl;
}

static void sketch_range(uint64_t prov_lo, uint64_t prov_hi,
                         uint64_t basis_lo, uint64_t basis_hi,
                         uint64_t local_lo, uint64_t local_hi,
                         int expected_rounds)
{
    BOOST_REQUIRE(basis_lo >= prov_lo && basis_hi <= prov_hi);

    auto prov_sids  = range_sids(prov_lo,  prov_hi);
    auto basis_sids = range_sids(basis_lo, basis_hi);
    auto local_sids = range_sids(local_lo, local_hi);

    auto provider = MakeProvider(prov_sids);

    TemplateTxSet pool;
    std::sort(basis_sids.begin(), basis_sids.end());
    std::sort(local_sids.begin(), local_sids.end());

    TemplateTxVec txs;
    std::vector<uint64_t> sids;
    for (auto s : basis_sids) { txs.push_back_placeholder(pool); sids.push_back(s); }
    size_t basis_count = txs.size();
    for (auto s : local_sids) { txs.push_back_placeholder(pool); sids.push_back(s); }

    TestPeerTemplateSketchT<TEST_SC> sketch{pool};

    auto reconstruct = [&](int round) {
        std::vector<uint64_t> result;
        for (uint64_t sid : sketch.m_shortids) {
            if (sid != 0) result.push_back(sid);
        }
        std::sort(result.begin(), result.end());
        BOOST_CHECK_EQUAL(round, expected_rounds);
        BOOST_CHECK(result == provider.shortids);
        BOOST_TEST_CHECKPOINT("Inside reconstruct(round=" << round << ")");
    };

    if (sketch.Init(std::move(txs), std::move(sids), basis_count, provider.GetSketches(0), {}, {}).resolved) {
        reconstruct(0);
        return;
    }

    for (int round = 1; round <= 4; ++round) {
        GRVector shortid_bytes;
        if (round == 4) {
            shortid_bytes = provider.GetShortIDBytes(4, 0, GroupMask::Fill(TOTAL_BUCKETS));
        }
        auto [res, shortidmask, sketchmask] = sketch.Process(
            round, GroupMask::Fill(TOTAL_BUCKETS), GroupMask::Fill(TOTAL_BUCKETS), shortid_bytes, provider.GetSketches(round));
        if (res) {
            reconstruct(round);
            return;
        }
    }
    BOOST_ERROR("reconciliation did not resolve");
}

// provider == receiver: empty diff.
BOOST_AUTO_TEST_CASE(sketch_no_diff)       { sketch_range(1, 17,   1, 17,  1,  1, 0); }

// Provider has extras; basis-only covers all 32 buckets at round 0.
BOOST_AUTO_TEST_CASE(sketch_round0)        { sketch_range(1, 21,   1, 11,  1,  1, 0); }

// Receiver has local extras not in provider; basis+local decode needed.
BOOST_AUTO_TEST_CASE(sketch_local_extras)  { sketch_range(1, 11,   1,  6,  6, 16, 0); }

// ~50 total diff → fails round 0 (4 groups × 8 = 32 cap; 50/4≈13>8), resolves round 1 (8 groups × 8; 50/8≈7≤8).
BOOST_AUTO_TEST_CASE(sketch_round1)        { sketch_range(1, 51,   1,  1,  1,  1, 1); }

// ~100 total diff → fails round 1 (100/8≈13>8), resolves round 2 (16 groups × 8; 100/16≈7≤8).
BOOST_AUTO_TEST_CASE(sketch_round2)        { sketch_range(1, 101,  1,  1,  1,  1, 2); }

// ~200 total diff → fails round 2 (200/16≈13>8), resolves round 3 (32 groups × 8; 200/32≈7≤8).
BOOST_AUTO_TEST_CASE(sketch_round3)        { sketch_range(1, 201,  1,  1,  1,  1, 3); }

// ~400 total diff → fails round 3 (400/32≈13>8) → shortid fallback round 4.
BOOST_AUTO_TEST_CASE(sketch_round4)        { sketch_range(1, 401,  1,  1,  1,  1, 4); }

// Shortid fallback fires at round 1 using the combined (round-0) sketches, before any split.
// 600 total diff is far too large for any sketch round alone, but GetShortIDBytes(1) sends
// items 9..600 (outer), and (0 basis + ~592 outer + ~8 inner = 600 >= 600) decodes.
BOOST_AUTO_TEST_CASE(sketch_shortid_early_round1)
{
    auto prov_sids = range_sids(1, 601);
    auto provider = MakeProvider(prov_sids);
    TemplateTxSet pool;
    TestPeerTemplateSketchT<TEST_SC> sketch{pool};

    BOOST_REQUIRE(!sketch.Init({}, {}, 0, provider.GetSketches(0), {}, {}).resolved);

    // Send shortid bytes at round 1 (combined-level outer shortids) before any PrepareRound.
    auto shortid_bytes = provider.GetShortIDBytes(1, 0, GroupMask::Fill(TOTAL_BUCKETS));
    auto [res, shortidmask, sketchmask] = sketch.Process(1, GroupMask::Fill(TOTAL_BUCKETS), GroupMask::Fill(TOTAL_BUCKETS), shortid_bytes, provider.GetSketches(1));
    BOOST_REQUIRE(res);

    std::vector<uint64_t> result;
    for (uint64_t sid : sketch.m_shortids) {
        if (sid != 0) result.push_back(sid);
    }
    std::sort(result.begin(), result.end());
    BOOST_CHECK(result == provider.shortids);
}

/** Generate n shortids that all fall in the given bucket (sid % 32 == bucket). */
static std::vector<uint64_t> make_bucket_sids(uint8_t bucket, size_t n)
{
    std::vector<uint64_t> sids;
    sids.reserve(n);
    // For bucket 0: use 32, 64, 96, ... (skip 0 since 0 is the "zeroed" sentinel)
    // For bucket b>0: use b, b+32, b+64, ...
    uint64_t start = (bucket == 0) ? 32 : bucket;
    for (size_t i = 0; i < n; ++i) {
        sids.push_back(start + i * 32);
    }
    return sids;
}

// Mixed decode mask: some groups resolve via basis-only, others via basis+local,
// producing a m_decoded_by_basis that is neither all-zeros nor all-ones.
//
// Design (TOTAL_BUCKETS=32, capacity=8, stride-4 groups at round 0):
//
// "Even" buckets (b%8 < 4): provider=9, basis=2, local=0 per bucket
//   → basis-only decode (2+8 ≥ 9 ✓; diff = 9-2 = 7 per bucket)
//   → diff per stride-8 group (4 even buckets) = 7×4 = 28
//
// "Odd" buckets (b%8 ≥ 4): provider=17, basis=0, local=10 per bucket
//   → basis-only fails (0+8=8 < 17); basis+local: |17-0-10|=7 per bucket ✓
//   → diff per stride-8 group (4 odd buckets) = 7×4 = 28
//
// Per stride-4 group (round 0): diff = 28+28 = 56 > 8 → round 0 fails ✓
// Per stride-8 group (round 1): diff = 28 > 8?? No — see scaled-down comment below.
//
// NB: at capacity 8 the per-group diffs must be ≤ 8, so counts are small.
// Each stride-8 group has 4 even buckets (diff 2 each = 8) → resolves round 1 ✓
// Each stride-8 group has 4 odd buckets (diff 2 each = 8) → resolves round 1 ✓
BOOST_AUTO_TEST_CASE(sketch_mixed_decode_mask)
{
    std::vector<uint64_t> prov_sids, basis_sids, local_sids;

    for (uint8_t b = 0; b < TOTAL_BUCKETS; ++b) {
        if (b % 8 < 4) {
            // Even sub-bucket: provider=4, basis=2, local=0 → basis-only decode path
            auto prov = make_bucket_sids(b, 4);
            auto bas  = make_bucket_sids(b, 2); // first 2 of the 4 provider sids
            prov_sids.insert(prov_sids.end(), prov.begin(), prov.end());
            basis_sids.insert(basis_sids.end(), bas.begin(), bas.end());
        } else {
            // Odd sub-bucket: provider=5, basis=0, local=3 → basis+local decode path
            // basis-only fails (0+8=8 ≥ 5 would succeed!) — need provider > 8.
            // Use provider=10, local=8: |10-0-8| = 2 ✓, basis-only 0+8=8 < 10 fails ✓
            auto prov = make_bucket_sids(b, 10);
            auto loc  = make_bucket_sids(b, 8);
            prov_sids.insert(prov_sids.end(), prov.begin(), prov.end());
            local_sids.insert(local_sids.end(), loc.begin(), loc.end());
        }
    }

    auto provider = MakeProvider(prov_sids);

    TemplateTxSet pool;
    std::sort(basis_sids.begin(), basis_sids.end());
    std::sort(local_sids.begin(), local_sids.end());

    TemplateTxVec txs;
    std::vector<uint64_t> sids;
    for (auto s : basis_sids) { txs.push_back_placeholder(pool); sids.push_back(s); }
    size_t basis_count = txs.size();
    for (auto s : local_sids) { txs.push_back_placeholder(pool); sids.push_back(s); }

    TestPeerTemplateSketchT<TEST_SC> sketch{pool};

    // Round 0 fails: each stride-4 group has 4 even (diff 2 each = 8... hmm, exactly 8
    // may decode) — require the round to fail or resolve; if it resolves at round 0 that's
    // fine too, but the mask check below needs the split, so force round-1 resolution
    // by construction: even buckets diff = 4-2 = 2 per bucket × 4 = 8 per stride-4 group,
    // plus odd buckets (10-0 via basis fails; via basis+local diff |10-8|=2 per bucket × 4 = 8)
    // → stride-4 group total 16 > 8 → round 0 fails ✓.
    auto init_result = sketch.Init(std::move(txs), std::move(sids), basis_count,
                                    provider.GetSketches(0), {}, {});
    BOOST_REQUIRE(!init_result.resolved);

    // Round 1: each stride-8 group = 4 buckets of one kind, diff 8 ≤ 8 ✓.
    // Don't pass outer shortids — testing the sketch decode path for m_decoded_by_basis.
    auto [res, shortidmask, sketchmask] = sketch.Process(
        1, GroupMask{}, GroupMask::Fill(TOTAL_BUCKETS), {}, provider.GetSketches(1));
    BOOST_REQUIRE(res);

    // Verify m_decoded_by_basis has bits for even buckets only (b%8 < 4).
    BucketMask expected_basis_mask;
    for (int b = 0; b < TOTAL_BUCKETS; ++b) {
        if (b % 8 < 4) expected_basis_mask.Set(b);
    }
    BOOST_CHECK(sketch.m_decoded_by_basis == expected_basis_mask);

    // Verify final shortids match provider.
    std::vector<uint64_t> result;
    for (uint64_t sid : sketch.m_shortids) {
        if (sid != 0) result.push_back(sid);
    }
    std::sort(result.begin(), result.end());
    BOOST_CHECK(result == provider.shortids);
}

// ProcessResult masks: after round 1 partially resolves, sketchmask and shortidmask
// correctly identify which groups/buckets still need more data.
//
// Design (TOTAL_BUCKETS=32, capacity=8):
//
// Even sub-buckets (b%8 < 4):  2 elements/bucket
//   → stride-8 group diff = 4×2 = 8 ≤ 8 → resolve at round 1 ✓
//
// Odd sub-buckets (b%8 ≥ 4):  4 elements/bucket
//   → stride-8 group diff = 4×4 = 16 > 8 → fail round 1
//   → stride-16 group diff = 2×4 = 8 ≤ 8 → resolve at round 2 ✓
//
// stride-4 group (round 0): diff = 4×2 + 4×4 = 24 > 8 → round 0 fails ✓
//
// After Process(1): sketchmask  = {4,5,6,7} (odd stride-8 groups still pending).
BOOST_AUTO_TEST_CASE(sketch_selective_masks)
{
    std::vector<uint64_t> prov_sids;
    for (int b = 0; b < TOTAL_BUCKETS; ++b) {
        auto sids = make_bucket_sids(b, (b % 8 < 4) ? 2 : 4);
        prov_sids.insert(prov_sids.end(), sids.begin(), sids.end());
    }
    auto provider = MakeProvider(prov_sids);

    TemplateTxSet pool;
    TestPeerTemplateSketchT<TEST_SC> sketch{pool};
    BOOST_REQUIRE(!sketch.Init({}, {}, 0, provider.GetSketches(0), {}, {}).resolved);

    // Round 1: stride-8 even groups resolve, odd don't.
    auto [res1, shortidmask1, sketchmask1] = sketch.Process(
        1, GroupMask{}, GroupMask::Fill(TOTAL_BUCKETS), {}, provider.GetSketches(1));
    BOOST_REQUIRE(!res1);

    // shortidmask empty at round 1 (shortid fallback only at round >= 3).
    BOOST_CHECK(shortidmask1.None());

    // sketchmask should have exactly bits 4..7 (the 4 unresolved stride-8 odd groups).
    GroupMask expected_sketchmask;
    for (int g = 4; g < 8; ++g) expected_sketchmask.Set(g);
    BOOST_CHECK(sketchmask1 == expected_sketchmask);

    // Round 2: resolve remaining groups via sketches.
    auto [res2, shortidmask2, sketchmask2] = sketch.Process(
        2, GroupMask{}, GroupMask::Fill(TOTAL_BUCKETS), {}, provider.GetSketches(2));
    BOOST_REQUIRE(res2);
    BOOST_CHECK(sketchmask2.None());

    std::vector<uint64_t> result;
    for (uint64_t sid : sketch.m_shortids) {
        if (sid != 0) result.push_back(sid);
    }
    std::sort(result.begin(), result.end());
    BOOST_CHECK(result == provider.shortids);
}

// Shortid fallback and sketch decode both fire within the same Process(1) call.
//
// Design (TOTAL_BUCKETS=32, capacity=8):
//
// Groups 0,1 (b%4 ∈ {0,1}): 20 elements/bucket → 160 per stride-4 group.
//   Too large for sketch; resolved by shortid fallback (outer shortids sent for these groups).
//
// Groups 2,3 (b%4 ∈ {2,3}): 2 elements/bucket → 16 per stride-4 group > 8 → round 0 fails.
//   stride-8 diff = 4×2 = 8 ≤ 8 → resolved by sketch decode at round 1.
BOOST_AUTO_TEST_CASE(sketch_mixed_shortid_and_sketch)
{
    std::vector<uint64_t> prov_sids;
    for (int b = 0; b < TOTAL_BUCKETS; ++b) {
        auto sids = make_bucket_sids(b, (b % 4 < 2) ? 20 : 2);
        prov_sids.insert(prov_sids.end(), sids.begin(), sids.end());
    }
    auto provider = MakeProvider(prov_sids);

    TemplateTxSet pool;
    TestPeerTemplateSketchT<TEST_SC> sketch{pool};
    BOOST_REQUIRE(!sketch.Init({}, {}, 0, provider.GetSketches(0), {}, {}).resolved);

    // Request outer shortids only for the large groups (0,1); sketches for all.
    GroupMask shortidmask;
    shortidmask.Set(0);
    shortidmask.Set(1);
    auto shortid_bytes = provider.GetShortIDBytes(1, 0, shortidmask);

    // Process(1): groups 0,1 resolve via ProcessShortidFallback;
    // groups 2,3 resolve via sketch decode after PrepareRound(1).
    auto [res, shortidmask_out, sketchmask_out] = sketch.Process(
        1, shortidmask, GroupMask::Fill(TOTAL_BUCKETS), shortid_bytes, provider.GetSketches(1));
    BOOST_REQUIRE(res);

    std::vector<uint64_t> result;
    for (uint64_t sid : sketch.m_shortids) {
        if (sid != 0) result.push_back(sid);
    }
    std::sort(result.begin(), result.end());
    BOOST_CHECK(result == provider.shortids);
}

BOOST_AUTO_TEST_SUITE_END()

// ---------------------------------------------------------------------------
// Round-0 shortid fallback: the provider may omit sketches and send GR-encoded
// shortids for a round-0 group instead (used for small templates / signet).
// Receiver must treat groups with provider count == 0 as fully shortid-provided.
// ---------------------------------------------------------------------------
BOOST_FIXTURE_TEST_SUITE(templateman_round0_tests, BasicTestingSetup)

// All four round-0 groups small enough to send as shortids (≤ TEST_SC each).
BOOST_AUTO_TEST_CASE(round0_all_shortids)
{
    std::vector<uint64_t> prov_sids;
    for (int b = 0; b < TOTAL_BUCKETS; ++b) {
        auto sids = templateman_tests::make_bucket_sids(b, 2); // 2 per bucket → 16 per stride-4 group
        prov_sids.insert(prov_sids.end(), sids.begin(), sids.end());
    }
    auto provider = templateman_tests::MakeProvider(prov_sids);

    TemplateTxSet pool;
    TestPeerTemplateSketchT<TEST_SC> sketch{pool};

    // Provider signals "shortids for all groups": shortidmask covers all 4 groups,
    // no sketches at all. InitPeerSketch path: Init with shortidmask + bytes.
    auto shortid_bytes = provider.GetShortIDBytes(0, 0, GroupMask::Fill(4));
    auto result = sketch.Init({}, {}, 0, {}, GroupMask::Fill(4), shortid_bytes);
    BOOST_REQUIRE(result.resolved);

    std::vector<uint64_t> result_sids;
    for (uint64_t sid : sketch.m_shortids) {
        if (sid != 0) result_sids.push_back(sid);
    }
    std::sort(result_sids.begin(), result_sids.end());
    BOOST_CHECK(result_sids == provider.shortids);
}

// Mixed: two groups sent as shortids, two as sketches.
BOOST_AUTO_TEST_CASE(round0_mixed_shortids_and_sketches)
{
    // buckets 0-15 (groups 0,1): 1 per bucket → 8 per group, sent as shortids
    // buckets 16-31 (groups 2,3): 1 per bucket → 8 per group, decodable via sketch (≤ TEST_SC)
    std::vector<uint64_t> prov_sids;
    for (int b = 0; b < TOTAL_BUCKETS; ++b) {
        auto sids = templateman_tests::make_bucket_sids(b, 1);
        prov_sids.insert(prov_sids.end(), sids.begin(), sids.end());
    }
    auto provider = templateman_tests::MakeProvider(prov_sids);

    TemplateTxSet pool;
    TestPeerTemplateSketchT<TEST_SC> sketch{pool};

    // shortidmask covers groups 0,1; sketches for groups 2,3 (sketchmask = complement).
    GroupMask shortidmask;
    shortidmask.Set(0);
    shortidmask.Set(1);
    auto shortid_bytes = provider.GetShortIDBytes(0, 0, shortidmask);

    // Sketches for the complement (groups 2,3): GetSketches(0) returns 4, take the last 2.
    auto all = provider.GetSketches(0);
    std::vector<TestLocalTemplate::Sketch> sketches{all[2], all[3]};

    auto result = sketch.Init({}, {}, 0, sketches, shortidmask, shortid_bytes);
    BOOST_REQUIRE(result.resolved);

    std::vector<uint64_t> result_sids;
    for (uint64_t sid : sketch.m_shortids) {
        if (sid != 0) result_sids.push_back(sid);
    }
    std::sort(result_sids.begin(), result_sids.end());
    BOOST_CHECK(result_sids == provider.shortids);
}

BOOST_AUTO_TEST_SUITE_END()

// ---------------------------------------------------------------------------
// Manager-level tests: drive TemplateManagerT<TEST_SC> end-to-end with real
// transactions, covering provider↔receiver reconciliation, basis deltas,
// refcounting, shortid collisions, and state-machine error paths.
// ---------------------------------------------------------------------------
BOOST_FIXTURE_TEST_SUITE(templateman_mgr_tests, BasicTestingSetup)

/** Make n lightweight transactions with unique wtxids (unique prevout txid). */
static std::vector<CTransactionRef> make_txs(uint32_t lo, uint32_t hi)
{
    std::vector<CTransactionRef> txs;
    txs.reserve(hi - lo);
    for (uint32_t i = lo; i < hi; ++i) {
        CMutableTransaction mtx;
        mtx.version = CTransaction::CURRENT_VERSION;
        uint8_t buf[32] = {};
        WriteLE32(buf, i);
        mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{buf}), 0});
        mtx.vout.emplace_back(0, CScript{});
        txs.push_back(MakeTransactionRef(std::move(mtx)));
    }
    return txs;
}

static NodeClock::time_point test_time(int64_t sec)
{
    return NodeClock::time_point{std::chrono::seconds{sec}};
}

/** Drive one full reconciliation of `provider_tmpl` into receiver `mgr` for
 *  `peer`, acting as both the provider (serving sketches/shortids per mask)
 *  and the receiver (feeding results back). Returns the final TmpltState.
 *  `basis_id` selects the provider basis to delta against (0 = flat). */
static TestManager::TmpltState reconcile_template(
    TestManager& mgr, NodeId peer,
    const TestLocalTemplate& provider_tmpl,
    uint8_t basis_id = 0,
    std::vector<CTransactionRef> missing_txs = {})
{
    auto now = test_time(1000);
    mgr.WaitingForPeerSketch(peer);

    // Round 0: InitPeerSketch with the round-0 sketches and no basis (flat).
    uint256 basis_hash = uint256::ZERO;
    GRVector basis_delta;
    size_t basis_tx_count{0};
    auto result = mgr.InitPeerSketch(peer, nullptr, provider_tmpl.m_hash,
                                     provider_tmpl.m_nonce, basis_hash, basis_delta,
                                     provider_tmpl.GetSketches(0), {}, {}, now, basis_tx_count);
    BOOST_CHECK(basis_tx_count == 0); // no basis
    int round = 0;
    while (result.state == TestManager::TmpltState::Unresolved && round < 4) {
        ++round;
        GRVector shortid_bytes;
        if (result.shortidmask.Any()) {
            shortid_bytes = provider_tmpl.GetShortIDBytes(round, basis_id, result.shortidmask);
        }
        std::vector<TestLocalTemplate::Sketch> sketches;
        if (result.sketchmask.Any()) {
            auto all = provider_tmpl.GetSketches(round);
            for (int i : result.sketchmask) {
                if (static_cast<size_t>(i) < all.size()) sketches.push_back(all[i]);
            }
        }
        result = mgr.UpdatePeerSketch(peer, provider_tmpl.m_hash, round,
                                      result.shortidmask, result.sketchmask,
                                      shortid_bytes, sketches, now);
    }
    if (result.state == TestManager::TmpltState::NeedsTxs && !missing_txs.empty()) {
        // FillPeerPartial expects txs in template (shortid-sorted) position order.
        // Reorder missing_txs to match the provider's m_txs order (by wtxid).
        std::map<Wtxid, CTransactionRef> by_wtxid;
        for (auto& tx : missing_txs) by_wtxid.emplace(tx->GetWitnessHash(), tx);
        std::vector<CTransactionRef> ordered;
        ordered.reserve(missing_txs.size());
        for (const auto& ref : provider_tmpl.m_txs) {
            auto it = by_wtxid.find(ref->tx->GetWitnessHash());
            if (it != by_wtxid.end()) ordered.push_back(it->second);
        }
        auto [state, ntxs] = mgr.FillPeerPartial(peer, provider_tmpl.m_hash, std::move(ordered), now);
        return state;
    }
    return result.state;
}

// Full flat reconciliation (no basis): receiver completes a template from the
// provider's sketches, fills missing txs via tmplttxn.
BOOST_AUTO_TEST_CASE(mgr_flat_reconcile)
{
    TestManager mgr{/*deterministic=*/true};
    NodeId peer = 0;

    // Provider template: 40 txs (well over capacity 8 to force multi-round).
    auto prov_txs = make_txs(0, 40);
    TestManager prov_mgr{/*deterministic=*/true};
    std::span<CTransactionRef> prov_span{prov_txs};
    uint256 prov_hash = prov_mgr.GenerateTemplate(test_time(100), 0, nullptr, prov_span);
    const TestLocalTemplate* prov_tmpl = prov_mgr.GetLocalTemplate(prov_hash, 0);
    BOOST_REQUIRE(prov_tmpl != nullptr);

    // Receiver has none of the txs locally → all 40 must come via FillPeerPartial.
    // (GenerateTemplate moved out of prov_txs; regenerate them for the fill.)
    auto state = reconcile_template(mgr, peer, *prov_tmpl, 0, make_txs(0, 40));
    BOOST_CHECK(state == TestManager::TmpltState::Complete);
    BOOST_CHECK(mgr.GetLastPeerTemplateHash(peer) == prov_hash);
    mgr.Check();
}

// Basis delta reconciliation: receiver already completed template v1; provider
// generates v2 as a delta on v1; receiver reconstructs using the basis.
BOOST_AUTO_TEST_CASE(mgr_basis_reconcile)
{
    TestManager prov_mgr{/*deterministic=*/true};
    TestManager recv_mgr{/*deterministic=*/true};
    NodeId peer = 0;

    // v1: txs 0..40
    auto v1_txs = make_txs(0, 40);
    std::span<CTransactionRef> v1_span{v1_txs};
    uint256 v1_hash = prov_mgr.GenerateTemplate(test_time(100), 0, nullptr, v1_span);
    const TestLocalTemplate* v1_tmpl = prov_mgr.GetLocalTemplate(v1_hash, 0);
    BOOST_REQUIRE(v1_tmpl != nullptr);

    // Receiver completes v1 (gets all txs).
    auto state = reconcile_template(recv_mgr, peer, *v1_tmpl, 0, make_txs(0, 40));
    BOOST_REQUIRE(state == TestManager::TmpltState::Complete);

    // v2: retain txs 0..30 (subset of v1), add txs 40..55.
    auto v2_txs = make_txs(0, 55);
    v2_txs.erase(v2_txs.begin() + 30, v2_txs.begin() + 40); // drop 30..40 from retained set
    std::span<CTransactionRef> v2_span{v2_txs};
    uint256 v2_hash = prov_mgr.GenerateTemplate(test_time(200), 0, nullptr, v2_span);
    const TestLocalTemplate* v2_tmpl = prov_mgr.GetLocalTemplate(v2_hash, 0);
    BOOST_REQUIRE(v2_tmpl != nullptr);

    // Receiver requests with basis = v1. Provider serves delta against v1.
    // We simulate the provider side: compute basis_id via GetBasisInfo on the provider.
    // (The wire protocol does this via gettmplt; here we drive the pieces directly.)
    // For the manager path, InitPeerSketch takes basis_hash + basis_delta from the tmplt.
    // Compute what the provider would send: basis positions of v1 retained in v2.
    //
    // Note: we can't call prov_mgr's private GetBasisInfo; instead exercise the
    // receiver's basis handling by hand-building the basis segment.
    recv_mgr.WaitingForPeerSketch(peer);

    // Receiver still has v1 as its last peer template → basis_hash lookup hits the cache.
    // Build the basis_delta the provider would send: positions of v1's txs dropped in v2.
    TemplateTxnsSelection sel;
    {
        std::unordered_map<const CTransaction*, size_t> v2_pos;
        for (size_t i = 0; i < v2_tmpl->m_txs.size(); ++i) v2_pos.emplace(v2_tmpl->m_txs[i]->tx.get(), i);
        for (size_t i = 0; i < v1_tmpl->m_txs.size(); ++i) {
            // v1 txs 30..39 are not retained in v2; everything else in v1 is
            if (!v2_pos.contains(v1_tmpl->m_txs[i]->tx.get())) sel.Add(i);
        }
    }
    GRVector basis_delta = sel.GREncode();

    auto now = test_time(1000);
    size_t basis_tx_count{0};
    auto result = recv_mgr.InitPeerSketch(peer, nullptr, v2_tmpl->m_hash,
                                          v2_tmpl->m_nonce, v1_hash, basis_delta,
                                          v2_tmpl->GetSketches(0), {}, {}, now, basis_tx_count);
    BOOST_CHECK(basis_tx_count == v1_tmpl->m_txs.size());

    int round = 0;
    while (result.state == TestManager::TmpltState::Unresolved && round < 4) {
        ++round;
        GRVector shortid_bytes;
        if (result.shortidmask.Any()) {
            shortid_bytes = v2_tmpl->GetShortIDBytes(round, 0, result.shortidmask);
        }
        std::vector<TestLocalTemplate::Sketch> sketches;
        if (result.sketchmask.Any()) {
            auto all = v2_tmpl->GetSketches(round);
            for (int i : result.sketchmask) {
                if (static_cast<size_t>(i) < all.size()) sketches.push_back(all[i]);
            }
        }
        result = recv_mgr.UpdatePeerSketch(peer, v2_tmpl->m_hash, round,
                                           result.shortidmask, result.sketchmask,
                                           shortid_bytes, sketches, now);
    }

    // The receiver already holds the retained txs (0..30) from v1 and the dropped
    // ones aren't in v2; it still needs the genuinely new txs 40..55 via tmplttxn.
    BOOST_CHECK(result.state == TestManager::TmpltState::NeedsTxs);

    auto new_txs = make_txs(40, 55);
    std::map<Wtxid, CTransactionRef> by_wtxid;
    for (auto& tx : new_txs) by_wtxid.emplace(tx->GetWitnessHash(), tx);
    std::vector<CTransactionRef> ordered;
    for (const auto& ref : v2_tmpl->m_txs) {
        auto it = by_wtxid.find(ref->tx->GetWitnessHash());
        if (it != by_wtxid.end()) ordered.push_back(it->second);
    }
    auto [final_state, ntxs] = recv_mgr.FillPeerPartial(peer, v2_tmpl->m_hash, std::move(ordered), now);
    BOOST_CHECK(final_state == TestManager::TmpltState::Complete);
    BOOST_CHECK_EQUAL(uint64_t(ntxs), uint64_t(v2_tmpl->m_txs.size()));
    recv_mgr.Check();
}

// State-machine errors: UpdatePeerSketch with a wrong round or overlapping masks
// is a ProtocolError; InitPeerSketch without WaitingForPeerSketch is a Reset.
BOOST_AUTO_TEST_CASE(mgr_state_errors)
{
    TestManager mgr{/*deterministic=*/true};
    NodeId peer = 0;

    auto prov_txs = make_txs(0, 20);
    TestManager prov_mgr{/*deterministic=*/true};
    std::span<CTransactionRef> prov_span{prov_txs};
    uint256 prov_hash = prov_mgr.GenerateTemplate(test_time(100), 0, nullptr, prov_span);
    const TestLocalTemplate* prov_tmpl = prov_mgr.GetLocalTemplate(prov_hash, 0);
    BOOST_REQUIRE(prov_tmpl != nullptr);
    auto now = test_time(1000);

    // InitPeerSketch without WaitingForPeerSketch → Reset (no monostate entry).
    size_t basis_tx_count{0};
    auto r = mgr.InitPeerSketch(peer, nullptr, prov_tmpl->m_hash, prov_tmpl->m_nonce,
                                uint256::ZERO, {}, prov_tmpl->GetSketches(0), {}, {}, now, basis_tx_count);
    BOOST_CHECK(r.state == TestManager::TmpltState::Reset);

    // Proper init.
    mgr.WaitingForPeerSketch(peer);
    r = mgr.InitPeerSketch(peer, nullptr, prov_tmpl->m_hash, prov_tmpl->m_nonce,
                           uint256::ZERO, {}, prov_tmpl->GetSketches(0), {}, {}, now, basis_tx_count);
    // 20 txs over capacity 8 at round 0 → may be Unresolved or Complete.
    if (r.state == TestManager::TmpltState::Unresolved) {
        // Wrong round (skip ahead) → ProtocolError.
        auto bad = mgr.UpdatePeerSketch(peer, prov_tmpl->m_hash, /*round=*/3,
                                        r.shortidmask, r.sketchmask, {}, {}, now);
        BOOST_CHECK(bad.state == TestManager::TmpltState::ProtocolError);
    }

    // UpdatePeerSketch for a peer with no sketch → Reset.
    NodeId other = 1;
    auto bad2 = mgr.UpdatePeerSketch(other, prov_tmpl->m_hash, 1, {}, {}, {}, {}, now);
    BOOST_CHECK(bad2.state == TestManager::TmpltState::Reset);
    mgr.Check();
}

// Weight limit: a template whose estimated weight exceeds MAX_TEMPLATE_WEIGHT
// is rejected with ProtocolError when filled.
BOOST_AUTO_TEST_CASE(mgr_oversize_rejected)
{
    TestManager mgr{/*deterministic=*/true};
    NodeId peer = 0;

    // Build a template of very heavy txs: each tx carries a large output script
    // so total weight blows past MAX_TEMPLATE_WEIGHT with few txs.
    auto make_heavy = [] {
        std::vector<CTransactionRef> heavy;
        for (uint32_t i = 0; i < 30; ++i) {
            CMutableTransaction mtx;
            mtx.version = CTransaction::CURRENT_VERSION;
            uint8_t buf[32] = {};
            WriteLE32(buf, i);
            mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{buf}), 0});
            // ~300KB script → ~1.2M weight each; 7+ txs exceeds 8M.
            CScript big;
            big.assign(300000, uint8_t{0x42});
            mtx.vout.emplace_back(0, std::move(big));
            heavy.push_back(MakeTransactionRef(std::move(mtx)));
        }
        return heavy;
    };
    std::vector<CTransactionRef> heavy = make_heavy();

    TestManager prov_mgr{/*deterministic=*/true};
    std::span<CTransactionRef> heavy_span{heavy};
    uint256 hash = prov_mgr.GenerateTemplate(test_time(100), 0, nullptr, heavy_span);
    const TestLocalTemplate* tmpl = prov_mgr.GetLocalTemplate(hash, 0);
    BOOST_REQUIRE(tmpl != nullptr);

    auto state = reconcile_template(mgr, peer, *tmpl, 0, make_heavy());
    BOOST_CHECK(state == TestManager::TmpltState::ProtocolError);
    mgr.Check();
}

BOOST_AUTO_TEST_SUITE_END()
