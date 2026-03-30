// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/templateman.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <vector>

using namespace node;

BOOST_FIXTURE_TEST_SUITE(templateman_tests, BasicTestingSetup)

static std::vector<uint64_t> range_sids(uint64_t lo, uint64_t hi)
{
    std::vector<uint64_t> v;
    for (uint64_t i = lo; i < hi; ++i) v.push_back(i);
    return v;
}

static LocalTemplate MakeProvider(std::vector<uint64_t> sids)
{
    LocalTemplate tmpl;
    std::sort(sids.begin(), sids.end());
    tmpl.shortids = std::move(sids);
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

    std::vector<TemplateTxRef> txs;
    std::vector<uint64_t> sids;
    for (auto s : basis_sids) { txs.push_back(pool.end()); sids.push_back(s); }
    size_t basis_count = txs.size();
    for (auto s : local_sids) { txs.push_back(pool.end()); sids.push_back(s); }

    PeerTemplateSketch sketch;

    auto reconstruct = [&](int round) {
        std::vector<uint64_t> result;
        for (uint64_t sid : sketch.m_shortids) {
            if (sid != 0) result.push_back(sid);
        }
        std::sort(result.begin(), result.end());
        BOOST_CHECK_EQUAL(round, expected_rounds);
        BOOST_CHECK(result == provider.shortids);
    };

    if (sketch.Init(std::move(txs), std::move(sids), basis_count,
                    provider.GetSketches(0)).resolved) { reconstruct(0); return; }

    for (int round = 1; round <= 4; ++round) {
        std::vector<uint8_t> shortid_bytes;
        if (round == 4) shortid_bytes = provider.GetShortIdBytes(4, GroupMask::Fill(TOTAL_BUCKETS));
        auto [res, shortidmask, sketchmask] = sketch.Process(
            round, GroupMask::Fill(TOTAL_BUCKETS), GroupMask::Fill(TOTAL_BUCKETS), shortid_bytes, provider.GetSketches(round));
        if (res) { reconstruct(round); return; }
    }
    BOOST_ERROR("reconciliation did not resolve");
}

// provider == receiver: empty diff.
BOOST_AUTO_TEST_CASE(sketch_no_diff)       { sketch_range(1, 17,   1, 17,  1,  1, 0); }

// Provider has extras; basis-only covers all 32 buckets at round 0.
BOOST_AUTO_TEST_CASE(sketch_round0)        { sketch_range(1, 21,   1, 11,  1,  1, 0); }

// Receiver has local extras not in provider; basis+local decode needed.
BOOST_AUTO_TEST_CASE(sketch_local_extras)  { sketch_range(1, 11,   1,  6,  6, 16, 0); }

// ~400 total diff → fails round 0 (4 groups × 64 = 256 cap; 400/4=100>64), resolves round 1 (8 groups × 64; 400/8=50≤64).
BOOST_AUTO_TEST_CASE(sketch_round1)        { sketch_range(1, 401,  1,  1,  1,  1, 1); }

// ~800 total diff → fails round 1 (800/8=100>64), resolves round 2 (16 groups × 64; 800/16=50≤64).
BOOST_AUTO_TEST_CASE(sketch_round2)        { sketch_range(1, 801,  1,  1,  1,  1, 2); }

// ~1600 total diff → fails round 2 (1600/16=100>64), resolves round 3 (32 groups × 64; 1600/32=50≤64).
BOOST_AUTO_TEST_CASE(sketch_round3)        { sketch_range(1, 1601, 1,  1,  1,  1, 3); }

// ~3000 total diff → fails round 3 (3000/32≈94>64) → shortid fallback round 4.
BOOST_AUTO_TEST_CASE(sketch_round4)        { sketch_range(1, 3001, 1,  1,  1,  1, 4); }

// Shortid fallback fires at round 1 using the combined (round-0) sketches, before any split.
// ~5000 total diff is far too large for any sketch round alone, but GetShortIdBytes(1) sends
// items 65..5000 (outer), and (0 basis + ~4744 outer + ~256 inner = 5000 >= 5000) decodes.
BOOST_AUTO_TEST_CASE(sketch_shortid_early_round1)
{
    auto prov_sids = range_sids(1, 5001);
    auto provider = MakeProvider(prov_sids);
    TemplateTxSet pool;
    PeerTemplateSketch sketch;

    BOOST_REQUIRE(!sketch.Init({}, {}, 0, provider.GetSketches(0)).resolved);

    // Send shortid bytes at round 1 (combined-level outer shortids) before any PrepareRound.
    auto shortid_bytes = provider.GetShortIdBytes(1, GroupMask::Fill(TOTAL_BUCKETS));
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
// Design (TOTAL_BUCKETS=32, SKETCH_CAPACITY=64, stride-4 groups at round 0):
//
// "Even" buckets (b%8 < 4): provider=15, basis=6, local=0 per bucket
//   → basis-only decode (6+64 ≥ 15 ✓; diff = 15-6 = 9 per bucket)
//   → diff per stride-8 group (4 even buckets) = 9×4 = 36
//
// "Odd" buckets (b%8 ≥ 4): provider=80, basis=0, local=71 per bucket
//   → basis-only fails (0+64=64 < 80); basis+local: |80-0-71|=9 per bucket ✓
//   → diff per stride-8 group (4 odd buckets) = 9×4 = 36
//
// Per stride-4 group (round 0): diff = 36+36 = 72 > 64 → round 0 fails ✓
// Per stride-8 group (round 1): diff = 36 ≤ 64 → round 1 resolves ✓
// m_decoded_by_basis: bits set for even buckets (basis-only), unset for odd ✓
BOOST_AUTO_TEST_CASE(sketch_mixed_decode_mask)
{
    std::vector<uint64_t> prov_sids, basis_sids, local_sids;

    for (uint8_t b = 0; b < TOTAL_BUCKETS; ++b) {
        if (b % 8 < 4) {
            // Even sub-bucket: provider=15, basis=6, local=0 → basis-only decode path
            auto prov = make_bucket_sids(b, 15);
            auto bas  = make_bucket_sids(b, 6); // first 6 of the 15 provider sids
            prov_sids.insert(prov_sids.end(), prov.begin(), prov.end());
            basis_sids.insert(basis_sids.end(), bas.begin(), bas.end());
        } else {
            // Odd sub-bucket: provider=80, basis=0, local=71 → basis+local decode path
            // basis-only fails (0+64=64 < 80); basis+local: |80-0-71|=9 ≤ 64 ✓
            auto prov = make_bucket_sids(b, 80);
            auto loc  = make_bucket_sids(b, 71);
            prov_sids.insert(prov_sids.end(), prov.begin(), prov.end());
            local_sids.insert(local_sids.end(), loc.begin(), loc.end());
        }
    }

    auto provider = MakeProvider(prov_sids);

    TemplateTxSet pool;
    std::sort(basis_sids.begin(), basis_sids.end());
    std::sort(local_sids.begin(), local_sids.end());

    std::vector<TemplateTxRef> txs;
    std::vector<uint64_t> sids;
    for (auto s : basis_sids) { txs.push_back(pool.end()); sids.push_back(s); }
    size_t basis_count = txs.size();
    for (auto s : local_sids) { txs.push_back(pool.end()); sids.push_back(s); }

    PeerTemplateSketch sketch;

    // Round 0 should fail: per stride-4 group diff = 72 > 64 (SKETCH_CAPACITY).
    // Each stride-4 group has 4 even buckets (diff 9 each = 36) + 4 odd buckets (diff 9 each = 36) = 72.
    BOOST_REQUIRE(!sketch.Init(std::move(txs), std::move(sids), basis_count,
                               provider.GetSketches(0)).resolved);

    // Round 1 should resolve: each stride-8 group has diff 36 ≤ 64.
    // Even stride-8 groups resolve via basis-only; odd stride-8 groups via basis+local.
    // m_decoded_by_basis should have exactly the even buckets set (b%8 < 4).
    // Don't pass outer shortids — testing the sketch decode path for m_decoded_by_basis.
    // Passing outer shortids would fire ProcessShortidFallback at level-0 (4 stride-4 groups),
    // each containing mixed even/odd buckets, corrupting m_decoded_by_basis.
    auto [res, shortidmask, sketchmask] = sketch.Process(
        1, GroupMask{}, GroupMask::Fill(TOTAL_BUCKETS), {}, provider.GetSketches(1));
    BOOST_REQUIRE(res);

    // Verify m_decoded_by_basis has bits for even buckets only.
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
// Design (TOTAL_BUCKETS=32, SKETCH_CAPACITY=64):
//
// Even sub-buckets (b%8 < 4):  10 elements/bucket
//   → stride-8 group diff = 4×10 = 40 ≤ 64 → resolve at round 1 ✓
//
// Odd sub-buckets (b%8 ≥ 4):  17 elements/bucket
//   → stride-8 group diff = 4×17 = 68 > 64 → fail round 1
//   → stride-16 group diff = 2×17 = 34 ≤ 64 → resolve at round 2 ✓
//
// stride-4 group (round 0): diff = 4×10 + 4×17 = 108 > 64 → round 0 fails ✓
//
// After Process(1): sketchmask  = {4,5,6,7} (odd stride-8 groups still pending).
//                   shortidmask = {b : b%8 ≥ 4} (16 unresolved buckets).
BOOST_AUTO_TEST_CASE(sketch_selective_masks)
{
    std::vector<uint64_t> prov_sids;
    for (int b = 0; b < TOTAL_BUCKETS; ++b) {
        auto sids = make_bucket_sids(b, (b % 8 < 4) ? 10 : 17);
        prov_sids.insert(prov_sids.end(), sids.begin(), sids.end());
    }
    auto provider = MakeProvider(prov_sids);

    TemplateTxSet pool;
    PeerTemplateSketch sketch;
    BOOST_REQUIRE(!sketch.Init({}, {}, 0, provider.GetSketches(0)).resolved);

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
// Design (TOTAL_BUCKETS=32, SKETCH_CAPACITY=64):
//
// Groups 0,1 (b%4 ∈ {0,1}): 100 elements/bucket → 800 per stride-4 group.
//   Too large for sketch; resolved by shortid fallback (outer shortids sent for these groups).
//
// Groups 2,3 (b%4 ∈ {2,3}): 10 elements/bucket → 80 per stride-4 group > 64 → round 0 fails.
//   stride-8 diff = 4×10 = 40 ≤ 64 → resolved by sketch decode at round 1.
//
// shortidmask_sent = {0,1}: only outer shortids for the large groups are sent.
// sketchmask_sent  = all:   round-1 sketches provided for all groups.
BOOST_AUTO_TEST_CASE(sketch_mixed_shortid_and_sketch)
{
    std::vector<uint64_t> prov_sids;
    for (int b = 0; b < TOTAL_BUCKETS; ++b) {
        auto sids = make_bucket_sids(b, (b % 4 < 2) ? 100 : 10);
        prov_sids.insert(prov_sids.end(), sids.begin(), sids.end());
    }
    auto provider = MakeProvider(prov_sids);

    TemplateTxSet pool;
    PeerTemplateSketch sketch;
    BOOST_REQUIRE(!sketch.Init({}, {}, 0, provider.GetSketches(0)).resolved);

    // Request outer shortids only for the large groups (0,1); sketches for all.
    GroupMask shortidmask;
    shortidmask.Set(0);
    shortidmask.Set(1);
    auto shortid_bytes = provider.GetShortIdBytes(1, shortidmask);

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
