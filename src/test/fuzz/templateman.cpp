// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/minisketchwrapper.h>
#include <node/templateman.h>
#include <random.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/util/random.h>

#include <algorithm>
#include <array>
#include <numeric>
#include <vector>

using namespace node;

static void initialize_templateman()
{
    // MakeMinisketch46 selects the best implementation on first call using timing
    // (which reads system time). Run it once here so the per-invocation seed below
    // is called before any code that uses the global PRNG.
    MakeMinisketch46(1);
}

// Core fuzzing logic, shared between the fast (few buckets) and full (all buckets) targets.
//
// For each active bucket b, three shortid sets are derived from the provider's bucket sids:
//   sketch_sids: bucket[j..]  — shortids that went into the sketch (honest: j=0, all sids)
//   send_sids:   bucket[..k]  — shortids used for GetShortIdBytes  (honest: k=n, all sids)
//   basis_sids:  bucket[..basis_count] — what the receiver thinks it already has
//
// When j=0 and k=n for every bucket, the provider is honest and reconciliation must
// produce exactly prov_sids.  Any deviation (j>0 or k<n) marks the run as dishonest;
// we then only verify there is no crash.
static void run_templateman(FuzzedDataProvider& fdp, int max_buckets)
{
    // Some code paths (e.g. Minisketch decode) may use the global PRNG.
    // Seed it deterministically so CheckGlobals doesn't abort.
    SeedRandomStateForTest(SeedRand::ZEROS);

    int num_active = fdp.ConsumeIntegralInRange<int>(0, max_buckets);

    bool is_honest = true;

    // RNG for shortid generation, seeded from fuzz data.
    InsecureRandomContext rng(fdp.ConsumeIntegral<uint64_t>());

    // Generate `count` shortids for bucket b: low 5 bits = b, high 41 bits from rng.
    auto make_bucket_sids = [](int b, uint16_t count, InsecureRandomContext& rng) {
        std::vector<uint64_t> sids;
        sids.reserve(count);
        for (int i = 0; i < count; ++i) {
            uint64_t sid = (rng.rand64() >> 23 << 5) | static_cast<uint64_t>(b);
            if (sid == 0) sid = 32; // sid=0 is the sentinel; remap to smallest bucket-0 sid
            sids.push_back(sid);
        }
        // Deduplicate (collisions are negligible but possible).
        std::sort(sids.begin(), sids.end());
        sids.erase(std::unique(sids.begin(), sids.end()), sids.end());
        return sids;
    };

    // Pick num_active distinct buckets randomly (so we don't always exercise only
    // the low-index buckets, which would leave higher sketch tree nodes empty).
    std::array<int, TOTAL_BUCKETS> bucket_indices;
    std::iota(bucket_indices.begin(), bucket_indices.end(), 0);
    for (int i = 0; i < num_active; ++i) {
        int j = fdp.ConsumeIntegralInRange<int>(i, TOTAL_BUCKETS - 1);
        std::swap(bucket_indices[i], bucket_indices[j]);
    }

    std::vector<uint64_t> prov_sids, sketch_sids, send_sids, basis_sids, local_sids;

    for (int ai = 0; ai < num_active; ++ai) {
        int b = bucket_indices[ai];
        uint8_t prov_count  = fdp.ConsumeIntegralInRange<uint8_t>(0, 100);
        uint8_t j           = fdp.ConsumeIntegralInRange<uint8_t>(0, prov_count);
        uint8_t k           = fdp.ConsumeIntegralInRange<uint8_t>(0, prov_count);
        uint8_t basis_count = fdp.ConsumeIntegralInRange<uint8_t>(0, prov_count);
        // local = (some items from provider's bucket) + (some fresh random items).
        // local_overlap gives the receiver shortids it shares with the provider,
        // enabling the basis+local decode path in TryDecodeGroups.
        uint8_t local_total   = fdp.ConsumeIntegralInRange<uint8_t>(0, 170);
        uint8_t local_overlap = fdp.ConsumeIntegralInRange<uint8_t>(0, std::min(prov_count, local_total));

        if (j > 0 || k < prov_count) is_honest = false;

        auto bucket = make_bucket_sids(b, prov_count, rng);
        size_t n = bucket.size(); // actual count after dedup

        size_t j_idx      = std::min<size_t>(j, n);
        size_t k_idx      = std::min<size_t>(k, n);
        size_t basis_idx  = std::min<size_t>(basis_count, n);
        // local_overlap items are taken from bucket[basis_idx..] (the part of provider
        // not in basis) so that local and basis remain disjoint in the sketch.
        size_t overlap_end = std::min(basis_idx + local_overlap, n);

        prov_sids.insert(prov_sids.end(), bucket.begin(), bucket.end());
        sketch_sids.insert(sketch_sids.end(), bucket.begin() + j_idx, bucket.end());
        send_sids.insert(send_sids.end(), bucket.begin(), bucket.begin() + k_idx);
        basis_sids.insert(basis_sids.end(), bucket.begin(), bucket.begin() + basis_idx);

        auto lbucket = make_bucket_sids(b, local_total - local_overlap, rng);
        lbucket.insert(lbucket.end(), bucket.begin() + basis_idx, bucket.begin() + overlap_end);
        std::sort(lbucket.begin(), lbucket.end());
        lbucket.erase(std::unique(lbucket.begin(), lbucket.end()), lbucket.end());
        local_sids.insert(local_sids.end(), lbucket.begin(), lbucket.end());
    }

    // Sort globally (required by GetShortIdBytes delta encoding).
    std::sort(prov_sids.begin(), prov_sids.end());
    std::sort(sketch_sids.begin(), sketch_sids.end());
    std::sort(send_sids.begin(), send_sids.end());
    std::sort(basis_sids.begin(), basis_sids.end());

    // Build provider: sketch from sketch_sids, outer shortids from send_sids.
    LocalTemplate provider;
    provider.shortids = sketch_sids;
    provider.GenerateSketches();
    provider.shortids = send_sids; // replace for GetShortIdBytes

    TemplateTxSet pool;
    std::vector<TemplateTxRef> txs;
    std::vector<uint64_t> sids;
    for (auto s : basis_sids) { txs.push_back(pool.end()); sids.push_back(s); }
    size_t basis_count = txs.size();
    for (auto s : local_sids) { txs.push_back(pool.end()); sids.push_back(s); }

    PeerTemplateSketch sketch;
    auto [resolved, _sid, _sk] = sketch.Init(std::move(txs), std::move(sids), basis_count,
                                             provider.GetSketches(0));

    // Use the masks returned by each Process() call for the next round's requests,
    // matching the real protocol flow and exercising the mask-filtering code paths.
    GroupMask shortidmask = GroupMask::Fill(TOTAL_BUCKETS);
    GroupMask sketchmask  = GroupMask::Fill(TOTAL_BUCKETS);
    for (int round = 1; round <= 4 && !resolved; ++round) {
        auto shortid_bytes = provider.GetShortIdBytes(round, shortidmask);
        auto [res, new_shortidmask, new_sketchmask] = sketch.Process(
            round, shortidmask, sketchmask,
            shortid_bytes, provider.GetSketches(round));
        resolved = res;
        shortidmask = new_shortidmask;
        sketchmask  = new_sketchmask;
    }

    if (!resolved) return;

    std::vector<uint64_t> result;
    for (uint64_t sid : sketch.m_shortids) {
        if (sid != 0) result.push_back(sid);
    }
    std::sort(result.begin(), result.end());

    if (!is_honest) return;

    if (result != prov_sids) {
        fprintf(stderr, "MISMATCH result.size=%zu prov_sids.size=%zu\n", result.size(), prov_sids.size());
        fprintf(stderr, "decoded_by_basis.Count()=%u basis_count=%zu\n", sketch.m_decoded_by_basis.Count(), sketch.m_basis_count);
        fprintf(stderr, "shortids(%zu):", sketch.m_shortids.size());
        for (uint64_t sid : sketch.m_shortids) fprintf(stderr, " %llu", (unsigned long long)sid);
        fprintf(stderr, "\nprov_sids(%zu):", prov_sids.size());
        for (uint64_t sid : prov_sids) fprintf(stderr, " %llu", (unsigned long long)sid);
        fprintf(stderr, "\nresult(%zu):", result.size());
        for (uint64_t sid : result) fprintf(stderr, " %llu", (unsigned long long)sid);
        fprintf(stderr, "\ndiff_shortids(%zu):", sketch.m_diff_shortids.size());
        for (uint64_t sid : sketch.m_diff_shortids) fprintf(stderr, " %llu", (unsigned long long)sid);
        fprintf(stderr, "\nextra_shortids(%zu):", sketch.m_extra_shortids.size());
        for (uint64_t sid : sketch.m_extra_shortids) fprintf(stderr, " %llu", (unsigned long long)sid);
        fprintf(stderr, "\n");
    }
    assert(result == prov_sids);
}

// Fast target: at most 4 active buckets — high iteration rate for quick exploration.
FUZZ_TARGET(templateman, .init = initialize_templateman)
{
    FuzzedDataProvider fdp{buffer.data(), buffer.size()};
    run_templateman(fdp, 4);
}

// Slow target: up to all 32 buckets — lower iteration rate, broader coverage.
FUZZ_TARGET(templateman_slow, .init = initialize_templateman)
{
    FuzzedDataProvider fdp{buffer.data(), buffer.size()};
    run_templateman(fdp, TOTAL_BUCKETS);
}
