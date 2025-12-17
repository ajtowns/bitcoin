// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <array>

#define CHACHA20_NAMESPACE chacha20_vec_base

// This file should define which states should be en/disabled for all
// supported architectures. For some, like x86-64 and armv8, simd features
// (sse2 and neon respectively) are safe to use without runtime detection.

#if defined(__x86_64__) || defined(__amd64__)
inline constexpr auto CHACHA20_VEC_SIZES = std::to_array<int>({ 4, 2 });
#elif defined(__ARM_NEON)
inline constexpr auto CHACHA20_VEC_SIZES = std::to_array<int>({ 16, 8, 6, 4 });
#else
// Be conservative and require platforms to opt-in
inline constexpr std::array<int,0> CHACHA20_VEC_SIZES;
#endif

#include <crypto/chacha20_vec.ipp>
