// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/chacha20_vec.h>

#include <bit>
#include <cassert>
#include <cstring>
#include <limits>

#if defined(ENABLE_CHACHA20_VEC)

#if defined(__has_attribute)
#  if __has_attribute(always_inline)
#    define ALWAYS_INLINE __attribute__ ((always_inline)) inline
#  endif
#endif

#if !defined(ALWAYS_INLINE)
#  define ALWAYS_INLINE inline
#endif

namespace {

using vec256 = uint32_t __attribute__((__vector_size__(32)));

/** Endian-conversion for big-endian */
ALWAYS_INLINE void vec_byteswap(vec256& vec)
{
    if constexpr (std::endian::native == std::endian::big)
    {
        vec256 ret;
        ret[0] = __builtin_bswap32(vec[0]);
        ret[1] = __builtin_bswap32(vec[1]);
        ret[2] = __builtin_bswap32(vec[2]);
        ret[3] = __builtin_bswap32(vec[3]);
        ret[4] = __builtin_bswap32(vec[4]);
        ret[5] = __builtin_bswap32(vec[5]);
        ret[6] = __builtin_bswap32(vec[6]);
        ret[7] = __builtin_bswap32(vec[7]);
        vec = ret;
    }
}

/** Left-rotate vector */
template <size_t BITS>
ALWAYS_INLINE void vec_rotl(vec256& vec)
{
    vec = (vec << BITS) | (vec >> (32 - BITS));
}

template <size_t REPS, typename Fn>
ALWAYS_INLINE void Repeat(Fn&& fn)
{
    if constexpr (REPS > 0) {
        fn();
        Repeat<REPS-1>(std::forward<Fn>(fn));
    }
}

template<size_t I>
class Vectorize
{
private:
    explicit Vectorize() = delete; // all methods are static

public:
    using arr_vec = std::array<vec256, I>;

    template <size_t ITER, typename T>
    ALWAYS_INLINE static auto& vectorize_param(T&& arg)
    {
        static_assert(ITER < I);
        if constexpr (std::is_same_v<arr_vec, std::remove_cvref_t<T>>) {
            return std::get<ITER>(arg);
        } else {
            return arg;
        }
    }

    template <size_t ITER=0, typename Fn, typename... Args>
    ALWAYS_INLINE static void vectorize(Fn&& fn, Args&... args)
    {
        if constexpr (ITER < I) {
            fn(vectorize_param<ITER>(args)...);
            vectorize<ITER+1>(std::forward<Fn>(fn), args...);
        }
    }

    /** Store a vector in all array elements */
    ALWAYS_INLINE static void arr_set_vec256(arr_vec& arr, const vec256& vec)
    {
        vectorize([&vec](auto& x) { x = vec; }, arr);
    }

    /** Add a vector to all array elements */
    ALWAYS_INLINE static void arr_add_vec256(arr_vec& arr, const vec256& vec)
    {
        vectorize([&vec](auto& x) { x += vec; }, arr);
    }

    /** Add corresponding vectors in arr1 to arr0 */
    ALWAYS_INLINE static void arr_add_arr(arr_vec& arr0, const arr_vec& arr1)
    {
        vectorize([](auto& x, auto& y) { x += y; }, arr0, arr1);
    }

    /** Perform add/xor/rotate for the round function */
    template <size_t BITS>
    ALWAYS_INLINE static void arr_add_xor_rot(arr_vec& arr0, const arr_vec& arr1, arr_vec& arr2)
    {
        vectorize([](auto& x, auto& y, auto& z) {
            x += y;
            z ^= x;
            vec_rotl<BITS>(z);
        }, arr0, arr1, arr2);
    }

    /*
    The first round:
                QUARTERROUND( x0, x4, x8,x12);
                QUARTERROUND( x1, x5, x9,x13);
                QUARTERROUND( x2, x6,x10,x14);
                QUARTERROUND( x3, x7,x11,x15);

    The second round:
                QUARTERROUND( x0, x5,x10,x15);
                QUARTERROUND( x1, x6,x11,x12);
                QUARTERROUND( x2, x7, x8,x13);
                QUARTERROUND( x3, x4, x9,x14);

    After the first round, arr_shuf0, arr_shuf1, and arr_shuf2 are used to shuffle
    the layout to prepare for the second round.

    After the second round, they are used (in reverse) to restore the original
    layout.

    */
    ALWAYS_INLINE static void arr_shuf0(arr_vec& arr)
    {
        vectorize([](auto& x) {
            x = __builtin_shufflevector(x, x, 1, 2, 3, 0, 5, 6, 7, 4);
        }, arr);
    }

    ALWAYS_INLINE static void arr_shuf1(arr_vec& arr)
    {
        vectorize([](auto& x) {
            x = __builtin_shufflevector(x, x, 2, 3, 0, 1, 6, 7, 4, 5);
        }, arr);
    }

    ALWAYS_INLINE static void arr_shuf2(arr_vec& arr)
    {
        vectorize([](auto& x) {
            x = __builtin_shufflevector(x, x, 3, 0, 1, 2, 7, 4, 5, 6);
        }, arr);
    }

    /* Main round function. */
    ALWAYS_INLINE static void doubleround(arr_vec& arr0, arr_vec& arr1, arr_vec& arr2, arr_vec& arr3)
    {
        Repeat<10>([&]() {
            arr_add_xor_rot<16>(arr0, arr1, arr3);
            arr_add_xor_rot<12>(arr2, arr3, arr1);
            arr_add_xor_rot<8>(arr0, arr1, arr3);
            arr_add_xor_rot<7>(arr2, arr3, arr1);
            arr_shuf0(arr1);
            arr_shuf1(arr2);
            arr_shuf2(arr3);
            arr_add_xor_rot<16>(arr0, arr1, arr3);
            arr_add_xor_rot<12>(arr2, arr3, arr1);
            arr_add_xor_rot<8>(arr0, arr1, arr3);
            arr_add_xor_rot<7>(arr2, arr3, arr1);
            arr_shuf2(arr1);
            arr_shuf1(arr2);
            arr_shuf0(arr3);
        });
    }

    /* Read 32bytes of input, xor with calculated state, write to output. Assumes
       that input and output are unaligned, and makes no assumptions about the
       internal layout of vec256;
    */
    ALWAYS_INLINE static void vec_read_xor_write(std::span<const std::byte, 32> in_bytes, std::span<std::byte, 32> out_bytes, const vec256& vec)
    {
        std::array<uint32_t, 8> temparr;
        memcpy(temparr.data(), in_bytes.data(), in_bytes.size());
        vec256 tempvec = vec ^ (vec256){temparr[0], temparr[1], temparr[2], temparr[3], temparr[4], temparr[5], temparr[6], temparr[7]};
        vec_byteswap(tempvec);
        temparr = {tempvec[0], tempvec[1], tempvec[2], tempvec[3], tempvec[4], tempvec[5], tempvec[6], tempvec[7]};
        memcpy(out_bytes.data(), temparr.data(), out_bytes.size());
    }

    /* Merge the 128 bit lanes from 2 states to the proper order, then pass each vec_read_xor_write */
    ALWAYS_INLINE static void arr_read_xor_write(std::span<const std::byte> in_bytes, std::span<std::byte> out_bytes, const arr_vec& arr0, const arr_vec& arr1, const arr_vec& arr2, const arr_vec& arr3)
    {
        vectorize([&in_bytes, &out_bytes](auto& w, auto& x, auto& y, auto& z) {
            vec_read_xor_write(in_bytes.first<32>(), out_bytes.first<32>(), __builtin_shufflevector(w, x, 4, 5, 6, 7, 12, 13, 14, 15));
            vec_read_xor_write(in_bytes.subspan<32, 32>(), out_bytes.subspan<32, 32>(), __builtin_shufflevector(y, z, 4, 5, 6, 7, 12, 13, 14, 15));
            vec_read_xor_write(in_bytes.subspan<64, 32>(), out_bytes.subspan<64, 32>(), __builtin_shufflevector(w, x, 0, 1, 2, 3, 8, 9, 10, 11));
            vec_read_xor_write(in_bytes.subspan<96, 32>(), out_bytes.subspan<96, 32>(), __builtin_shufflevector(y, z, 0, 1, 2, 3, 8, 9, 10, 11));
            in_bytes = in_bytes.subspan<128>();
            out_bytes = out_bytes.subspan<128>();
        }, arr0, arr1, arr2, arr3);
    }

    /* Compile-time helper to create addend vectors which used to increment the states

        Generates vectors of the pattern:
        1 0 0 0 0 0 0 0
        3 0 0 0 2 0 0 0
        5 0 0 0 4 0 0 0
        ...
    */
    static consteval arr_vec generate_increments()
    {
        arr_vec rows;
        for (uint32_t i = 0; i < I; ++i)
        {
            rows[i] = (i * (vec256){2, 0, 0, 0, 2, 0, 0, 0}) + (vec256){1, 0, 0, 0, 0, 0, 0, 0};
        }
        return rows;
    }

    /* Main crypt function. Calculates up to 16 states.

        Each array contains one or more vectors, with each array representing a
        quarter of a state. Initially, the high and low parts of each vector are
        duplicated. They each contain a portion of the current and next state.

        arr0[0]    arr1[0]    arr2[0]    arr3[0]   increment
        ----------|---------|----------|----------|---------
        0x61707865 input[0]   input[4]   input[8]   [1]
        0x3320646e input[1]   input[5]   input[9]   [0]
        0x79622d32 input[2]   input[6]   input[10]  [0]
        0x6b206574 input[3]   input[7]   input[11]  [0]

        0x61707865 input[0]   input[4]   input[8]   [0]
        0x3320646e input[1]   input[5]   input[9]   [0]
        0x79622d32 input[2]   input[6]   input[10]  [0]
        0x6b206574 input[3]   input[7]   input[11]  [0]

        After loading the states, arr3's vectors are incremented as-necessary to
        contain the correct counter values.

        This way, operations like "arr0[0] += arr1[0]" can perform all 8 operations
        in parallel, taking advantage of 256bit registers where available.

        arrX[0] represents states 0 and 1.
        arrX[1] represents states 2 and 3 (if present)
        etc.

        After the doublerounds have been run and the initial state has been mixed
        back in, the high and low portions of the vectors in each array are
        shuffled in order to prepare them for mixing with the input bytes. Finally,
        each state is xor'd with its corresponding input, byteswapped if necessary,
        and written to its output.
    */
    ALWAYS_INLINE static void multi_block_crypt(std::span<const std::byte> in_bytes, std::span<std::byte> out_bytes, const vec256& state0, const vec256& state1, const vec256& state2)
    {
        static constexpr vec256 nums256 = (vec256){0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
        static constinit arr_vec increments = generate_increments();

        arr_vec arr0, arr1, arr2, arr3;

        arr_set_vec256(arr0, nums256);
        arr_set_vec256(arr1, state0);
        arr_set_vec256(arr2, state1);
        arr_set_vec256(arr3, state2);

        arr_add_arr(arr3, increments);

        doubleround(arr0, arr1, arr2, arr3);

        arr_add_vec256(arr0, nums256);
        arr_add_vec256(arr1, state0);
        arr_add_vec256(arr2, state1);
        arr_add_vec256(arr3, state2);

        arr_add_arr(arr3, increments);

        arr_read_xor_write(in_bytes, out_bytes, arr0, arr1, arr2, arr3);
    }
};

template <int STATES>
ALWAYS_INLINE void multi_block_crypt(std::span<const std::byte> in_bytes, std::span<std::byte> out_bytes, const vec256& state0, const vec256& state1, const vec256& state2)
{
    static_assert(STATES >= 2 && STATES % 2 == 0 && STATES < 10000);
    return Vectorize<STATES/2>::multi_block_crypt(in_bytes, out_bytes, state0, state1, state2);
}

template <size_t STATES>
ALWAYS_INLINE void process_block(std::span<const std::byte>& in_bytes, std::span<std::byte>& out_bytes, const vec256& state0, const vec256& state1, vec256& state2)
{
    while(in_bytes.size() >= CHACHA20_VEC_BLOCKLEN * STATES) {
        multi_block_crypt<STATES>(in_bytes, out_bytes, state0, state1, state2);
        state2 += (vec256){STATES, 0, 0, 0, STATES, 0, 0, 0};
        in_bytes = in_bytes.subspan(CHACHA20_VEC_BLOCKLEN * STATES);
        out_bytes = out_bytes.subspan(CHACHA20_VEC_BLOCKLEN * STATES);
    }
}

template <size_t S=0>
ALWAYS_INLINE void process_vec_block(std::span<const std::byte>& in_bytes, std::span<std::byte>& out_bytes, const vec256& state0, const vec256& state1, vec256& state2)
{
    if constexpr (S < std::tuple_size_v<decltype(CHACHA20_VEC_SIZES)>) {
        if constexpr (S > 0) static_assert(std::get<S-1>(CHACHA20_VEC_SIZES) > std::get<S>(CHACHA20_VEC_SIZES), "CHACHA20_VEC_SIZES must be strictly decreasing");

        process_block<CHACHA20_VEC_SIZES[S]>(in_bytes, out_bytes, state0, state1, state2);
        process_vec_block<S+1>(in_bytes, out_bytes, state0, state1, state2);
    }
}

} // anonymous namespace

#if defined(CHACHA20_NAMESPACE)
namespace CHACHA20_NAMESPACE {
#endif

void chacha20_crypt_vectorized(std::span<const std::byte>& in_bytes, std::span<std::byte>& out_bytes, const std::array<uint32_t, 12>& input) noexcept
{
    if constexpr (std::tuple_size_v<decltype(CHACHA20_VEC_SIZES)> == 0) return;

    assert(in_bytes.size() == out_bytes.size());
    const vec256 state0 =  (vec256){input[0], input[1], input[2], input[3], input[0], input[1], input[2], input[3]};
    const vec256 state1 =  (vec256){input[4], input[5], input[6], input[7], input[4], input[5], input[6], input[7]};
    vec256 state2 =  (vec256){input[8], input[9], input[10], input[11], input[8], input[9], input[10], input[11]};
    process_vec_block(in_bytes, out_bytes, state0, state1, state2);
}

#if defined(CHACHA20_NAMESPACE)
}
#endif

#endif // ENABLE_CHACHA20_VEC
