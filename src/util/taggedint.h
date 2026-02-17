// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_TAGGEDINT_H
#define BITCOIN_UTIL_TAGGEDINT_H

#include <compare>
#include <concepts>
#include <cstdint>
#include <type_traits>
#include <utility>

namespace util {

template<typename Underlying, typename Tag>
struct TaggedInt
{
    using value_type = Underlying;

    static_assert(std::integral<value_type>);

    value_type value;

    // === Constructors ===
    constexpr TaggedInt() : value{0} { }
    constexpr TaggedInt(value_type v) noexcept : value(v) {}

    // Implicit conversion *to* underlying type
    constexpr operator value_type() const noexcept { return value; }

    // === Prevent mixing different tags ===

    // Delete construction from other tagged ints
    template <typename OtherU, typename OtherTag>
        requires (!std::same_as<OtherTag, Tag>)
    constexpr TaggedInt(TaggedInt<OtherU, OtherTag>) = delete;

    // Delete assignment from other tagged ints
    template <typename OtherU, typename OtherTag>
        requires (!std::same_as<OtherTag, Tag>)
    constexpr TaggedInt& operator=(TaggedInt<OtherU, OtherTag>) = delete;

    // === Comparison ===

    friend constexpr bool operator==(TaggedInt a, TaggedInt b) noexcept { return a.value == b.value; }
    friend constexpr auto operator<=>(TaggedInt a, TaggedInt b) noexcept { return a.value <=> b.value; }

    friend constexpr bool operator==(TaggedInt a, std::integral auto b) noexcept { return a.value == static_cast<value_type>(b); }
    friend constexpr auto operator<=>(TaggedInt a, std::integral auto b) noexcept { return a.value <=> static_cast<value_type>(b); }
    friend constexpr bool operator==(std::integral auto a, TaggedInt b) noexcept { return static_cast<value_type>(a) == b.value; }
    friend constexpr auto operator<=>(std::integral auto a, TaggedInt b) noexcept { return static_cast<value_type>(a) <=> b.value; }

    // === Arithmetic ===
    constexpr TaggedInt& operator++() noexcept { ++value; return *this; }
    constexpr TaggedInt& operator+=(TaggedInt rhs) noexcept { value += rhs.value; return *this; }
    constexpr TaggedInt  operator+ (TaggedInt rhs) const noexcept { return TaggedInt(value + rhs.value); }

    constexpr TaggedInt& operator--() noexcept { --value; return *this; }
    constexpr TaggedInt& operator-=(TaggedInt rhs) noexcept { value -= rhs.value; return *this; }
    constexpr TaggedInt  operator- (TaggedInt rhs) const noexcept { return TaggedInt(value - rhs.value); }

    constexpr TaggedInt& operator*=(TaggedInt rhs) noexcept { value *= rhs.value; return *this; }
    constexpr TaggedInt  operator* (TaggedInt rhs) const noexcept { return TaggedInt(value * rhs.value); }

    constexpr TaggedInt& operator/=(TaggedInt rhs) noexcept { value /= rhs.value; return *this; }
    constexpr TaggedInt  operator/ (TaggedInt rhs) const noexcept { return TaggedInt(value / rhs.value); }
};

} // util namespace

// Make it work nicely with std::hash, range-based for, etc.
template<typename U, typename Tag>
struct std::hash<util::TaggedInt<U, Tag>>
{
    std::size_t operator()(util::TaggedInt<U, Tag> x) const noexcept {
        return std::hash<U>{}(x.value);
    }
};



#endif // BITCOIN_UTIL_TAGGEDINT_H
