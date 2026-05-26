// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_KVFORMAT_H
#define BITCOIN_UTIL_KVFORMAT_H

/**
 * Parsing and formatting of format strings that carry structured
 * key-value tokens.
 *
 * A format string is a prose msg (possibly with `%` format specifiers),
 * followed by an optional run of `name=fmt` key-value tokens (each with
 * a single `%` format specifier), e.g. `"rcvd: %s peer=%d size=%dkB"`.
 *
 * `ConstevalMsgWithKVs`'s consteval ctor parses the format string at
 * compile time; the msg-side positional specs and per-kv values are
 * formatted at runtime by `format()`. `KVProvider` and `MakeKVs` use
 * `ConstevalKVSpec`, a kvs-only variant of `ConstevalMsgWithKVs`.
 */

#include <tinyformat.h>
#include <util/string.h>

#include <array>
#include <concepts>
#include <cstddef>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

namespace util::kvformat {

/**
 * Kind (type) of a structured value, derived from the printf-style spec's type
 * character. Used by downstream consumers (e.g. a JSON sink) to decide
 * whether a formatted value should be emitted unquoted (number) or quoted
 * (string).
 */
enum class Kind {
    String,
    Integer,
    Float
};

/**
 * Runtime structured value: name, kind, and formatted value. Owned
 * (`std::string`) so the holder has no lifetime dependencies on its
 * source — including for paths that build entries from runtime-built
 * format strings. Produced by `format()`, consumed by sinks (debug.log
 * writer, JSON sink).
 */
struct KV {
    std::string name;
    Kind kind;
    std::string value;
};

/**
 * Output of a `format(args...)` call: the formatted msg string and the
 * accumulated kvs (format-string kvs followed by any trailing-provider
 * kvs, in source-arg order).
 */
struct Formatted {
    std::string msg;
    std::vector<KV> kvs;
};

/**
 * Compile-time spec for one key-value pair, parsed from a format
 * string's trailing `key=value key=value ...` run. The runtime
 * counterpart, produced once the args are formatted, is `KV`.
 *
 * `spec` is the whole value portion after `=` (i.e. everything that
 * tinyformat will format with the arg), including any literal text
 * before and after the printf-style `%`-spec. Any literal text around
 * the spec forces `kind=String`, since the final formatted value won't
 * be a bare number. For example:
 *
 *     "height=%d"     -> name="height", spec="%d",    kind=Integer
 *     "peer=#%d"      -> name="peer",   spec="#%d",   kind=String
 *     "t=%dms"        -> name="t",      spec="%dms",  kind=String
 *     "addr=[%s]"     -> name="addr",   spec="[%s]",  kind=String
 *
 * Exactly one `%`-spec must appear in the value; multi-spec tokens
 * (which would consume more than one arg) fail to match and fall
 * through to the prose msg. To structure a compound value, pre-format
 * with `strprintf` at the call site and use `name=%s`.
 *
 * The string_views point into the source format string. For the macro
 * path, the source is a string literal (static storage, valid for the
 * program's lifetime).
 */
struct KVSpec {
    std::string_view name;
    std::string_view spec;
    Kind kind;
};

/**
 * Concept: a type that exposes `t.kvs()` (a span of `KVSpec`) and
 * `t.values()` (formatted strings matching `kvs()`). Any such type can
 * be attached as a trailing arg to contribute structured context.
 */
template <typename T>
concept IsKVProvider = requires(const T& t) {
    { std::span<const KVSpec>{t.kvs()} };
    { t.values() } -> std::convertible_to<std::vector<std::string>>;
};

namespace detail {

consteval bool IsKeyStart(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}
consteval bool IsKeyCont(char c)
{
    return IsKeyStart(c) || (c >= '0' && c <= '9');
}

//! Map a printf-style spec's type character to a `Kind`.
consteval Kind KindFromSpecType(char c)
{
    switch (c) {
    case 'd':
    case 'i':
    case 'u':
        return Kind::Integer;
    case 'f':
    case 'F':
    case 'e':
    case 'E':
    case 'g':
    case 'G':
    case 'a':
    case 'A':
        return Kind::Float;
    default:
        return Kind::String;
    }
}

/**
 * If `sv[i]` begins a printf-style `%`-spec, return one past the type
 * character. Returns `nullopt` on malformed input. Does NOT handle the
 * `%%` literal-percent escape (caller checks).
 */
consteval std::optional<std::size_t> FindSpecEnd(std::string_view sv, std::size_t i)
{
    ++i; // skip '%'
    if (i >= sv.size()) return std::nullopt;
    // flags
    while (i < sv.size() && (sv[i] == '#' || sv[i] == '0' || sv[i] == '-' || sv[i] == ' ' || sv[i] == '+')) {
        ++i;
    }
    // width
    if (i < sv.size() && sv[i] == '*') {
        ++i;
    } else {
        while (i < sv.size() && sv[i] >= '0' && sv[i] <= '9') {
            ++i;
        }
    }
    // .precision
    if (i < sv.size() && sv[i] == '.') {
        ++i;
        if (i < sv.size() && sv[i] == '*') {
            ++i;
        } else {
            while (i < sv.size() && sv[i] >= '0' && sv[i] <= '9') {
                ++i;
            }
        }
    }
    // length modifiers
    while (i < sv.size() && (sv[i] == 'h' || sv[i] == 'l' || sv[i] == 'j' || sv[i] == 'z' || sv[i] == 't' || sv[i] == 'L')) {
        ++i;
    }
    // type character
    if (i >= sv.size()) return std::nullopt;
    ++i;
    return i;
}

/**
 * Match a token against `name=[lit]%spec[lit]` -- a key, `=`, then a
 * value containing exactly one printf-style `%`-spec, with arbitrary
 * literal text allowed before and after it. Multiple `%`-specs (other
 * than `%%`) cause the match to fail; the token then falls through to
 * the prose msg.
 */
consteval std::optional<KVSpec> TryMatchKVToken(std::string_view token)
{
    if (token.size() < 4) return std::nullopt; // need at least "x=%c"
    if (!IsKeyStart(token[0])) return std::nullopt;
    std::size_t i = 1;
    while (i < token.size() && IsKeyCont(token[i])) {
        ++i;
    }
    if (i >= token.size() || token[i] != '=') return std::nullopt;
    std::size_t name_end = i;
    std::size_t value_start = i + 1;

    // Locate the first non-`%%` `%`-spec in the value portion.
    std::size_t spec_pos = std::string_view::npos;
    for (std::size_t j = value_start; j < token.size(); ++j) {
        if (token[j] != '%') continue;
        if (j + 1 < token.size() && token[j + 1] == '%') {
            ++j;
            continue;
        }
        spec_pos = j;
        break;
    }
    if (spec_pos == std::string_view::npos) return std::nullopt; // no spec in value

    auto spec_end_opt = FindSpecEnd(token, spec_pos);
    if (!spec_end_opt) return std::nullopt; // spec didn't parse cleanly
    std::size_t spec_end = *spec_end_opt;

    // Reject if a second `%`-spec appears after the first (would
    // consume an extra arg).
    for (std::size_t j = spec_end; j < token.size(); ++j) {
        if (token[j] != '%') continue;
        if (j + 1 < token.size() && token[j + 1] == '%') {
            ++j;
            continue;
        }
        return std::nullopt;
    }

    // Any literal text around the `%`-spec means the final formatted
    // value won't be a bare number — force Kind::String so downstream
    // consumers (e.g. a JSON sink) don't mis-emit "#7" or "42ms"
    // unquoted on the basis of the spec's type char.
    const bool has_literal = (spec_pos > value_start) || (spec_end < token.size());
    return KVSpec{
        .name = token.substr(0, name_end),
        .spec = token.substr(value_start),
        .kind = has_literal ? Kind::String : KindFromSpecType(token[spec_end - 1]),
    };
}

} // namespace detail

/**
 * Compile-time-parsed format string: a prose msg (which may contain
 * positional `%`-specs) followed by an optional trailing run of
 * `name=value` tokens. `N` is the total spec count expected from the
 * format string; the kv-token count is at most `N` and is stored in
 * `kvs_size`.
 *
 * The ctor is `consteval` -- the format string must be a constant
 * expression. Spec-count mismatch and duplicate-name checks become
 * compile-time errors. Paths that need a runtime-built format string
 * bypass this type entirely and assemble runtime `KV`s by hand.
 */
template <std::size_t N>
struct ConstevalMsgWithKVs {
    std::string_view msg;
    std::array<KVSpec, N> kvs_storage{};
    std::size_t kvs_size{};

    consteval ConstevalMsgWithKVs(const char* fmt)
    {
        // Validate that the total format-specifier count in `fmt` equals
        // `N`. Callers (via `ConstevalMsgFor<Args...>`) set `N` to the
        // non-provider arg count; any mismatch means the call site has
        // the wrong number of args for the format string.
        const auto counts = util::detail::CountNumFormatSpecifiers(fmt);
        if (counts.count_pos != 0) throw "kvformat does not support positional format specifiers (%N$...)";
        if (counts.count_normal != N) throw "format-string spec count does not match ConstevalMsgWithKVs<N>";

        // Strip trailing spaces and newlines before the parse.
        std::string_view sv{fmt};
        std::size_t end = sv.size();
        while (end > 0 && (sv[end - 1] == ' ' || sv[end - 1] == '\n')) {
            --end;
        }

        // Walk from end, collecting matched tokens in reverse order.
        std::array<KVSpec, N> rev{};
        std::size_t n = 0;
        while (end > 0 && n < N) {
            std::size_t start = end;
            while (start > 0 && sv[start - 1] != ' ') {
                --start;
            }
            auto matched = detail::TryMatchKVToken(sv.substr(start, end - start));
            if (!matched) break;
            rev[n++] = *matched;
            if (start == 0) {
                end = 0;
                break;
            }
            end = start - 1;
        }

        // Reverse `rev` into source order in `kvs_storage`.
        for (std::size_t i = 0; i < n; ++i) {
            kvs_storage[i] = rev[n - 1 - i];
        }

        // Compute the msg (substring up to the trailing run, with
        // trailing spaces and newlines trimmed).
        std::string_view msg_view = sv.substr(0, end);
        while (!msg_view.empty() && (msg_view.back() == ' ' || msg_view.back() == '\n')) {
            msg_view.remove_suffix(1);
        }

        // Reject duplicate names -- almost certainly a bug at the call site.
        for (std::size_t i = 0; i < n; ++i) {
            for (std::size_t j = i + 1; j < n; ++j) {
                if (kvs_storage[i].name == kvs_storage[j].name) {
                    throw "duplicate kv name in format string";
                }
            }
        }

        msg = msg_view;
        kvs_size = n;
    }

    //! View of this object's kvs.
    constexpr std::span<const KVSpec> kvs() const
    {
        return {kvs_storage.data(), kvs_size};
    }

    /**
     * Format this msg against `args`, returning the assembled `Formatted`.
     *
     * The leading N args are the positional values for the format string.
     * `Args` may contain trailing types satisfying `IsKVProvider`; those
     * providers' values are extracted and appended after the format-string
     * kvs in source-arg order.
     */
    template <typename... Args>
    Formatted format(const Args&... args) const;
};

namespace detail {

/**
 * Count the trailing `Args...` types that satisfy `IsKVProvider`. Used to
 * derive the positional-arg count
 * (= `sizeof...(Args) - CountTrailingProviders<Args...>()`) that
 * `ConstevalMsgFor<Args...>` (and `ConstevalKVSpecFor<Args...>`) uses
 * for its `N`.
 */
template <typename... Args>
consteval std::size_t CountTrailingProviders()
{
    constexpr std::array<bool, sizeof...(Args)> is_provider{
        IsKVProvider<std::remove_cvref_t<Args>>...};
    std::size_t count = 0;
    for (std::size_t i = is_provider.size(); i > 0; --i) {
        if (!is_provider[i - 1]) break;
        ++count;
    }
    return count;
}

/**
 * `ConstevalMsgWithKVs` variant whose consteval ctor additionally
 * enforces that the format string is *only* a run of `name=fmt` kv
 * tokens -- no prose msg, no msg-side `%`-specs. The base `.msg` field
 * is therefore always empty here; this struct is effectively an array
 * of `KVSpec`. Used internally by `KVProvider` (and `MakeKVs`), which
 * holds the args alongside the format string and has no separate
 * msg-args slot.
 */
template <std::size_t N>
struct ConstevalKVSpec : ConstevalMsgWithKVs<N> {
    consteval ConstevalKVSpec(const char* fmt) : ConstevalMsgWithKVs<N>{fmt}
    {
        // Base ctor already enforced total-spec count == N. If kvs_size < N,
        // some of those specs were in the prose msg.
        if (this->kvs_size != N) {
            throw "kvs-only format string can't have %-specs outside kv tokens";
        }
        // Prose text without a %-spec would be silently dropped by
        // `KVProvider::values()`, so reject it at the call site.
        if (!this->msg.empty()) {
            throw "kvs-only format string can't have prose text";
        }
    }
};

template <typename... Args>
using ConstevalKVSpecFor = ConstevalKVSpec<sizeof...(Args) - CountTrailingProviders<Args...>()>;

//! Append one (name, kind, formatted value) tuple to `out`.
inline void AppendKV(std::vector<KV>& out, const KVSpec& spec, std::string value)
{
    out.push_back(KV{std::string{spec.name}, spec.kind, std::move(value)});
}

//! Append a provider's kvs to `out.kvs`, in the provider's source order.
template <IsKVProvider P>
inline void AppendProvider(Formatted& out, const P& provider)
{
    auto pkvs = provider.kvs();
    auto pvals = provider.values();
    for (std::size_t i = 0; i < pkvs.size(); ++i) {
        AppendKV(out.kvs, pkvs[i], std::move(pvals[i]));
    }
}

//! Format `msg`'s prose-portion + format-string kvs into `out` using
//! `args` as the positional values. Caller has already sliced out
//! providers; `sizeof...(Args)` must equal `N`.
template <std::size_t N, typename... Args>
inline void FormatCore(Formatted& out, const ConstevalMsgWithKVs<N>& msg, const Args&... args)
{
    static_assert(sizeof...(Args) == N, "FormatCore: arg count must equal format spec count");
    auto fmt_list = tinyformat::makeFormatList(args...);
    const std::size_t num_msg_args = N - msg.kvs_size;

    {
        std::string msg_str{msg.msg};
        std::ostringstream oss;
        tinyformat::vformat(oss, msg_str.c_str(), fmt_list.sublist(0, num_msg_args));
        out.msg = std::move(oss).str();
    }
    for (std::size_t i = 0; i < msg.kvs_size; ++i) {
        std::string spec_str{msg.kvs()[i].spec};
        std::ostringstream oss;
        tinyformat::vformat(oss, spec_str.c_str(),
                            fmt_list.sublist(num_msg_args + i, 1));
        AppendKV(out.kvs, msg.kvs()[i], std::move(oss).str());
    }
}

} // namespace detail

template <std::size_t N>
template <typename... Args>
Formatted ConstevalMsgWithKVs<N>::format(const Args&... args) const
{
    static_assert(sizeof...(Args) >= N, "too few args for the format string");

    using ArgTuple = std::tuple<std::remove_cvref_t<Args>...>;
    constexpr std::size_t n_trailing = sizeof...(Args) - N;

    // (a) The leading N args are the positional values for the format
    // string -- none of them may satisfy `IsKVProvider`, since they'd
    // otherwise be silently fed to tinyformat as positional values.
    constexpr bool leading_are_positional = []<std::size_t... Is>(std::index_sequence<Is...>) {
        return (!IsKVProvider<std::tuple_element_t<Is, ArgTuple>> && ...);
    }(std::make_index_sequence<N>{});
    static_assert(leading_are_positional, "positional argument cannot be a KVProvider");

    // (b) Any remaining args must all be providers.
    constexpr bool trailing_are_providers = []<std::size_t... Is>(std::index_sequence<Is...>) {
        return (IsKVProvider<std::tuple_element_t<N + Is, ArgTuple>> && ...);
    }(std::make_index_sequence<n_trailing>{});
    static_assert(trailing_are_providers, "args after the positional values must be KVProviders");

    auto tup = std::forward_as_tuple(args...);
    Formatted out;

    // Reserve: format-string kvs + each trailing provider's kvs (runtime sizes).
    std::size_t total = kvs_size;
    [&]<std::size_t... Is>(std::index_sequence<Is...>) {
        ((total += std::get<N + Is>(tup).kvs().size()), ...);
    }(std::make_index_sequence<n_trailing>{});
    out.kvs.reserve(total);

    // Format-string portion using the positional args.
    [&]<std::size_t... Is>(std::index_sequence<Is...>) {
        detail::FormatCore(out, *this, std::get<Is>(tup)...);
    }(std::make_index_sequence<N>{});

    // Trailing providers, in source order.
    [&]<std::size_t... Is>(std::index_sequence<Is...>) {
        (detail::AppendProvider(out, std::get<N + Is>(tup)), ...);
    }(std::make_index_sequence<n_trailing>{});

    return out;
}

/**
 * The `ConstevalMsgWithKVs` type for a call site with argument pack
 * `Args...`. Capacity is the positional (non-provider) arg count.
 */
template <typename... Args>
using ConstevalMsgFor = ConstevalMsgWithKVs<sizeof...(Args) - detail::CountTrailingProviders<Args...>()>;

/**
 * A bundle of (compile-time-parsed named-only format string, runtime
 * arg values). Satisfies `IsKVProvider`, so it can be attached as a
 * trailing arg to contribute structured context.
 *
 * Owns its `meta` by value, so it carries the parsed `KVSpec[]` storage
 * with it -- no external lifetime dependency.
 */
template <typename... Args>
struct KVProvider {
    detail::ConstevalKVSpecFor<Args...> meta;
    std::tuple<Args...> args;

    template <typename... InitArgs>
    constexpr KVProvider(detail::ConstevalKVSpecFor<Args...> m, InitArgs&&... init)
        : meta{m}, args{std::forward<InitArgs>(init)...}
    {
    }

    std::span<const KVSpec> kvs() const { return meta.kvs(); }

    //! Format each held value with its per-kv spec. Delegates to
    //! `meta.format`, then strips the KV-name/kind metadata since the
    //! `IsKVProvider` concept just needs the value strings (kvs() already
    //! supplies the metadata).
    std::vector<std::string> values() const
    {
        auto f = [this]<std::size_t... Is>(std::index_sequence<Is...>) {
            return meta.format(std::get<Is>(args)...);
        }(std::make_index_sequence<sizeof...(Args)>{});
        std::vector<std::string> out;
        out.reserve(f.kvs.size());
        for (auto& kv : f.kvs) {
            out.push_back(std::move(kv.value));
        }
        return out;
    }
};

/**
 * Factory for `KVProvider`. The `LogKVs(fmt, args...)` macro in
 * `util/log.h` expands to a call here -- `fmt` becomes the consteval-
 * parsed `ConstevalKVSpec`, `args` go into the tuple.
 */
template <typename... Args>
auto MakeKVs(detail::ConstevalKVSpecFor<Args...> msg, Args&&... args)
{
    return KVProvider<std::decay_t<Args>...>{msg, std::forward<Args>(args)...};
}

} // namespace util::kvformat

#endif // BITCOIN_UTIL_KVFORMAT_H
