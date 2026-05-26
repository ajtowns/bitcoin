// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/kvformat.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace kv = util::kvformat;

BOOST_AUTO_TEST_SUITE(util_kvformat_tests)

// ---------------------------------------------------------------------------
// Compile-time count assertions. ConstevalMsgWithKVs<N> has a consteval ctor;
// full-parse tests in the BOOST_AUTO_TEST_CASEs below declare it `constexpr`
// and access the resulting fields at runtime.
// (`p` is a `ConstevalMsgWithKVs`; `r` is the `Formatted` result.)
// ---------------------------------------------------------------------------
namespace compile_tests {

static_assert(kv::ConstevalMsgWithKVs<0>{""}.kvs_size == 0);
static_assert(kv::ConstevalMsgWithKVs<0>{"just some prose"}.kvs_size == 0);
static_assert(kv::ConstevalMsgWithKVs<2>{"loaded %s in %dms"}.kvs_size == 0);
static_assert(kv::ConstevalMsgWithKVs<2>{"hash=%s height=%d"}.kvs_size == 2);
static_assert(kv::ConstevalMsgWithKVs<3>{"hello %s, foo=%d bar=%.2fms"}.kvs_size == 2);

// Multi-spec token does NOT match as a kv; falls through to the msg,
// where the two specs are consumed as positional values (so N=2 here).
static_assert(kv::ConstevalMsgWithKVs<2>{"foo bar=%d%s"}.kvs_size == 0);

// Token without a %-spec falls through (e.g. "tag=foo" is prose, not a kv).
static_assert(kv::ConstevalMsgWithKVs<1>{"event=foo bar=%d"}.kvs_size == 1);

// %% in msg is not counted as a positional spec.
static_assert(kv::ConstevalMsgWithKVs<1>{"100%% done count=%d"}.kvs_size == 1);

} // namespace compile_tests

BOOST_AUTO_TEST_CASE(parse_basics)
{
    using kv::Kind;

    // Empty / pure-prose format strings.
    {
        constexpr kv::ConstevalMsgWithKVs<0> p{""};
        BOOST_CHECK_EQUAL(p.kvs_size, 0u);
        BOOST_CHECK(p.msg == "");
    }
    {
        constexpr kv::ConstevalMsgWithKVs<0> p{"just some prose"};
        BOOST_CHECK_EQUAL(p.kvs_size, 0u);
        BOOST_CHECK(p.msg == "just some prose");
    }
    // Positional %-specs in the prefix, no structured tail.
    {
        constexpr kv::ConstevalMsgWithKVs<2> p{"loaded %s in %dms"};
        BOOST_CHECK_EQUAL(p.kvs_size, 0u);
        BOOST_CHECK(p.msg == "loaded %s in %dms");
    }
    // Structured tail only.
    {
        constexpr kv::ConstevalMsgWithKVs<2> p{"hash=%s height=%d"};
        BOOST_CHECK_EQUAL(p.kvs_size, 2u);
        BOOST_CHECK(p.msg == "");
        BOOST_CHECK(p.kvs()[0].name == "hash");
        BOOST_CHECK(p.kvs()[0].spec == "%s");
        BOOST_CHECK(p.kvs()[0].kind == Kind::String);
        BOOST_CHECK(p.kvs()[1].name == "height");
        BOOST_CHECK(p.kvs()[1].spec == "%d");
        BOOST_CHECK(p.kvs()[1].kind == Kind::Integer);
    }
    // Mixed: prefix with positional %s, structured tail.
    {
        constexpr kv::ConstevalMsgWithKVs<3> p{"hello %s, foo=%d bar=%.2fms"};
        BOOST_CHECK_EQUAL(p.kvs_size, 2u);
        BOOST_CHECK(p.msg == "hello %s,");
        BOOST_CHECK(p.kvs()[0].name == "foo");
        BOOST_CHECK(p.kvs()[0].spec == "%d");
        BOOST_CHECK(p.kvs()[0].kind == Kind::Integer);
        BOOST_CHECK(p.kvs()[1].name == "bar");
        BOOST_CHECK(p.kvs()[1].spec == "%.2fms");
        BOOST_CHECK(p.kvs()[1].kind == Kind::String);
    }
    // Trailing newline tolerated.
    {
        constexpr kv::ConstevalMsgWithKVs<2> p{"sending getdata (%d bytes) peer=%d\n"};
        BOOST_CHECK_EQUAL(p.kvs_size, 1u);
        BOOST_CHECK(p.msg == "sending getdata (%d bytes)");
        BOOST_CHECK(p.kvs()[0].name == "peer");
        BOOST_CHECK(p.kvs()[0].kind == Kind::Integer);
    }
    // Leading-literal in value: [lit]%spec[lit].
    {
        constexpr kv::ConstevalMsgWithKVs<2> p{"addr=[%s] peer=#%d"};
        BOOST_CHECK_EQUAL(p.kvs_size, 2u);
        BOOST_CHECK(p.kvs()[0].name == "addr");
        BOOST_CHECK(p.kvs()[0].spec == "[%s]");
        BOOST_CHECK(p.kvs()[0].kind == Kind::String);
        BOOST_CHECK(p.kvs()[1].name == "peer");
        BOOST_CHECK(p.kvs()[1].spec == "#%d");
        BOOST_CHECK(p.kvs()[1].kind == Kind::String);
    }
    // Kind comes from the spec's type char for bare specs; any literal
    // text around the spec forces String, since the formatted value
    // won't be a bare number.
    {
        constexpr kv::ConstevalMsgWithKVs<3> p{"n=%d r=%.2f s=%s"};
        BOOST_CHECK(p.kvs()[0].kind == Kind::Integer);
        BOOST_CHECK(p.kvs()[1].kind == Kind::Float);
        BOOST_CHECK(p.kvs()[2].kind == Kind::String);
    }
    {
        constexpr kv::ConstevalMsgWithKVs<3> p{"n=#%d r=%.2fms s=[%s]"};
        BOOST_CHECK(p.kvs()[0].kind == Kind::String);
        BOOST_CHECK(p.kvs()[1].kind == Kind::String);
        BOOST_CHECK(p.kvs()[2].kind == Kind::String);
    }
    // Token without a %-spec falls through.
    {
        constexpr kv::ConstevalMsgWithKVs<1> p{"event=foo bar=%d"};
        BOOST_CHECK_EQUAL(p.kvs_size, 1u);
        BOOST_CHECK(p.msg == "event=foo");
        BOOST_CHECK(p.kvs()[0].name == "bar");
    }
}

BOOST_AUTO_TEST_CASE(format_basics)
{
    // No params, plain prose — prefix-only format.
    {
        constexpr kv::ConstevalMsgWithKVs<0> p{"just prose"};
        auto r = p.format();
        BOOST_CHECK_EQUAL(r.msg, "just prose");
        BOOST_CHECK_EQUAL(r.kvs.size(), 0u);
    }

    // Positional %-specs in prefix, no structured tail.
    {
        constexpr kv::ConstevalMsgWithKVs<2> p{"loaded %s in %dms"};
        auto r = p.format(std::string{"foo.bin"}, 42);
        BOOST_CHECK_EQUAL(r.msg, "loaded foo.bin in 42ms");
        BOOST_CHECK_EQUAL(r.kvs.size(), 0u);
    }

    // Structured tail only.
    {
        constexpr kv::ConstevalMsgWithKVs<2> p{"hash=%s height=%d"};
        auto r = p.format(std::string{"deadbeef"}, 944000);
        BOOST_CHECK_EQUAL(r.msg, "");
        BOOST_REQUIRE_EQUAL(r.kvs.size(), 2u);
        BOOST_CHECK_EQUAL(r.kvs[0].value, "deadbeef");
        BOOST_CHECK_EQUAL(r.kvs[1].value, "944000");
    }

    // Mixed prefix + tail + leading-literal in value.
    {
        constexpr kv::ConstevalMsgWithKVs<3> p{"got %s peer=#%d ms=%.1fms"};
        auto r = p.format(std::string{"hello"}, 7, 12.34);
        BOOST_CHECK_EQUAL(r.msg, "got hello");
        BOOST_REQUIRE_EQUAL(r.kvs.size(), 2u);
        BOOST_CHECK_EQUAL(r.kvs[0].value, "#7");
        BOOST_CHECK_EQUAL(r.kvs[1].value, "12.3ms");
    }

    // Trailing newline tolerated; doesn't appear in prefix.
    {
        constexpr kv::ConstevalMsgWithKVs<1> p{"sent peer=%d\n"};
        auto r = p.format(3);
        BOOST_CHECK_EQUAL(r.msg, "sent");
        BOOST_REQUIRE_EQUAL(r.kvs.size(), 1u);
        BOOST_CHECK_EQUAL(r.kvs[0].value, "3");
    }
}

BOOST_AUTO_TEST_CASE(providers)
{
    // MakeKVs builds a KVProvider that satisfies IsKVProvider.
    auto lp = kv::MakeKVs("peer=%d disconnect=%d", 100, true);
    static_assert(kv::IsKVProvider<decltype(lp)>);
    BOOST_CHECK_EQUAL(lp.kvs().size(), 2u);
    auto vals = lp.values();
    BOOST_REQUIRE_EQUAL(vals.size(), 2u);
    BOOST_CHECK_EQUAL(vals[0], "100");
    BOOST_CHECK_EQUAL(vals[1], "1");

    // Provider metadata exposes name/kind correctly.
    BOOST_CHECK(lp.kvs()[0].name == "peer");
    BOOST_CHECK(lp.kvs()[0].kind == kv::Kind::Integer);
    BOOST_CHECK(lp.kvs()[1].name == "disconnect");
    BOOST_CHECK(lp.kvs()[1].kind == kv::Kind::Integer);
}

BOOST_AUTO_TEST_CASE(format_with_trailing_provider)
{
    // format() splices trailing-provider kvs in after format-string kvs,
    // in source-arg order.
    constexpr kv::ConstevalMsgWithKVs<2> p{"got %s height=%d"};
    auto prov = kv::MakeKVs("peer=%d ok=%d", 7, true);
    auto r = p.format(std::string{"block"}, 944000, prov);

    BOOST_CHECK_EQUAL(r.msg, "got block");
    BOOST_REQUIRE_EQUAL(r.kvs.size(), 3u);
    // Format-string kv first.
    BOOST_CHECK_EQUAL(r.kvs[0].name, "height");
    BOOST_CHECK_EQUAL(r.kvs[0].value, "944000");
    // Then the provider's kvs, in source order.
    BOOST_CHECK_EQUAL(r.kvs[1].name, "peer");
    BOOST_CHECK_EQUAL(r.kvs[1].value, "7");
    BOOST_CHECK_EQUAL(r.kvs[2].name, "ok");
    BOOST_CHECK_EQUAL(r.kvs[2].value, "1");
}

BOOST_AUTO_TEST_SUITE_END()
