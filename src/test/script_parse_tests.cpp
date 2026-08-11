// Copyright (c) 2021-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <script/script.h>
#include <util/strencodings.h>
#include <test/util/common.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(script_parse_tests)
BOOST_AUTO_TEST_CASE(parse_script)
{
    const std::vector<std::pair<std::string,std::string>> IN_OUT{
        // {IN: script string , OUT: hex string }
        {"", ""},
        {"0", "00"},
        {"1", "51"},
        {"2", "52"},
        {"3", "53"},
        {"4", "54"},
        {"5", "55"},
        {"6", "56"},
        {"7", "57"},
        {"8", "58"},
        {"9", "59"},
        {"10", "5a"},
        {"11", "5b"},
        {"12", "5c"},
        {"13", "5d"},
        {"14", "5e"},
        {"15", "5f"},
        {"16", "60"},
        {"17", "0111"},
        {"-9", "0189"},
        {"0x17", "17"},
        {"'17'", "023137"},
        {"ELSE", "67"},
        {"NOP10", "b9"},
        {"CHECKSIGADD", "ba"},
        {"OP_15", "5f"},
        {"TRUE", "51"},
        {"FALSE", "00"},
        {"OP_0", "00"},
    };
    std::string all_in;
    std::string all_out;
    for (const auto& [in, out] : IN_OUT) {
        BOOST_CHECK_EQUAL(HexStr(ParseScript(in)), out);
        all_in += " " + in + " ";
        all_out += out;
    }
    BOOST_CHECK_EQUAL(HexStr(ParseScript(all_in)), all_out);

    BOOST_CHECK_EXCEPTION(ParseScript("11111111111111111111"), std::runtime_error, HasReason("script parse error: decimal numeric value only allowed in the range -0xFFFFFFFF...0xFFFFFFFF"));
    BOOST_CHECK_EXCEPTION(ParseScript("11111111111"), std::runtime_error, HasReason("script parse error: decimal numeric value only allowed in the range -0xFFFFFFFF...0xFFFFFFFF"));
    BOOST_CHECK_EXCEPTION(ParseScript("OP_DOESNOTEXIST"), std::runtime_error, HasReason("script parse error: unknown opcode"));
}

BOOST_AUTO_TEST_CASE(script_ParseAsmStr)
{
    // ScriptToAsmStr output must round-trip through ParseAsmStr back to the
    // original script.
    const std::vector<CScript> scripts = {
        CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0x11) << OP_EQUALVERIFY << OP_CHECKSIG,
        CScript() << 0 << std::vector<unsigned char>(33, 0x22) << OP_CHECKSIG,
        CScript() << 1 << std::vector<unsigned char>(33, 0x33) << OP_CHECKSIG,
        CScript() << OP_1NEGATE << OP_ADD,
        CScript() << OP_2DUP,
        CScript() << 500000 << OP_CHECKLOCKTIMEVERIFY << OP_DROP,
        CScript() << -123456 << OP_NUMEQUAL,
        CScript() << std::vector<unsigned char>(76, 0x44),  // OP_PUSHDATA1
        CScript() << std::vector<unsigned char>(256, 0x55), // OP_PUSHDATA2
        CScript() << OP_RETURN << std::vector<unsigned char>(3, 0x66),
        CScript() << OP_CHECKSIGADD,
        CScript() << OP_5,             // lone number that's an op code: "+5"
        CScript() << 17,               // lone number: "+17"
        CScript() << 0x7F'FFFF'FFFF,   // largest decimal number: "+549755813887"
        CScript() << -0x7F'FFFF'FFFF,  // smallest decimal number: "-549755813887"
    };
    for (const auto& script : scripts) {
        const std::string asm_str = ScriptToAsmStr(script);
        const auto parsed = ParseAsmStr(asm_str);
        BOOST_CHECK_MESSAGE(parsed.has_value(), "ParseAsmStr failed for: " << asm_str);
        if (parsed) {
            BOOST_CHECK_MESSAGE(*parsed == script, "round trip mismatch for: " << asm_str << " -> " << HexStr(*parsed) << " != " << HexStr(script));
        }
    }

    // A push of a small number (1..16, OP_1..OP_16) is shown as the number,
    // with a '+' prefix when it is the only element of the script (so it
    // cannot be mistaken for the hex encoding of a script).
    for (const auto& [script, expected_asm] : std::vector<std::pair<CScript, std::string>>{
             {CScript() << OP_1, "+1"},
             {CScript() << OP_5, "+5"},
             {CScript() << OP_16, "+16"},
             {CScript() << OP_5 << OP_DROP, "5 OP_DROP"},
             {CScript() << OP_16 << OP_EQUAL, "16 OP_EQUAL"},
             {CScript() << OP_1 << OP_2 << OP_ADD, "1 2 OP_ADD"},
         }) {
        BOOST_CHECK_EQUAL(ScriptToAsmStr(script), expected_asm);
        const auto parsed = ParseAsmStr(expected_asm);
        BOOST_REQUIRE(parsed.has_value());
        BOOST_CHECK(*parsed == script);
    }

    // OP_0 and OP_1NEGATE are shown as their numbers too. A lone OP_0 gets a
    // '+' prefix like any other lone non-negative push; OP_1NEGATE is negative
    // and needs no prefix.
    for (const auto& [script, expected_asm] : std::vector<std::pair<CScript, std::string>>{
             {CScript() << OP_0, "+0"},
             {CScript() << OP_1NEGATE, "-1"},
             {CScript() << OP_0 << OP_EQUAL, "0 OP_EQUAL"},
             {CScript() << OP_1NEGATE << OP_ADD, "-1 OP_ADD"},
         }) {
        BOOST_CHECK_EQUAL(ScriptToAsmStr(script), expected_asm);
        const auto parsed = ParseAsmStr(expected_asm);
        BOOST_REQUIRE(parsed.has_value());
        BOOST_CHECK(*parsed == script);
    }

    // Larger numbers (17 and above) are data pushes, shown as the number with
    // a '+' prefix only when lone.
    for (const auto& [script, expected_asm] : std::vector<std::pair<CScript, std::string>>{
             {CScript() << 17, "+17"},
             {CScript() << 17 << OP_ADD, "17 OP_ADD"},
             {CScript() << 500000, "+500000"},
         }) {
        BOOST_CHECK_EQUAL(ScriptToAsmStr(script), expected_asm);
        const auto parsed = ParseAsmStr(expected_asm);
        BOOST_REQUIRE(parsed.has_value());
        BOOST_CHECK(*parsed == script);
    }

    BOOST_CHECK(ParseAsmStr("2DUP") == (CScript() << OP_2DUP));
    // "2SUB" is not an opcode, and is not treated as "2 SUB".
    BOOST_CHECK(!ParseAsmStr("2SUB").has_value());

    // Scripts that cannot be built with CScript::operator<<: a non-minimal
    // push of {07} (distinct from OP_7's "7"), a truncated push, and an
    // unassigned opcode.
    for (const auto& [hex, expected_asm] : std::vector<std::pair<std::string, std::string>>{
             {"0107", "<07>"},
             {"57", "+7"},
             {"4c", "#4c"},
             {"bb", "#bb"},
         }) {
        const auto bytes = ParseHex(hex);
        const CScript script(bytes.begin(), bytes.end());
        BOOST_CHECK_EQUAL(ScriptToAsmStr(script), expected_asm);
        const auto parsed = ParseAsmStr(expected_asm);
        BOOST_REQUIRE_MESSAGE(parsed.has_value(), "ParseAsmStr failed for: " << expected_asm);
        BOOST_CHECK_MESSAGE(*parsed == script, "round trip mismatch for: " << expected_asm);
    }

    // Nested pushes (parsing only; the renderer never nests).
    const CScript nested_inner = CScript() << OP_2 << std::vector<unsigned char>{0xaa, 0xbb} << OP_2 << OP_CHECKMULTISIG;
    const CScript nested_expected = CScript() << OP_0 << std::vector<unsigned char>(nested_inner.begin(), nested_inner.end());
    BOOST_CHECK(ParseAsmStr("0 <2 <aabb> 2 CHECKMULTISIG>") == nested_expected);

    // Whitespace in nested pushes is okay
    BOOST_CHECK(ParseAsmStr("< abcd   >") == ParseAsmStr("<abcd>"));

    // Nesting depth is capped: 99 levels parse, 100 are rejected.
    BOOST_CHECK(ParseAsmStr(std::string(99, '<') + "0" + std::string(99, '>')).has_value());
    BOOST_CHECK(!ParseAsmStr(std::string(100, '<') + "0" + std::string(100, '>')).has_value());
    BOOST_CHECK(ParseAsmStr(std::string(99, '<') + "aa" + std::string(99, '>')).has_value());
    BOOST_CHECK(!ParseAsmStr(std::string(100, '<') + "aa" + std::string(100, '>')).has_value());

    // Decimal range: magnitudes above 0x7F'FFFF'FFFF (2**39 - 1, the largest
    // 5-byte number, 549755813887) are rejected. Without the sign, an
    // even-length string of digits is parsed as raw hex instead.
    BOOST_CHECK(ParseAsmStr("+549755813887") == (CScript() << 0x7F'FFFF'FFFF));
    BOOST_CHECK(!ParseAsmStr("+549755813888").has_value());
    BOOST_CHECK(!ParseAsmStr("-549755813888").has_value());
    const auto digits_bytes = ParseHex("549755813887");
    BOOST_CHECK(ParseAsmStr("549755813887") == CScript(digits_bytes.begin(), digits_bytes.end()));

    // ParseAsmStr also accepts raw hex scripts directly.
    const std::string raw_hex = "76a914111111111111111111111111111111111111111188ac";
    const auto parsed_hex = ParseAsmStr(raw_hex);
    BOOST_REQUIRE(parsed_hex.has_value());
    BOOST_CHECK_EQUAL(HexStr(*parsed_hex), raw_hex);

    // Garbage input is rejected.
    BOOST_CHECK(!ParseAsmStr("not a script").has_value());
    BOOST_CHECK(!ParseAsmStr("<").has_value());
    BOOST_CHECK(!ParseAsmStr(">").has_value());
    BOOST_CHECK(!ParseAsmStr("1 <").has_value());
}
BOOST_AUTO_TEST_SUITE_END()
