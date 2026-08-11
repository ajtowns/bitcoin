// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>

#include <addresstype.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <crypto/common.h>
#include <crypto/hex_base.h>
#include <key_io.h>
#include <prevector.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/descriptor.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <serialize.h>
#include <streams.h>
#include <tinyformat.h>
#include <uint256.h>
#include <undo.h>
#include <univalue.h>
#include <util/check.h>
#include <util/result.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/translation.h>

#include <algorithm>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using util::SplitString;

namespace {
class OpCodeParser
{
private:
    std::map<std::string, opcodetype, std::less<>> mapOpNames;

public:
    OpCodeParser()
    {
        // Add names for the opcodes whose GetOpName() name differs from the
        // name used when writing scripts.
        // * OP_1NEGATE is skipped by the loop below (it is below OP_RESERVED,
        //   in the data-push range), and GetOpName() calls it "-1" anyway.
        // * OP_TRUE/OP_FALSE are aliases for OP_1/OP_0, which GetOpName()
        //   reports as "1"/"0".
        // * OP_NOP2/OP_NOP3 are CHECKLOCKTIMEVERIFY/CHECKSEQUENCEVERIFY.
        mapOpNames["OP_1NEGATE"] = mapOpNames["1NEGATE"] = OP_1NEGATE;
        mapOpNames["OP_TRUE"] = mapOpNames["TRUE"] = OP_TRUE;
        mapOpNames["OP_FALSE"] = mapOpNames["FALSE"] = OP_FALSE;
        mapOpNames["OP_NOP2"] = mapOpNames["NOP2"] = OP_NOP2; // CHECKLOCKTIMEVERIFY
        mapOpNames["OP_NOP3"] = mapOpNames["NOP3"] = OP_NOP3; // CHECKSEQUENCEVERIFY

        // Every named opcode from OP_RESERVED (0x50) up to MAX_DECODE_OPCODE
        // gets its GetOpName() name plus an unprefixed alias. The opcodes
        // below OP_RESERVED are the data-push range -- direct pushes
        // (0x01..0x4b), OP_PUSHDATA1/2/4 (0x4c..0x4e) and OP_1NEGATE (0x4f)
        // -- which either have no opcode name or are covered above, so skip
        // them.
        for (unsigned int op = 0; op <= MAX_DECODE_OPCODE; ++op) {
            if (0 < op && op < OP_RESERVED) continue;

            std::string strName = GetOpName(static_cast<opcodetype>(op));
            if (strName == "OP_UNKNOWN") {
                continue;
            }
            mapOpNames[strName] = static_cast<opcodetype>(op);
            // Convenience: OP_ADD and just ADD are both recognized:
            if (strName.starts_with("OP_")) {
                mapOpNames[strName.substr(3)] = static_cast<opcodetype>(op);
            } else {
                mapOpNames[strprintf("OP_%s", strName)] = static_cast<opcodetype>(op);
            }
        }
    }
    std::optional<opcodetype> Parse(std::string_view s) const
    {
        auto it = mapOpNames.find(s);
        if (it == mapOpNames.end()) return std::nullopt;
        return it->second;
    }
};

std::optional<opcodetype> ParseOpCodeNoThrow(const std::string_view s)
{
    static const OpCodeParser ocp;
    return ocp.Parse(s);
}

opcodetype ParseOpCode(const std::string_view s)
{
    auto opcode = ParseOpCodeNoThrow(s);
    if (!opcode) throw std::runtime_error("script parse error: unknown opcode");
    return *opcode;
}

} // namespace

CScript ParseScript(const std::string& s)
{
    CScript result;

    std::vector<std::string> words = SplitString(s, " \t\n");

    for (const std::string& w : words) {
        if (w.empty()) {
            // Empty string, ignore. (SplitString doesn't combine multiple separators)
        } else if (std::all_of(w.begin(), w.end(), ::IsDigit) ||
                   (w.front() == '-' && w.size() > 1 && std::all_of(w.begin() + 1, w.end(), ::IsDigit)))
        {
            // Number
            const auto num{ToIntegral<int64_t>(w)};

            // limit the range of numbers ParseScript accepts in decimal
            // since numbers outside -0xFFFFFFFF...0xFFFFFFFF are illegal in scripts
            if (!num.has_value() || num > int64_t{0xffffffff} || num < -1 * int64_t{0xffffffff}) {
                throw std::runtime_error("script parse error: decimal numeric value only allowed in the "
                                         "range -0xFFFFFFFF...0xFFFFFFFF");
            }

            result << num.value();
        } else if (w.starts_with("0x") && w.size() > 2 && IsHex(std::string(w.begin() + 2, w.end()))) {
            // Raw hex data, inserted NOT pushed onto stack:
            std::vector<unsigned char> raw = ParseHex(std::string(w.begin() + 2, w.end()));
            result.insert(result.end(), raw.begin(), raw.end());
        } else if (w.size() >= 2 && w.front() == '\'' && w.back() == '\'') {
            // Single-quoted string, pushed as data. NOTE: this is poor-man's
            // parsing, spaces/tabs/newlines in single-quoted strings won't work.
            std::vector<unsigned char> value(w.begin() + 1, w.end() - 1);
            result << value;
        } else {
            // opcode, e.g. OP_ADD or ADD:
            result << ParseOpCode(w);
        }
    }

    return result;
}

namespace {
/** Maximum nesting depth of <..> pushes. */
constexpr size_t MAX_ASM_NEST_DEPTH{100};
/** The whitespace characters that separate units in an asm string. */
constexpr std::string_view WS_CHARS = " \f\n\r\t\v";
/** The hex digit characters. */
constexpr std::string_view HEX_CHARS = "0123456789abcdefABCDEF";
/** The characters that may appear in an opcode name. */
constexpr std::string_view OPCODE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789";
/** The maximum absolute value specifiable as a decimal */
constexpr int64_t MAX_DECIMAL_VALUE{0x7F'FFFF'FFFF};
/** The number of decimal digits that value has */
constexpr size_t MAX_DECIMAL_DIGITS = 12;

/**
 * Append a push of data to a script.
 *
 * If pushop is OP_0, use the smallest push opcode for the data (either a
 * direct push, or OP_PUSHDATA1/2/4 as the size requires). Otherwise use the
 * specified OP_PUSHDATA1/2/4 opcode, failing if the data is too large for it.
 */
bool AppendPush(opcodetype pushop, std::span<const uint8_t> data, CScript& script)
{
    if (pushop == OP_0) {
        script << data;
        return true;
    }

    if (pushop == OP_PUSHDATA1 && data.size() <= 0xff) {
        script.insert(script.end(), OP_PUSHDATA1);
        script.insert(script.end(), static_cast<unsigned char>(data.size()));
    } else if (pushop == OP_PUSHDATA2 && data.size() <= 0xffff) {
        script.insert(script.end(), OP_PUSHDATA2);
        unsigned char len[2];
        WriteLE16(len, data.size());
        script.insert(script.end(), std::begin(len), std::end(len));
    } else if (pushop == OP_PUSHDATA4 && data.size() <= 0xffffffff) {
        script.insert(script.end(), OP_PUSHDATA4);
        unsigned char len[4];
        WriteLE32(len, data.size());
        script.insert(script.end(), std::begin(len), std::end(len));
    } else {
        return false;
    }
    script.insert(script.end(), data.begin(), data.end());
    return true;
}
} // namespace

std::optional<CScript> ParseAsmStr(std::string_view asmstr)
{
    // A script that is entirely an even-length hex string is decoded as
    // raw bytes, matching the encoding's disambiguation rule for scripts
    // that consist of a single number.
    asmstr = util::TrimStringView(asmstr);
    if (asmstr.empty()) {
        return CScript{};
    }
    if (IsHex(asmstr)) {
        auto bytes = TryParseHex<unsigned char>(asmstr);
        if (!bytes) return std::nullopt;
        return CScript{bytes->begin(), bytes->end()};
    }

    // Otherwise the string is parsed as whitespace-separated units:
    // opcode names (with or without the OP_ prefix), decimal numbers,
    // <...> / PUSHDATA1<...> pushes of recursively decoded content, and
    // #hex raw data. Pushes may be nested arbitrarily, so an explicit
    // stack of scripts being built is kept rather than recursing.
    struct SubScript
    {
        // How this subscript's content is pushed into its parent. OP_0 is the
        // sentinel for "use the smallest push opcode"; otherwise this is the
        // OP_PUSHDATA1/2/4 opcode to push with. The root script never uses it.
        opcodetype pushop{OP_FALSE};
        CScript script{};
    };
    std::vector<SubScript> scripts{SubScript{}};

    auto check_subscript = [&]() -> std::optional<opcodetype> {
        // Open a push. Determine the push opcode (if any) and skip
        // to the content.
        if (asmstr.starts_with("<")) {
            asmstr.remove_prefix(1);
            return OP_0;
        } else if (asmstr.starts_with("PUSHDATA1<")) {
            asmstr.remove_prefix(10);
            return OP_PUSHDATA1;
        } else if (asmstr.starts_with("PUSHDATA2<")) {
            asmstr.remove_prefix(10);
            return OP_PUSHDATA2;
        } else if (asmstr.starts_with("PUSHDATA4<")) {
            asmstr.remove_prefix(10);
            return OP_PUSHDATA4;
        } else {
            return std::nullopt;
        }
    };

    while (true) {
        asmstr = util::TrimStringView(asmstr);
        if (asmstr.empty()) {
            if (scripts.size() == 1) return scripts.back().script;
            return std::nullopt; // unterminated push
        }

        if (asmstr.front() == '>') {
            // Close the innermost push.
            if (scripts.size() == 1) return std::nullopt;
            SubScript inner = std::move(scripts.back());
            scripts.pop_back();
            if (!AppendPush(inner.pushop, inner.script, scripts.back().script)) return std::nullopt;
            asmstr.remove_prefix(1);
            continue;
        }

        if (auto pushop = check_subscript(); pushop.has_value()) {
            if (scripts.size() >= MAX_ASM_NEST_DEPTH) return std::nullopt;

            if (size_t ws = asmstr.find_first_not_of(WS_CHARS); ws != std::string_view::npos) {
                asmstr.remove_prefix(ws);
            }
            std::string_view content = asmstr;
            size_t hexlen = content.find_first_not_of(HEX_CHARS);
            if (hexlen == std::string_view::npos) hexlen = content.size();
            if (hexlen % 2 == 0) {
                size_t wslen = content.substr(hexlen).find_first_not_of(WS_CHARS);
                if (wslen == std::string_view::npos) return std::nullopt; // no closing >
                size_t end = hexlen + wslen;
                if (end < content.size() && content[end] == '>') {
                    auto bytes = TryParseHex<unsigned char>(content.substr(0, hexlen));
                    if (!bytes) return std::nullopt;
                    if (!AppendPush(*pushop, *bytes, scripts.back().script)) return std::nullopt;
                    asmstr.remove_prefix(end + 1);
                    continue;
                }
            }

            scripts.emplace_back(*pushop);
            continue;
        }

        if (asmstr.front() == '#') {
            // Raw hex data, inserted into the script as-is.
            asmstr.remove_prefix(1);
            size_t hexlen = asmstr.find_first_not_of(HEX_CHARS);
            if (hexlen == std::string_view::npos) hexlen = asmstr.size();
            if (hexlen < 2 || hexlen % 2 != 0) return std::nullopt;
            auto bytes = TryParseHex<unsigned char>(asmstr.substr(0, hexlen));
            if (!bytes) return std::nullopt;
            scripts.back().script.insert(scripts.back().script.end(), bytes->begin(), bytes->end());
            asmstr.remove_prefix(hexlen);
            continue;
        }

        // An opcode name. Names are scanned before numbers so that digit-led
        // names (eg "2DUP") parse as a single opcode rather than as the
        // number "2" followed by "DUP".
        {
            size_t oplen = asmstr.find_first_not_of(OPCODE_CHARS);
            if (oplen == std::string_view::npos) oplen = asmstr.size();
            if (oplen > 0) {
                auto opcode = ParseOpCodeNoThrow(asmstr.substr(0, oplen));
                if (opcode) {
                    scripts.back().script << *opcode;
                    asmstr.remove_prefix(oplen);
                    continue;
                }
            }
        }

        // A decimal number, optionally preceded by a sign. Numbers are
        // pushed using their minimal encoding (OP_1NEGATE, OP_0..OP_16,
        // or a direct push).
        {
            bool negate = false;
            size_t sign_len = 0;
            if (asmstr.front() == '-' || asmstr.front() == '+') {
                negate = (asmstr.front() == '-');
                sign_len = 1;
            }
            size_t numlen = asmstr.substr(sign_len).find_first_not_of("0123456789");
            if (numlen == std::string_view::npos) numlen = asmstr.size() - sign_len;
            const size_t unit_end = sign_len + numlen;
            if (unit_end < asmstr.size() && OPCODE_CHARS.find(asmstr[unit_end]) != std::string_view::npos) {
                // Reject a digit run continuing into an opcode name (eg "2ADD"),
                // rather than parsing it as two units.
                return std::nullopt;
            }
            if (numlen > 0 && numlen <= MAX_DECIMAL_DIGITS) {
                const auto num = ToIntegral<int64_t>(asmstr.substr(sign_len, numlen));
                if (!Assume(num)) return std::nullopt;
                if (*num > MAX_DECIMAL_VALUE) return std::nullopt;
                scripts.back().script << (negate ? -*num : *num);
                asmstr.remove_prefix(sign_len + numlen);
                continue;
            }
        }

        return std::nullopt;
    }
}

/// Check that all of the input and output scripts of a transaction contain valid opcodes
static bool CheckTxScriptsSanity(const CMutableTransaction& tx)
{
    // Check input scripts for non-coinbase txs
    if (!CTransaction(tx).IsCoinBase()) {
        for (unsigned int i = 0; i < tx.vin.size(); i++) {
            if (!tx.vin[i].scriptSig.HasValidOps() || tx.vin[i].scriptSig.size() > MAX_SCRIPT_SIZE) {
                return false;
            }
        }
    }
    // Check output scripts
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        if (!tx.vout[i].scriptPubKey.HasValidOps() || tx.vout[i].scriptPubKey.size() > MAX_SCRIPT_SIZE) {
            return false;
        }
    }

    return true;
}

static bool DecodeTx(CMutableTransaction& tx, const std::vector<unsigned char>& tx_data, bool try_no_witness, bool try_witness)
{
    // General strategy:
    // - Decode both with extended serialization (which interprets the 0x0001 tag as a marker for
    //   the presence of witnesses) and with legacy serialization (which interprets the tag as a
    //   0-input 1-output incomplete transaction).
    //   - Restricted by try_no_witness (which disables legacy if false) and try_witness (which
    //     disables extended if false).
    //   - Ignore serializations that do not fully consume the hex string.
    // - If neither succeeds, fail.
    // - If only one succeeds, return that one.
    // - If both decode attempts succeed:
    //   - If only one passes the CheckTxScriptsSanity check, return that one.
    //   - If neither or both pass CheckTxScriptsSanity, return the extended one.

    CMutableTransaction tx_extended, tx_legacy;
    bool ok_extended = false, ok_legacy = false;

    // Try decoding with extended serialization support, and remember if the result successfully
    // consumes the entire input.
    if (try_witness) {
        SpanReader ssData{tx_data};
        try {
            ssData >> TX_WITH_WITNESS(tx_extended);
            if (ssData.empty()) ok_extended = true;
        } catch (const std::exception&) {
            // Fall through.
        }
    }

    // Optimization: if extended decoding succeeded and the result passes CheckTxScriptsSanity,
    // don't bother decoding the other way.
    if (ok_extended && CheckTxScriptsSanity(tx_extended)) {
        tx = std::move(tx_extended);
        return true;
    }

    // Try decoding with legacy serialization, and remember if the result successfully consumes the entire input.
    if (try_no_witness) {
        SpanReader ssData{tx_data};
        try {
            ssData >> TX_NO_WITNESS(tx_legacy);
            if (ssData.empty()) ok_legacy = true;
        } catch (const std::exception&) {
            // Fall through.
        }
    }

    // If legacy decoding succeeded and passes CheckTxScriptsSanity, that's our answer, as we know
    // at this point that extended decoding either failed or doesn't pass the sanity check.
    if (ok_legacy && CheckTxScriptsSanity(tx_legacy)) {
        tx = std::move(tx_legacy);
        return true;
    }

    // If extended decoding succeeded, and neither decoding passes sanity, return the extended one.
    if (ok_extended) {
        tx = std::move(tx_extended);
        return true;
    }

    // If legacy decoding succeeded and extended didn't, return the legacy one.
    if (ok_legacy) {
        tx = std::move(tx_legacy);
        return true;
    }

    // If none succeeded, we failed.
    return false;
}

bool DecodeHexTx(CMutableTransaction& tx, const std::string& hex_tx, bool try_no_witness, bool try_witness)
{
    if (!IsHex(hex_tx)) {
        return false;
    }

    std::vector<unsigned char> txData(ParseHex(hex_tx));
    return DecodeTx(tx, txData, try_no_witness, try_witness);
}

bool DecodeHexBlockHeader(CBlockHeader& header, const std::string& hex_header)
{
    if (!IsHex(hex_header)) return false;

    const std::vector<unsigned char> header_data{ParseHex(hex_header)};
    try {
        SpanReader{header_data} >> header;
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

bool DecodeHexBlk(CBlock& block, const std::string& strHexBlk)
{
    if (!IsHex(strHexBlk))
        return false;

    std::vector<unsigned char> blockData(ParseHex(strHexBlk));
    try {
        SpanReader{blockData} >> TX_WITH_WITNESS(block);
    }
    catch (const std::exception&) {
        return false;
    }

    return true;
}

util::Result<int> SighashFromStr(const std::string& sighash)
{
    static const std::map<std::string, int> map_sighash_values = {
        {std::string("DEFAULT"), int(SIGHASH_DEFAULT)},
        {std::string("ALL"), int(SIGHASH_ALL)},
        {std::string("ALL|ANYONECANPAY"), int(SIGHASH_ALL|SIGHASH_ANYONECANPAY)},
        {std::string("NONE"), int(SIGHASH_NONE)},
        {std::string("NONE|ANYONECANPAY"), int(SIGHASH_NONE|SIGHASH_ANYONECANPAY)},
        {std::string("SINGLE"), int(SIGHASH_SINGLE)},
        {std::string("SINGLE|ANYONECANPAY"), int(SIGHASH_SINGLE|SIGHASH_ANYONECANPAY)},
    };
    const auto& it = map_sighash_values.find(sighash);
    if (it != map_sighash_values.end()) {
        return it->second;
    } else {
        return util::Error{Untranslated("'" + sighash + "' is not a valid sighash parameter.")};
    }
}

UniValue ValueFromAmount(const CAmount amount)
{
    static_assert(COIN > 1);
    int64_t quotient = amount / COIN;
    int64_t remainder = amount % COIN;
    if (amount < 0) {
        quotient = -quotient;
        remainder = -remainder;
    }
    return UniValue(UniValue::VNUM,
            strprintf("%s%d.%08d", amount < 0 ? "-" : "", quotient, remainder));
}

std::string FormatScript(const CScript& script)
{
    std::string ret;
    CScript::const_iterator it = script.begin();
    opcodetype op;
    while (it != script.end()) {
        CScript::const_iterator it2 = it;
        std::vector<unsigned char> vch;
        if (script.GetOp(it, op, vch)) {
            if (op == OP_0) {
                ret += "0 ";
                continue;
            } else if ((op >= OP_1 && op <= OP_16) || op == OP_1NEGATE) {
                ret += strprintf("%i ", op - OP_1NEGATE - 1);
                continue;
            } else if (op >= OP_NOP && op <= OP_NOP10) {
                std::string str(GetOpName(op));
                if (str.substr(0, 3) == std::string("OP_")) {
                    ret += str.substr(3, std::string::npos) + " ";
                    continue;
                }
            }
            if (vch.size() > 0) {
                ret += strprintf("0x%x 0x%x ", HexStr(std::vector<uint8_t>(it2, it - vch.size())),
                                               HexStr(std::vector<uint8_t>(it - vch.size(), it)));
            } else {
                ret += strprintf("0x%x ", HexStr(std::vector<uint8_t>(it2, it)));
            }
            continue;
        }
        ret += strprintf("0x%x ", HexStr(std::vector<uint8_t>(it2, script.end())));
        break;
    }
    return ret.substr(0, ret.empty() ? ret.npos : ret.size() - 1);
}

const std::map<unsigned char, std::string> mapSigHashTypes = {
    {static_cast<unsigned char>(SIGHASH_ALL), std::string("ALL")},
    {static_cast<unsigned char>(SIGHASH_ALL|SIGHASH_ANYONECANPAY), std::string("ALL|ANYONECANPAY")},
    {static_cast<unsigned char>(SIGHASH_NONE), std::string("NONE")},
    {static_cast<unsigned char>(SIGHASH_NONE|SIGHASH_ANYONECANPAY), std::string("NONE|ANYONECANPAY")},
    {static_cast<unsigned char>(SIGHASH_SINGLE), std::string("SINGLE")},
    {static_cast<unsigned char>(SIGHASH_SINGLE|SIGHASH_ANYONECANPAY), std::string("SINGLE|ANYONECANPAY")},
};

std::string SighashToStr(unsigned char sighash_type)
{
    const auto& it = mapSigHashTypes.find(sighash_type);
    if (it == mapSigHashTypes.end()) return "";
    return it->second;
}

/**
 * Create the assembly string representation of a CScript object.
 * @param[in] script    CScript object to convert into the asm string representation.
 */
std::string ScriptToAsmStr(const CScript& script)
{
    std::string str;
    opcodetype opcode;
    std::vector<unsigned char> vch;
    CScript::const_iterator pc = script.begin();

    while (pc < script.end()) {
        if (!str.empty()) {
            str += " ";
        }
        CScript::const_iterator pc_orig = pc;
        if (!script.GetOp(pc, opcode, vch)) {
            str += strprintf("#%s", HexStr(std::vector<uint8_t>(pc_orig, script.end())));
            return str;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            bool minpush = CheckMinimalPush(vch, opcode);
            if (minpush && vch.size() <= 5 && CScriptNum::CheckMinimalNumber(vch)) {
                auto n = CScriptNum(vch, /*fRequireMinimal=*/false, /*nMaxNumSize=*/5).GetInt64();
                if (n >= 0 && str.empty() && pc == script.end()) {
                    // disambiguate a script that is just a small number, versus the hex encoding of a script
                    str += strprintf("+%d", n);
                } else {
                    str += strprintf("%d", n);
                }
            } else if (minpush || opcode < OP_PUSHDATA1) {
                str += strprintf("<%s>", HexStr(vch));
            } else {
                str += strprintf("PUSHDATA%d<%s>", (1 << (opcode - OP_PUSHDATA1)), HexStr(vch));
            }
        } else if (opcode <= MAX_DECODE_OPCODE) {
            if (OP_1 <= opcode && opcode <= OP_16) {
                // Small number pushes are shown as numbers. A lone push gets
                // a '+' prefix so it cannot be mistaken for the hex encoding
                // of a script.
                if (str.empty() && pc == script.end()) str += "+";
                str += strprintf("%d", opcode - OP_1 + 1);
            } else {
                str += GetOpName(opcode);
            }
        } else {
            str += strprintf("#%02x%s", opcode, HexStr(vch));
        }
    }
    return str;
}

std::string EncodeHexTx(const CTransaction& tx)
{
    DataStream ssTx;
    ssTx << TX_WITH_WITNESS(tx);
    return HexStr(ssTx);
}

void ScriptToUniv(const CScript& script, UniValue& out, bool include_hex, bool include_address, const SigningProvider* provider)
{
    CTxDestination address;

    out.pushKV("asm", ScriptToAsmStr(script));
    if (include_address) {
        out.pushKV("desc", InferDescriptor(script, provider ? *provider : DUMMY_SIGNING_PROVIDER)->ToString());
    }
    if (include_hex) {
        out.pushKV("hex", HexStr(script));
    }

    std::vector<std::vector<unsigned char>> solns;
    const TxoutType type{Solver(script, solns)};

    if (include_address && ExtractDestination(script, address) && type != TxoutType::PUBKEY) {
        out.pushKV("address", EncodeDestination(address));
    }
    out.pushKV("type", GetTxnOutputType(type));
}

void TxToUniv(const CTransaction& tx, const uint256& block_hash, UniValue& entry, bool include_hex, const CTxUndo* txundo, TxVerbosity verbosity, std::function<bool(const CTxOut&)> is_change_func)
{
    CHECK_NONFATAL(verbosity >= TxVerbosity::SHOW_DETAILS);

    entry.pushKV("txid", tx.GetHash().GetHex());
    entry.pushKV("hash", tx.GetWitnessHash().GetHex());
    entry.pushKV("version", tx.version);
    entry.pushKV("size", tx.ComputeTotalSize());
    entry.pushKV("vsize", (GetTransactionWeight(tx) + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR);
    entry.pushKV("weight", GetTransactionWeight(tx));
    entry.pushKV("locktime", tx.nLockTime);

    UniValue vin{UniValue::VARR};
    vin.reserve(tx.vin.size());

    // If available, use Undo data to calculate the fee. Note that txundo == nullptr
    // for coinbase transactions and for transactions where undo data is unavailable.
    const bool have_undo = txundo != nullptr;
    CAmount amt_total_in = 0;
    CAmount amt_total_out = 0;

    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const CTxIn& txin = tx.vin[i];
        UniValue in(UniValue::VOBJ);
        if (tx.IsCoinBase()) {
            in.pushKV("coinbase", HexStr(txin.scriptSig));
        } else {
            in.pushKV("txid", txin.prevout.hash.GetHex());
            in.pushKV("vout", txin.prevout.n);
            UniValue o(UniValue::VOBJ);
            o.pushKV("asm", ScriptToAsmStr(txin.scriptSig));
            o.pushKV("hex", HexStr(txin.scriptSig));
            in.pushKV("scriptSig", std::move(o));
        }
        if (!tx.vin[i].scriptWitness.IsNull()) {
            UniValue txinwitness(UniValue::VARR);
            txinwitness.reserve(tx.vin[i].scriptWitness.stack.size());
            for (const auto& item : tx.vin[i].scriptWitness.stack) {
                txinwitness.push_back(HexStr(item));
            }
            in.pushKV("txinwitness", std::move(txinwitness));
        }
        if (have_undo) {
            const Coin& prev_coin = txundo->vprevout[i];
            const CTxOut& prev_txout = prev_coin.out;

            amt_total_in += prev_txout.nValue;

            if (verbosity == TxVerbosity::SHOW_DETAILS_AND_PREVOUT) {
                UniValue o_script_pub_key(UniValue::VOBJ);
                ScriptToUniv(prev_txout.scriptPubKey, /*out=*/o_script_pub_key, /*include_hex=*/true, /*include_address=*/true);

                UniValue p(UniValue::VOBJ);
                p.pushKV("generated", prev_coin.IsCoinBase());
                p.pushKV("height", prev_coin.nHeight);
                p.pushKV("value", ValueFromAmount(prev_txout.nValue));
                p.pushKV("scriptPubKey", std::move(o_script_pub_key));
                in.pushKV("prevout", std::move(p));
            }
        }
        in.pushKV("sequence", txin.nSequence);
        vin.push_back(std::move(in));
    }
    entry.pushKV("vin", std::move(vin));

    UniValue vout(UniValue::VARR);
    vout.reserve(tx.vout.size());
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& txout = tx.vout[i];

        UniValue out(UniValue::VOBJ);

        out.pushKV("value", ValueFromAmount(txout.nValue));
        out.pushKV("n", i);

        UniValue o(UniValue::VOBJ);
        ScriptToUniv(txout.scriptPubKey, /*out=*/o, /*include_hex=*/true, /*include_address=*/true);
        out.pushKV("scriptPubKey", std::move(o));

        if (is_change_func && is_change_func(txout)) {
            out.pushKV("ischange", true);
        }

        vout.push_back(std::move(out));

        if (have_undo) {
            amt_total_out += txout.nValue;
        }
    }
    entry.pushKV("vout", std::move(vout));

    if (have_undo) {
        const CAmount fee = amt_total_in - amt_total_out;
        CHECK_NONFATAL(MoneyRange(fee));
        entry.pushKV("fee", ValueFromAmount(fee));
    }

    if (!block_hash.IsNull()) {
        entry.pushKV("blockhash", block_hash.GetHex());
    }

    if (include_hex) {
        entry.pushKV("hex", EncodeHexTx(tx)); // The hex-encoded transaction. Used the name "hex" to be consistent with the verbose output of "getrawtransaction".
    }
}
