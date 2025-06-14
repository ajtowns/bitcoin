// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>

#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/sign.h>
#include <serialize.h>
#include <streams.h>
#include <util/result.h>
#include <util/strencodings.h>

#include <algorithm>
#include <string>

using util::SplitString;

namespace {
class OpCodeParser
{
private:
    std::map<std::string, opcodetype, std::less<>> mapOpNames;

public:
    OpCodeParser()
    {
        for (unsigned int op = 0; op <= OP_CHECKSIGADD; ++op) {
            if (op < OP_1NEGATE) {
                continue;
            }

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
class AsmStrReader {
public:
    enum class Token {
        ASMSTR,
        WORDS,
        WORD,
        HEXWORD,
        NUMBER,
        OPCODE,
        PUSHDATA,
        WS,
    };

    static size_t count_chars(std::string_view s, const std::string_view::value_type* chars, std::size_t pos=0)
    {
        auto c = s.find_first_not_of(chars, pos);
        if (c == std::string_view::npos) c = s.size();
        return c - pos;
    }

    static bool pushdata(std::optional<opcodetype> pushop, CScript& script, std::span<unsigned char> vch)
    {
        if (!pushop.has_value()) {
            script << vch;
            return true;
        } else {
            if (*pushop == OP_PUSHDATA1 && vch.size() <= 0xff) {
                script.insert(script.end(), OP_PUSHDATA1);
                script.insert(script.end(), static_cast<unsigned char>(vch.size()));
            } else if (*pushop == OP_PUSHDATA2 && vch.size() <= 0xffff) {
                script.insert(script.end(), OP_PUSHDATA2);
                unsigned char data[2];
                WriteLE16(data, vch.size());
                script.insert(script.end(), std::cbegin(data), std::cend(data));
            } else if (*pushop == OP_PUSHDATA4 && vch.size() <= std::numeric_limits<uint32_t>::max()) {
                script.insert(script.end(), OP_PUSHDATA4);
                unsigned char data[4];
                WriteLE32(data, vch.size());
                script.insert(script.end(), std::cbegin(data), std::cend(data));
            } else {
                return false;
            }
            script.insert(script.end(), vch.begin(), vch.end());
            return true;
        }
    }

    static constexpr int MAX_DEPTH = 20;
    static bool ReadAsmStr(std::string_view& asmstr, CScript& script)
    {
        return ReadAsmStr(AsmStrReader::Token::ASMSTR, asmstr, script, 0);
    }

    static bool ReadAsmStr(Token tok, std::string_view& asmstr, CScript& script, int depth)
    {
        if (depth > MAX_DEPTH) return false;

        constexpr auto ws_chars = " \f\n\r\t\v";

        switch (tok) {
        case Token::ASMSTR: {
            asmstr = util::TrimStringView(asmstr);
            if (asmstr.size() == 0) return true; // IsHex would be false
            if (IsHex(asmstr)) {
                auto b = ParseHex(asmstr);
                script.insert(script.end(), b.begin(), b.end());
                return true;
            }
            if (!ReadAsmStr(Token::WORDS, asmstr, script, depth)) return false;
            if (asmstr.size() > 0) return false;
            return true;
        }

        /*** Remaining tokens do not update armstr or script if they return false ***/
        case Token::WORDS: {
            if (!ReadAsmStr(Token::WORD, asmstr, script, depth)) return false;
            while (true) {
                if (!ReadAsmStr(Token::WS, asmstr, script, depth)) break;
                if (!ReadAsmStr(Token::WORD, asmstr, script, depth)) break;
            }
            return true;
        }
        case Token::WORD: {
            if (ReadAsmStr(Token::HEXWORD, asmstr, script, depth)) return true;
            if (ReadAsmStr(Token::NUMBER, asmstr, script, depth)) return true;
            if (ReadAsmStr(Token::OPCODE, asmstr, script, depth)) return true;
            return ReadAsmStr(Token::PUSHDATA, asmstr, script, depth);
        }
        case Token::HEXWORD: {
            if (!asmstr.starts_with('#')) return false;
            auto hexlen = count_chars(asmstr, "0123456789abcdefABCDEF", 1);
            if (hexlen < 2) return false;
            asmstr.remove_prefix(1);
            if (hexlen % 2 != 0) --hexlen;
            auto b = ParseHex(asmstr.substr(0, hexlen));
            script.insert(script.end(), b.begin(), b.end());
            asmstr.remove_prefix(hexlen);
            return true;
        }
        case Token::NUMBER: {
            if (asmstr.size() == 0) return false;
            bool negate = (asmstr.front() == '-');
            size_t offset_sign = (asmstr.front() == '-' || asmstr.front() == '+') ? 1 : 0;
            auto numlen = count_chars(asmstr, "0123456789", offset_sign);
            if (numlen == 0 || numlen > 12) return false;
            auto n = ToIntegral<int64_t>(asmstr.substr(offset_sign, numlen));
            if (!n) return false;
            asmstr.remove_prefix(offset_sign + numlen);
            script << (negate ? -*n : *n);
            return true;
        }
        case Token::OPCODE: {
            if (asmstr.size() == 0) return false;
            auto oplen = count_chars(asmstr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789");
            if (oplen == 0) return false;
            auto opcode = ParseOpCodeNoThrow(asmstr.substr(0, oplen));
            if (!opcode) return false;
            asmstr.remove_prefix(oplen);
            script << *opcode;
            return true;
        }
        case Token::PUSHDATA: {
            if (asmstr.size() == 0) return false;
            std::optional<opcodetype> pushop = std::nullopt;
            std::string_view pushasm;
            if (asmstr.starts_with("PUSHDATA1<")) {
                pushop = OP_PUSHDATA1;
                pushasm = asmstr.substr(10);
            } else if (asmstr.starts_with("PUSHDATA2<")) {
                pushop = OP_PUSHDATA2;
                pushasm = asmstr.substr(10);
            } else if (asmstr.starts_with("PUSHDATA4<")) {
                pushop = OP_PUSHDATA4;
                pushasm = asmstr.substr(10);
            } else if (asmstr.starts_with("<")) {
                pushasm = asmstr.substr(1);
            } else {
                return false;
            }
            CScript pushscript;
            (void)ReadAsmStr(Token::WS, pushasm, pushscript, depth);

            auto hexlen = count_chars(pushasm, "0123456789abcdefABCDEF");
            if (hexlen % 2 == 0) {
                auto wslen = count_chars(pushasm, ws_chars, hexlen);
                if (pushasm.substr(hexlen + wslen).starts_with('>')) {
                    auto b = TryParseHex<unsigned char>(pushasm.substr(0, hexlen));
                    if (b) {
                        pushscript.insert(pushscript.end(), b->begin(), b->end());
                        if (!pushdata(pushop, script, pushscript)) return false;
                        pushasm.remove_prefix(hexlen + wslen + 1);
                        asmstr = pushasm;
                        return true;
                    }
                }
            }

            if (!ReadAsmStr(Token::WORDS, pushasm, pushscript, depth+1)) return false;
            (void)ReadAsmStr(Token::WS, pushasm, pushscript, depth);
            if (!pushasm.starts_with('>')) return false;
            if (!pushdata(pushop, script, pushscript)) return false;
            pushasm.remove_prefix(1);
            asmstr = pushasm;
            return true;
        }
        case Token::WS: {
            auto wslen = count_chars(asmstr, ws_chars);
            if (wslen == 0) return false;
            asmstr.remove_prefix(wslen);
            return true;
        }
        } // switch (tok)
        return false;
    }
};
}

std::optional<CScript> ParseAsmStr(std::string_view asmstr)
{
    CScript script;
    if (AsmStrReader::ReadAsmStr(asmstr, script)) {
        return script;
    } else {
        return std::nullopt;
    }
}

// Check that all of the input and output scripts of a transaction contains valid opcodes
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
        DataStream ssData(tx_data);
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
        DataStream ssData(tx_data);
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
    DataStream ser_header{header_data};
    try {
        ser_header >> header;
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
    DataStream ssBlock(blockData);
    try {
        ssBlock >> TX_WITH_WITNESS(block);
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
