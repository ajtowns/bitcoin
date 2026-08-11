// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <script/script.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>

FUZZ_TARGET(script_parseasm)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    std::string asmscript = fuzzed_data_provider.ConsumeRandomLengthString();

    std::optional<CScript> script = ParseAsmStr(asmscript);
    if (script.has_value()) {
        // Re-encoding and parsing must recover the same script.
        std::string decode = ScriptToAsmStr(*script);
        auto recover = ParseAsmStr(decode);
        assert(recover.has_value());
        assert(*recover == *script);
    }
}
