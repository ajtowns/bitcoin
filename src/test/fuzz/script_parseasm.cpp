// Copyright (c) 2019-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/consensus.h>
#include <core_io.h>
#include <policy/policy.h>
#include <script/script.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <univalue.h>
#include <util/chaintype.h>

void initialize_script_parseasm()
{
    SelectParams(ChainType::REGTEST);
}

FUZZ_TARGET(script_parseasm, .init = initialize_script_parseasm)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    std::string asmscript = fuzzed_data_provider.ConsumeRandomLengthString();

    std::optional<CScript> script = ParseAsmStr(asmscript);
    if (script.has_value()) {
        std::string decode = ScriptToAsmStr(*script);
        // decode == asmscript is possible, but not necessary
        auto recover = ParseAsmStr(decode);
        assert(recover.has_value());
        assert(*recover == *script);
    }
}
