// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/twobitesc.h>

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <cstdint>
#include <vector>

namespace {
FUZZ_TARGET(twobitesc)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    if (fuzzed_data_provider.ConsumeBool()) {
        auto stream = ConsumeDataStream(fuzzed_data_provider);
        util::TwoBitEsc tbe{stream};
        DataStream ds;
        ds << tbe;
        util::TwoBitEsc tbe2{ds};
        assert(tbe.vals == tbe2.vals);
    } else {
    }
}
} // namespace
