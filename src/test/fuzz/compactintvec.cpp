// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/compactintvec.h>

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <cstdint>
#include <iostream>
#include <vector>

template <typename S, typename I>
S& operator<<(S& stream, const std::vector<I>& v)
{
    stream << "V[" << v.size() << "]=[";
    for (size_t i = 0; i < v.size(); ++i) {
        if (i != 0) stream << ", ";
        stream << v[i];
    }
    stream << "]";
    return stream;
}

namespace {

template<typename Formatter>
void TestRoundTrips(FuzzedDataProvider& fuzzed_data_provider)
{
    using Int = typename Formatter::int32;

    if (fuzzed_data_provider.ConsumeBool()) {
        // round-trip: values -> serialize -> deserialize -> compare
        std::vector<Int> vals;
        int nval = fuzzed_data_provider.ConsumeIntegralInRange<unsigned>(0, 1000);
        while (nval-- > 0) {
            vals.push_back(fuzzed_data_provider.ConsumeIntegral<Int>());
        }

        DataStream ds;
        ds << Using<Formatter>(vals);
        ds.Rewind();
        assert(ds.size() > 0);

        DataStream ds2{std::span(ds.data(), ds.size())};
        assert(ds.size() > 0);

        std::vector<Int> vals2;
        ds2 >> Using<Formatter>(vals2);
        if (ds2.size() != 0 || vals != vals2) {
            std::cout << "ds:  " << HexStr(std::span(ds.data(), ds.size())) << std::endl;
            std::cout << "ds2: " << HexStr(std::span(ds2.data(), ds2.size())) << std::endl;
            std::cout << "enc: " << vals << std::endl;
            std::cout << "dec: " << vals2 << std::endl;
        }
        assert(ds2.size() == 0);
        assert(vals == vals2);
    } else {
        // round-trip: deserialize -> serialize -> compare bytes

        auto ds = ConsumeDataStream(fuzzed_data_provider);
        if (ds.size() == 0) return; // uninteresting

        DataStream ds2{std::span(ds.data(), ds.size())};
        std::vector<Int> vals;
        try {
            ds >> Using<Formatter>(vals);
        } catch (const std::ios_base::failure&) {
            return;
        }
        DataStream ds3;
        ds3 << Using<Formatter>(vals);
        ds3.Rewind();

        assert(ds3.size() >= 1 && ds3[ds3.size() - 1] == std::byte{0});
        if (ds3.size() > ds2.size() || !std::equal(ds3.begin(), ds3.end(), ds2.begin())) {
            std::cout << "ds2:  " << HexStr(std::span(ds2.data(), ds2.size())) << std::endl;
            std::cout << "val: " << vals << std::endl;
            std::cout << "ds3: " << HexStr(std::span(ds3.data(), ds3.size())) << std::endl;
        }
        assert(ds3.size() <= ds2.size());
        assert(std::equal(ds3.begin(), ds3.end(), ds2.begin()));
    }
}

FUZZ_TARGET(compactintvec)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    if (fuzzed_data_provider.ConsumeBool()) {
        TestRoundTrips<util::CompactIntVecFormatter>(fuzzed_data_provider);
    } else {
        TestRoundTrips<util::CompactUIntVecFormatter>(fuzzed_data_provider);
    }
}

} // namespace
