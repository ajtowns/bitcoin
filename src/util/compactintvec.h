// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_COMPACTINTVEC_H
#define BITCOIN_UTIL_COMPACTINTVEC_H

#include <serialize.h>
#include <streams.h>

#include <cstdint>
#include <vector>

namespace util {

template<bool Signed = true>
struct CompactUSIntVecFormatter {
    using int32 = std::conditional_t<Signed, int32_t, uint32_t>;
    static constexpr int64_t MAX_T = (Signed ? 0x6eeeeeee : 0xeeeeeeee);

    template <typename Stream>
    void Ser(Stream& s, const std::vector<int32>& vals) const
    {
        auto bs = BitStreamWriter(s);
        for (auto v : vals) {
            bool pos = (v >= 0);
            if constexpr (Signed) {
                if (!pos) v = -(v + 1);
            }
            int i = 0;
            for (int64_t m = 1; v >= m; m *= 16) {
                v -= m;
                ++i;
            }
            bs.Write(0, i);
            bs.Write(1, 1);
            if constexpr (Signed) bs.Write(pos, 1);
            bs.Write(v, i * 4);
        }
        bs.Write(0, 9);
        bs.Flush();
    }

    template <typename Stream>
    void Unser(Stream& s, std::vector<int32>& vals) const
    {
        auto bs = BitStreamReader(s);
        vals.clear();
        while (true) {
            int i = 0;
            int64_t m = 1;
            int64_t v = 0;
            while (i < 9 && bs.Read(1) == 0) {
                v += m;
                ++i;
                m *= 16;
            }
            if (i >= 9) break;
            bool pos = true;
            if constexpr (Signed) pos = bs.Read(1);
            uint64_t t = bs.Read(i * 4);
            if (t > MAX_T) throw std::ios_base::failure("CompactUSIntVecFormatter::Unser(): value out of range");
            v += t;
            if constexpr (Signed) {
                vals.push_back(pos ? v : -v - 1);
            } else {
                vals.push_back(v);
            }
        }
        if (!bs.Flush()) throw std::ios_base::failure("CompactUSIntVecFormatter::Unser(): garbage in padding");
    }
};

using CompactIntVecFormatter = CompactUSIntVecFormatter<true>;
using CompactUIntVecFormatter = CompactUSIntVecFormatter<false>;

} // namespace util

#endif // BITCOIN_UTIL_COMPACTINTVEC_H
