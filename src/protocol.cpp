// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <protocol.h>

#include <common/system.h>

namespace BIP324 {
static constexpr bool GetMsgById(MsgByShortId& r, std::span<const std::pair<uint8_t, std::string>> inp)
{
    uint8_t sentinal{ALL_NET_MESSAGE_TYPES.size()};
    r.fill(sentinal); // invalid value, in case some entries are blank
    bool duplicates = false;
    for (auto&& [id, msg_type] : inp) {
        if (id <= 0 || id > r.size()) return false;
        bool found = false;
        for (size_t i = 0; i < ALL_NET_MESSAGE_TYPES.size(); ++i) {
            if (ALL_NET_MESSAGE_TYPES[i] == msg_type) {
                if (r[id-1] != sentinal) duplicates = true;
                r[id-1] = i;
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return !duplicates;
}

static consteval auto LiteralGetMsgById(std::initializer_list<std::pair<uint8_t, std::string>> inp)
{
    MsgByShortId r;
    if (!GetMsgById(r, inp)) throw "Bad inputs (unknown msg, duplicates or entry with id == 0)";
    return r;
}

MsgByShortId GetMsgById(std::span<const std::pair<uint8_t, std::string>> inp)
{
    MsgByShortId r;
    (void)GetMsgById(r, inp);
    return r;
}

/** List of short messages as defined in BIP324, in order.
 *
 * Only message types that are actually implemented in this codebase need to be listed, as other
 * messages get ignored anyway - whether we know how to decode them or not.
 */
const MsgByShortId DEFAULT_MSG_BY_ID = LiteralGetMsgById({
    {1, NetMsgType::ADDR},
    {2, NetMsgType::BLOCK},
    {3, NetMsgType::BLOCKTXN},
    {4, NetMsgType::CMPCTBLOCK},
    {5, NetMsgType::FEEFILTER},
    {6, NetMsgType::FILTERADD},
    {7, NetMsgType::FILTERCLEAR},
    {8, NetMsgType::FILTERLOAD},
    {9, NetMsgType::GETBLOCKS},
    {10, NetMsgType::GETBLOCKTXN},
    {11, NetMsgType::GETDATA},
    {12, NetMsgType::GETHEADERS},
    {13, NetMsgType::HEADERS},
    {14, NetMsgType::INV},
    {15, NetMsgType::MEMPOOL},
    {16, NetMsgType::MERKLEBLOCK},
    {17, NetMsgType::NOTFOUND},
    {18, NetMsgType::PING},
    {19, NetMsgType::PONG},
    {20, NetMsgType::SENDCMPCT},
    {21, NetMsgType::TX},
    {22, NetMsgType::GETCFILTERS},
    {23, NetMsgType::CFILTER},
    {24, NetMsgType::GETCFHEADERS},
    {25, NetMsgType::CFHEADERS},
    {26, NetMsgType::GETCFCHECKPT},
    {27, NetMsgType::CFCHECKPT},
    {28, NetMsgType::ADDRV2},
});

const MsgByShortId CRAZY_MSG_BY_ID = LiteralGetMsgById({
    {100, NetMsgType::VERSION},
    {101, NetMsgType::VERACK},
    {102, NetMsgType::ADDR},
    {103, NetMsgType::ADDRV2},
    {104, NetMsgType::SENDADDRV2},
    {105, NetMsgType::INV},
    {106, NetMsgType::GETDATA},
    {107, NetMsgType::MERKLEBLOCK},
    {108, NetMsgType::GETBLOCKS},
    {109, NetMsgType::GETHEADERS},
    {120, NetMsgType::TX},
    {121, NetMsgType::HEADERS},
    {122, NetMsgType::BLOCK},
    {123, NetMsgType::GETADDR},
    {124, NetMsgType::MEMPOOL},
    {125, NetMsgType::PING},
    {126, NetMsgType::PONG},
    {127, NetMsgType::NOTFOUND},
    {128, NetMsgType::FILTERLOAD},
    {129, NetMsgType::FILTERADD},
    {140, NetMsgType::FILTERCLEAR},
    {141, NetMsgType::SENDHEADERS},
    {142, NetMsgType::FEEFILTER},
    {143, NetMsgType::SENDCMPCT},
    {144, NetMsgType::CMPCTBLOCK},
    {145, NetMsgType::GETBLOCKTXN},
    {146, NetMsgType::BLOCKTXN},
    {147, NetMsgType::GETCFILTERS},
    {148, NetMsgType::CFILTER},
    {149, NetMsgType::GETCFHEADERS},
    {160, NetMsgType::CFHEADERS},
    {161, NetMsgType::GETCFCHECKPT},
    {162, NetMsgType::CFCHECKPT},
    {163, NetMsgType::WTXIDRELAY},
    {164, NetMsgType::SENDTXRCNCL},
    {165, NetMsgType::FEATURE},
    {166, NetMsgType::SET324ID},
});

} // namespace BIP324

CInv::CInv()
{
    type = 0;
    hash.SetNull();
}

CInv::CInv(uint32_t typeIn, const uint256& hashIn) : type(typeIn), hash(hashIn) {}

bool operator<(const CInv& a, const CInv& b)
{
    return (a.type < b.type || (a.type == b.type && a.hash < b.hash));
}

std::string CInv::GetMessageType() const
{
    std::string cmd;
    if (type & MSG_WITNESS_FLAG)
        cmd.append("witness-");
    int masked = type & MSG_TYPE_MASK;
    switch (masked)
    {
    case MSG_TX:             return cmd.append(NetMsgType::TX);
    // WTX is not a message type, just an inv type
    case MSG_WTX:            return cmd.append("wtx");
    case MSG_BLOCK:          return cmd.append(NetMsgType::BLOCK);
    case MSG_FILTERED_BLOCK: return cmd.append(NetMsgType::MERKLEBLOCK);
    case MSG_CMPCT_BLOCK:    return cmd.append(NetMsgType::CMPCTBLOCK);
    default:
        throw std::out_of_range(strprintf("CInv::GetMessageType(): type=%d unknown type", type));
    }
}

std::string CInv::ToString() const
{
    try {
        return strprintf("%s %s", GetMessageType(), hash.ToString());
    } catch(const std::out_of_range &) {
        return strprintf("0x%08x %s", type, hash.ToString());
    }
}

/**
 * Convert a service flag (NODE_*) to a human readable string.
 * It supports unknown service flags which will be returned as "UNKNOWN[...]".
 * @param[in] bit the service flag is calculated as (1 << bit)
 */
static std::string serviceFlagToStr(size_t bit)
{
    const uint64_t service_flag = 1ULL << bit;
    switch ((ServiceFlags)service_flag) {
    case NODE_NONE: abort();  // impossible
    case NODE_NETWORK:         return "NETWORK";
    case NODE_BLOOM:           return "BLOOM";
    case NODE_WITNESS:         return "WITNESS";
    case NODE_COMPACT_FILTERS: return "COMPACT_FILTERS";
    case NODE_NETWORK_LIMITED: return "NETWORK_LIMITED";
    case NODE_P2P_V2:          return "P2P_V2";
    // Not using default, so we get warned when a case is missing
    }

    return strprintf("UNKNOWN[2^%u]", bit);
}

std::vector<std::string> serviceFlagsToStr(uint64_t flags)
{
    std::vector<std::string> str_flags;

    for (size_t i = 0; i < sizeof(flags) * 8; ++i) {
        if (flags & (1ULL << i)) {
            str_flags.emplace_back(serviceFlagToStr(i));
        }
    }

    return str_flags;
}

GenTxid ToGenTxid(const CInv& inv)
{
    assert(inv.IsGenTxMsg());
    return inv.IsMsgWtx() ? GenTxid{Wtxid::FromUint256(inv.hash)} : GenTxid{Txid::FromUint256(inv.hash)};
}
