// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <protocol.h>

#include <bip324.h>
#include <common/system.h>

namespace BIP324 {
static consteval RecvMsgMap LiteralRecvMsgMap(std::span<const std::pair<uint8_t, std::string_view>> inp)
{
    RecvMsgMap r;
    uint8_t sentinel{ALL_NET_MESSAGE_TYPES.size()};
    r.fill(sentinel); // invalid value, in case some entries are blank
    for (auto&& [id, msg_type] : inp) {
        if (id <= 0 || id > r.size()) throw "Bad inputs (id out of range)";
        bool found = false;
        for (size_t i = 0; i < ALL_NET_MESSAGE_TYPES.size(); ++i) {
            if (std::string_view{ALL_NET_MESSAGE_TYPES[i]} == msg_type) {
                if (r[id-1] != sentinel) throw "Bad inputs (duplicates)";
                r[id-1] = i;
                found = true;
                break;
            }
        }
        if (!found) throw "Bad inputs (unknown msg)";
    }
    return r;
}

static consteval auto CheckDefaultRecvMsgMap(RecvMsgMap m)
{
    static_assert(MAX_ONE_BYTE_MSGTYPE_IMPLEMENTED >= 1);
    for (size_t i = 0; i < m.size(); ++i) {
        if (i + 1 == MAX_ONE_BYTE_MSGTYPE_IMPLEMENTED) {
            if (m[i] >= ALL_NET_MESSAGE_TYPES.size()) throw "BIP324::MAX_ONE_BYTE_MSGTYPE_IMPLEMENTED isn't actually implemented";
        }
        if (i + 1 > MAX_ONE_BYTE_MSGTYPE_IMPLEMENTED) {
            if (m[i] < ALL_NET_MESSAGE_TYPES.size()) throw "MsgType greater than BIP324::MAX_ONE_BYTE_MSGTYPE_IMPLEMENTED is implemented";
        }
    }

    return m;
}

/** List of short messages as defined in BIP324, in order.
 *
 * Only message types that are actually implemented in this codebase need to be listed, as other
 * messages get ignored anyway - whether we know how to decode them or not.
 */
static constexpr std::array BIP324Defaults{std::to_array<std::pair<uint8_t, std::string_view>>({
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
    {37, NetMsgType::FEATURE},
})};

const RecvMsgMap DEFAULT_RECVMSGMAP{CheckDefaultRecvMsgMap(LiteralRecvMsgMap(BIP324Defaults))};

void RecvMsgMap::Update(std::span<const AliasPayloadEntry> ids)
{
    uint8_t sentinel{ALL_NET_MESSAGE_TYPES.size()};
    for (auto& sio : ids) {
        if (sio.id == 0 || sio.id > size()) continue;
        (*this)[sio.id-1] = sentinel; // if msg is unknown, leave it as dummy
        for (size_t pos = 0; pos < ALL_NET_MESSAGE_TYPES.size(); ++pos) {
            if (sio.msg == ALL_NET_MESSAGE_TYPES[pos]) {
                (*this)[sio.id-1] = pos; // if msg is known, track it
                break;
            }
        }
    }
}

SendMsgMap RecvMsgMap::ToSendMsgMap() const
{
    SendMsgMap r{};
    size_t i = 0;
    for (uint8_t v : *this) {
        ++i;
        if (v >= ALL_NET_MESSAGE_TYPES.size()) continue;
        r.emplace(ALL_NET_MESSAGE_TYPES[v], i);
    }
    return r;
}

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
