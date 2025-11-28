// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <protocol.h>

#include <common/system.h>

static_assert(sizeof(NetMsgType) == sizeof(NetMsgTypeConv));

static consteval std::string_view GetNetMsgTypeString_internal(NetMsgType msg_type)
{
    using enum NetMsgType;

    switch (msg_type) {
    case VERSION: return "version";
    case VERACK: return "verack";
    case ADDR: return "addr";
    case ADDRV2: return "addrv2";
    case SENDADDRV2: return "sendaddrv2";
    case INV: return "inv";
    case GETDATA: return "getdata";
    case MERKLEBLOCK: return "merkleblock";
    case GETBLOCKS: return "getblocks";
    case GETHEADERS: return "getheaders";
    case TX: return "tx";
    case HEADERS: return "headers";
    case BLOCK: return "block";
    case GETADDR: return "getaddr";
    case MEMPOOL: return "mempool";
    case PING: return "ping";
    case PONG: return "pong";
    case NOTFOUND: return "notfound";
    case FILTERLOAD: return "filterload";
    case FILTERADD: return "filteradd";
    case FILTERCLEAR: return "filterclear";
    case SENDHEADERS: return "sendheaders";
    case FEEFILTER: return "feefilter";
    case SENDCMPCT: return "sendcmpct";
    case CMPCTBLOCK: return "cmpctblock";
    case GETBLOCKTXN: return "getblocktxn";
    case BLOCKTXN: return "blocktxn";
    case GETCFILTERS: return "getcfilters";
    case CFILTER: return "cfilter";
    case GETCFHEADERS: return "getcfheaders";
    case CFHEADERS: return "cfheaders";
    case GETCFCHECKPT: return "getcfcheckpt";
    case CFCHECKPT: return "cfcheckpt";
    case WTXIDRELAY: return "wtxidrelay";
    case SENDTXRCNCL: return "sendtxrcncl";
    case ALERT: return "alert";
    }
    throw;
}

static consteval auto GetAllNetMsgTypes() {
    std::array<std::string_view, NUM_NETMSGTYPE> r;
    for (size_t i = 0; i < r.size(); ++i) {
        r[i] = GetNetMsgTypeString_internal(static_cast<NetMsgType>(i));
    }
    return r;
};
const std::array<std::string_view, NUM_NETMSGTYPE> ALL_NET_MESSAGE_TYPES = GetAllNetMsgTypes();

static consteval auto GetSortedNetMsgTypes()
{
    std::array<std::pair<std::string_view, NetMsgType>, NUM_NETMSGTYPE> result;
    for (size_t i = 0; i < result.size(); ++i) {
        NetMsgType msg_type = static_cast<NetMsgType>(i);
        result[i].first = GetNetMsgTypeString_internal(msg_type);
        result[i].second = msg_type;
    }
    std::sort(result.begin(), result.end(), std::less{});
    return result;
}
const std::array<std::pair<std::string_view, NetMsgType>, NUM_NETMSGTYPE> NetMsgTypeConv::g_sorted_msgs = GetSortedNetMsgTypes();

CMessageHeader::CMessageHeader(const MessageStartChars& pchMessageStartIn, const char* msg_type, unsigned int nMessageSizeIn)
    : pchMessageStart{pchMessageStartIn}
{
    // Copy the message type name
    size_t i = 0;
    for (; i < MESSAGE_TYPE_SIZE && msg_type[i] != 0; ++i) m_msg_type[i] = msg_type[i];
    assert(msg_type[i] == 0); // Assert that the message type name passed in is not longer than MESSAGE_TYPE_SIZE

    nMessageSize = nMessageSizeIn;
}

std::string CMessageHeader::GetMessageType() const
{
    return std::string(m_msg_type, m_msg_type + strnlen(m_msg_type, MESSAGE_TYPE_SIZE));
}

bool CMessageHeader::IsMessageTypeValid() const
{
    // Check the message type string for errors
    for (const char* p1 = m_msg_type; p1 < m_msg_type + MESSAGE_TYPE_SIZE; ++p1) {
        if (*p1 == 0) {
            // Must be all zeros after the first zero
            for (; p1 < m_msg_type + MESSAGE_TYPE_SIZE; ++p1) {
                if (*p1 != 0) {
                    return false;
                }
            }
        } else if (*p1 < ' ' || *p1 > 0x7E) {
            return false;
        }
    }

    return true;
}

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
    case MSG_TX:             return cmd.append("tx");
    // WTX is not a message type, just an inv type
    case MSG_WTX:            return cmd.append("wtx");
    case MSG_BLOCK:          return cmd.append("block");
    case MSG_FILTERED_BLOCK: return cmd.append("merkleblock");
    case MSG_CMPCT_BLOCK:    return cmd.append("cmpctblock");
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
