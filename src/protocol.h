// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PROTOCOL_H
#define BITCOIN_PROTOCOL_H

#include <kernel/messagestartchars.h> // IWYU pragma: export
#include <netaddress.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <streams.h>
#include <uint256.h>
#include <util/time.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <type_traits>

/** Message header.
 * (4) message start.
 * (12) message type.
 * (4) size.
 * (4) checksum.
 */
class CMessageHeader
{
public:
    static constexpr size_t MESSAGE_TYPE_SIZE = 12;
    static constexpr size_t MESSAGE_SIZE_SIZE = 4;
    static constexpr size_t CHECKSUM_SIZE = 4;
    static constexpr size_t MESSAGE_SIZE_OFFSET = std::tuple_size_v<MessageStartChars> + MESSAGE_TYPE_SIZE;
    static constexpr size_t CHECKSUM_OFFSET = MESSAGE_SIZE_OFFSET + MESSAGE_SIZE_SIZE;
    static constexpr size_t HEADER_SIZE = std::tuple_size_v<MessageStartChars> + MESSAGE_TYPE_SIZE + MESSAGE_SIZE_SIZE + CHECKSUM_SIZE;

    explicit CMessageHeader() = default;

    /** Construct a P2P message header from message-start characters, a message type and the size of the message.
     * @note Passing in a `msg_type` longer than MESSAGE_TYPE_SIZE will result in a run-time assertion error.
     */
    CMessageHeader(const MessageStartChars& pchMessageStartIn, const char* msg_type, unsigned int nMessageSizeIn);

    std::string GetMessageType() const;
    bool IsMessageTypeValid() const;

    SERIALIZE_METHODS(CMessageHeader, obj) { READWRITE(obj.pchMessageStart, obj.m_msg_type, obj.nMessageSize, obj.pchChecksum); }

    MessageStartChars pchMessageStart{};
    char m_msg_type[MESSAGE_TYPE_SIZE]{};
    uint32_t nMessageSize{std::numeric_limits<uint32_t>::max()};
    uint8_t pchChecksum[CHECKSUM_SIZE]{};
};

/**
 * Bitcoin protocol message types. When adding new message types, don't forget
 * to update ALL_NET_MESSAGE_TYPES below.
 */
enum class NetMsgType : uint8_t {
    /**
     * The version message provides information about the transmitting node to the
     * receiving node at the beginning of a connection.
     */
    VERSION,
    /**
     * The verack message acknowledges a previously-received version message,
     * informing the connecting node that it can begin to send other messages.
     */
    VERACK,
    /**
     * The addr (IP address) message relays connection information for peers on the
     * network.
     */
    ADDR,
    /**
     * The addrv2 message relays connection information for peers on the network just
     * like the addr message, but is extended to allow gossiping of longer node
     * addresses (see BIP155).
     */
    ADDRV2,
    /**
     * The sendaddrv2 message signals support for receiving ADDRV2 messages (BIP155).
     * It also implies that its sender can encode as ADDRV2 and would send ADDRV2
     * instead of ADDR to a peer that has signaled ADDRV2 support by sending SENDADDRV2.
     */
    SENDADDRV2,
    /**
     * The inv message (inventory message) transmits one or more inventories of
     * objects known to the transmitting peer.
     */
    INV,
    /**
     * The getdata message requests one or more data objects from another node.
     */
    GETDATA,
    /**
     * The merkleblock message is a reply to a getdata message which requested a
     * block using the inventory type MSG_MERKLEBLOCK.
     * @since protocol version 70001 as described by BIP37.
     */
    MERKLEBLOCK,
    /**
     * The getblocks message requests an inv message that provides block header
     * hashes starting from a particular point in the block chain.
     */
    GETBLOCKS,
    /**
     * The getheaders message requests a headers message that provides block
     * headers starting from a particular point in the block chain.
     * @since protocol version 31800.
     */
    GETHEADERS,
    /**
     * The tx message transmits a single transaction.
     */
    TX,
    /**
     * The headers message sends one or more block headers to a node which
     * previously requested certain headers with a getheaders message.
     * @since protocol version 31800.
     */
    HEADERS,
    /**
     * The block message transmits a single serialized block.
     */
    BLOCK,
    /**
     * The getaddr message requests an addr message from the receiving node,
     * preferably one with lots of IP addresses of other receiving nodes.
     */
    GETADDR,
    /**
     * The mempool message requests the TXIDs of transactions that the receiving
     * node has verified as valid but which have not yet appeared in a block.
     * @since protocol version 60002 as described by BIP35.
     *   Only available with service bit NODE_BLOOM, see also BIP111.
     */
    MEMPOOL,
    /**
     * The ping message is sent periodically to help confirm that the receiving
     * peer is still connected.
     */
    PING,
    /**
     * The pong message replies to a ping message, proving to the pinging node that
     * the ponging node is still alive.
     * @since protocol version 60001 as described by BIP31.
     */
    PONG,
    /**
     * The notfound message is a reply to a getdata message which requested an
     * object the receiving node does not have available for relay.
     * @since protocol version 70001.
     */
    NOTFOUND,
    /**
     * The filterload message tells the receiving peer to filter all relayed
     * transactions and requested merkle blocks through the provided filter.
     * @since protocol version 70001 as described by BIP37.
     *   Only available with service bit NODE_BLOOM since protocol version
     *   70011 as described by BIP111.
     */
    FILTERLOAD,
    /**
     * The filteradd message tells the receiving peer to add a single element to a
     * previously-set bloom filter, such as a new public key.
     * @since protocol version 70001 as described by BIP37.
     *   Only available with service bit NODE_BLOOM since protocol version
     *   70011 as described by BIP111.
     */
    FILTERADD,
    /**
     * The filterclear message tells the receiving peer to remove a previously-set
     * bloom filter.
     * @since protocol version 70001 as described by BIP37.
     *   Only available with service bit NODE_BLOOM since protocol version
     *   70011 as described by BIP111.
     */
    FILTERCLEAR,
    /**
     * Indicates that a node prefers to receive new block announcements via a
     * "headers" message rather than an "inv".
     * @since protocol version 70012 as described by BIP130.
     */
    SENDHEADERS,
    /**
     * The feefilter message tells the receiving peer not to inv us any txs
     * which do not meet the specified min fee rate.
     * @since protocol version 70013 as described by BIP133
     */
    FEEFILTER,
    /**
     * Contains a 1-byte bool and 8-byte LE version number.
     * Indicates that a node is willing to provide blocks via "cmpctblock" messages.
     * May indicate that a node prefers to receive new block announcements via a
     * "cmpctblock" message rather than an "inv", depending on message contents.
     * @since protocol version 70014 as described by BIP 152
     */
    SENDCMPCT,
    /**
     * Contains a CBlockHeaderAndShortTxIDs object - providing a header and
     * list of "short txids".
     * @since protocol version 70014 as described by BIP 152
     */
    CMPCTBLOCK,
    /**
     * Contains a BlockTransactionsRequest
     * Peer should respond with "blocktxn" message.
     * @since protocol version 70014 as described by BIP 152
     */
    GETBLOCKTXN,
    /**
     * Contains a BlockTransactions.
     * Sent in response to a "getblocktxn" message.
     * @since protocol version 70014 as described by BIP 152
     */
    BLOCKTXN,
    /**
     * getcfilters requests compact filters for a range of blocks.
     * Only available with service bit NODE_COMPACT_FILTERS as described by
     * BIP 157 & 158.
     */
    GETCFILTERS,
    /**
     * cfilter is a response to a getcfilters request containing a single compact
     * filter.
     */
    CFILTER,
    /**
     * getcfheaders requests a compact filter header and the filter hashes for a
     * range of blocks, which can then be used to reconstruct the filter headers
     * for those blocks.
     * Only available with service bit NODE_COMPACT_FILTERS as described by
     * BIP 157 & 158.
     */
    GETCFHEADERS,
    /**
     * cfheaders is a response to a getcfheaders request containing a filter header
     * and a vector of filter hashes for each subsequent block in the requested range.
     */
    CFHEADERS,
    /**
     * getcfcheckpt requests evenly spaced compact filter headers, enabling
     * parallelized download and validation of the headers between them.
     * Only available with service bit NODE_COMPACT_FILTERS as described by
     * BIP 157 & 158.
     */
    GETCFCHECKPT,
    /**
     * cfcheckpt is a response to a getcfcheckpt request containing a vector of
     * evenly spaced filter headers for blocks on the requested chain.
     */
    CFCHECKPT,
    /**
     * Indicates that a node prefers to relay transactions via wtxid, rather than
     * txid.
     * @since protocol version 70016 as described by BIP 339.
     */
    WTXIDRELAY,
    /**
     * Contains a 4-byte version number and an 8-byte salt.
     * The salt is used to compute short txids needed for efficient
     * txreconciliation, as described by BIP 330.
     */
    SENDTXRCNCL,
    /**
     * The alert message. Obsolete, but still sent to old peers.
     */
    ALERT,
}; // enum class NetMsgType

static constexpr size_t NUM_NETMSGTYPE{36};

/** All known message types (see above). Keep this in enum order. */
extern const std::array<std::string_view, NUM_NETMSGTYPE> ALL_NET_MESSAGE_TYPES;

constexpr std::string NET_MESSAGE_TYPE_OTHER = "*other*";

/* Helper class that implicitly converts NetMsgType */
class NetMsgTypeConv
{
private:
    using type = std::underlying_type_t<NetMsgType>;
    type msg_type{NUM_NETMSGTYPE};

    static const std::array<std::pair<std::string_view, NetMsgType>, NUM_NETMSGTYPE> g_sorted_msgs;

    std::string_view sv() const
    {
        return valid() ? ALL_NET_MESSAGE_TYPES[msg_type] : NET_MESSAGE_TYPE_OTHER;
    }

public:
    // implicit conversions

    constexpr NetMsgTypeConv() = default;
    constexpr NetMsgTypeConv(NetMsgType m) : msg_type{static_cast<type>(m)} { }

    explicit NetMsgTypeConv(std::string_view msv)
    {
        auto fst = [](auto& x) { return x.first; };
        if (auto eqr = std::ranges::equal_range(g_sorted_msgs, msv, std::less{}, fst); !eqr.empty()) {
            msg_type = static_cast<type>(eqr.front().second);
        } else {
            msg_type = NUM_NETMSGTYPE;
        }
    }

    constexpr bool valid() const { return 0 <= msg_type && msg_type < NUM_NETMSGTYPE; }

    friend bool operator==(NetMsgTypeConv a, NetMsgTypeConv b) = default;

    operator std::string() const { return std::string{sv()}; }
    operator std::string_view() const { return sv(); }

    template<typename Stream>
    friend inline Stream& operator<<(Stream& s, NetMsgTypeConv msg_type)
    {
        s << msg_type.sv();
        return s;
    }

    friend inline bool operator==(NetMsgTypeConv msg_type, std::string_view sv)
    {
        return msg_type.sv() == sv;
    }

    friend std::optional<NetMsgType> GetNetMsgTypeFromString(std::string_view sv);
};

inline std::optional<NetMsgType> GetNetMsgTypeFromString(std::string_view sv)
{
    std::optional<NetMsgType> r{std::nullopt};
    NetMsgTypeConv nmt{sv};
    if (nmt.valid()) r = static_cast<NetMsgType>(nmt.msg_type);
    return r;
}

template<typename Stream>
inline Stream& operator<<(Stream& s, NetMsgType msg_type)
{
    s << NetMsgTypeConv{msg_type};
    return s;
}

inline std::string_view GetNetMsgTypeString(NetMsgTypeConv msg_type)
{
    return msg_type;
}

/** nServices flags */
enum ServiceFlags : uint64_t {
    // NOTE: When adding here, be sure to update serviceFlagToStr too
    // Nothing
    NODE_NONE = 0,
    // NODE_NETWORK means that the node is capable of serving the complete block chain. It is currently
    // set by all Bitcoin Core non pruned nodes, and is unset by SPV clients or other light clients.
    NODE_NETWORK = (1 << 0),
    // NODE_BLOOM means the node is capable and willing to handle bloom-filtered connections.
    NODE_BLOOM = (1 << 2),
    // NODE_WITNESS indicates that a node can be asked for blocks and transactions including
    // witness data.
    NODE_WITNESS = (1 << 3),
    // NODE_COMPACT_FILTERS means the node will service basic block filter requests.
    // See BIP157 and BIP158 for details on how this is implemented.
    NODE_COMPACT_FILTERS = (1 << 6),
    // NODE_NETWORK_LIMITED means the same as NODE_NETWORK with the limitation of only
    // serving the last 288 (2 day) blocks
    // See BIP159 for details on how this is implemented.
    NODE_NETWORK_LIMITED = (1 << 10),

    // NODE_P2P_V2 means the node supports BIP324 transport
    NODE_P2P_V2 = (1 << 11),

    // Bits 24-31 are reserved for temporary experiments. Just pick a bit that
    // isn't getting used, or one not being used much, and notify the
    // bitcoin-development mailing list. Remember that service bits are just
    // unauthenticated advertisements, so your code must be robust against
    // collisions and other cases where nodes may be advertising a service they
    // do not actually support. Other service bits should be allocated via the
    // BIP process.
};

/**
 * Convert service flags (a bitmask of NODE_*) to human readable strings.
 * It supports unknown service flags which will be returned as "UNKNOWN[...]".
 * @param[in] flags multiple NODE_* bitwise-OR-ed together
 */
std::vector<std::string> serviceFlagsToStr(uint64_t flags);

/**
 * State independent service flags.
 * If the return value is changed, contrib/seeds/makeseeds.py
 * should be updated appropriately to filter for nodes with
 * desired service flags (compatible with our new flags).
 */
constexpr ServiceFlags SeedsServiceFlags() { return ServiceFlags(NODE_NETWORK | NODE_WITNESS); }

/**
 * Checks if a peer with the given service flags may be capable of having a
 * robust address-storage DB.
 */
static inline bool MayHaveUsefulAddressDB(ServiceFlags services)
{
    return (services & NODE_NETWORK) || (services & NODE_NETWORK_LIMITED);
}

/** A CService with information about it as peer */
class CAddress : public CService
{
    static constexpr std::chrono::seconds TIME_INIT{100000000};

    /** Historically, CAddress disk serialization stored the CLIENT_VERSION, optionally OR'ed with
     *  the ADDRV2_FORMAT flag to indicate V2 serialization. The first field has since been
     *  disentangled from client versioning, and now instead:
     *  - The low bits (masked by DISK_VERSION_IGNORE_MASK) store the fixed value DISK_VERSION_INIT,
     *    (in case any code exists that treats it as a client version) but are ignored on
     *    deserialization.
     *  - The high bits (masked by ~DISK_VERSION_IGNORE_MASK) store actual serialization information.
     *    Only 0 or DISK_VERSION_ADDRV2 (equal to the historical ADDRV2_FORMAT) are valid now, and
     *    any other value triggers a deserialization failure. Other values can be added later if
     *    needed.
     *
     *  For disk deserialization, ADDRV2_FORMAT in the stream version signals that ADDRV2
     *  deserialization is permitted, but the actual format is determined by the high bits in the
     *  stored version field. For network serialization, the stream version having ADDRV2_FORMAT or
     *  not determines the actual format used (as it has no embedded version number).
     */
    static constexpr uint32_t DISK_VERSION_INIT{220000};
    static constexpr uint32_t DISK_VERSION_IGNORE_MASK{0b00000000'00000111'11111111'11111111};
    /** The version number written in disk serialized addresses to indicate V2 serializations.
     * It must be exactly 1<<29, as that is the value that historical versions used for this
     * (they used their internal ADDRV2_FORMAT flag here). */
    static constexpr uint32_t DISK_VERSION_ADDRV2{1 << 29};
    static_assert((DISK_VERSION_INIT & ~DISK_VERSION_IGNORE_MASK) == 0, "DISK_VERSION_INIT must be covered by DISK_VERSION_IGNORE_MASK");
    static_assert((DISK_VERSION_ADDRV2 & DISK_VERSION_IGNORE_MASK) == 0, "DISK_VERSION_ADDRV2 must not be covered by DISK_VERSION_IGNORE_MASK");

public:
    CAddress() : CService{} {};
    CAddress(CService ipIn, ServiceFlags nServicesIn) : CService{ipIn}, nServices{nServicesIn} {};
    CAddress(CService ipIn, ServiceFlags nServicesIn, NodeSeconds time) : CService{ipIn}, nTime{time}, nServices{nServicesIn} {};

    enum class Format {
        Disk,
        Network,
    };
    struct SerParams : CNetAddr::SerParams {
        const Format fmt;
        SER_PARAMS_OPFUNC
    };
    static constexpr SerParams V1_NETWORK{{CNetAddr::Encoding::V1}, Format::Network};
    static constexpr SerParams V2_NETWORK{{CNetAddr::Encoding::V2}, Format::Network};
    static constexpr SerParams V1_DISK{{CNetAddr::Encoding::V1}, Format::Disk};
    static constexpr SerParams V2_DISK{{CNetAddr::Encoding::V2}, Format::Disk};

    SERIALIZE_METHODS(CAddress, obj)
    {
        bool use_v2;
        auto& params = SER_PARAMS(SerParams);
        if (params.fmt == Format::Disk) {
            // In the disk serialization format, the encoding (v1 or v2) is determined by a flag version
            // that's part of the serialization itself. ADDRV2_FORMAT in the stream version only determines
            // whether V2 is chosen/permitted at all.
            uint32_t stored_format_version = DISK_VERSION_INIT;
            if (params.enc == Encoding::V2) stored_format_version |= DISK_VERSION_ADDRV2;
            READWRITE(stored_format_version);
            stored_format_version &= ~DISK_VERSION_IGNORE_MASK; // ignore low bits
            if (stored_format_version == 0) {
                use_v2 = false;
            } else if (stored_format_version == DISK_VERSION_ADDRV2 && params.enc == Encoding::V2) {
                // Only support v2 deserialization if V2 is set.
                use_v2 = true;
            } else {
                throw std::ios_base::failure("Unsupported CAddress disk format version");
            }
        } else {
            assert(params.fmt == Format::Network);
            // In the network serialization format, the encoding (v1 or v2) is determined directly by
            // the value of enc in the stream params, as no explicitly encoded version
            // exists in the stream.
            use_v2 = params.enc == Encoding::V2;
        }

        READWRITE(Using<LossyChronoFormatter<uint32_t>>(obj.nTime));
        // nServices is serialized as CompactSize in V2; as uint64_t in V1.
        if (use_v2) {
            uint64_t services_tmp;
            SER_WRITE(obj, services_tmp = obj.nServices);
            READWRITE(Using<CompactSizeFormatter<false>>(services_tmp));
            SER_READ(obj, obj.nServices = static_cast<ServiceFlags>(services_tmp));
        } else {
            READWRITE(Using<CustomUintFormatter<8>>(obj.nServices));
        }
        // Invoke V1/V2 serializer for CService parent object.
        const auto ser_params{use_v2 ? CNetAddr::V2 : CNetAddr::V1};
        READWRITE(ser_params(AsBase<CService>(obj)));
    }

    //! Always included in serialization. The behavior is unspecified if the value is not representable as uint32_t.
    NodeSeconds nTime{TIME_INIT};
    //! Serialized as uint64_t in V1, and as CompactSize in V2.
    ServiceFlags nServices{NODE_NONE};

    friend bool operator==(const CAddress& a, const CAddress& b)
    {
        return a.nTime == b.nTime &&
               a.nServices == b.nServices &&
               static_cast<const CService&>(a) == static_cast<const CService&>(b);
    }
};

/** getdata message type flags */
const uint32_t MSG_WITNESS_FLAG = 1 << 30;
const uint32_t MSG_TYPE_MASK = 0xffffffff >> 2;

/** getdata / inv message types.
 * These numbers are defined by the protocol. When adding a new value, be sure
 * to mention it in the respective BIP.
 */
enum GetDataMsg : uint32_t {
    UNDEFINED = 0,
    MSG_TX = 1,
    MSG_BLOCK = 2,
    MSG_WTX = 5,                                      //!< Defined in BIP 339
    // The following can only occur in getdata. Invs always use TX/WTX or BLOCK.
    MSG_FILTERED_BLOCK = 3,                           //!< Defined in BIP37
    MSG_CMPCT_BLOCK = 4,                              //!< Defined in BIP152
    MSG_WITNESS_BLOCK = MSG_BLOCK | MSG_WITNESS_FLAG, //!< Defined in BIP144
    MSG_WITNESS_TX = MSG_TX | MSG_WITNESS_FLAG,       //!< Defined in BIP144
    // MSG_FILTERED_WITNESS_BLOCK is defined in BIP144 as reserved for future
    // use and remains unused.
    // MSG_FILTERED_WITNESS_BLOCK = MSG_FILTERED_BLOCK | MSG_WITNESS_FLAG,
};

/** inv message data */
class CInv
{
public:
    CInv();
    CInv(uint32_t typeIn, const uint256& hashIn);

    SERIALIZE_METHODS(CInv, obj) { READWRITE(obj.type, obj.hash); }

    friend bool operator<(const CInv& a, const CInv& b);

    std::string GetMessageType() const;
    std::string ToString() const;

    // Single-message helper methods
    bool IsMsgTx() const { return type == MSG_TX; }
    bool IsMsgBlk() const { return type == MSG_BLOCK; }
    bool IsMsgWtx() const { return type == MSG_WTX; }
    bool IsMsgFilteredBlk() const { return type == MSG_FILTERED_BLOCK; }
    bool IsMsgCmpctBlk() const { return type == MSG_CMPCT_BLOCK; }
    bool IsMsgWitnessBlk() const { return type == MSG_WITNESS_BLOCK; }

    // Combined-message helper methods
    bool IsGenTxMsg() const
    {
        return type == MSG_TX || type == MSG_WTX || type == MSG_WITNESS_TX;
    }
    bool IsGenBlkMsg() const
    {
        return type == MSG_BLOCK || type == MSG_FILTERED_BLOCK || type == MSG_CMPCT_BLOCK || type == MSG_WITNESS_BLOCK;
    }

    uint32_t type;
    uint256 hash;
};

/** Convert a TX/WITNESS_TX/WTX CInv to a GenTxid. */
GenTxid ToGenTxid(const CInv& inv);

#endif // BITCOIN_PROTOCOL_H
