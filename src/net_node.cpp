// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_node.h>

#include <chainparams.h>
#include <common/args.h>
#include <crypto/common.h>
#include <hash.h>
#include <i2p.h>
#include <logging.h>
#include <netaddress.h>
#include <node/connection_types.h>
#include <node/eviction.h>
#include <protocol.h>
#include <random.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <sync.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/sock.h>
#include <util/time.h>
#include <util/strencodings.h>
#include <version.h>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <optional>

const std::string NET_MESSAGE_TYPE_OTHER = "*other*";

void CNode::CloseSocketDisconnect()
{
    fDisconnect = true;
    LOCK(m_sock_mutex);
    if (m_sock) {
        LogPrint(BCLog::NET, "disconnecting peer=%d\n", id);
        m_sock.reset();
    }
    m_i2p_sam_session.reset();
}

CService CNode::GetAddrLocal() const
{
    AssertLockNotHeld(m_addr_local_mutex);
    LOCK(m_addr_local_mutex);
    return addrLocal;
}

void CNode::SetAddrLocal(const CService& addrLocalIn) {
    AssertLockNotHeld(m_addr_local_mutex);
    LOCK(m_addr_local_mutex);
    if (addrLocal.IsValid()) {
        error("Addr local already set for node: %i. Refusing to change from %s to %s", id, addrLocal.ToStringAddrPort(), addrLocalIn.ToStringAddrPort());
    } else {
        addrLocal = addrLocalIn;
    }
}

Network CNode::ConnectedThroughNetwork() const
{
    return m_inbound_onion ? NET_ONION : addr.GetNetClass();
}

#undef X
#define X(name) stats.name = name
void CNode::CopyStats(CNodeStats& stats)
{
    stats.nodeid = this->GetId();
    X(addr);
    X(addrBind);
    stats.m_network = ConnectedThroughNetwork();
    X(m_last_send);
    X(m_last_recv);
    X(m_last_tx_time);
    X(m_last_block_time);
    X(m_connected);
    X(nTimeOffset);
    X(m_addr_name);
    X(nVersion);
    {
        LOCK(m_subver_mutex);
        X(cleanSubVer);
    }
    stats.fInbound = IsInboundConn();
    X(m_bip152_highbandwidth_to);
    X(m_bip152_highbandwidth_from);
    {
        LOCK(cs_vSend);
        X(mapSendBytesPerMsgType);
        X(nSendBytes);
    }
    {
        LOCK(cs_vRecv);
        X(mapRecvBytesPerMsgType);
        X(nRecvBytes);
    }
    X(m_permission_flags);

    X(m_last_ping_time);
    X(m_min_ping_time);

    // Leave string empty if addrLocal invalid (not filled in yet)
    CService addrLocalUnlocked = GetAddrLocal();
    stats.addrLocal = addrLocalUnlocked.IsValid() ? addrLocalUnlocked.ToStringAddrPort() : "";

    X(m_conn_type);
}
#undef X

bool CNode::ReceiveMsgBytes(Span<const uint8_t> msg_bytes, bool& complete)
{
    complete = false;
    const auto time = GetTime<std::chrono::microseconds>();
    LOCK(cs_vRecv);
    m_last_recv = std::chrono::duration_cast<std::chrono::seconds>(time);
    nRecvBytes += msg_bytes.size();
    while (msg_bytes.size() > 0) {
        // absorb network data
        int handled = m_deserializer->Read(msg_bytes);
        if (handled < 0) {
            // Serious header problem, disconnect from the peer.
            return false;
        }

        if (m_deserializer->Complete()) {
            // decompose a transport agnostic CNetMessage from the deserializer
            bool reject_message{false};
            CNetMessage msg = m_deserializer->GetMessage(time, reject_message);
            if (reject_message) {
                // Message deserialization failed. Drop the message but don't disconnect the peer.
                // store the size of the corrupt message
                mapRecvBytesPerMsgType.at(NET_MESSAGE_TYPE_OTHER) += msg.m_raw_message_size;
                continue;
            }

            // Store received bytes per message type.
            // To prevent a memory DOS, only allow known message types.
            auto i = mapRecvBytesPerMsgType.find(msg.m_type);
            if (i == mapRecvBytesPerMsgType.end()) {
                i = mapRecvBytesPerMsgType.find(NET_MESSAGE_TYPE_OTHER);
            }
            assert(i != mapRecvBytesPerMsgType.end());
            i->second += msg.m_raw_message_size;

            // push the message to the process queue,
            vRecvMsg.push_back(std::move(msg));

            complete = true;
        }
    }

    return true;
}

int V1TransportDeserializer::readHeader(Span<const uint8_t> msg_bytes)
{
    // copy data to temporary parsing buffer
    unsigned int nRemaining = CMessageHeader::HEADER_SIZE - nHdrPos;
    unsigned int nCopy = std::min<unsigned int>(nRemaining, msg_bytes.size());

    memcpy(&hdrbuf[nHdrPos], msg_bytes.data(), nCopy);
    nHdrPos += nCopy;

    // if header incomplete, exit
    if (nHdrPos < CMessageHeader::HEADER_SIZE)
        return nCopy;

    // deserialize to CMessageHeader
    try {
        hdrbuf >> hdr;
    }
    catch (const std::exception&) {
        LogPrint(BCLog::NET, "Header error: Unable to deserialize, peer=%d\n", m_node_id);
        return -1;
    }

    // Check start string, network magic
    if (memcmp(hdr.pchMessageStart, m_chain_params.MessageStart(), CMessageHeader::MESSAGE_START_SIZE) != 0) {
        LogPrint(BCLog::NET, "Header error: Wrong MessageStart %s received, peer=%d\n", HexStr(hdr.pchMessageStart), m_node_id);
        return -1;
    }

    // reject messages larger than MAX_SIZE or MAX_PROTOCOL_MESSAGE_LENGTH
    if (hdr.nMessageSize > MAX_SIZE || hdr.nMessageSize > MAX_PROTOCOL_MESSAGE_LENGTH) {
        LogPrint(BCLog::NET, "Header error: Size too large (%s, %u bytes), peer=%d\n", SanitizeString(hdr.GetCommand()), hdr.nMessageSize, m_node_id);
        return -1;
    }

    // switch state to reading message data
    in_data = true;

    return nCopy;
}

int V1TransportDeserializer::readData(Span<const uint8_t> msg_bytes)
{
    unsigned int nRemaining = hdr.nMessageSize - nDataPos;
    unsigned int nCopy = std::min<unsigned int>(nRemaining, msg_bytes.size());

    if (vRecv.size() < nDataPos + nCopy) {
        // Allocate up to 256 KiB ahead, but never more than the total message size.
        vRecv.resize(std::min(hdr.nMessageSize, nDataPos + nCopy + 256 * 1024));
    }

    hasher.Write(msg_bytes.first(nCopy));
    memcpy(&vRecv[nDataPos], msg_bytes.data(), nCopy);
    nDataPos += nCopy;

    return nCopy;
}

const uint256& V1TransportDeserializer::GetMessageHash() const
{
    assert(Complete());
    if (data_hash.IsNull())
        hasher.Finalize(data_hash);
    return data_hash;
}

CNetMessage V1TransportDeserializer::GetMessage(const std::chrono::microseconds time, bool& reject_message)
{
    // Initialize out parameter
    reject_message = false;
    // decompose a single CNetMessage from the TransportDeserializer
    CNetMessage msg(std::move(vRecv));

    // store message type string, time, and sizes
    msg.m_type = hdr.GetCommand();
    msg.m_time = time;
    msg.m_message_size = hdr.nMessageSize;
    msg.m_raw_message_size = hdr.nMessageSize + CMessageHeader::HEADER_SIZE;

    uint256 hash = GetMessageHash();

    // We just received a message off the wire, harvest entropy from the time (and the message checksum)
    RandAddEvent(ReadLE32(hash.begin()));

    // Check checksum and header message type string
    if (memcmp(hash.begin(), hdr.pchChecksum, CMessageHeader::CHECKSUM_SIZE) != 0) {
        LogPrint(BCLog::NET, "Header error: Wrong checksum (%s, %u bytes), expected %s was %s, peer=%d\n",
                 SanitizeString(msg.m_type), msg.m_message_size,
                 HexStr(Span{hash}.first(CMessageHeader::CHECKSUM_SIZE)),
                 HexStr(hdr.pchChecksum),
                 m_node_id);
        reject_message = true;
    } else if (!hdr.IsCommandValid()) {
        LogPrint(BCLog::NET, "Header error: Invalid message type (%s, %u bytes), peer=%d\n",
                 SanitizeString(hdr.GetCommand()), msg.m_message_size, m_node_id);
        reject_message = true;
    }

    // Always reset the network deserializer (prepare for the next message)
    Reset();
    return msg;
}

void V1TransportSerializer::prepareForTransport(CSerializedNetMsg& msg, std::vector<unsigned char>& header) const
{
    // create dbl-sha256 checksum
    uint256 hash = Hash(msg.data);

    // create header
    CMessageHeader hdr(Params().MessageStart(), msg.m_type.c_str(), msg.data.size());
    memcpy(hdr.pchChecksum, hash.begin(), CMessageHeader::CHECKSUM_SIZE);

    // serialize header
    header.reserve(CMessageHeader::HEADER_SIZE);
    CVectorWriter{SER_NETWORK, INIT_PROTO_VERSION, header, 0, hdr};
}

CNode::CNode(NodeId idIn,
             std::shared_ptr<Sock> sock,
             const CAddress& addrIn,
             uint64_t nKeyedNetGroupIn,
             uint64_t nLocalHostNonceIn,
             const CAddress& addrBindIn,
             const std::string& addrNameIn,
             ConnectionType conn_type_in,
             bool inbound_onion,
             CNodeOptions&& node_opts)
    : m_deserializer{std::make_unique<V1TransportDeserializer>(V1TransportDeserializer(Params(), idIn, SER_NETWORK, INIT_PROTO_VERSION))},
      m_serializer{std::make_unique<V1TransportSerializer>(V1TransportSerializer())},
      m_permission_flags{node_opts.permission_flags},
      m_sock{sock},
      m_connected{GetTime<std::chrono::seconds>()},
      addr{addrIn},
      addrBind{addrBindIn},
      m_addr_name{addrNameIn.empty() ? addr.ToStringAddrPort() : addrNameIn},
      m_inbound_onion{inbound_onion},
      m_prefer_evict{node_opts.prefer_evict},
      nKeyedNetGroup{nKeyedNetGroupIn},
      m_conn_type{conn_type_in},
      id{idIn},
      nLocalHostNonce{nLocalHostNonceIn},
      m_recv_flood_size{node_opts.recv_flood_size},
      m_i2p_sam_session{std::move(node_opts.i2p_sam_session)}
{
    if (inbound_onion) assert(conn_type_in == ConnectionType::INBOUND);

    for (const std::string &msg : getAllNetMessageTypes())
        mapRecvBytesPerMsgType[msg] = 0;
    mapRecvBytesPerMsgType[NET_MESSAGE_TYPE_OTHER] = 0;

    if (fLogIPs) {
        LogPrint(BCLog::NET, "Added connection to %s peer=%d\n", m_addr_name, id);
    } else {
        LogPrint(BCLog::NET, "Added connection peer=%d\n", id);
    }
}

void CNode::MarkReceivedMsgsForProcessing()
{
    AssertLockNotHeld(m_msg_process_queue_mutex);

    size_t nSizeAdded = 0;
    for (const auto& msg : vRecvMsg) {
        // vRecvMsg contains only completed CNetMessage
        // the single possible partially deserialized message are held by TransportDeserializer
        nSizeAdded += msg.m_raw_message_size;
    }

    LOCK(m_msg_process_queue_mutex);
    m_msg_process_queue.splice(m_msg_process_queue.end(), vRecvMsg);
    m_msg_process_queue_size += nSizeAdded;
    fPauseRecv = m_msg_process_queue_size > m_recv_flood_size;
}

std::optional<std::pair<CNetMessage, bool>> CNode::PollMessage()
{
    LOCK(m_msg_process_queue_mutex);
    if (m_msg_process_queue.empty()) return std::nullopt;

    std::list<CNetMessage> msgs;
    // Just take one message
    msgs.splice(msgs.begin(), m_msg_process_queue, m_msg_process_queue.begin());
    m_msg_process_queue_size -= msgs.front().m_raw_message_size;
    fPauseRecv = m_msg_process_queue_size > m_recv_flood_size;

    return std::make_pair(std::move(msgs.front()), !m_msg_process_queue.empty());
}

void CaptureMessageToFile(const CAddress& addr,
                          const std::string& msg_type,
                          Span<const unsigned char> data,
                          bool is_incoming)
{
    // Note: This function captures the message at the time of processing,
    // not at socket receive/send time.
    // This ensures that the messages are always in order from an application
    // layer (processing) perspective.
    auto now = GetTime<std::chrono::microseconds>();

    // Windows folder names cannot include a colon
    std::string clean_addr = addr.ToStringAddrPort();
    std::replace(clean_addr.begin(), clean_addr.end(), ':', '_');

    fs::path base_path = gArgs.GetDataDirNet() / "message_capture" / fs::u8path(clean_addr);
    fs::create_directories(base_path);

    fs::path path = base_path / (is_incoming ? "msgs_recv.dat" : "msgs_sent.dat");
    AutoFile f{fsbridge::fopen(path, "ab")};

    ser_writedata64(f, now.count());
    f.write(MakeByteSpan(msg_type));
    for (auto i = msg_type.length(); i < CMessageHeader::COMMAND_SIZE; ++i) {
        f << uint8_t{'\0'};
    }
    uint32_t size = data.size();
    ser_writedata32(f, size);
    f.write(AsBytes(data));
}

std::function<void(const CAddress& addr,
                   const std::string& msg_type,
                   Span<const unsigned char> data,
                   bool is_incoming)>
    CaptureMessage = CaptureMessageToFile;
