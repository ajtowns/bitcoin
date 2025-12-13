// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <net.h>

#include <addrdb.h>
#include <addrman.h>
#include <banman.h>
#include <clientversion.h>
#include <common/args.h>
#include <common/netif.h>
#include <compat/compat.h>
#include <consensus/consensus.h>
#include <crypto/sha256.h>
#include <i2p.h>
#include <key.h>
#include <logging.h>
#include <memusage.h>
#include <net_permissions.h>
#include <netaddress.h>
#include <netbase.h>
#include <node/eviction.h>
#include <node/interface_ui.h>
#include <protocol.h>
#include <random.h>
#include <scheduler.h>
#include <util/fs.h>
#include <util/sock.h>
#include <util/strencodings.h>
#include <util/thread.h>
#include <util/threadinterrupt.h>
#include <util/trace.h>
#include <util/translation.h>
#include <util/vector.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <string_view>
#include <unordered_map>

TRACEPOINT_SEMAPHORE(net, evicted_inbound_connection);
TRACEPOINT_SEMAPHORE(net, inbound_connection);
TRACEPOINT_SEMAPHORE(net, outbound_connection);

/** Maximum number of block-relay-only anchor connections */
static constexpr size_t MAX_BLOCK_RELAY_ONLY_ANCHORS = 2;
static_assert (MAX_BLOCK_RELAY_ONLY_ANCHORS <= static_cast<size_t>(MAX_BLOCK_RELAY_ONLY_CONNECTIONS), "MAX_BLOCK_RELAY_ONLY_ANCHORS must not exceed MAX_BLOCK_RELAY_ONLY_CONNECTIONS.");

/** Number of DNS seeds to query when the number of connections is low. */
static constexpr int DNSSEEDS_TO_QUERY_AT_ONCE = 3;

/** Minimum number of outbound connections under which we will keep fetching our address seeds. */
static constexpr int SEED_OUTBOUND_CONNECTION_THRESHOLD = 2;

/** How long to delay before querying DNS seeds
 *
 * If we have more than THRESHOLD entries in addrman, then it's likely
 * that we got those addresses from having previously connected to the P2P
 * network, and that we'll be able to successfully reconnect to the P2P
 * network via contacting one of them. So if that's the case, spend a
 * little longer trying to connect to known peers before querying the
 * DNS seeds.
 */
static constexpr std::chrono::seconds DNSSEEDS_DELAY_FEW_PEERS{11};
static constexpr std::chrono::minutes DNSSEEDS_DELAY_MANY_PEERS{5};
static constexpr int DNSSEEDS_DELAY_PEER_THRESHOLD = 1000; // "many" vs "few" peers

// A random time period (0 to 1 seconds) is added to feeler connections to prevent synchronization.
static constexpr auto FEELER_SLEEP_WINDOW{1s};

/** Frequency to attempt extra connections to reachable networks we're not connected to yet **/
static constexpr auto EXTRA_NETWORK_PEER_INTERVAL{5min};

//
// Global state variables
//
bool fDiscover = true;
bool fListen = true;
GlobalMutex g_maplocalhost_mutex;
std::map<CNetAddr, LocalServiceInfo> mapLocalHost GUARDED_BY(g_maplocalhost_mutex);

void CConnman::AddAddrFetch(const std::string& strDest)
{
    LOCK(m_addr_fetches_mutex);
    m_addr_fetches.push_back(strDest);
}

// Determine the "best" local address for a particular peer.
[[nodiscard]] static std::optional<CService> GetLocal(const CNode& peer)
{
    if (!fListen) return std::nullopt;

    std::optional<CService> addr;
    int nBestScore = -1;
    int nBestReachability = -1;
    {
        LOCK(g_maplocalhost_mutex);
        for (const auto& [local_addr, local_service_info] : mapLocalHost) {
            // For privacy reasons, don't advertise our privacy-network address
            // to other networks and don't advertise our other-network address
            // to privacy networks.
            if (local_addr.GetNetwork() != peer.ConnectedThroughNetwork()
                && (local_addr.IsPrivacyNet() || peer.IsConnectedThroughPrivacyNet())) {
                continue;
            }
            const int nScore{local_service_info.nScore};
            const int nReachability{local_addr.GetReachabilityFrom(peer.addr)};
            if (nReachability > nBestReachability || (nReachability == nBestReachability && nScore > nBestScore)) {
                addr.emplace(CService{local_addr, local_service_info.nPort});
                nBestReachability = nReachability;
                nBestScore = nScore;
            }
        }
    }
    return addr;
}

//! Convert the serialized seeds into usable address objects.
static std::vector<CAddress> ConvertSeeds(const std::vector<uint8_t> &vSeedsIn)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const auto one_week{7 * 24h};
    std::vector<CAddress> vSeedsOut;
    FastRandomContext rng;
    ParamsStream s{DataStream{vSeedsIn}, CAddress::V2_NETWORK};
    while (!s.eof()) {
        CService endpoint;
        s >> endpoint;
        CAddress addr{endpoint, SeedsServiceFlags()};
        addr.nTime = rng.rand_uniform_delay(Now<NodeSeconds>() - one_week, -one_week);
        LogDebug(BCLog::NET, "Added hardcoded seed: %s\n", addr.ToStringAddrPort());
        vSeedsOut.push_back(addr);
    }
    return vSeedsOut;
}

// Determine the "best" local address for a particular peer.
// If none, return the unroutable 0.0.0.0 but filled in with
// the normal parameters, since the IP may be changed to a useful
// one by discovery.
CService GetLocalAddress(const CNode& peer)
{
    return GetLocal(peer).value_or(CService{CNetAddr(), GetListenPort()});
}

static int GetnScore(const CService& addr)
{
    LOCK(g_maplocalhost_mutex);
    const auto it = mapLocalHost.find(addr);
    return (it != mapLocalHost.end()) ? it->second.nScore : 0;
}

// Is our peer's addrLocal potentially useful as an external IP source?
[[nodiscard]] static bool IsPeerAddrLocalGood(CNode *pnode)
{
    CService addrLocal = pnode->GetAddrLocal();
    return fDiscover && pnode->addr.IsRoutable() && addrLocal.IsRoutable() &&
           g_reachable_nets.Contains(addrLocal);
}

std::optional<CService> GetLocalAddrForPeer(CNode& node)
{
    CService addrLocal{GetLocalAddress(node)};
    // If discovery is enabled, sometimes give our peer the address it
    // tells us that it sees us as in case it has a better idea of our
    // address than we do.
    FastRandomContext rng;
    if (IsPeerAddrLocalGood(&node) && (!addrLocal.IsRoutable() ||
         rng.randbits((GetnScore(addrLocal) > LOCAL_MANUAL) ? 3 : 1) == 0))
    {
        if (node.IsInboundConn()) {
            // For inbound connections, assume both the address and the port
            // as seen from the peer.
            addrLocal = CService{node.GetAddrLocal()};
        } else {
            // For outbound connections, assume just the address as seen from
            // the peer and leave the port in `addrLocal` as returned by
            // `GetLocalAddress()` above. The peer has no way to observe our
            // listening port when we have initiated the connection.
            addrLocal.SetIP(node.GetAddrLocal());
        }
    }
    if (addrLocal.IsRoutable()) {
        LogDebug(BCLog::NET, "Advertising address %s to peer=%d\n", addrLocal.ToStringAddrPort(), node.GetId());
        return addrLocal;
    }
    // Address is unroutable. Don't advertise.
    return std::nullopt;
}

void ClearLocal()
{
    LOCK(g_maplocalhost_mutex);
    return mapLocalHost.clear();
}

// learn a new local address
bool AddLocal(const CService& addr_, int nScore)
{
    CService addr{MaybeFlipIPv6toCJDNS(addr_)};

    if (!addr.IsRoutable())
        return false;

    if (!fDiscover && nScore < LOCAL_MANUAL)
        return false;

    if (!g_reachable_nets.Contains(addr))
        return false;

    LogInfo("AddLocal(%s,%i)\n", addr.ToStringAddrPort(), nScore);

    {
        LOCK(g_maplocalhost_mutex);
        const auto [it, is_newly_added] = mapLocalHost.emplace(addr, LocalServiceInfo());
        LocalServiceInfo &info = it->second;
        if (is_newly_added || nScore >= info.nScore) {
            info.nScore = nScore + (is_newly_added ? 0 : 1);
            info.nPort = addr.GetPort();
        }
    }

    return true;
}

bool AddLocal(const CNetAddr &addr, int nScore)
{
    return AddLocal(CService(addr, GetListenPort()), nScore);
}

void RemoveLocal(const CService& addr)
{
    LOCK(g_maplocalhost_mutex);
    LogInfo("RemoveLocal(%s)\n", addr.ToStringAddrPort());
    mapLocalHost.erase(addr);
}

/** vote for a local address */
bool SeenLocal(const CService& addr)
{
    LOCK(g_maplocalhost_mutex);
    const auto it = mapLocalHost.find(addr);
    if (it == mapLocalHost.end()) return false;
    ++it->second.nScore;
    return true;
}


/** check whether a given address is potentially local */
bool IsLocal(const CService& addr)
{
    LOCK(g_maplocalhost_mutex);
    return mapLocalHost.count(addr) > 0;
}

/** Try to find a connection to evict when the node is full.
 *  Extreme care must be taken to avoid opening the node to attacker
 *   triggered network partitioning.
 *  The strategy used here is to protect a small number of peers
 *   for each of several distinct characteristics which are difficult
 *   to forge.  In order to partition a node the attacker must be
 *   simultaneously better at all of them than honest peers.
 */
bool CConnman::AttemptToEvictConnection()
{
    std::vector<NodeEvictionCandidate> vEvictionCandidates;
    {

        LOCK(m_nodes_mutex);
        for (const CNode* node : m_nodes) {
            if (node->fDisconnect)
                continue;
            NodeEvictionCandidate candidate{
                .id = node->GetId(),
                .m_connected = node->m_connected,
                .m_min_ping_time = node->m_min_ping_time,
                .m_last_block_time = node->m_last_block_time,
                .m_last_tx_time = node->m_last_tx_time,
                .fRelevantServices = node->m_has_all_wanted_services,
                .m_relay_txs = node->m_relays_txs.load(),
                .fBloomFilter = node->m_bloom_filter_loaded.load(),
                .nKeyedNetGroup = node->nKeyedNetGroup,
                .prefer_evict = node->m_prefer_evict,
                .m_is_local = node->addr.IsLocal(),
                .m_network = node->ConnectedThroughNetwork(),
                .m_noban = node->HasPermission(NetPermissionFlags::NoBan),
                .m_conn_type = node->m_conn_type,
            };
            vEvictionCandidates.push_back(candidate);
        }
    }
    const std::optional<NodeId> node_id_to_evict = SelectNodeToEvict(std::move(vEvictionCandidates));
    if (!node_id_to_evict) {
        return false;
    }
    LOCK(m_nodes_mutex);
    for (CNode* pnode : m_nodes) {
        if (pnode->GetId() == *node_id_to_evict) {
            LogDebug(BCLog::NET, "selected %s connection for eviction, %s", pnode->ConnectionTypeAsString(), pnode->DisconnectMsg(fLogIPs));
            TRACEPOINT(net, evicted_inbound_connection,
                pnode->GetId(),
                pnode->m_addr_name.c_str(),
                pnode->ConnectionTypeAsString().c_str(),
                pnode->ConnectedThroughNetwork(),
                Ticks<std::chrono::seconds>(pnode->m_connected));
            pnode->fDisconnect = true;
            return true;
        }
    }
    return false;
}

bool CConnman::AddConnection(const std::string& address, ConnectionType conn_type, bool use_v2transport = false)
{
    AssertLockNotHeld(m_unused_i2p_sessions_mutex);
    std::optional<int> max_connections;
    switch (conn_type) {
    case ConnectionType::INBOUND:
    case ConnectionType::MANUAL:
        return false;
    case ConnectionType::OUTBOUND_FULL_RELAY:
        max_connections = m_max_outbound_full_relay;
        break;
    case ConnectionType::BLOCK_RELAY:
        max_connections = m_max_outbound_block_relay;
        break;
    // no limit for ADDR_FETCH because -seednode has no limit either
    case ConnectionType::ADDR_FETCH:
        break;
    // no limit for FEELER connections since they're short-lived
    case ConnectionType::FEELER:
        break;
    } // no default case, so the compiler can warn about missing cases

    // Count existing connections
    int existing_connections = WITH_LOCK(m_nodes_mutex,
                                         return std::count_if(m_nodes.begin(), m_nodes.end(), [conn_type](CNode* node) { return node->m_conn_type == conn_type; }););

    // Max connections of specified type already exist
    if (max_connections != std::nullopt && existing_connections >= max_connections) return false;

    // Max total outbound connections already exist
    CountingSemaphoreGrant<> grant(*semOutbound, true);
    if (!grant) return false;

    OpenNetworkConnection(CAddress(), false, std::move(grant), address.c_str(), conn_type, /*use_v2transport=*/use_v2transport);
    return true;
}

void CConnman::ThreadDNSAddressSeed()
{
    int outbound_connection_count = 0;

    if (!gArgs.GetArgs("-seednode").empty()) {
        auto start = NodeClock::now();
        constexpr std::chrono::seconds SEEDNODE_TIMEOUT = 30s;
        LogInfo("-seednode enabled. Trying the provided seeds for %d seconds before defaulting to the dnsseeds.\n", SEEDNODE_TIMEOUT.count());
        while (!m_interrupt_net->interrupted()) {
            if (!m_interrupt_net->sleep_for(500ms)) {
                return;
            }

            // Abort if we have spent enough time without reaching our target.
            // Giving seed nodes 30 seconds so this does not become a race against fixedseeds (which triggers after 1 min)
            if (NodeClock::now() > start + SEEDNODE_TIMEOUT) {
                LogInfo("Couldn't connect to enough peers via seed nodes. Handing fetch logic to the DNS seeds.\n");
                break;
            }

            outbound_connection_count = GetFullOutboundConnCount();
            if (outbound_connection_count >= SEED_OUTBOUND_CONNECTION_THRESHOLD) {
                LogInfo("P2P peers available. Finished fetching data from seed nodes.\n");
                break;
            }
        }
    }

    FastRandomContext rng;
    std::vector<std::string> seeds = m_params.DNSSeeds();
    std::shuffle(seeds.begin(), seeds.end(), rng);
    int seeds_right_now = 0; // Number of seeds left before testing if we have enough connections

    if (gArgs.GetBoolArg("-forcednsseed", DEFAULT_FORCEDNSSEED)) {
        // When -forcednsseed is provided, query all.
        seeds_right_now = seeds.size();
    } else if (addrman.Size() == 0) {
        // If we have no known peers, query all.
        // This will occur on the first run, or if peers.dat has been
        // deleted.
        seeds_right_now = seeds.size();
    }

    // Proceed with dnsseeds if seednodes hasn't reached the target or if forcednsseed is set
    if (outbound_connection_count < SEED_OUTBOUND_CONNECTION_THRESHOLD || seeds_right_now) {
        // goal: only query DNS seed if address need is acute
        // * If we have a reasonable number of peers in addrman, spend
        //   some time trying them first. This improves user privacy by
        //   creating fewer identifying DNS requests, reduces trust by
        //   giving seeds less influence on the network topology, and
        //   reduces traffic to the seeds.
        // * When querying DNS seeds query a few at once, this ensures
        //   that we don't give DNS seeds the ability to eclipse nodes
        //   that query them.
        // * If we continue having problems, eventually query all the
        //   DNS seeds, and if that fails too, also try the fixed seeds.
        //   (done in ThreadOpenConnections)
        int found = 0;
        const std::chrono::seconds seeds_wait_time = (addrman.Size() >= DNSSEEDS_DELAY_PEER_THRESHOLD ? DNSSEEDS_DELAY_MANY_PEERS : DNSSEEDS_DELAY_FEW_PEERS);

        for (const std::string& seed : seeds) {
            if (seeds_right_now == 0) {
                seeds_right_now += DNSSEEDS_TO_QUERY_AT_ONCE;

                if (addrman.Size() > 0) {
                    LogInfo("Waiting %d seconds before querying DNS seeds.\n", seeds_wait_time.count());
                    std::chrono::seconds to_wait = seeds_wait_time;
                    while (to_wait.count() > 0) {
                        // if sleeping for the MANY_PEERS interval, wake up
                        // early to see if we have enough peers and can stop
                        // this thread entirely freeing up its resources
                        std::chrono::seconds w = std::min(DNSSEEDS_DELAY_FEW_PEERS, to_wait);
                        if (!m_interrupt_net->sleep_for(w)) return;
                        to_wait -= w;

                        if (GetFullOutboundConnCount() >= SEED_OUTBOUND_CONNECTION_THRESHOLD) {
                            if (found > 0) {
                                LogInfo("%d addresses found from DNS seeds\n", found);
                                LogInfo("P2P peers available. Finished DNS seeding.\n");
                            } else {
                                LogInfo("P2P peers available. Skipped DNS seeding.\n");
                            }
                            return;
                        }
                    }
                }
            }

            if (m_interrupt_net->interrupted()) return;

            // hold off on querying seeds if P2P network deactivated
            if (!fNetworkActive) {
                LogInfo("Waiting for network to be reactivated before querying DNS seeds.\n");
                do {
                    if (!m_interrupt_net->sleep_for(1s)) return;
                } while (!fNetworkActive);
            }

            LogInfo("Loading addresses from DNS seed %s\n", seed);
            // If -proxy is in use, we make an ADDR_FETCH connection to the DNS resolved peer address
            // for the base dns seed domain in chainparams
            if (HaveNameProxy()) {
                AddAddrFetch(seed);
            } else {
                std::vector<CAddress> vAdd;
                constexpr ServiceFlags requiredServiceBits{SeedsServiceFlags()};
                std::string host = strprintf("x%x.%s", requiredServiceBits, seed);
                CNetAddr resolveSource;
                if (!resolveSource.SetInternal(host)) {
                    continue;
                }
                // Limit number of IPs learned from a single DNS seed. This limit exists to prevent the results from
                // one DNS seed from dominating AddrMan. Note that the number of results from a UDP DNS query is
                // bounded to 33 already, but it is possible for it to use TCP where a larger number of results can be
                // returned.
                unsigned int nMaxIPs = 32;
                const auto addresses{LookupHost(host, nMaxIPs, true)};
                if (!addresses.empty()) {
                    for (const CNetAddr& ip : addresses) {
                        CAddress addr = CAddress(CService(ip, m_params.GetDefaultPort()), requiredServiceBits);
                        addr.nTime = rng.rand_uniform_delay(Now<NodeSeconds>() - 3 * 24h, -4 * 24h); // use a random age between 3 and 7 days old
                        vAdd.push_back(addr);
                        found++;
                    }
                    addrman.Add(vAdd, resolveSource);
                } else {
                    // If the seed does not support a subdomain with our desired service bits,
                    // we make an ADDR_FETCH connection to the DNS resolved peer address for the
                    // base dns seed domain in chainparams
                    AddAddrFetch(seed);
                }
            }
            --seeds_right_now;
        }
        LogInfo("%d addresses found from DNS seeds\n", found);
    } else {
        LogInfo("Skipping DNS seeds. Enough peers have been found\n");
    }
}

void CConnman::DumpAddresses()
{
    const auto start{SteadyClock::now()};

    DumpPeerAddresses(::gArgs, addrman);

    LogDebug(BCLog::NET, "Flushed %d addresses to peers.dat  %dms\n",
             addrman.Size(), Ticks<std::chrono::milliseconds>(SteadyClock::now() - start));
}

void CConnman::ProcessAddrFetch()
{
    AssertLockNotHeld(m_unused_i2p_sessions_mutex);
    std::string strDest;
    {
        LOCK(m_addr_fetches_mutex);
        if (m_addr_fetches.empty())
            return;
        strDest = m_addr_fetches.front();
        m_addr_fetches.pop_front();
    }
    // Attempt v2 connection if we support v2 - we'll reconnect with v1 if our
    // peer doesn't support it or immediately disconnects us for another reason.
    const bool use_v2transport(GetLocalServices() & NODE_P2P_V2);
    CAddress addr;
    CountingSemaphoreGrant<> grant(*semOutbound, /*fTry=*/true);
    if (grant) {
        OpenNetworkConnection(addr, false, std::move(grant), strDest.c_str(), ConnectionType::ADDR_FETCH, use_v2transport);
    }
}

bool CConnman::GetTryNewOutboundPeer() const
{
    return m_try_another_outbound_peer;
}

void CConnman::SetTryNewOutboundPeer(bool flag)
{
    m_try_another_outbound_peer = flag;
    LogDebug(BCLog::NET, "setting try another outbound peer=%s\n", flag ? "true" : "false");
}

void CConnman::StartExtraBlockRelayPeers()
{
    LogDebug(BCLog::NET, "enabling extra block-relay-only peers\n");
    m_start_extra_block_relay_peers = true;
}

// Return the number of outbound connections that are full relay (not blocks only)
int CConnman::GetFullOutboundConnCount() const
{
    int nRelevant = 0;
    {
        LOCK(m_nodes_mutex);
        for (const CNode* pnode : m_nodes) {
            if (pnode->fSuccessfullyConnected && pnode->IsFullOutboundConn()) ++nRelevant;
        }
    }
    return nRelevant;
}

// Return the number of peers we have over our outbound connection limit
// Exclude peers that are marked for disconnect, or are going to be
// disconnected soon (eg ADDR_FETCH and FEELER)
// Also exclude peers that haven't finished initial connection handshake yet
// (so that we don't decide we're over our desired connection limit, and then
// evict some peer that has finished the handshake)
int CConnman::GetExtraFullOutboundCount() const
{
    int full_outbound_peers = 0;
    {
        LOCK(m_nodes_mutex);
        for (const CNode* pnode : m_nodes) {
            if (pnode->fSuccessfullyConnected && !pnode->fDisconnect && pnode->IsFullOutboundConn()) {
                ++full_outbound_peers;
            }
        }
    }
    return std::max(full_outbound_peers - m_max_outbound_full_relay, 0);
}

int CConnman::GetExtraBlockRelayCount() const
{
    int block_relay_peers = 0;
    {
        LOCK(m_nodes_mutex);
        for (const CNode* pnode : m_nodes) {
            if (pnode->fSuccessfullyConnected && !pnode->fDisconnect && pnode->IsBlockOnlyConn()) {
                ++block_relay_peers;
            }
        }
    }
    return std::max(block_relay_peers - m_max_outbound_block_relay, 0);
}

std::unordered_set<Network> CConnman::GetReachableEmptyNetworks() const
{
    std::unordered_set<Network> networks{};
    for (int n = 0; n < NET_MAX; n++) {
        enum Network net = (enum Network)n;
        if (net == NET_UNROUTABLE || net == NET_INTERNAL) continue;
        if (g_reachable_nets.Contains(net) && addrman.Size(net, std::nullopt) == 0) {
            networks.insert(net);
        }
    }
    return networks;
}

bool CConnman::MultipleManualOrFullOutboundConns(Network net) const
{
    AssertLockHeld(m_nodes_mutex);
    return m_network_conn_counts[net] > 1;
}

bool CConnman::MaybePickPreferredNetwork(std::optional<Network>& network)
{
    std::array<Network, 5> nets{NET_IPV4, NET_IPV6, NET_ONION, NET_I2P, NET_CJDNS};
    std::shuffle(nets.begin(), nets.end(), FastRandomContext());

    LOCK(m_nodes_mutex);
    for (const auto net : nets) {
        if (g_reachable_nets.Contains(net) && m_network_conn_counts[net] == 0 && addrman.Size(net) != 0) {
            network = net;
            return true;
        }
    }

    return false;
}

void CConnman::ThreadOpenConnections(const std::vector<std::string> connect, std::span<const std::string> seed_nodes)
{
    AssertLockNotHeld(m_unused_i2p_sessions_mutex);
    AssertLockNotHeld(m_reconnections_mutex);
    FastRandomContext rng;
    // Connect to specific addresses
    if (!connect.empty())
    {
        // Attempt v2 connection if we support v2 - we'll reconnect with v1 if our
        // peer doesn't support it or immediately disconnects us for another reason.
        const bool use_v2transport(GetLocalServices() & NODE_P2P_V2);
        for (int64_t nLoop = 0;; nLoop++)
        {
            for (const std::string& strAddr : connect)
            {
                CAddress addr(CService(), NODE_NONE);
                OpenNetworkConnection(addr, false, {}, strAddr.c_str(), ConnectionType::MANUAL, /*use_v2transport=*/use_v2transport);
                for (int i = 0; i < 10 && i < nLoop; i++)
                {
                    if (!m_interrupt_net->sleep_for(500ms)) {
                        return;
                    }
                }
            }
            if (!m_interrupt_net->sleep_for(500ms)) {
                return;
            }
            PerformReconnections();
        }
    }

    // Initiate network connections
    auto start = GetTime<std::chrono::microseconds>();

    // Minimum time before next feeler connection (in microseconds).
    auto next_feeler = start + rng.rand_exp_duration(FEELER_INTERVAL);
    auto next_extra_block_relay = start + rng.rand_exp_duration(EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL);
    auto next_extra_network_peer{start + rng.rand_exp_duration(EXTRA_NETWORK_PEER_INTERVAL)};
    const bool dnsseed = gArgs.GetBoolArg("-dnsseed", DEFAULT_DNSSEED);
    bool add_fixed_seeds = gArgs.GetBoolArg("-fixedseeds", DEFAULT_FIXEDSEEDS);
    const bool use_seednodes{!gArgs.GetArgs("-seednode").empty()};

    auto seed_node_timer = NodeClock::now();
    bool add_addr_fetch{addrman.Size() == 0 && !seed_nodes.empty()};
    constexpr std::chrono::seconds ADD_NEXT_SEEDNODE = 10s;

    if (!add_fixed_seeds) {
        LogInfo("Fixed seeds are disabled\n");
    }

    while (!m_interrupt_net->interrupted()) {
        if (add_addr_fetch) {
            add_addr_fetch = false;
            const auto& seed{SpanPopBack(seed_nodes)};
            AddAddrFetch(seed);

            if (addrman.Size() == 0) {
                LogInfo("Empty addrman, adding seednode (%s) to addrfetch\n", seed);
            } else {
                LogInfo("Couldn't connect to peers from addrman after %d seconds. Adding seednode (%s) to addrfetch\n", ADD_NEXT_SEEDNODE.count(), seed);
            }
        }

        ProcessAddrFetch();

        if (!m_interrupt_net->sleep_for(500ms)) {
            return;
        }

        PerformReconnections();

        CountingSemaphoreGrant<> grant(*semOutbound);
        if (m_interrupt_net->interrupted()) {
            return;
        }

        const std::unordered_set<Network> fixed_seed_networks{GetReachableEmptyNetworks()};
        if (add_fixed_seeds && !fixed_seed_networks.empty()) {
            // When the node starts with an empty peers.dat, there are a few other sources of peers before
            // we fallback on to fixed seeds: -dnsseed, -seednode, -addnode
            // If none of those are available, we fallback on to fixed seeds immediately, else we allow
            // 60 seconds for any of those sources to populate addrman.
            bool add_fixed_seeds_now = false;
            // It is cheapest to check if enough time has passed first.
            if (GetTime<std::chrono::seconds>() > start + std::chrono::minutes{1}) {
                add_fixed_seeds_now = true;
                LogInfo("Adding fixed seeds as 60 seconds have passed and addrman is empty for at least one reachable network\n");
            }

            // Perform cheap checks before locking a mutex.
            else if (!dnsseed && !use_seednodes) {
                LOCK(m_added_nodes_mutex);
                if (m_added_node_params.empty()) {
                    add_fixed_seeds_now = true;
                    LogInfo("Adding fixed seeds as -dnsseed=0 (or IPv4/IPv6 connections are disabled via -onlynet) and neither -addnode nor -seednode are provided\n");
                }
            }

            if (add_fixed_seeds_now) {
                std::vector<CAddress> seed_addrs{ConvertSeeds(m_params.FixedSeeds())};
                // We will not make outgoing connections to peers that are unreachable
                // (e.g. because of -onlynet configuration).
                // Therefore, we do not add them to addrman in the first place.
                // In case previously unreachable networks become reachable
                // (e.g. in case of -onlynet changes by the user), fixed seeds will
                // be loaded only for networks for which we have no addresses.
                seed_addrs.erase(std::remove_if(seed_addrs.begin(), seed_addrs.end(),
                                                [&fixed_seed_networks](const CAddress& addr) { return fixed_seed_networks.count(addr.GetNetwork()) == 0; }),
                                 seed_addrs.end());
                CNetAddr local;
                local.SetInternal("fixedseeds");
                addrman.Add(seed_addrs, local);
                add_fixed_seeds = false;
                LogInfo("Added %d fixed seeds from reachable networks.\n", seed_addrs.size());
            }
        }

        //
        // Choose an address to connect to based on most recently seen
        //
        CAddress addrConnect;

        // Only connect out to one peer per ipv4/ipv6 network group (/16 for IPv4).
        int nOutboundFullRelay = 0;
        int nOutboundBlockRelay = 0;
        int outbound_privacy_network_peers = 0;
        std::set<std::vector<unsigned char>> outbound_ipv46_peer_netgroups;

        {
            LOCK(m_nodes_mutex);
            for (const CNode* pnode : m_nodes) {
                if (pnode->IsFullOutboundConn()) nOutboundFullRelay++;
                if (pnode->IsBlockOnlyConn()) nOutboundBlockRelay++;

                // Make sure our persistent outbound slots to ipv4/ipv6 peers belong to different netgroups.
                switch (pnode->m_conn_type) {
                    // We currently don't take inbound connections into account. Since they are
                    // free to make, an attacker could make them to prevent us from connecting to
                    // certain peers.
                    case ConnectionType::INBOUND:
                    // Short-lived outbound connections should not affect how we select outbound
                    // peers from addrman.
                    case ConnectionType::ADDR_FETCH:
                    case ConnectionType::FEELER:
                        break;
                    case ConnectionType::MANUAL:
                    case ConnectionType::OUTBOUND_FULL_RELAY:
                    case ConnectionType::BLOCK_RELAY:
                        const CAddress address{pnode->addr};
                        if (address.IsTor() || address.IsI2P() || address.IsCJDNS()) {
                            // Since our addrman-groups for these networks are
                            // random, without relation to the route we
                            // take to connect to these peers or to the
                            // difficulty in obtaining addresses with diverse
                            // groups, we don't worry about diversity with
                            // respect to our addrman groups when connecting to
                            // these networks.
                            ++outbound_privacy_network_peers;
                        } else {
                            outbound_ipv46_peer_netgroups.insert(m_netgroupman.GetGroup(address));
                        }
                } // no default case, so the compiler can warn about missing cases
            }
        }

        if (!seed_nodes.empty() && nOutboundFullRelay < SEED_OUTBOUND_CONNECTION_THRESHOLD) {
            if (NodeClock::now() > seed_node_timer + ADD_NEXT_SEEDNODE) {
                seed_node_timer = NodeClock::now();
                add_addr_fetch = true;
            }
        }

        ConnectionType conn_type = ConnectionType::OUTBOUND_FULL_RELAY;
        auto now = GetTime<std::chrono::microseconds>();
        bool anchor = false;
        bool fFeeler = false;
        std::optional<Network> preferred_net;

        // Determine what type of connection to open. Opening
        // BLOCK_RELAY connections to addresses from anchors.dat gets the highest
        // priority. Then we open OUTBOUND_FULL_RELAY priority until we
        // meet our full-relay capacity. Then we open BLOCK_RELAY connection
        // until we hit our block-relay-only peer limit.
        // GetTryNewOutboundPeer() gets set when a stale tip is detected, so we
        // try opening an additional OUTBOUND_FULL_RELAY connection. If none of
        // these conditions are met, check to see if it's time to try an extra
        // block-relay-only peer (to confirm our tip is current, see below) or the next_feeler
        // timer to decide if we should open a FEELER.

        if (!m_anchors.empty() && (nOutboundBlockRelay < m_max_outbound_block_relay)) {
            conn_type = ConnectionType::BLOCK_RELAY;
            anchor = true;
        } else if (nOutboundFullRelay < m_max_outbound_full_relay) {
            // OUTBOUND_FULL_RELAY
        } else if (nOutboundBlockRelay < m_max_outbound_block_relay) {
            conn_type = ConnectionType::BLOCK_RELAY;
        } else if (GetTryNewOutboundPeer()) {
            // OUTBOUND_FULL_RELAY
        } else if (now > next_extra_block_relay && m_start_extra_block_relay_peers) {
            // Periodically connect to a peer (using regular outbound selection
            // methodology from addrman) and stay connected long enough to sync
            // headers, but not much else.
            //
            // Then disconnect the peer, if we haven't learned anything new.
            //
            // The idea is to make eclipse attacks very difficult to pull off,
            // because every few minutes we're finding a new peer to learn headers
            // from.
            //
            // This is similar to the logic for trying extra outbound (full-relay)
            // peers, except:
            // - we do this all the time on an exponential timer, rather than just when
            //   our tip is stale
            // - we potentially disconnect our next-youngest block-relay-only peer, if our
            //   newest block-relay-only peer delivers a block more recently.
            //   See the eviction logic in net_processing.cpp.
            //
            // Because we can promote these connections to block-relay-only
            // connections, they do not get their own ConnectionType enum
            // (similar to how we deal with extra outbound peers).
            next_extra_block_relay = now + rng.rand_exp_duration(EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL);
            conn_type = ConnectionType::BLOCK_RELAY;
        } else if (now > next_feeler) {
            next_feeler = now + rng.rand_exp_duration(FEELER_INTERVAL);
            conn_type = ConnectionType::FEELER;
            fFeeler = true;
        } else if (nOutboundFullRelay == m_max_outbound_full_relay &&
                   m_max_outbound_full_relay == MAX_OUTBOUND_FULL_RELAY_CONNECTIONS &&
                   now > next_extra_network_peer &&
                   MaybePickPreferredNetwork(preferred_net)) {
            // Full outbound connection management: Attempt to get at least one
            // outbound peer from each reachable network by making extra connections
            // and then protecting "only" peers from a network during outbound eviction.
            // This is not attempted if the user changed -maxconnections to a value
            // so low that less than MAX_OUTBOUND_FULL_RELAY_CONNECTIONS are made,
            // to prevent interactions with otherwise protected outbound peers.
            next_extra_network_peer = now + rng.rand_exp_duration(EXTRA_NETWORK_PEER_INTERVAL);
        } else {
            // skip to next iteration of while loop
            continue;
        }

        addrman.ResolveCollisions();

        const auto current_time{NodeClock::now()};
        int nTries = 0;
        const auto reachable_nets{g_reachable_nets.All()};

        while (!m_interrupt_net->interrupted()) {
            if (anchor && !m_anchors.empty()) {
                const CAddress addr = m_anchors.back();
                m_anchors.pop_back();
                if (!addr.IsValid() || IsLocal(addr) || !g_reachable_nets.Contains(addr) ||
                    !m_msgproc->HasAllDesirableServiceFlags(addr.nServices) ||
                    outbound_ipv46_peer_netgroups.count(m_netgroupman.GetGroup(addr))) continue;
                addrConnect = addr;
                LogDebug(BCLog::NET, "Trying to make an anchor connection to %s\n", addrConnect.ToStringAddrPort());
                break;
            }

            // If we didn't find an appropriate destination after trying 100 addresses fetched from addrman,
            // stop this loop, and let the outer loop run again (which sleeps, adds seed nodes, recalculates
            // already-connected network ranges, ...) before trying new addrman addresses.
            nTries++;
            if (nTries > 100)
                break;

            CAddress addr;
            NodeSeconds addr_last_try{0s};

            if (fFeeler) {
                // First, try to get a tried table collision address. This returns
                // an empty (invalid) address if there are no collisions to try.
                std::tie(addr, addr_last_try) = addrman.SelectTriedCollision();

                if (!addr.IsValid()) {
                    // No tried table collisions. Select a new table address
                    // for our feeler.
                    std::tie(addr, addr_last_try) = addrman.Select(true, reachable_nets);
                } else if (AlreadyConnectedToAddress(addr)) {
                    // If test-before-evict logic would have us connect to a
                    // peer that we're already connected to, just mark that
                    // address as Good(). We won't be able to initiate the
                    // connection anyway, so this avoids inadvertently evicting
                    // a currently-connected peer.
                    addrman.Good(addr);
                    // Select a new table address for our feeler instead.
                    std::tie(addr, addr_last_try) = addrman.Select(true, reachable_nets);
                }
            } else {
                // Not a feeler
                // If preferred_net has a value set, pick an extra outbound
                // peer from that network. The eviction logic in net_processing
                // ensures that a peer from another network will be evicted.
                std::tie(addr, addr_last_try) = preferred_net.has_value()
                    ? addrman.Select(false, {*preferred_net})
                    : addrman.Select(false, reachable_nets);
            }

            // Require outbound IPv4/IPv6 connections, other than feelers, to be to distinct network groups
            if (!fFeeler && outbound_ipv46_peer_netgroups.count(m_netgroupman.GetGroup(addr))) {
                continue;
            }

            // if we selected an invalid or local address, restart
            if (!addr.IsValid() || IsLocal(addr)) {
                break;
            }

            if (!g_reachable_nets.Contains(addr)) {
                continue;
            }

            // only consider very recently tried nodes after 30 failed attempts
            if (current_time - addr_last_try < 10min && nTries < 30) {
                continue;
            }

            // for non-feelers, require all the services we'll want,
            // for feelers, only require they be a full node (only because most
            // SPV clients don't have a good address DB available)
            if (!fFeeler && !m_msgproc->HasAllDesirableServiceFlags(addr.nServices)) {
                continue;
            } else if (fFeeler && !MayHaveUsefulAddressDB(addr.nServices)) {
                continue;
            }

            // Do not connect to bad ports, unless 50 invalid addresses have been selected already.
            if (nTries < 50 && (addr.IsIPv4() || addr.IsIPv6()) && IsBadPort(addr.GetPort())) {
                continue;
            }

            // Do not make automatic outbound connections to addnode peers, to
            // not use our limited outbound slots for them and to ensure
            // addnode connections benefit from their intended protections.
            if (AddedNodesContain(addr)) {
                LogDebug(BCLog::NET, "Not making automatic %s%s connection to %s peer selected for manual (addnode) connection%s\n",
                              preferred_net.has_value() ? "network-specific " : "",
                              ConnectionTypeAsString(conn_type), GetNetworkName(addr.GetNetwork()),
                              fLogIPs ? strprintf(": %s", addr.ToStringAddrPort()) : "");
                continue;
            }

            addrConnect = addr;
            break;
        }

        if (addrConnect.IsValid()) {
            if (fFeeler) {
                // Add small amount of random noise before connection to avoid synchronization.
                if (!m_interrupt_net->sleep_for(rng.rand_uniform_duration<CThreadInterrupt::Clock>(FEELER_SLEEP_WINDOW))) {
                    return;
                }
                LogDebug(BCLog::NET, "Making feeler connection to %s\n", addrConnect.ToStringAddrPort());
            }

            if (preferred_net != std::nullopt) LogDebug(BCLog::NET, "Making network specific connection to %s on %s.\n", addrConnect.ToStringAddrPort(), GetNetworkName(preferred_net.value()));

            // Record addrman failure attempts when node has at least 2 persistent outbound connections to peers with
            // different netgroups in ipv4/ipv6 networks + all peers in Tor/I2P/CJDNS networks.
            // Don't record addrman failure attempts when node is offline. This can be identified since all local
            // network connections (if any) belong in the same netgroup, and the size of `outbound_ipv46_peer_netgroups` would only be 1.
            const bool count_failures{((int)outbound_ipv46_peer_netgroups.size() + outbound_privacy_network_peers) >= std::min(m_max_automatic_connections - 1, 2)};
            // Use BIP324 transport when both us and them have NODE_V2_P2P set.
            const bool use_v2transport(addrConnect.nServices & GetLocalServices() & NODE_P2P_V2);
            OpenNetworkConnection(addrConnect, count_failures, std::move(grant), /*pszDest=*/nullptr, conn_type, use_v2transport);
        }
    }
}

std::vector<CAddress> CConnman::GetCurrentBlockRelayOnlyConns() const
{
    std::vector<CAddress> ret;
    LOCK(m_nodes_mutex);
    for (const CNode* pnode : m_nodes) {
        if (pnode->IsBlockOnlyConn()) {
            ret.push_back(pnode->addr);
        }
    }

    return ret;
}

std::vector<AddedNodeInfo> CConnman::GetAddedNodeInfo(bool include_connected) const
{
    std::vector<AddedNodeInfo> ret;

    std::list<AddedNodeParams> lAddresses(0);
    {
        LOCK(m_added_nodes_mutex);
        ret.reserve(m_added_node_params.size());
        std::copy(m_added_node_params.cbegin(), m_added_node_params.cend(), std::back_inserter(lAddresses));
    }


    // Build a map of all already connected addresses (by IP:port and by name) to inbound/outbound and resolved CService
    std::map<CService, bool> mapConnected;
    std::map<std::string, std::pair<bool, CService>> mapConnectedByName;
    {
        LOCK(m_nodes_mutex);
        for (const CNode* pnode : m_nodes) {
            if (pnode->addr.IsValid()) {
                mapConnected[pnode->addr] = pnode->IsInboundConn();
            }
            std::string addrName{pnode->m_addr_name};
            if (!addrName.empty()) {
                mapConnectedByName[std::move(addrName)] = std::make_pair(pnode->IsInboundConn(), static_cast<const CService&>(pnode->addr));
            }
        }
    }

    for (const auto& addr : lAddresses) {
        CService service{MaybeFlipIPv6toCJDNS(LookupNumeric(addr.m_added_node, GetDefaultPort(addr.m_added_node)))};
        AddedNodeInfo addedNode{addr, CService(), false, false};
        if (service.IsValid()) {
            // strAddNode is an IP:port
            auto it = mapConnected.find(service);
            if (it != mapConnected.end()) {
                if (!include_connected) {
                    continue;
                }
                addedNode.resolvedAddress = service;
                addedNode.fConnected = true;
                addedNode.fInbound = it->second;
            }
        } else {
            // strAddNode is a name
            auto it = mapConnectedByName.find(addr.m_added_node);
            if (it != mapConnectedByName.end()) {
                if (!include_connected) {
                    continue;
                }
                addedNode.resolvedAddress = it->second.second;
                addedNode.fConnected = true;
                addedNode.fInbound = it->second.first;
            }
        }
        ret.emplace_back(std::move(addedNode));
    }

    return ret;
}

void CConnman::ThreadOpenAddedConnections()
{
    AssertLockNotHeld(m_unused_i2p_sessions_mutex);
    AssertLockNotHeld(m_reconnections_mutex);
    while (true)
    {
        CountingSemaphoreGrant<> grant(*semAddnode);
        std::vector<AddedNodeInfo> vInfo = GetAddedNodeInfo(/*include_connected=*/false);
        bool tried = false;
        for (const AddedNodeInfo& info : vInfo) {
            if (!grant) {
                // If we've used up our semaphore and need a new one, let's not wait here since while we are waiting
                // the addednodeinfo state might change.
                break;
            }
            tried = true;
            CAddress addr(CService(), NODE_NONE);
            OpenNetworkConnection(addr, false, std::move(grant), info.m_params.m_added_node.c_str(), ConnectionType::MANUAL, info.m_params.m_use_v2transport);
            if (!m_interrupt_net->sleep_for(500ms)) return;
            grant = CountingSemaphoreGrant<>(*semAddnode, /*fTry=*/true);
        }
        // See if any reconnections are desired.
        PerformReconnections();
        // Retry every 60 seconds if a connection was attempted, otherwise two seconds
        if (!m_interrupt_net->sleep_for(tried ? 60s : 2s)) {
            return;
        }
    }
}

// if successful, this moves the passed grant to the constructed node
bool CConnman::OpenNetworkConnection(const CAddress& addrConnect,
                                     bool fCountFailure,
                                     CountingSemaphoreGrant<>&& grant_outbound,
                                     const char* pszDest,
                                     ConnectionType conn_type,
                                     bool use_v2transport,
                                     const std::optional<Proxy>& proxy_override)
{
    AssertLockNotHeld(m_unused_i2p_sessions_mutex);
    assert(conn_type != ConnectionType::INBOUND);

    //
    // Initiate outbound network connection
    //
    if (m_interrupt_net->interrupted()) {
        return false;
    }
    if (!fNetworkActive) {
        return false;
    }
    if (!pszDest) {
        bool banned_or_discouraged = m_banman && (m_banman->IsDiscouraged(addrConnect) || m_banman->IsBanned(addrConnect));
        if (IsLocal(addrConnect) || banned_or_discouraged || AlreadyConnectedToAddress(addrConnect)) {
            return false;
        }
    } else if (AlreadyConnectedToHost(pszDest)) {
        return false;
    }

    CNode* pnode = ConnectNode(addrConnect, pszDest, fCountFailure, conn_type, use_v2transport, proxy_override);

    if (!pnode)
        return false;
    pnode->grantOutbound = std::move(grant_outbound);

    m_msgproc->InitializeNode(*pnode, m_local_services);
    {
        LOCK(m_nodes_mutex);
        m_nodes.push_back(pnode);

        // update connection count by network
        if (pnode->IsManualOrFullOutboundConn()) ++m_network_conn_counts[pnode->addr.GetNetwork()];
    }

    TRACEPOINT(net, outbound_connection,
        pnode->GetId(),
        pnode->m_addr_name.c_str(),
        pnode->ConnectionTypeAsString().c_str(),
        pnode->ConnectedThroughNetwork(),
        GetNodeCount(ConnectionDirection::Out));

    return true;
}

void Discover()
{
    if (!fDiscover)
        return;

    for (const CNetAddr &addr: GetLocalAddresses()) {
        if (AddLocal(addr, LOCAL_IF))
            LogInfo("%s: %s\n", __func__, addr.ToStringAddr());
    }
}

std::vector<CAddress> CConnman::GetAddressesUnsafe(size_t max_addresses, size_t max_pct, std::optional<Network> network, const bool filtered) const
{
    std::vector<CAddress> addresses = addrman.GetAddr(max_addresses, max_pct, network, filtered);
    if (m_banman) {
        addresses.erase(std::remove_if(addresses.begin(), addresses.end(),
                        [this](const CAddress& addr){return m_banman->IsDiscouraged(addr) || m_banman->IsBanned(addr);}),
                        addresses.end());
    }
    return addresses;
}

std::vector<CAddress> CConnman::GetAddresses(CNode& requestor, size_t max_addresses, size_t max_pct)
{
    uint64_t network_id = requestor.m_network_key;
    const auto current_time = GetTime<std::chrono::microseconds>();
    auto r = m_addr_response_caches.emplace(network_id, CachedAddrResponse{});
    CachedAddrResponse& cache_entry = r.first->second;
    if (cache_entry.m_cache_entry_expiration < current_time) { // If emplace() added new one it has expiration 0.
        cache_entry.m_addrs_response_cache = GetAddressesUnsafe(max_addresses, max_pct, /*network=*/std::nullopt);
        // Choosing a proper cache lifetime is a trade-off between the privacy leak minimization
        // and the usefulness of ADDR responses to honest users.
        //
        // Longer cache lifetime makes it more difficult for an attacker to scrape
        // enough AddrMan data to maliciously infer something useful.
        // By the time an attacker scraped enough AddrMan records, most of
        // the records should be old enough to not leak topology info by
        // e.g. analyzing real-time changes in timestamps.
        //
        // It takes only several hundred requests to scrape everything from an AddrMan containing 100,000 nodes,
        // so ~24 hours of cache lifetime indeed makes the data less inferable by the time
        // most of it could be scraped (considering that timestamps are updated via
        // ADDR self-announcements and when nodes communicate).
        // We also should be robust to those attacks which may not require scraping *full* victim's AddrMan
        // (because even several timestamps of the same handful of nodes may leak privacy).
        //
        // On the other hand, longer cache lifetime makes ADDR responses
        // outdated and less useful for an honest requestor, e.g. if most nodes
        // in the ADDR response are no longer active.
        //
        // However, the churn in the network is known to be rather low. Since we consider
        // nodes to be "terrible" (see IsTerrible()) if the timestamps are older than 30 days,
        // max. 24 hours of "penalty" due to cache shouldn't make any meaningful difference
        // in terms of the freshness of the response.
        cache_entry.m_cache_entry_expiration = current_time +
            21h + FastRandomContext().randrange<std::chrono::microseconds>(6h);
    }
    return cache_entry.m_addrs_response_cache;
}

bool CConnman::AddNode(const AddedNodeParams& add)
{
    const CService resolved(LookupNumeric(add.m_added_node, GetDefaultPort(add.m_added_node)));
    const bool resolved_is_valid{resolved.IsValid()};

    LOCK(m_added_nodes_mutex);
    for (const auto& it : m_added_node_params) {
        if (add.m_added_node == it.m_added_node || (resolved_is_valid && resolved == LookupNumeric(it.m_added_node, GetDefaultPort(it.m_added_node)))) return false;
    }

    m_added_node_params.push_back(add);
    return true;
}

bool CConnman::RemoveAddedNode(std::string_view node)
{
    LOCK(m_added_nodes_mutex);
    for (auto it = m_added_node_params.begin(); it != m_added_node_params.end(); ++it) {
        if (node == it->m_added_node) {
            m_added_node_params.erase(it);
            return true;
        }
    }
    return false;
}

bool CConnman::AddedNodesContain(const CAddress& addr) const
{
    AssertLockNotHeld(m_added_nodes_mutex);
    const std::string addr_str{addr.ToStringAddr()};
    const std::string addr_port_str{addr.ToStringAddrPort()};
    LOCK(m_added_nodes_mutex);
    return (m_added_node_params.size() < 24 // bound the query to a reasonable limit
            && std::any_of(m_added_node_params.cbegin(), m_added_node_params.cend(),
                           [&](const auto& p) { return p.m_added_node == addr_str || p.m_added_node == addr_port_str; }));
}

size_t CConnman::GetNodeCount(ConnectionDirection flags) const
{
    LOCK(m_nodes_mutex);
    if (flags == ConnectionDirection::Both) // Shortcut if we want total
        return m_nodes.size();

    int nNum = 0;
    for (const auto& pnode : m_nodes) {
        if (flags & (pnode->IsInboundConn() ? ConnectionDirection::In : ConnectionDirection::Out)) {
            nNum++;
        }
    }

    return nNum;
}


std::map<CNetAddr, LocalServiceInfo> CConnman::getNetLocalAddresses() const
{
    LOCK(g_maplocalhost_mutex);
    return mapLocalHost;
}

uint32_t CConnman::GetMappedAS(const CNetAddr& addr) const
{
    return m_netgroupman.GetMappedAS(addr);
}


void CConnman::PerformReconnections()
{
    AssertLockNotHeld(m_reconnections_mutex);
    AssertLockNotHeld(m_unused_i2p_sessions_mutex);
    while (true) {
        // Move first element of m_reconnections to todo (avoiding an allocation inside the lock).
        decltype(m_reconnections) todo;
        {
            LOCK(m_reconnections_mutex);
            if (m_reconnections.empty()) break;
            todo.splice(todo.end(), m_reconnections, m_reconnections.begin());
        }

        auto& item = *todo.begin();
        OpenNetworkConnection(item.addr_connect,
                              // We only reconnect if the first attempt to connect succeeded at
                              // connection time, but then failed after the CNode object was
                              // created. Since we already know connecting is possible, do not
                              // count failure to reconnect.
                              /*fCountFailure=*/false,
                              std::move(item.grant),
                              item.destination.empty() ? nullptr : item.destination.c_str(),
                              item.conn_type,
                              item.use_v2transport);
    }
}

void CConnman::ASMapHealthCheck()
{
    const std::vector<CAddress> v4_addrs{GetAddressesUnsafe(/*max_addresses=*/0, /*max_pct=*/0, Network::NET_IPV4, /*filtered=*/false)};
    const std::vector<CAddress> v6_addrs{GetAddressesUnsafe(/*max_addresses=*/0, /*max_pct=*/0, Network::NET_IPV6, /*filtered=*/false)};
    std::vector<CNetAddr> clearnet_addrs;
    clearnet_addrs.reserve(v4_addrs.size() + v6_addrs.size());
    std::transform(v4_addrs.begin(), v4_addrs.end(), std::back_inserter(clearnet_addrs),
        [](const CAddress& addr) { return static_cast<CNetAddr>(addr); });
    std::transform(v6_addrs.begin(), v6_addrs.end(), std::back_inserter(clearnet_addrs),
        [](const CAddress& addr) { return static_cast<CNetAddr>(addr); });
    m_netgroupman.ASMapHealthCheck(clearnet_addrs);
}
