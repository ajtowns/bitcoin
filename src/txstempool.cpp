// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txstempool.h>

#include <util/hasher.h>

#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/mem_fun.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index_container.hpp>

namespace {
struct Entry
{
    CTransactionRef tx;
    NodeClock::time_point added_time;
    uint64_t spaminess;
    std::set<NodeId> seen_nodes;

    const uint256& wtxid() const { return tx->GetWitnessHash(); }
};
struct ByWtxid { };
struct BySpaminess { };
using EntryIndex = boost::multi_index_container<Entry,
    boost::multi_index::indexed_by<
        // sorted by wtxid
        boost::multi_index::ordered_unique<boost::multi_index::tag<ByWtxid>, boost::multi_index::const_mem_fun<Entry,const uint256&,&Entry::wtxid> >,
        // sorted by spaminess
        boost::multi_index::ordered_non_unique<boost::multi_index::tag<BySpaminess>, boost::multi_index::member<Entry,uint64_t,&Entry::spaminess> >
    >
>;
template<typename Tag>
using EntryIter = typename EntryIndex::index<Tag>::type::iterator;

struct Action
{
    EntryIter<ByWtxid> entry;
    NodeClock::time_point action_time;
    NodeId dest_peer; // -1 == inbounds and outbounds connected after entry->added_time

    using tuple_wtxid_dest = std::tuple<const uint256&, NodeId>;
    using tuple_dest_time = std::tuple<NodeId, NodeClock::time_point>;
    tuple_wtxid_dest wtxid_dest() const { return {entry->tx->GetWitnessHash(), dest_peer}; }
    tuple_dest_time dest_time() const { return {dest_peer, action_time}; }
};
struct ByDestTime { };
struct ByWtxidDest { };
using ActionIndex = boost::multi_index_container<Action,
    boost::multi_index::indexed_by<
        // sorted by wtxid/dest_peer
        boost::multi_index::ordered_unique<boost::multi_index::tag<ByWtxidDest>, boost::multi_index::const_mem_fun<Action,Action::tuple_wtxid_dest,&Action::wtxid_dest> >,
        // sorted by dest_peer/action_time
        boost::multi_index::ordered_non_unique<boost::multi_index::tag<ByDestTime>, boost::multi_index::const_mem_fun<Action,Action::tuple_dest_time,&Action::dest_time> >
    >
>;

} // anon namespace

class TxStemPool::Impl
{
public:
    EntryIndex m_entries;
    ActionIndex m_actions;
};

TxStemPool::TxStemPool() : m_impl{std::make_unique<Impl>()} { }
TxStemPool::~TxStemPool() = default;

