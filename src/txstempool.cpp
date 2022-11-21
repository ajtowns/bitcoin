// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txstempool.h>

#include <memusage.h>
#include <core_memusage.h>
#include <util/hasher.h>

#include <boost/multi_index/composite_key.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/mem_fun.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index_container.hpp>

namespace {
class Entry
{
public:
    CTransactionRef tx;
    NodeClock::time_point added_time;
    uint64_t spaminess;
    std::set<NodeId> stemmed_to;
    size_t tx_usage;

    Entry(CTransactionRef&& ptx, NodeClock::time_point time, uint64_t spaminess) : tx{ptx}, added_time{time}, spaminess{spaminess}, tx_usage{RecursiveDynamicUsage(tx)} { }
    Entry(const Entry&) = delete;
    Entry(Entry&&) = delete;
    Entry& operator=(const Entry&) = delete;
    Entry& operator=(Entry&&) = delete;

    const uint256& txid() const { return tx->GetHash(); }
    const uint256& wtxid() const { return tx->GetWitnessHash(); }
};
struct ByWtxid { };
struct ByTxid { };
struct BySpaminess { };
using EntryIndex = boost::multi_index_container<Entry,
    boost::multi_index::indexed_by<
        // sorted by wtxid
        boost::multi_index::ordered_unique<boost::multi_index::tag<ByWtxid>, boost::multi_index::const_mem_fun<Entry,const uint256&,&Entry::wtxid> >,
        // sorted by txid
        boost::multi_index::ordered_unique<boost::multi_index::tag<ByTxid>, boost::multi_index::const_mem_fun<Entry,const uint256&,&Entry::txid> >,
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
};
struct ByDestTime { };
struct ByEntryDest { };
using ActionIndex = boost::multi_index_container<Action,
    boost::multi_index::indexed_by<
        // sorted by entry/dest_peer
        boost::multi_index::ordered_unique<boost::multi_index::tag<ByEntryDest>,
                                           boost::multi_index::composite_key<Action,
                                                boost::multi_index::member<Action,EntryIter<ByWtxid>,&Action::entry>,
                                                boost::multi_index::member<Action,NodeId,&Action::dest_peer>>
                                          >,
        // sorted by dest_peer/action_time
        boost::multi_index::ordered_unique<boost::multi_index::tag<ByDestTime>,
                                           boost::multi_index::composite_key<Action,
                                                boost::multi_index::member<Action,NodeId,&Action::dest_peer>,
                                                boost::multi_index::member<Action,NodeClock::time_point,&Action::action_time>>
                                          >
    >
>;

} // anon namespace

class TxStemPool::Impl
{
private:
    EntryIndex m_entries;
    ActionIndex m_actions;

    size_t m_cached_inner_usage{0};
public:
    size_t DynamicMemoryUsage() const
    {
        // Estimate the overhead of multiindex to be 3*index pointers + an allocation, as no exact formula for boost::multi_index_contained is implemented.
        return m_cached_inner_usage + memusage::MallocUsage((sizeof(Entry) + 3*3*sizeof(void*)) * m_entries.size() + (sizeof(Action) + 3*2*sizeof(void*)) * m_actions.size());
    }
    size_t size() const { return m_entries.size(); }

    bool AddEntry(CTransactionRef ptx, const NodeClock::time_point& now, uint64_t spaminess)
    {
        auto& index = m_entries.get<ByTxid>();
        auto it = index.lower_bound(ptx->GetHash());
        if (it != index.end() && it->tx->GetHash() == ptx->GetHash()) {
            return false;
        }
        auto entry = index.emplace_hint(it, std::move(ptx), now, spaminess);
        // XXX EntryIter<ByTxid>().get(ptx->GetHash());
        return true;
    }
};

TxStemPool::TxStemPool() : m_impl{std::make_unique<Impl>()} { }
TxStemPool::~TxStemPool() = default;

bool TxStemPool::HaveTx(const uint256& txid, const uint256& wtxid, NodeId peer)
{
    return false;
}

void TxStemPool::AddTx(CTransactionRef&& ptx, uint64_t spaminess, const std::vector<std::tuple<NodeClock::time_point, NodeId>>& outbounds)
{
    return;
}

std::tuple<NodeId, CTransactionRef> TxStemPool::ExtractTrickleTx(NodeClock::time_point now)
{
    return {STEMPOOL_FLOOD_NODEID, nullptr}; // nothing
}

std::vector<CTransactionRef> TxStemPool::ExtractFloodTxs(NodeClock::time_point now, size_t maxdmu)
{
    return {}; // nothing
}

void TxStemPool::DropWtx(const uint256& wtxid)
{
    return;
}

void TxStemPool::DropTx(const uint256& txid)
{
    return;
}

size_t TxStemPool::size() const
{
    return m_impl->size();
}

size_t TxStemPool::DynamicMemoryUsage() const
{
    return m_impl->DynamicMemoryUsage();
}

