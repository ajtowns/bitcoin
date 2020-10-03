// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txrequest.h>

#include <crypto/siphash.h>
#include <net.h>
#include <primitives/transaction.h>
#include <random.h>
#include <uint256.h>
#include <util/memory.h>

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>

#include <chrono>
#include <unordered_map>
#include <utility>

#include <assert.h>

namespace {

/** The various states a (txhash,peer) pair can be in.
 *
 * Note that CANDIDATE is split up into 3 substates (DELAYED, BEST, READY), allowing more efficient implementation.
 * Also note that the sorting order of ByTxHashView relies on the specific order of values in this enum.
 *
 * Expected behaviour is:
 *   - When first announced by a peer, the state is CANDIDATE_DELAYED until reqtime is reached.
 *   - Announcemnets that have reached their reqtime but not been requested will be either CANDIDATE_READY or
 *     CANDIDATE_BEST
 *   - When requested, an announcement will be in state REQUESTED until expiry is reached.
 *   - If expiry is reached, or the peer replies to the request (either with NOTFOUND or the tx), the state becomes
 *     COMPLETED
 */
enum class State : uint8_t {
    /** A CANDIDATE announcement whose reqtime is in the future. */
    CANDIDATE_DELAYED,
    /** The best CANDIDATE for a given txhash; only if there is no REQUESTED announcement already for that txhash.
     *  The CANDIDATE_BEST is the lowest-priority announcement among all CANDIDATE_READY (and _BEST) ones for that
     *  txhash. */
    CANDIDATE_BEST,
    /** A REQUESTED announcement. */
    REQUESTED,
    /** A CANDIDATE announcement that's not CANDIDATE_DELAYED or CANDIDATE_BEST. */
    CANDIDATE_READY,
    /** A COMPLETED announcement. */
    COMPLETED,

    /** An invalid State value that's larger than all valid ones. */
    TOO_LARGE,
};

//! Type alias for sequence numbers.
using SequenceNumber = uint64_t;

/** An announcement. This is the data we track for each txid or wtxid that is announced to us by each peer. */
struct Announcement {
    /** Txid or wtxid that was announced. */
    const uint256 m_txhash;
    /** For CANDIDATE_{DELAYED,BEST,READY} the reqtime; for REQUESTED the expiry. */
    std::chrono::microseconds m_time;
    /** What peer the request was from. */
    const NodeId m_peer;
    /** What sequence number this announcement has. */
    const SequenceNumber m_sequence : 59;
    /** Whether the request is preferred. */
    const bool m_preferred : 1;
    /** Whether this is a wtxid request. */
    const bool m_is_wtxid : 1;

    /** What state this announcement is in. This is a uint8_t instead of a State to silence a GCC warning. */
    uint8_t m_state : 3;

    /** Convert the m_state variable to a State enum. */
    State GetState() const { return State(m_state); }
    /** Convert a State to a uint8_t and store it in m_state. */
    void SetState(State state) { m_state = uint8_t(state); }

    /** Whether this announcement is selected. There can be at most 1 selected peer per txhash. */
    bool IsSelected() const
    {
        return GetState() == State::CANDIDATE_BEST || GetState() == State::REQUESTED;
    }

    /** Whether this announcement is waiting for a certain time to pass. */
    bool IsWaiting() const
    {
        return GetState() == State::REQUESTED || GetState() == State::CANDIDATE_DELAYED;
    }

    /** Whether this announcement can feasibly be selected if the current IsSelected() one disappears. */
    bool IsSelectable() const
    {
        return GetState() == State::CANDIDATE_READY || GetState() == State::CANDIDATE_BEST;
    }

    /** Construct a new announcement from scratch, initially in CANDIDATE_DELAYED state. */
    Announcement(const GenTxid& gtxid, NodeId peer, bool preferred, std::chrono::microseconds reqtime,
        SequenceNumber sequence) :
        m_txhash(gtxid.GetHash()), m_time(reqtime), m_peer(peer), m_sequence(sequence), m_preferred(preferred),
        m_is_wtxid(gtxid.IsWtxid()), m_state(uint8_t(State::CANDIDATE_DELAYED)) {}
};

//! Type alias for priorities.
using Priority = uint64_t;

/** A functor with embedded salt that computes priority of an announcement.
 *
 * Lower priorities are selected first.
 */
class PriorityComputer {
    const uint64_t m_k0, m_k1;
public:
    explicit PriorityComputer(bool deterministic) :
        m_k0{deterministic ? 0 : GetRand(0xFFFFFFFFFFFFFFFF)},
        m_k1{deterministic ? 0 : GetRand(0xFFFFFFFFFFFFFFFF)} {}

    Priority operator()(const uint256& txhash, NodeId peer, bool preferred) const
    {
        uint64_t low_bits = CSipHasher(m_k0, m_k1).Write(txhash.begin(), txhash.size()).Write(peer).Finalize() >> 1;
        return low_bits | uint64_t{!preferred} << 63;
    }

    Priority operator()(const Announcement& ann) const
    {
        return operator()(ann.m_txhash, ann.m_peer, ann.m_preferred);
    }
};

// Definitions for the 3 indexes used in the main data structure.
//
// Each index has a By* type to identify it, a By*View data type to represent the view of Announcement it is sorted
// by, and an By*ViewExtractor type to convert an Announcement into the By*View type.
// See https://www.boost.org/doc/libs/1_54_0/libs/multi_index/doc/reference/key_extraction.html#key_extractors
// for more information about the key extraction concept.

// The ByPeer index is sorted by (peer, state == CANDIDATE_BEST, txhash)
//
// Uses:
// * Looking up existing announcements by peer/txhash, by checking both (peer, false, txhash) and
//   (peer, true, txhash).
// * Finding all CANDIDATE_BEST announcements for a given peer in GetRequestable.
struct ByPeer {};
using ByPeerView = std::tuple<NodeId, bool, const uint256&>;
struct ByPeerViewExtractor
{
    using result_type = ByPeerView;
    result_type operator()(const Announcement& ann) const
    {
        return ByPeerView{ann.m_peer, ann.GetState() == State::CANDIDATE_BEST, ann.m_txhash};
    }
};

// The ByTxHash index is sorted by (txhash, state, priority [CANDIDATE_READY]; 0 [otherwise])
//
// Uses:
// * Deleting all Announcements with a given txhash in ForgetTxHash.
// * Finding the best CANDIDATE_READY to convert to CANDIDATE_BEST, when no other CANDIDATE_READY or REQUESTED
//   Announcement exists for that txhash.
// * Determining when no more non-COMPLETED Announcements for a given txhash exist, so the COMPLETED ones can be
//   deleted.
struct ByTxHash {};
using ByTxHashView = std::tuple<const uint256&, State, Priority>;
class ByTxHashViewExtractor {
    const PriorityComputer& m_computer;
public:
    ByTxHashViewExtractor(const PriorityComputer& computer) : m_computer(computer) {}
    using result_type = ByTxHashView;
    result_type operator()(const Announcement& ann) const
    {
        const State state = ann.GetState();
        const Priority prio = (state == State::CANDIDATE_READY) ? m_computer(ann) : 0;
        return ByTxHashView{ann.m_txhash, state, prio};
    }
};

// The ByTime index is sorted by (0 [CANDIDATE_DELAYED,REQUESTED]; 1 [COMPLETED];
// 2 [CANDIDATE_READY,CANDIDATE_BEST], time)
//
// Uses:
// * Finding CANDIDATE_DELAYED announcements whose reqtime has passed, and REQUESTED announcements whose expiry has
//   passed.
// * Finding CANDIDATE_READY/BEST announcements whose reqtime is in the future (when the clock time went backwards).
struct ByTime {};
using ByTimeView = std::pair<int, std::chrono::microseconds>;
struct ByTimeViewExtractor
{
    using result_type = ByTimeView;
    result_type operator()(const Announcement& ann) const
    {
        return ByTimeView{ann.IsWaiting() ? 0 : ann.IsSelectable() ? 2 : 1, ann.m_time};
    }
};

/** Data type for the main data structure (Announcement objects with ByPeer/ByTxHash/ByTime indexes). */
using Index = boost::multi_index_container<
    Announcement,
    boost::multi_index::indexed_by<
        boost::multi_index::ordered_unique<boost::multi_index::tag<ByPeer>, ByPeerViewExtractor>,
        boost::multi_index::ordered_non_unique<boost::multi_index::tag<ByTxHash>, ByTxHashViewExtractor>,
        boost::multi_index::ordered_non_unique<boost::multi_index::tag<ByTime>, ByTimeViewExtractor>
    >
>;

/** Helper type to simplify syntax of iterator types. */
template<typename Tag>
using Iter = typename Index::index<Tag>::type::iterator;

/** Per-peer statistics object. */
struct PeerInfo {
    size_t m_total = 0; //!< Total number of announcements for this peer.
    size_t m_completed = 0; //!< Number of COMPLETED announcements for this peer.
    size_t m_requested = 0; //!< Number of REQUESTED announcements for this peer.
};

/** Per-txhash statistics object. Only used for sanity checking. */
struct TxHashInfo
{
    //! Number of CANDIDATE_DELAYED entries for this txhash.
    size_t m_candidate_delayed = 0;
    //! Number of CANDIDATE_READY entries for this txhash.
    size_t m_candidate_ready = 0;
    //! Number of CANDIDATE_BEST entries for this txhash (at most one).
    size_t m_candidate_best = 0;
    //! Number of REQUESTED entries for this txhash.
    size_t m_requested = 0;
    //! The priority of the CANDIDATE_BEST announcement if one exists, or 0 otherwise.
    uint64_t m_priority_candidate_best = 0;
    //! The lowest priority of all CANDIDATE_READY entries (or max() if none exist).
    uint64_t m_priority_best_candidate_ready = std::numeric_limits<uint64_t>::max();
    //! All peers we have an announcement for this txhash for.
    std::vector<uint64_t> m_peers;
};

/** Compare two PeerInfo objects. Only used for sanity checking. */
bool operator==(const PeerInfo& a, const PeerInfo& b)
{
    return std::tie(a.m_total, a.m_completed, a.m_requested) ==
           std::tie(b.m_total, b.m_completed, b.m_requested);
};

/** (Re)compute the PeerInfo map from the index. Only used for sanity checking. */
std::unordered_map<NodeId, PeerInfo> RecomputePeerInfo(const Index& index)
{
    std::unordered_map<NodeId, PeerInfo> ret;
    for (const Announcement& ann : index) {
        PeerInfo& info = ret[ann.m_peer];
        ++info.m_total;
        info.m_requested += (ann.GetState() == State::REQUESTED);
        info.m_completed += (ann.GetState() == State::COMPLETED);
    }
    return ret;
}

/** Compute the TxHashInfo map. Only used for sanity checking. */
std::map<uint256, TxHashInfo> ComputeTxHashInfo(const Index& index, const PriorityComputer& computer)
{
    std::map<uint256, TxHashInfo> ret;
    for (const Announcement& ann : index) {
        TxHashInfo& info = ret[ann.m_txhash];
        // Classify how many Entrys of each state we have for this txhash.
        info.m_candidate_delayed += (ann.GetState() == State::CANDIDATE_DELAYED);
        info.m_candidate_ready += (ann.GetState() == State::CANDIDATE_READY);
        info.m_candidate_best += (ann.GetState() == State::CANDIDATE_BEST);
        info.m_requested += (ann.GetState() == State::REQUESTED);
        // And track the priority of the best CANDIDATE_READY/CANDIDATE_BEST entries.
        if (ann.GetState() == State::CANDIDATE_BEST) {
            info.m_priority_candidate_best = computer(ann);
        }
        if (ann.GetState() == State::CANDIDATE_READY) {
            info.m_priority_best_candidate_ready = std::min(info.m_priority_best_candidate_ready, computer(ann));
        }
        // Also keep track of which peers this txhash has a Entry for (so we can detect duplicates).
        info.m_peers.push_back(ann.m_peer);
        // Track preferred/first.
    }
    return ret;
}

const uint256 UINT256_ZERO;

}  // namespace

/** Actual implementation for TxRequestTracker's data structure. */
class TxRequestTracker::Impl {
    //! The current sequence number. Increases for every announcement. This is used to sort txhashes returned by
    //! GetRequestable in announcement order.
    SequenceNumber m_current_sequence{0};

    //! This tracker's priority computer.
    const PriorityComputer m_computer;

    //! This tracker's main data structure. See SanityCheck() for the invariants that apply to it.
    Index m_index;

    //! Map with this tracker's per-peer statistics.
    std::unordered_map<NodeId, PeerInfo> m_peerinfo;

    //! Whether to do debug logging
    bool m_logging = false;

public:
    void SanityCheck() const
    {
        // Recompute m_peerdata from m_index. This verifies the data in it as it should just be caching statistics
        // on m_index. It also verifies the invariant that no PeerInfo entries exist with m_total==0 exist.
        assert(m_peerinfo == RecomputePeerInfo(m_index));

        // Calculate per-txhash statistics from m_index, and validate invariants.
        for (auto& item : ComputeTxHashInfo(m_index, m_computer)) {
            TxHashInfo& info = item.second;

            // Cannot have only COMPLETED peer (txhash should have been forgotten already)
            assert(info.m_candidate_delayed + info.m_candidate_ready + info.m_candidate_best + info.m_requested > 0);

            // Can have at most 1 CANDIDATE_BEST/REQUESTED peer
            assert(info.m_candidate_best + info.m_requested <= 1);

            // If there are any CANDIDATE_READY entries, there must be exactly one CANDIDATE_BEST or REQUESTED
            // announcement.
            if (info.m_candidate_ready > 0) {
                assert(info.m_candidate_best + info.m_requested == 1);
            }

            // If there is both a CANDIDATE_READY and a CANDIDATE_BEST announcement, the CANDIDATE_BEST one must be
            // at least as good (equal or lower priority) as the best CANDIDATE_READY.
            if (info.m_candidate_ready && info.m_candidate_best) {
                assert(info.m_priority_candidate_best <= info.m_priority_best_candidate_ready);
            }

            // No txhash can have been announced by the same peer twice.
            std::sort(info.m_peers.begin(), info.m_peers.end());
            assert(std::adjacent_find(info.m_peers.begin(), info.m_peers.end()) == info.m_peers.end());

            // Looking up the last ByTxHash announcement with the given txhash must return an Announcement with that
            // txhash or the multi_index is very bad.
            auto it_last = std::prev(m_index.get<ByTxHash>().lower_bound(
                ByTxHashView{item.first, State::TOO_LARGE, 0}));
            assert(it_last != m_index.get<ByTxHash>().end() && it_last->m_txhash == item.first);
        }
    }

    void PostGetRequestableSanityCheck(std::chrono::microseconds now) const
    {
        for (const Announcement& ann : m_index) {
            if (ann.IsWaiting()) {
                // REQUESTED and CANDIDATE_DELAYED must have a time in the future (they should have been converted
                // to COMPLETED/CANDIDATE_READY respectively).
                assert(ann.m_time > now);
            } else if (ann.IsSelectable()) {
                // CANDIDATE_READY and CANDIDATE_BEST cannot have a time in the future (they should have remained
                // CANDIDATE_DELAYED, or should have been converted back to it if time went backwards).
                assert(ann.m_time <= now);
            }
        }
    }

private:
    //! Wrapper around Index::...::erase that keeps m_peerinfo up to date.
    template<typename Tag>
    Iter<Tag> Erase(Iter<Tag> it)
    {
        auto peerit = m_peerinfo.find(it->m_peer);
        peerit->second.m_completed -= it->GetState() == State::COMPLETED;
        peerit->second.m_requested -= it->GetState() == State::REQUESTED;
        if (--peerit->second.m_total == 0) m_peerinfo.erase(peerit);
        return m_index.get<Tag>().erase(it);
    }

    //! Wrapper around Index::...::modify that keeps m_peerinfo up to date.
    template<typename Tag, typename Modifier>
    void Modify(Iter<Tag> it, Modifier modifier)
    {
        auto peerit = m_peerinfo.find(it->m_peer);
        peerit->second.m_completed -= it->GetState() == State::COMPLETED;
        peerit->second.m_requested -= it->GetState() == State::REQUESTED;
        m_index.get<Tag>().modify(it, std::move(modifier));
        peerit->second.m_completed += it->GetState() == State::COMPLETED;
        peerit->second.m_requested += it->GetState() == State::REQUESTED;
    }

    //! Convert a CANDIDATE_DELAYED announcement into a CANDIDATE_READY. If this makes it the new best
    //! CANDIDATE_READY (and no REQUESTED exists) and better than the CANDIDATE_BEST (if any), it becomes the new
    //! CANDIDATE_BEST.
    void PromoteCandidateReady(Iter<ByTxHash> it)
    {
        assert(it != m_index.get<ByTxHash>().end());
        assert(it->GetState() == State::CANDIDATE_DELAYED);
        // Convert CANDIDATE_DELAYED to CANDIDATE_READY first.
        Modify<ByTxHash>(it, [](Announcement& ann){ ann.SetState(State::CANDIDATE_READY); });
        // The following code relies on the fact that the ByTxHash is sorted by txhash, and then by state (first
        // _DELAYED, then _BEST/REQUESTED, then _READY). Within the _READY announcements, the best one (lowest
        // priority) comes first. Thus, if an existing _BEST exists for the same txhash that this announcement may
        // be preferred over, it must immediately precede the newly created _READY.
        if (it == m_index.get<ByTxHash>().begin() || std::prev(it)->m_txhash != it->m_txhash ||
            std::prev(it)->GetState() == State::CANDIDATE_DELAYED) {
            // This is the new best CANDIDATE_READY, and there is no IsSelected() announcement for this txhash
            // already.
            Modify<ByTxHash>(it, [](Announcement& ann){ ann.SetState(State::CANDIDATE_BEST); });
        } else if (std::prev(it)->GetState() == State::CANDIDATE_BEST) {
            Priority priority_old = m_computer(*std::prev(it));
            Priority priority_new = m_computer(*it);
            if (priority_new < priority_old) {
                // There is a CANDIDATE_BEST announcement already, but this one is better.
                auto new_ready_it = std::prev(it);
                Modify<ByTxHash>(new_ready_it, [](Announcement& ann){ ann.SetState(State::CANDIDATE_READY); });
                Modify<ByTxHash>(it, [](Announcement& ann){ ann.SetState(State::CANDIDATE_BEST); });
            }
        }
    }

    //! Change the state of an announcement to something non-IsSelected(). If it was IsSelected(), the next best
    //! announcement will be marked CANDIDATE_BEST.
    void ChangeAndReselect(Iter<ByTxHash> it, State new_state)
    {
        assert(it != m_index.get<ByTxHash>().end());
        if (it->IsSelected()) {
            auto it_next = std::next(it);
            // The next best CANDIDATE_READY, if any, immediately follows the REQUESTED or CANDIDATE_BEST
            // announcement in the ByTxHash index.
            if (it_next != m_index.get<ByTxHash>().end() && it_next->m_txhash == it->m_txhash &&
                it_next->GetState() == State::CANDIDATE_READY) {
                // If one such CANDIDATE_READY exists (for this txhash), convert it to CANDIDATE_BEST.
                Modify<ByTxHash>(it_next, [](Announcement& ann){ ann.SetState(State::CANDIDATE_BEST); });
            }
        }
        Modify<ByTxHash>(it, [new_state](Announcement& ann){ ann.SetState(new_state); });
        assert(!it->IsSelected());
    }

    //! Check if 'it' is the only Announcement for a given txhash that isn't COMPLETED.
    bool IsOnlyNonCompleted(Iter<ByTxHash> it)
    {
        assert(it != m_index.get<ByTxHash>().end());
        assert(it->GetState() != State::COMPLETED); // Not allowed to call this on COMPLETED announcements.

        // If this Announcement's predecessor exists, and belongs to the same txhash, it can't be COMPLETED either.
        if (it != m_index.get<ByTxHash>().begin() && std::prev(it)->m_txhash == it->m_txhash) return false;

        // If this Announcement's successor exists, belongs to the same txhash, and isn't COMPLETED, fail.
        if (std::next(it) != m_index.get<ByTxHash>().end() && std::next(it)->m_txhash == it->m_txhash &&
            std::next(it)->GetState() != State::COMPLETED) return false;

        return true;
    }

    /** Convert any announcement to a COMPLETED one. If there are no non-COMPLETED announcements left for this
     *  txhash, they are deleted. If this was a REQUESTED announcement, and there are other CANDIDATEs left, the
     *  best one is made CANDIDATE_BEST. Returns whether the Announcement still exists. */
    bool MakeCompleted(Iter<ByTxHash> it)
    {
        assert(it != m_index.get<ByTxHash>().end());

        // Nothing to be done if it's already COMPLETED.
        if (it->GetState() == State::COMPLETED) return true;

        if (IsOnlyNonCompleted(it)) {
            // This is the last non-COMPLETED announcement for this txhash. Delete all.
            uint256 txhash = it->m_txhash;
            int count = 0;
            do {
                it = Erase<ByTxHash>(it);
                ++count;
            } while (it != m_index.get<ByTxHash>().end() && it->m_txhash == txhash);
            if (m_logging) {
                LogPrint(BCLog::NET, "txrequest expiring txid=%s completed=%d\n", txhash.ToString(), count);
            }
            return false;
        }

        // Mark the announcement COMPLETED, and select the next best announcement (the first CANDIDATE_READY) if
        // needed.
        ChangeAndReselect(it, State::COMPLETED);

        return true;
    }

    //! Make the data structure consistent with a given point in time:
    //! - REQUESTED annoucements with expiry <= now are turned into COMPLETED.
    //! - CANDIDATE_DELAYED announcements with reqtime <= now are turned into CANDIDATE_{READY,BEST}.
    //! - CANDIDATE_{READY,BEST} announcements with reqtime > now are turned into CANDIDATE_DELAYED.
    void SetTimePoint(std::chrono::microseconds now)
    {
        // Iterate over all CANDIDATE_DELAYED and REQUESTED from old to new, as long as they're in the past,
        // and convert them to CANDIDATE_READY and COMPLETED respectively.
        while (!m_index.empty()) {
            auto it = m_index.get<ByTime>().begin();
            if (it->GetState() == State::CANDIDATE_DELAYED && it->m_time <= now) {
                PromoteCandidateReady(m_index.project<ByTxHash>(it));
            } else if (it->GetState() == State::REQUESTED && it->m_time <= now) {
                MakeCompleted(m_index.project<ByTxHash>(it));
            } else {
                break;
            }
        }

        while (!m_index.empty()) {
            // If time went backwards, we may need to demote CANDIDATE_BEST and CANDIDATE_READY announcements back
            // to CANDIDATE_DELAYED. This is an unusual edge case, and unlikely to matter in production. However,
            // it makes it much easier to specify and test TxRequestTracker::Impl's behaviour.
            auto it = std::prev(m_index.get<ByTime>().end());
            if (it->IsSelectable() && it->m_time > now) {
                ChangeAndReselect(m_index.project<ByTxHash>(it), State::CANDIDATE_DELAYED);
            } else {
                break;
            }
        }
    }

public:
    Impl(bool deterministic) :
        m_computer(deterministic),
        // Explicitly initialize m_index as we need to pass a reference to m_computer to ByTxHashViewExtractor.
        m_index(boost::make_tuple(
            boost::make_tuple(ByPeerViewExtractor(), std::less<ByPeerView>()),
            boost::make_tuple(ByTxHashViewExtractor(m_computer), std::less<ByTxHashView>()),
            boost::make_tuple(ByTimeViewExtractor(), std::less<ByTimeView>())
        )) {}

    // Disable copying and assigning (a default copy won't work due the stateful ByTxHashViewExtractor).
    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;

    void DisconnectedPeer(NodeId peer)
    {
        auto& index = m_index.get<ByPeer>();
        auto it = index.lower_bound(ByPeerView{peer, false, UINT256_ZERO});
        while (it != index.end() && it->m_peer == peer) {
            // Check what to continue with after this iteration. Note that 'it' may change position, and
            // std::next(it) may be deleted in the process, so this needs to be decided beforehand.
            auto it_next = (std::next(it) == index.end() || std::next(it)->m_peer != peer) ?
                index.end() : std::next(it);
            // If the announcement isn't already COMPLETED, first make it COMPLETED (which will mark other
            // CANDIDATEs as CANDIDATE_BEST, or delete all of a txhash's announcements if no non-COMPLETED ones are
            // left).
            if (MakeCompleted(m_index.project<ByTxHash>(it))) {
                // Then actually delete the announcement (unless it was already deleted by MakeCompleted).
                Erase<ByPeer>(it);
            }
            it = it_next;
        }
    }

    void ForgetTxHash(const uint256& txhash)
    {
        auto it = m_index.get<ByTxHash>().lower_bound(ByTxHashView{txhash, State::CANDIDATE_DELAYED, 0});
        while (it != m_index.get<ByTxHash>().end() && it->m_txhash == txhash) {
            it = Erase<ByTxHash>(it);
        }
    }

    void ReceivedInv(NodeId peer, const GenTxid& gtxid, bool preferred,
        std::chrono::microseconds reqtime)
    {
        // Bail out if we already have a CANDIDATE_BEST announcement for this (txhash, peer) combination. The case
        // where there is a non-CANDIDATE_BEST announcement already will be caught by the uniqueness property of the
        // ByPeer index when we try to emplace the new object below.
        if (m_index.get<ByPeer>().count(ByPeerView{peer, true, gtxid.GetHash()})) return;

        // Try creating the announcement with CANDIDATE_DELAYED state (which will fail due to the uniqueness
        // of the ByPeer index if a non-CANDIDATE_BEST announcement already exists with the same txhash and peer).
        // Bail out in that case.
        auto ret = m_index.get<ByPeer>().emplace(gtxid, peer, preferred, reqtime, m_current_sequence);
        if (!ret.second) return;

        // Update accounting metadata.
        ++m_peerinfo[peer].m_total;
        ++m_current_sequence;
    }

    //! Find the GenTxids to request now from peer.
    std::vector<GenTxid> GetRequestable(NodeId peer, std::chrono::microseconds now)
    {
        // Move time.
        SetTimePoint(now);

        // Find all CANDIDATE_BEST announcements for this peer.
        std::vector<std::pair<SequenceNumber, const Announcement*>> selected;
        auto it_peer = m_index.get<ByPeer>().lower_bound(ByPeerView{peer, true, UINT256_ZERO});
        while (it_peer != m_index.get<ByPeer>().end() && it_peer->m_peer == peer &&
            it_peer->GetState() == State::CANDIDATE_BEST) {
            selected.emplace_back(it_peer->m_sequence, &*it_peer);
            ++it_peer;
        }

        // Return them, sorted by sequence number.
        std::sort(selected.begin(), selected.end());
        std::vector<GenTxid> ret;
        for (const auto& item : selected) {
            ret.emplace_back(item.second->m_is_wtxid, item.second->m_txhash);
        }
        return ret;
    }

    void RequestedTx(NodeId peer, const uint256& txhash, std::chrono::microseconds expiry)
    {
        if (m_logging && LogAcceptCategory(BCLog::NET)) {
            int delayed[2] = {0,0};
            int candidate[2] = {0,0};
            int completed[2] = {0,0};
            bool requested = false;
            int preferred = -1;
            for (Iter<ByTxHash> it_txid = m_index.get<ByTxHash>().lower_bound(ByTxHashView{txhash, State::CANDIDATE_DELAYED, 0});
                 it_txid != m_index.get<ByTxHash>().end() && it_txid->m_txhash == txhash;
                 ++it_txid)
           {
                switch (it_txid->GetState()) {
                case State::CANDIDATE_DELAYED:
                    ++delayed[it_txid->m_preferred];
                    break;
                case State::CANDIDATE_READY:
                case State::CANDIDATE_BEST:
                    ++candidate[it_txid->m_preferred];
                    break;
                case State::COMPLETED:
                    ++completed[it_txid->m_preferred];
                    break;
                case State::REQUESTED:
                    requested = true;
                    break;
                case State::TOO_LARGE: break; // invalid
                }
                if (it_txid->m_peer == peer) preferred = it_txid->m_preferred ? 1 : 0;
            }
            LogPrint(BCLog::NET, "txrequest requested txid=%s preferred=%d delayed=[%d,%d] candidate=[%d,%d] completed=[%d,%d]%s peer=%d\n",
                txhash.ToString(), preferred,
                delayed[1], delayed[0],
                candidate[1], candidate[0],
                completed[1], completed[0],
                (requested ? " REPLACEMENT" : ""),
                peer);
        }

        auto it = m_index.get<ByPeer>().find(ByPeerView{peer, true, txhash});
        if (it == m_index.get<ByPeer>().end()) {
            // There is no CANDIDATE_BEST announcement, look for a _READY or _DELAYED instead. If the caller only
            // ever invokes RequestedTx with the values returned by GetRequestable, and no other non-const functions
            // other than ForgetTxHash and GetRequestable in between, this branch will never execute (as txhashes
            // returned by GetRequestable always correspond to CANDIDATE_BEST announcements).

            it = m_index.get<ByPeer>().find(ByPeerView{peer, false, txhash});
            if (it == m_index.get<ByPeer>().end() || (it->GetState() != State::CANDIDATE_DELAYED &&
                it->GetState() != State::CANDIDATE_READY)) {
                // The txhash was not tracked for this peer, so we have nothing to do. The caller should have called
                // ReceivedInv first.
                return;
            }

            // Look for an existing CANDIDATE_BEST or REQUESTED.
            auto it_old = m_index.get<ByTxHash>().lower_bound(ByTxHashView{txhash, State::CANDIDATE_BEST, 0});
            if (it_old != m_index.get<ByTxHash>().end() && it_old->m_txhash == txhash) {
                if (it_old->GetState() == State::CANDIDATE_BEST) {
                    // The data structure's invariants require that there can be at most one CANDIDATE_BEST or one
                    // REQUESTED announcement per txhash (but not both simultaneously), so we have to convert any
                    // existing CANDIDATE_BEST to another CANDIDATE_* when constructing another REQUESTED.
                    // It doesn't matter whether we pick CANDIDATE_READY or _DELAYED here, as SetTimePoint()
                    // will correct it at GetRequestable() time. If time only goes forward, it will always be
                    // _READY, so pick that to avoid extra work in SetTimePoint().
                    Modify<ByTxHash>(it_old, [](Announcement& ann) { ann.SetState(State::CANDIDATE_READY); });
                } else if (it_old->GetState() == State::REQUESTED) {
                    // As we're no longer waiting for a response to the previous REQUESTED announcement, convert it
                    // to COMPLETED. This also helps guaranteeing progress.
                    Modify<ByTxHash>(it_old, [](Announcement& ann) { ann.SetState(State::COMPLETED); });
                }
            }
        }

        Modify<ByPeer>(it, [expiry](Announcement& ann) {
            ann.SetState(State::REQUESTED);
            ann.m_time = expiry;
        });
    }

    void ReceivedResponse(NodeId peer, const uint256& txhash)
    {
        // We need to search the ByPeer index for both (peer, false, txhash) and (peer, true, txhash).
        auto it = m_index.get<ByPeer>().find(ByPeerView{peer, false, txhash});
        if (it == m_index.get<ByPeer>().end()) {
            it = m_index.get<ByPeer>().find(ByPeerView{peer, true, txhash});
        }
        if (it != m_index.get<ByPeer>().end()) MakeCompleted(m_index.project<ByTxHash>(it));
    }

    size_t CountInFlight(NodeId peer) const
    {
        auto it = m_peerinfo.find(peer);
        if (it != m_peerinfo.end()) return it->second.m_requested;
        return 0;
    }

    size_t CountCandidates(NodeId peer) const
    {
        auto it = m_peerinfo.find(peer);
        if (it != m_peerinfo.end()) return it->second.m_total - it->second.m_requested - it->second.m_completed;
        return 0;
    }

    size_t Count(NodeId peer) const
    {
        auto it = m_peerinfo.find(peer);
        if (it != m_peerinfo.end()) return it->second.m_total;
        return 0;
    }

    //! Count how many announcements are being tracked in total across all peers and transactions.
    size_t Size() const { return m_index.size(); }

    uint64_t ComputePriority(const uint256& txhash, NodeId peer, bool preferred) const
    {
        // Return Priority as a uint64_t as Priority is internal.
        return uint64_t{m_computer(txhash, peer, preferred)};
    }

    void SetLogging(bool enabled)
    {
        m_logging = enabled;
    }
};

TxRequestTracker::TxRequestTracker(bool deterministic) :
    m_impl{MakeUnique<TxRequestTracker::Impl>(deterministic)} {}

TxRequestTracker::~TxRequestTracker() = default;

void TxRequestTracker::ForgetTxHash(const uint256& txhash) { m_impl->ForgetTxHash(txhash); }
void TxRequestTracker::DisconnectedPeer(NodeId peer) { m_impl->DisconnectedPeer(peer); }
size_t TxRequestTracker::CountInFlight(NodeId peer) const { return m_impl->CountInFlight(peer); }
size_t TxRequestTracker::CountCandidates(NodeId peer) const { return m_impl->CountCandidates(peer); }
size_t TxRequestTracker::Count(NodeId peer) const { return m_impl->Count(peer); }
size_t TxRequestTracker::Size() const { return m_impl->Size(); }
void TxRequestTracker::SanityCheck() const { m_impl->SanityCheck(); }

void TxRequestTracker::PostGetRequestableSanityCheck(std::chrono::microseconds now) const
{
    m_impl->PostGetRequestableSanityCheck(now);
}

void TxRequestTracker::ReceivedInv(NodeId peer, const GenTxid& gtxid, bool preferred,
    std::chrono::microseconds reqtime)
{
    m_impl->ReceivedInv(peer, gtxid, preferred, reqtime);
}

void TxRequestTracker::RequestedTx(NodeId peer, const uint256& txhash, std::chrono::microseconds expiry)
{
    m_impl->RequestedTx(peer, txhash, expiry);
}

void TxRequestTracker::ReceivedResponse(NodeId peer, const uint256& txhash)
{
    m_impl->ReceivedResponse(peer, txhash);
}

std::vector<GenTxid> TxRequestTracker::GetRequestable(NodeId peer, std::chrono::microseconds now)
{
    return m_impl->GetRequestable(peer, now);
}

uint64_t TxRequestTracker::ComputePriority(const uint256& txhash, NodeId peer, bool preferred) const
{
    return m_impl->ComputePriority(txhash, peer, preferred);
}

void TxRequestTracker::SetLogging(bool enabled)
{
    m_impl->SetLogging(enabled);
}
