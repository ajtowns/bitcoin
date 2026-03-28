// SKETCH: receiver-side net_processing flow for BIN25-2.2 gettmplt protocol

// SendMessages
void MaybeRequestTemplate(CNode& node, Peer& peer)
{
    if (NodeClock::now() < peer.m_next_gettmplt) return;
    uint256 basis_hash = WITH_LOCK(m_template_mutex, return templateman.GetLastPeerTemplateHash(node.GetId()));
    MakeAndPushMessage(node, NetMsgType::GETTMPLT, 0, basis_hash);
    peer.m_next_gettmplt = NodeClock::now() + 2min;

    // clear previous incomplete request; set new request as monostate
    WITH_LOCK(templateman.ResetReconciliation());
}

// TMPLT handler
void ProcessTmpltRound0(node, peer, hash, tip_hash, basis_hash, nonce, basis_delta, sketches)
{

    const CBlockIndex* tip = WITH_LOCK(cs_main, return LookupBlockIndex(tip_hash));

    LOCK(m_template_mutex);
    auto req = templateman.GetReconciliation<std::monostate>(nodeid);
    if (!req) throw; // if previous request is not monostate, throw
    auto result = templateman.InitPeerSketch(req, hash, tip, nonce,
                                             basis_hash, basis_delta, sketches);
    HandleTmpltResult(node, peer, round, result);
}

void ProcessTmpltRoundLater(node, peer, hash, round, shortid_bytes, sketches)
{
    // if previous request is not PeerTemplateSketch, throw
    // if PTS hash or round is unexpected, throw

    LOCK(m_template_mutex);
    auto result = templateman.UpdatePeerSketch(node.GetId(), hash, round, shortid_bytes, sketches);
    HandleTmpltResult(node, peer, round, result);
}

void HandleTmpltResult(node, peer, round, result)
  EXCLUSIVE_LOCKS_REQUIRED(m_template_mutex)
{
    switch(result.state) {
    case node::TmpltState::ERROR:
        throw;
    case node::TmpltState::UNRESOLVED:
        assert(round < 4); // result.error if unresolved after round 4
        MakeAndPushMessage(node, NetMsgType::GETTMPLT, round + 1, result.hash,
                           result.shortidmask, result.sketchmask);
        break;
    case node::TmpltState::NEEDS_TXS:
        assert(!result.missing_gr.empty());
        MakeAndPushMessage(node, NetMsgType::GETTMPLTTXN, result.hash, result.missing_gr);
        break;
    case node::TmpltState::DONE:
        // nothing to do
        break;
    }
}

// TMPLTTXN handler
void ProcessTmplttxn(node, peer, hash, txns)
{
    // if previous request is not PeerTemplatePartial, throw
    // if hash doesn't match previous request, throw

    LOCK(m_template_mutex);
    if (!templateman.FillPeerPartial(node.GetId(), txns)) {
        throw; // bad data. on good data, templateman will handle everything
    }
}

enum class TmpltState { ERROR, UNRESOLVED, NEEDS_TXS, DONE };
class TemplateManager
{
...
public:
    uint256 GetLastPeerTemplateHash(NodeId);

    struct TmpltResult {
        TmpltState state;
        uint256 hash; // template hash
        GroupMask shortidmask{}, sketchmask{}; // only if state == UNRESOLVED
        vector<uint8_t> missing_gr{}; // only if state == NEEDS_TXS
    };

    TmpltResult InitPeerSketch(NodeId nodeid, const CBlockIndex* tip, uint256 tiphash, uint64_t nonce, uint256 basis_hash, vector<uint8_t> basis_delta, vector<uint8_t> sketches);
    TmpltResult UpdatePeerSketch(NodeId nodeid, uint256 templatehash, int round, vector<uint8_t> shortid_bytes, vector<uint8_t> sketches);
    bool FillPeerPartial(NodeId nodeid, vector<CTransactionRef> txs); // returns true on success
};
