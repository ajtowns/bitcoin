// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_VALIDATION_H
#define BITCOIN_CONSENSUS_VALIDATION_H

#include <string>
#include <version.h>
#include <consensus/consensus.h>
#include <primitives/transaction.h>
#include <primitives/block.h>

/** "reject" message codes */
static const unsigned char REJECT_MALFORMED = 0x01;
static const unsigned char REJECT_INVALID = 0x10;
static const unsigned char REJECT_OBSOLETE = 0x11;
static const unsigned char REJECT_DUPLICATE = 0x12;
static const unsigned char REJECT_NONSTANDARD = 0x40;
// static const unsigned char REJECT_DUST = 0x41; // part of BIP 61
static const unsigned char REJECT_INSUFFICIENTFEE = 0x42;
static const unsigned char REJECT_CHECKPOINT = 0x43;

/** A "reason" why a transaction was invalid, suitable for determining whether the
  * provider of the object should be banned/ignored/disconnected/etc.
  * These are much more granular than the rejection codes, which may be more
  * useful for some other use-cases.
  */
enum class TxValidationResult {
    // txn and blocks:
    NONE,                    //!< not actually invalid
    CONSENSUS,               //!< invalid by consensus rules (excluding any below reasons)
    /**
     * Invalid by a change to consensus rules more recent than SegWit.
     * Currently unused as there are no such consensus rule changes, and any download
     * sources realistically need to support SegWit in order to provide useful data,
     * so differentiating between always-invalid and invalid-by-pre-SegWit-soft-fork
     * is uninteresting.
     */
    RECENT_CONSENSUS_CHANGE,
    // Only loose txn:
    TX_NOT_STANDARD,          //!< didn't meet our local policy rules
    TX_MISSING_INPUTS,        //!< a transaction was missing some of its inputs
    TX_PREMATURE_SPEND,       //!< transaction spends a coinbase too early, or violates locktime/sequence locks
    /**
     * Transaction might be missing a witness, have a witness prior to SegWit
     * activation, or witness may have been malleated (which includes
     * non-standard witnesses).
     */
    TX_WITNESS_MUTATED,
    /**
     * Tx already in mempool or conflicts with a tx in the chain
     * (if it conflicts with another tx in mempool, we use MEMPOOL_POLICY as it failed to reach the RBF threshold)
     * TODO: Currently this is only used if the transaction already exists in the mempool or on chain,
     * TODO: ATMP's fMissingInputs and a valid CValidationState being used to indicate missing inputs
     */
    TX_CONFLICT,
    TX_MEMPOOL_POLICY,        //!< violated mempool's fee/size/descendant/RBF/etc limits
};

/** A "reason" why a block was invalid, suitable for determining whether the
  * provider of the object should be banned/ignored/disconnected/etc.
  * These are much more granular than the rejection codes, which may be more
  * useful for some other use-cases.
  */
enum class BlockValidationResult {
    // txn and blocks:
    NONE,                    //!< not actually invalid
    CONSENSUS,               //!< invalid by consensus rules (excluding any below reasons)
    /**
     * Invalid by a change to consensus rules more recent than SegWit.
     * Currently unused as there are no such consensus rule changes, and any download
     * sources realistically need to support SegWit in order to provide useful data,
     * so differentiating between always-invalid and invalid-by-pre-SegWit-soft-fork
     * is uninteresting.
     */
    RECENT_CONSENSUS_CHANGE,
    // Only blocks (or headers):
    CACHED_INVALID,          //!< this object was cached as being invalid, but we don't know why
    BLOCK_INVALID_HEADER,    //!< invalid proof of work or time too old
    BLOCK_MUTATED,           //!< the block's data didn't match the data committed to by the PoW
    BLOCK_MISSING_PREV,      //!< We don't have the previous block the checked one is built on
    BLOCK_INVALID_PREV,      //!< A block this one builds on is invalid
    BLOCK_BAD_TIME,          //!< block timestamp was > 2 hours in the future (or our clock is bad)
    BLOCK_CHECKPOINT,        //!< the block failed to meet one of our checkpoints
};



/** Capture information about block/transaction validation */
class BaseValidationState {
private:
    enum mode_state {
        MODE_VALID,   //!< everything ok
        MODE_INVALID, //!< network rule violation (DoS value may be set)
        MODE_ERROR,   //!< run-time error
    } mode;
    int nDoS;
    std::string strRejectReason;
    unsigned int chRejectCode;
    bool corruptionPossible;
    std::string strDebugMessage;
protected:
    bool DoS(int level, bool ret = false,
             unsigned int chRejectCodeIn=0, const std::string &strRejectReasonIn="",
             bool corruptionIn=false,
             const std::string &strDebugMessageIn="") {
        chRejectCode = chRejectCodeIn;
        strRejectReason = strRejectReasonIn;
        corruptionPossible = corruptionIn;
        strDebugMessage = strDebugMessageIn;
        nDoS = level;
        if (mode == MODE_ERROR)
            return ret;
        mode = MODE_INVALID;
        return ret;
    }
public:
    BaseValidationState() : mode(MODE_VALID), nDoS(0), chRejectCode(0), corruptionPossible(false) {}
    bool Error(const std::string& strRejectReasonIn) {
        if (mode == MODE_VALID)
            strRejectReason = strRejectReasonIn;
        mode = MODE_ERROR;
        return false;
    }
    bool IsValid() const {
        return mode == MODE_VALID;
    }
    bool IsInvalid() const {
        return mode == MODE_INVALID;
    }
    bool IsError() const {
        return mode == MODE_ERROR;
    }
    bool CorruptionPossible() const {
        return corruptionPossible;
    }
    void SetCorruptionPossible() {
        corruptionPossible = true;
    }
    int GetDoS(void) const { return nDoS; }
    unsigned int GetRejectCode() const { return chRejectCode; }
    std::string GetRejectReason() const { return strRejectReason; }
    std::string GetDebugMessage() const { return strDebugMessage; }
};

class TxValidationState : public BaseValidationState {
private:
    TxValidationResult m_result;
public:
    bool DoS(int level, TxValidationResult result, bool ret = false,
             unsigned int chRejectCodeIn=0, const std::string &strRejectReasonIn="",
             bool corruptionIn=false,
             const std::string &strDebugMessageIn="") {
        m_result = result;
        assert(corruptionIn == (m_result == TxValidationResult::TX_WITNESS_MUTATED));
        assert(level == GetDoSForResult());
        return BaseValidationState::DoS(level, ret, chRejectCodeIn, strRejectReasonIn, corruptionIn, strDebugMessageIn);
    }
    bool Invalid(TxValidationResult result, bool ret = false,
                 unsigned int _chRejectCode=0, const std::string &_strRejectReason="",
                 const std::string &_strDebugMessage="") {
        assert(result != TxValidationResult::TX_WITNESS_MUTATED);
        return DoS(0, result, ret, _chRejectCode, _strRejectReason, false, _strDebugMessage);
    }
    TxValidationResult GetResult() const { return m_result; }
    int GetDoSForResult() const {
        switch (m_result) {
        case TxValidationResult::NONE:
            return 0;
        case TxValidationResult::CONSENSUS:
            return 100;
        case TxValidationResult::RECENT_CONSENSUS_CHANGE:
        case TxValidationResult::TX_NOT_STANDARD:
        case TxValidationResult::TX_MISSING_INPUTS:
        case TxValidationResult::TX_PREMATURE_SPEND:
        case TxValidationResult::TX_WITNESS_MUTATED:
        case TxValidationResult::TX_CONFLICT:
        case TxValidationResult::TX_MEMPOOL_POLICY:
            return 0;
        }
    }
};

class BlockValidationState : public BaseValidationState {
private:
    BlockValidationResult m_result;
public:
    bool DoS(int level, BlockValidationResult result, bool ret = false,
             unsigned int chRejectCodeIn=0, const std::string &strRejectReasonIn="",
             bool corruptionIn=false,
             const std::string &strDebugMessageIn="") {
        m_result = result;
        assert(corruptionIn == (m_result == BlockValidationResult::BLOCK_MUTATED));
        assert(level == GetDoSForResult());
        return BaseValidationState::DoS(level, ret, chRejectCodeIn, strRejectReasonIn, corruptionIn, strDebugMessageIn);
    }
    bool Invalid(BlockValidationResult result, bool ret = false,
                 unsigned int _chRejectCode=0, const std::string &_strRejectReason="",
                 const std::string &_strDebugMessage="") {
        assert(result != BlockValidationResult::BLOCK_MUTATED);
        return DoS(0, result, ret, _chRejectCode, _strRejectReason, false, _strDebugMessage);
    }
    BlockValidationResult GetResult() const { return m_result; }
    int GetDoSForResult() const {
        switch (m_result) {
        case BlockValidationResult::NONE:
            return 0;
        case BlockValidationResult::CONSENSUS:
        case BlockValidationResult::BLOCK_MUTATED:
        case BlockValidationResult::BLOCK_INVALID_HEADER:
        case BlockValidationResult::BLOCK_CHECKPOINT:
        case BlockValidationResult::BLOCK_INVALID_PREV:
            return 100;
        case BlockValidationResult::BLOCK_MISSING_PREV:
            return 10;
        case BlockValidationResult::CACHED_INVALID:
        case BlockValidationResult::RECENT_CONSENSUS_CHANGE:
        case BlockValidationResult::BLOCK_BAD_TIME:
            return 0;
        }
    }
    void FromTxValidationState(TxValidationState tx_state) {
        switch (tx_state.GetResult()) {
        case TxValidationResult::NONE:
        case TxValidationResult::TX_NOT_STANDARD:
        case TxValidationResult::TX_MEMPOOL_POLICY:
            m_result = BlockValidationResult::NONE;
            break;
        case TxValidationResult::CONSENSUS:
        case TxValidationResult::TX_MISSING_INPUTS:
        case TxValidationResult::TX_PREMATURE_SPEND:
        case TxValidationResult::TX_CONFLICT:
        case TxValidationResult::TX_WITNESS_MUTATED:
            m_result = BlockValidationResult::CONSENSUS;
            break;
        case TxValidationResult::RECENT_CONSENSUS_CHANGE:
            m_result = BlockValidationResult::RECENT_CONSENSUS_CHANGE;
            break;
        }
        BaseValidationState::DoS(GetDoSForResult(), false, tx_state.GetRejectCode(), tx_state.GetRejectReason(), false, tx_state.GetDebugMessage());
    }
};

// These implement the weight = (stripped_size * 4) + witness_size formula,
// using only serialization with and without witness data. As witness_size
// is equal to total_size - stripped_size, this formula is identical to:
// weight = (stripped_size * 3) + total_size.
static inline int64_t GetTransactionWeight(const CTransaction& tx)
{
    return ::GetSerializeSize(tx, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (WITNESS_SCALE_FACTOR - 1) + ::GetSerializeSize(tx, PROTOCOL_VERSION);
}
static inline int64_t GetBlockWeight(const CBlock& block)
{
    return ::GetSerializeSize(block, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (WITNESS_SCALE_FACTOR - 1) + ::GetSerializeSize(block, PROTOCOL_VERSION);
}
static inline int64_t GetTransactionInputWeight(const CTxIn& txin)
{
    // scriptWitness size is added here because witnesses and txins are split up in segwit serialization.
    return ::GetSerializeSize(txin, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (WITNESS_SCALE_FACTOR - 1) + ::GetSerializeSize(txin, PROTOCOL_VERSION) + ::GetSerializeSize(txin.scriptWitness.stack, PROTOCOL_VERSION);
}

#endif // BITCOIN_CONSENSUS_VALIDATION_H
