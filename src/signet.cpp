// Copyright (c) 2019-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <signet.h>

#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <hash.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/standard.h>
#include <streams.h>
#include <util/strencodings.h>
#include <util/system.h>

static constexpr uint8_t SIGNET_HEADER_SCRIPTSIG[4] = {0xec, 0xc7, 0xda, 0xa2};
static constexpr uint8_t SIGNET_HEADER_WITNESS[4] = {0xec, 0xc7, 0xda, 0xa3};

static constexpr unsigned int BLOCK_SCRIPT_VERIFY_FLAGS = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_NULLDUMMY;

static bool ExtractCommitmentSection(CScript& script, const Span<const uint8_t> header, std::vector<uint8_t>& result)
{
    CScript replacement;
    bool found = false;

    opcodetype opcode;
    CScript::const_iterator pc = script.begin();
    std::vector<uint8_t> pushdata;
    while (script.GetOp(pc, opcode, pushdata)) {
        if (pushdata.size() > 0) {
            if (!found && pushdata.size() > (size_t) header.size() && Span<const uint8_t>(pushdata.data(), header.size()) == header) {
                // pushdata only counts if it has the header _and_ some data
                result.clear();
                result.insert(result.end(), pushdata.begin() + header.size(), pushdata.end());
                pushdata.erase(pushdata.begin() + header.size(), pushdata.end());
                found = true;
            }
            replacement << pushdata;
        } else {
            replacement << opcode;
        }
    }

    if (found) script = replacement;
    return found;
}

bool AddOrUpdateCommitmentSection(CScript& script, const Span<const uint8_t> header, const std::vector<uint8_t>& data)
{
    CScript replacement;
    bool found = false;

    opcodetype opcode;
    CScript::const_iterator pc = script.begin();
    std::vector<uint8_t> pushdata;
    while (script.GetOp(pc, opcode, pushdata)) {
        if (pushdata.size() > 0) {
            if (!found && pushdata.size() >= (size_t) header.size() && Span<const uint8_t>(pushdata.data(), header.size()) == header) {
                pushdata.erase(pushdata.begin() + header.size());
                pushdata.insert(pushdata.end(), data.begin(), data.end());
                found = true;
            }
            replacement << pushdata;
        } else {
            replacement << opcode;
        }
    }

    if (!found) {
        pushdata.clear();
        pushdata.insert(pushdata.end(), header.begin(), header.end());
        pushdata.insert(pushdata.end(), data.begin(), data.end());
        replacement << pushdata;
    }
    script = replacement;
    return found;
}

static uint256 ComputeModifiedMerkleRoot(const CMutableTransaction& cb, const CBlock& block)
{
    std::vector<uint256> leaves;
    leaves.resize(block.vtx.size());
    leaves[0] = cb.GetHash();
    for (size_t s = 1; s < block.vtx.size(); ++s) {
        leaves[s] = block.vtx[s]->GetHash();
    }
    return ComputeMerkleRoot(std::move(leaves));
}

CTransaction SignetTx(const CBlock& block, const std::vector<std::vector<uint8_t>>& witness_prefix)
{
    CMutableTransaction tx;

    tx.vin.emplace_back(COutPoint(block.hashPrevBlock, 0), CScript(), 0);
    tx.vout.emplace_back((uint32_t)block.nVersion, CScript());
    tx.nVersion = 1;
    tx.nLockTime = block.nTime;

    {
        // find and delete signet signature
        CMutableTransaction mtx(*block.vtx.at(0));

        int cidx = GetWitnessCommitmentIndex(mtx);
        assert(cidx != NO_WITNESS_COMMITMENT);

        CScript& script = mtx.vout.at(cidx).scriptPubKey;

        std::vector<uint8_t> data;
        if (ExtractCommitmentSection(script, SIGNET_HEADER_SCRIPTSIG, data)) {
            tx.vin[0].scriptSig.insert(tx.vin[0].scriptSig.begin(), data.begin(), data.end());
        }
        if (ExtractCommitmentSection(script, SIGNET_HEADER_WITNESS, data)) {
            try {
                VectorReader(SER_NETWORK, INIT_PROTO_VERSION, data, 0, tx.vin[0].scriptWitness.stack);
            } catch (const std::exception& e) {
                // treat invalid encoding as a single witness item to minimise malleability
                tx.vin[0].scriptWitness.stack.clear();
                tx.vin[0].scriptWitness.stack.push_back(data);
            }
            for (const auto& i : witness_prefix) {
                tx.vin[0].scriptWitness.stack.push_back(i);
            }
        }
        uint256 signet_merkle = ComputeModifiedMerkleRoot(mtx, block);
        tx.vout[0].scriptPubKey << std::vector<uint8_t>(signet_merkle.begin(), signet_merkle.end());
    }

    return tx;
}

// Signet block solution checker
bool CheckBlockSolution(const CBlock& block, const Consensus::Params& consensusParams)
{
    int cidx = GetWitnessCommitmentIndex(block);
    if (cidx == NO_WITNESS_COMMITMENT) {
        return error("CheckBlockSolution: Errors in block (no witness comittment)");
    }

    CScript challenge(consensusParams.signet_challenge.begin(), consensusParams.signet_challenge.end());
    const CTransaction signet_tx = SignetTx(block, consensusParams.signet_witness_prefix);

    const CScript& scriptSig = signet_tx.vin[0].scriptSig;
    const CScriptWitness& witness = signet_tx.vin[0].scriptWitness;

    if (scriptSig.empty() && witness.stack.empty()) {
        return error("CheckBlockSolution: Errors in block (block solution missing)");
    }

    TransactionSignatureChecker sigcheck(&signet_tx, /*nIn=*/ 0, /*amount=*/ MAX_MONEY-1);

    if (!VerifyScript(scriptSig, challenge, &witness, BLOCK_SCRIPT_VERIFY_FLAGS, sigcheck)) {
        return error("CheckBlockSolution: Errors in block (block solution invalid)");
    }
    return true;
}
