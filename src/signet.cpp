// Copyright (c) 2019-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <signet.h>

#include <consensus/merkle.h>
#include <consensus/params.h>
#include <hash.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/standard.h>        // MANDATORY_SCRIPT_VERIFY_FLAGS
#include <util/system.h>

int GetWitnessCommitmentIndex(const CBlock& block);
template<typename T> int GetWitnessCommitmentIndex(const T& tx);

static constexpr int NO_WITNESS_COMMITMENT{-1}; // note: this is copied from validation.h, to avoid a circular dependency issue

// Signet block solution checker
bool CheckBlockSolution(const CBlock& block, const Consensus::Params& consensusParams)
{
    std::vector<uint8_t> signet_data;
    if (!GetWitnessCommitmentSection(block, SIGNET_HEADER, signet_data)) {
        return error("CheckBlockSolution: Errors in block (block solution missing)");
    }
    if (!CheckBlockSolution(GetSignetHash(block), signet_data, consensusParams)) {
        return error("CheckBlockSolution: Errors in block (block solution invalid)");
    }
    return true;
}

bool CheckBlockSolution(const uint256& signet_hash, const std::vector<uint8_t>& signature, const Consensus::Params& params)
{
    SimpleSignatureChecker bsc(signet_hash);
    CScript challenge(params.signet_challenge.begin(), params.signet_challenge.end());
    CScript solution = CScript(signature.begin(), signature.end());
    return VerifyScript(solution, challenge, nullptr, MANDATORY_SCRIPT_VERIFY_FLAGS, bsc);
}

uint256 BlockSignetMerkleRoot(const CBlock& block, bool* mutated = nullptr)
{
    std::vector<uint256> leaves;
    leaves.resize(block.vtx.size());
    {
        // find and delete signet signature
        CMutableTransaction mtx(*block.vtx.at(0));
        SetWitnessCommitmentSection(mtx, SIGNET_HEADER, std::vector<uint8_t>{});
        leaves[0] = mtx.GetHash();
    }
    for (size_t s = 1; s < block.vtx.size(); ++s) {
        leaves[s] = block.vtx[s]->GetHash();
    }
    return ComputeMerkleRoot(std::move(leaves), mutated);
}

uint256 GetSignetHash(const CBlock& block)
{
    if (block.vtx.size() == 0) return block.GetHash();
    return (CHashWriter(SER_DISK, PROTOCOL_VERSION) << block.nVersion << block.hashPrevBlock << BlockSignetMerkleRoot(block) << block.nTime << block.nBits).GetHash();
}

bool GetWitnessCommitmentSection(const CBlock& block, const uint8_t header[4], std::vector<uint8_t>& result)
{
    int cidx = GetWitnessCommitmentIndex(block);
    if (cidx == NO_WITNESS_COMMITMENT) return false;
    auto script = block.vtx.at(0)->vout.at(cidx).scriptPubKey;
    opcodetype opcode;
    CScript::const_iterator pc = script.begin();
    // move beyond initial OP_RETURN
    if (pc != script.end() && script.GetOp(pc, opcode, result) && opcode == OP_RETURN) {
        while (script.GetOp(pc, opcode, result)) {
            if (result.size() > 3 && !memcmp(result.data(), header, 4)) {
                result.erase(result.begin(), result.begin() + 4);
                return true;
            }
        }
    }
    result.clear();
    return false;
}

bool SetWitnessCommitmentSection(CMutableTransaction& mtx, const uint8_t header[4], const std::vector<uint8_t>& data)
{
    int cidx = GetWitnessCommitmentIndex(mtx);
    if (cidx == NO_WITNESS_COMMITMENT) return false;

    CScript result;
    std::vector<uint8_t> pushdata;
    auto script = mtx.vout[cidx].scriptPubKey;
    opcodetype opcode;
    CScript::const_iterator pc = script.begin();
    result.emplace_back(*pc++);
    bool found = false;
    while (script.GetOp(pc, opcode, pushdata)) {
        if (pushdata.size() > 0) {
            if (pushdata.size() > 3 && !memcmp(pushdata.data(), header, 4)) {
                // replace pushdata
                found = true;
                pushdata.erase(pushdata.begin() + 4, pushdata.end());
                pushdata.insert(pushdata.end(), data.begin(), data.end());
            }
            result << pushdata;
        } else {
            result << opcode;
        }
    }
    if (!found) {
        // append section as it did not exist
        pushdata.clear();
        pushdata.insert(pushdata.end(), header, header + 4);
        pushdata.insert(pushdata.end(), data.begin(), data.end());
        result << pushdata;
    }
    mtx.vout[cidx].scriptPubKey = result;
    return true;
}

bool SetWitnessCommitmentSection(CBlock& block, const uint8_t header[4], const std::vector<uint8_t>& data)
{
    auto mtx = CMutableTransaction(*block.vtx[0]);
    if (!SetWitnessCommitmentSection(mtx, header, data)) return false;
    block.vtx[0] = std::make_shared<CTransaction>(mtx);
    return true;
}
