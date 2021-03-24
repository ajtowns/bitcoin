// Copyright (c) 2013-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <hash.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <test/data/sighash.json.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <version.h>

#include <iostream>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

UniValue read_json(const std::string& jsondata);

// Old script.cpp SignatureHash function
uint256 static SignatureHashOld(CScript scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType)
{
    if (nIn >= txTo.vin.size())
    {
        return uint256::ONE;
    }
    CMutableTransaction txTmp(txTo);

    // In case concatenating two scripts ends up with two codeseparators,
    // or an extra one at the end, this prevents all those possible incompatibilities.
    FindAndDelete(scriptCode, CScript(OP_CODESEPARATOR));

    // Blank out other inputs' signatures
    for (unsigned int i = 0; i < txTmp.vin.size(); i++)
        txTmp.vin[i].scriptSig = CScript();
    txTmp.vin[nIn].scriptSig = scriptCode;

    // Blank out some of the outputs
    if ((nHashType & 0x1f) == SIGHASH_NONE)
    {
        // Wildcard payee
        txTmp.vout.clear();

        // Let the others update at will
        for (unsigned int i = 0; i < txTmp.vin.size(); i++)
            if (i != nIn)
                txTmp.vin[i].nSequence = 0;
    }
    else if ((nHashType & 0x1f) == SIGHASH_SINGLE)
    {
        // Only lock-in the txout payee at same index as txin
        unsigned int nOut = nIn;
        if (nOut >= txTmp.vout.size())
        {
            return uint256::ONE;
        }
        txTmp.vout.resize(nOut+1);
        for (unsigned int i = 0; i < nOut; i++)
            txTmp.vout[i].SetNull();

        // Let the others update at will
        for (unsigned int i = 0; i < txTmp.vin.size(); i++)
            if (i != nIn)
                txTmp.vin[i].nSequence = 0;
    }

    // Blank out other inputs completely, not recommended for open transactions
    if (nHashType & SIGHASH_ANYONECANPAY)
    {
        txTmp.vin[0] = txTmp.vin[nIn];
        txTmp.vin.resize(1);
    }

    // Serialize and hash
    CHashWriter ss(SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
    ss << txTmp << nHashType;
    return ss.GetHash();
}

void static RandomScript(CScript &script) {
    static const opcodetype oplist[] = {OP_FALSE, OP_1, OP_2, OP_3, OP_CHECKSIG, OP_IF, OP_VERIF, OP_RETURN, OP_CODESEPARATOR};
    script = CScript();
    int ops = (InsecureRandRange(10));
    for (int i=0; i<ops; i++)
        script << oplist[InsecureRandRange(std::size(oplist))];
}

void static RandomTransaction(CMutableTransaction &tx, bool fSingle) {
    tx.nVersion = InsecureRand32();
    tx.vin.clear();
    tx.vout.clear();
    tx.nLockTime = (InsecureRandBool()) ? InsecureRand32() : 0;
    int ins = (InsecureRandBits(2)) + 1;
    int outs = fSingle ? ins : (InsecureRandBits(2)) + 1;
    for (int in = 0; in < ins; in++) {
        tx.vin.push_back(CTxIn());
        CTxIn &txin = tx.vin.back();
        txin.prevout.hash = InsecureRand256();
        txin.prevout.n = InsecureRandBits(2);
        RandomScript(txin.scriptSig);
        txin.nSequence = (InsecureRandBool()) ? InsecureRand32() : std::numeric_limits<uint32_t>::max();
    }
    for (int out = 0; out < outs; out++) {
        tx.vout.push_back(CTxOut());
        CTxOut &txout = tx.vout.back();
        txout.nValue = InsecureRandRange(100000000);
        RandomScript(txout.scriptPubKey);
    }
}

void static MutateInputs(CMutableTransaction &tx, const bool inPrevout, const bool inInputSequence) {

    // mutate previous input
    for (std::size_t in = 0; in < tx.vin.size(); in++) {
        CTxIn &txin = tx.vin[in];

        if (inPrevout) {
            txin.prevout.hash = InsecureRand256();
            txin.prevout.n = InsecureRandBits(2);
        }

        // mutate input sequences
        if (inInputSequence) {
            txin.nSequence = InsecureRand32();
        }
    }
}

BOOST_FIXTURE_TEST_SUITE(sighash_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(sighash_test)
{
    #if defined(PRINT_SIGHASH_JSON)
    std::cout << "[\n";
    std::cout << "\t[\"raw_transaction, script, input_index, hashType, signature_hash (result)\"],\n";
    int nRandomTests = 500;
    #else
    int nRandomTests = 50000;
    #endif
    for (int i=0; i<nRandomTests; i++) {
        int nHashType = InsecureRand32();
        CMutableTransaction txTo;
        RandomTransaction(txTo, (nHashType & 0x1f) == SIGHASH_SINGLE);
        CScript scriptCode;
        RandomScript(scriptCode);
        int nIn = InsecureRandRange(txTo.vin.size());

        uint256 sh, sho;
        sho = SignatureHashOld(scriptCode, CTransaction(txTo), nIn, nHashType);
        sh = SignatureHash(scriptCode, txTo, nIn, nHashType, 0, SigVersion::BASE);
        #if defined(PRINT_SIGHASH_JSON)
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << txTo;

        std::cout << "\t[\"" ;
        std::cout << HexStr(ss) << "\", \"";
        std::cout << HexStr(scriptCode) << "\", ";
        std::cout << nIn << ", ";
        std::cout << nHashType << ", \"";
        std::cout << sho.GetHex() << "\"]";
        if (i+1 != nRandomTests) {
          std::cout << ",";
        }
        std::cout << "\n";
        #endif
        BOOST_CHECK(sh == sho);
    }
    #if defined(PRINT_SIGHASH_JSON)
    std::cout << "]\n";
    #endif
}

// Goal: check that SignatureHash generates correct hash
BOOST_AUTO_TEST_CASE(sighash_from_data)
{
    UniValue tests = read_json(std::string(json_tests::sighash, json_tests::sighash + sizeof(json_tests::sighash)));

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        UniValue test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 1) // Allow for extra stuff (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        if (test.size() == 1) continue; // comment

        std::string raw_tx, raw_script, sigHashHex;
        int nIn, nHashType;
        uint256 sh;
        CTransactionRef tx;
        CScript scriptCode = CScript();

        try {
          // deserialize test data
          raw_tx = test[0].get_str();
          raw_script = test[1].get_str();
          nIn = test[2].get_int();
          nHashType = test[3].get_int();
          sigHashHex = test[4].get_str();

          CDataStream stream(ParseHex(raw_tx), SER_NETWORK, PROTOCOL_VERSION);
          stream >> tx;

          TxValidationState state;
          BOOST_CHECK_MESSAGE(CheckTransaction(*tx, state), strTest);
          BOOST_CHECK(state.IsValid());

          std::vector<unsigned char> raw = ParseHex(raw_script);
          scriptCode.insert(scriptCode.end(), raw.begin(), raw.end());
        } catch (...) {
          BOOST_ERROR("Bad test, couldn't deserialize data: " << strTest);
          continue;
        }

        sh = SignatureHash(scriptCode, *tx, nIn, nHashType, 0, SigVersion::BASE);
        BOOST_CHECK_MESSAGE(sh.GetHex() == sigHashHex, strTest);
    }
}

// Goal: check that SignatureHashOld and SignatureHash ignore sighash flags SIGHASH_ANYPREVOUT and SIGHASH_ANYPREVOUTANYSCRIPT
BOOST_AUTO_TEST_CASE(sighash_anyprevout_legacy)
{
    #if defined(PRINT_SIGHASH_JSON)
    std::cout << "[\n";
    std::cout << "\t[\"raw_transaction, script, input_index, hashType, signature_hash (result)\"],\n";
    int nRandomTests = 500;
    #else
    int nRandomTests = 50000;
    #endif

    for (int i=0; i<nRandomTests; i++) {

        // random sighashs, with and without ANYPREVOUT*
        int nHashType = InsecureRand32() & ~SIGHASH_INPUT_MASK;
        int nHashTypeApo = nHashType | SIGHASH_ANYPREVOUT;
        int nHashTypeApoas = nHashType | SIGHASH_ANYPREVOUTANYSCRIPT;

        CMutableTransaction tx;
        RandomTransaction(tx, (nHashType & SIGHASH_OUTPUT_MASK) == SIGHASH_SINGLE);
        CScript scriptCode, mut_scriptCode;
        RandomScript(scriptCode);
        RandomScript(mut_scriptCode);

        // remove code separators from old scripts because they are not serialized
        CScript old_scriptCode(scriptCode), old_mut_scriptCode(mut_scriptCode);
        FindAndDelete(old_scriptCode, CScript(OP_CODESEPARATOR));
        FindAndDelete(old_mut_scriptCode, CScript(OP_CODESEPARATOR));
        
        int nIn = InsecureRandRange(tx.vin.size());

        CMutableTransaction tx_mut_prevout(tx);      
        MutateInputs(tx_mut_prevout, true, false); 

        CMutableTransaction tx_mut_sequence(tx);      
        MutateInputs(tx_mut_sequence, false, true); 

        // test OLD signature hash ignores SIGHASH_ANYPREVOUT and SIGHASH_ANYPREVOUTANYSCRIPT
        uint256 sho = SignatureHashOld(old_scriptCode, CTransaction(tx), nIn, nHashType);
        uint256 sho_apo = SignatureHashOld(old_scriptCode, CTransaction(tx), nIn, nHashTypeApo);
        uint256 sho_apoas = SignatureHashOld(old_scriptCode, CTransaction(tx), nIn, nHashTypeApoas);

        // mutate the previous output transaction
        uint256 sho_mut_prevout = SignatureHashOld(old_scriptCode, CTransaction(tx_mut_prevout), nIn, nHashType);
        uint256 sho_mut_prevout_apo = SignatureHashOld(old_scriptCode, CTransaction(tx_mut_prevout), nIn, nHashTypeApo);
        uint256 sho_mut_prevout_apoas = SignatureHashOld(old_scriptCode, CTransaction(tx_mut_prevout), nIn, nHashTypeApoas);

        // mutate the previous input script
        uint256 sho_mut_script = SignatureHashOld(old_mut_scriptCode, CTransaction(tx), nIn, nHashType);
        uint256 sho_mut_script_apo = SignatureHashOld(old_mut_scriptCode, CTransaction(tx), nIn, nHashTypeApo);
        uint256 sho_mut_script_apoas = SignatureHashOld(old_mut_scriptCode, CTransaction(tx), nIn, nHashTypeApoas);

        // mutate the input sequence
        uint256 sho_mut_sequence = SignatureHashOld(old_scriptCode, CTransaction(tx_mut_sequence), nIn, nHashType);
        uint256 sho_mut_sequence_apo = SignatureHashOld(old_scriptCode, CTransaction(tx_mut_sequence), nIn, nHashTypeApo);
        uint256 sho_mut_sequence_apoas = SignatureHashOld(old_scriptCode, CTransaction(tx_mut_sequence), nIn, nHashTypeApoas);

        // test BASE signature hash ignores SIGHASH_ANYPREVOUT and SIGHASH_ANYPREVOUTANYSCRIPT
        uint256 shb = SignatureHash(old_scriptCode, tx, nIn, nHashType, 0, SigVersion::BASE);
        uint256 shb_apo = SignatureHash(old_scriptCode, tx, nIn, nHashTypeApo, 0, SigVersion::BASE);
        uint256 shb_apoas = SignatureHash(old_scriptCode, tx, nIn, nHashTypeApoas, 0, SigVersion::BASE);
        
        // mutate the previous output transaction
        uint256 shb_mut_prevout = SignatureHash(old_scriptCode, tx_mut_prevout, nIn, nHashType, 0, SigVersion::BASE);
        uint256 shb_mut_prevout_apo = SignatureHash(old_scriptCode, tx_mut_prevout, nIn, nHashTypeApo, 0, SigVersion::BASE);
        uint256 shb_mut_prevout_apoas = SignatureHash(old_scriptCode, tx_mut_prevout, nIn, nHashTypeApoas, 0, SigVersion::BASE);

        // mutate the previous input script
        uint256 shb_mut_script = SignatureHash(old_mut_scriptCode, tx, nIn, nHashType, 0, SigVersion::BASE);
        uint256 shb_mut_script_apo = SignatureHash(old_mut_scriptCode, tx, nIn, nHashTypeApo, 0, SigVersion::BASE);
        uint256 shb_mut_script_apoas = SignatureHash(old_mut_scriptCode, tx, nIn, nHashTypeApoas, 0, SigVersion::BASE);

        // mutate the input sequence
        uint256 shb_mut_sequence = SignatureHash(old_scriptCode, tx_mut_sequence, nIn, nHashType, 0, SigVersion::BASE);
        uint256 shb_mut_sequence_apo = SignatureHash(old_scriptCode, tx_mut_sequence, nIn, nHashTypeApo, 0, SigVersion::BASE);
        uint256 shb_mut_sequence_apoas = SignatureHash(old_scriptCode, tx_mut_sequence, nIn, nHashTypeApoas, 0, SigVersion::BASE);

        // test v0 signature hash ignores SIGHASH_ANYPREVOUT and SIGHASH_ANYPREVOUTANYSCRIPT
        uint256 shv0 = SignatureHash(scriptCode, tx, nIn, nHashType, 0, SigVersion::WITNESS_V0);
        uint256 shv0_apo = SignatureHash(scriptCode, tx, nIn, nHashTypeApo, 0, SigVersion::WITNESS_V0);
        uint256 shv0_apoas = SignatureHash(scriptCode, tx, nIn, nHashTypeApoas, 0, SigVersion::WITNESS_V0);

        // mutate the previous output transaction
        uint256 shv0_mut_prevout = SignatureHash(scriptCode, tx_mut_prevout, nIn, nHashType, 0, SigVersion::WITNESS_V0);
        uint256 shv0_mut_prevout_apo = SignatureHash(scriptCode, tx_mut_prevout, nIn, nHashTypeApo, 0, SigVersion::WITNESS_V0);
        uint256 shv0_mut_prevout_apoas = SignatureHash(scriptCode, tx_mut_prevout, nIn, nHashTypeApoas, 0, SigVersion::WITNESS_V0);

        // mutate the previous input script
        uint256 shv0_mut_script = SignatureHash(mut_scriptCode, tx, nIn, nHashType, 0, SigVersion::WITNESS_V0);
        uint256 shv0_mut_script_apo = SignatureHash(mut_scriptCode, tx, nIn, nHashTypeApo, 0, SigVersion::WITNESS_V0);
        uint256 shv0_mut_script_apoas = SignatureHash(mut_scriptCode, tx, nIn, nHashTypeApoas, 0, SigVersion::WITNESS_V0);

        // mutate the input sequence
        uint256 shv0_mut_sequence = SignatureHash(scriptCode, tx_mut_sequence, nIn, nHashType, 0, SigVersion::BASE);
        uint256 shv0_mut_sequence_apo = SignatureHash(scriptCode, tx_mut_sequence, nIn, nHashTypeApo, 0, SigVersion::BASE);
        uint256 shv0_mut_sequence_apoas = SignatureHash(scriptCode, tx_mut_sequence, nIn, nHashTypeApoas, 0, SigVersion::BASE);

        #if defined(PRINT_SIGHASH_JSON)
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << tx;

        std::cout << "\t[\"" ;
        std::cout << HexStr(ss.begin(), ss.end()) << "\", \"";
        std::cout << HexStr(scriptCode) << "\", ";
        std::cout << nIn << ", ";
        std::cout << nHashType << ", \"";
        std::cout << sho.GetHex() << "\"]";
        if (i+1 != nRandomTests) {
          std::cout << ",";
        }
        std::cout << "\n";
        #endif

        // check that legacy, base and v0/SEGWIT transactions ignore SIGHASH_ANYPREVOUT and SIGHASH_ANYPREVOUTANYSCRIPT

        // check maleated previous input transaction creates different digests
        BOOST_CHECK(sho != sho_mut_prevout);
        BOOST_CHECK(sho_apo != sho_mut_prevout_apo);
        BOOST_CHECK(sho_apoas != sho_mut_prevout_apoas);
        BOOST_CHECK(shb != shb_mut_prevout);
        BOOST_CHECK(shb_apo != shb_mut_prevout_apo);
        BOOST_CHECK(shb_apoas != shb_mut_prevout_apoas);
        BOOST_CHECK(shv0 != shv0_mut_prevout);
        BOOST_CHECK(shv0_apo != shv0_mut_prevout_apo);
        BOOST_CHECK(shv0_apoas != shv0_mut_prevout_apoas);

        // check maleated input script creates different digests
        if (old_scriptCode != old_mut_scriptCode) {
            BOOST_CHECK(sho != sho_mut_script);
            BOOST_CHECK(sho_apo != sho_mut_script_apo);
            BOOST_CHECK(sho_apoas != sho_mut_script_apoas);
            BOOST_CHECK(shb != shb_mut_script);
            BOOST_CHECK(shb_apo != shb_mut_script_apo);
            BOOST_CHECK(shb_apoas != shb_mut_script_apoas);
            BOOST_CHECK(shv0 != shv0_mut_script);
            BOOST_CHECK(shv0_apo != shv0_mut_script_apo);
            BOOST_CHECK(shv0_apoas != shv0_mut_script_apoas);
        }

        // check maleated sequence creates different digests
        BOOST_CHECK(sho != sho_mut_sequence);
        BOOST_CHECK(sho_apo != sho_mut_sequence_apo);
        BOOST_CHECK(sho_apoas != sho_mut_sequence_apoas);
        BOOST_CHECK(shb != shb_mut_sequence);
        BOOST_CHECK(shb_apo != shb_mut_sequence_apo);
        BOOST_CHECK(shb_apoas != shb_mut_sequence_apoas);
        BOOST_CHECK(shv0 != shv0_mut_sequence);
        BOOST_CHECK(shv0_apo != shv0_mut_sequence_apo);
        BOOST_CHECK(shv0_apoas != shv0_mut_sequence_apoas);
    }

    #if defined(PRINT_SIGHASH_JSON)
    std::cout << "]\n";
    #endif
}

BOOST_AUTO_TEST_SUITE_END()
