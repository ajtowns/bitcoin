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

extern UniValue read_json(const std::string& jsondata);

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
        script << oplist[InsecureRandRange(sizeof(oplist)/sizeof(oplist[0]))];
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

void static MutateInputs(CMutableTransaction &tx, const bool inSequence, const bool inValue) {

    // mutate previous input
    for (std::size_t in = 0; in < tx.vin.size(); in++) {
        CTxIn &txin = tx.vin[in];
        txin.prevout.hash = InsecureRand256();
        txin.prevout.n = InsecureRandBits(2);

        // mutate script and sequence
        if (inSequence) {
            RandomScript(txin.scriptSig);
            txin.nSequence = (InsecureRandBool()) ? InsecureRand32() : std::numeric_limits<uint32_t>::max();
        }
    }

    // mutate output value
    if (inValue) {
        for (std::size_t out = 0; out < tx.vout.size(); out++) {
            tx.vout[out].nValue = InsecureRandRange(100000000);
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

        // Random SigHash, excluding ANYPREVOUT*
        int nHashType = InsecureRand32() & ~SIGHASH_INPUT_MASK;
        int nHashTypeApo = nHashType | SIGHASH_ANYPREVOUT;
        int nHashTypeApoas = nHashType | SIGHASH_ANYPREVOUTANYSCRIPT;

        CMutableTransaction txTo;
        RandomTransaction(txTo, (nHashType & SIGHASH_OUTPUT_MASK) == SIGHASH_SINGLE);
        CScript scriptCode;
        RandomScript(scriptCode);
        int nIn = InsecureRandRange(txTo.vin.size());

        // tx2 is same as tx1 but mutates the input transactions
        CMutableTransaction tx2To(txTo);      
        MutateInputs(tx2To, false, false);

        // tx3 is same as tx1 but mutates the input transaction, input script and sequence
        CMutableTransaction tx3To(txTo);      
        MutateInputs(tx3To, true, false);   

        // tx4 is same as tx1 but mutates the output values of the inputs
        CMutableTransaction tx4To(txTo);      
        MutateInputs(tx4To, false, true);    

        // test that old signature hash ignores SIGHASH_ANYPREVOUT and SIGHASH_ANYPREVOUTANYSCRIPT
        uint256 sho = SignatureHashOld(scriptCode, CTransaction(txTo), nIn, nHashType);
        uint256 sho_apo = SignatureHashOld(scriptCode, CTransaction(txTo), nIn, nHashTypeApo);
        uint256 sho_apoas = SignatureHashOld(scriptCode, CTransaction(txTo), nIn, nHashTypeApoas);
        uint256 sho_tx2 = SignatureHashOld(scriptCode, CTransaction(tx2To), nIn, nHashType);
        uint256 sho_tx2_apo = SignatureHashOld(scriptCode, CTransaction(tx2To), nIn, nHashTypeApo);
        uint256 sho_tx2_apoas = SignatureHashOld(scriptCode, CTransaction(tx2To), nIn, nHashTypeApoas);
        uint256 sho_tx3 = SignatureHashOld(scriptCode, CTransaction(tx3To), nIn, nHashType);
        uint256 sho_tx3_apo = SignatureHashOld(scriptCode, CTransaction(tx3To), nIn, nHashTypeApo);
        uint256 sho_tx3_apoas = SignatureHashOld(scriptCode, CTransaction(tx3To), nIn, nHashTypeApoas);
        uint256 sho_tx4 = SignatureHashOld(scriptCode, CTransaction(tx4To), nIn, nHashType);
        uint256 sho_tx4_apo = SignatureHashOld(scriptCode, CTransaction(tx4To), nIn, nHashTypeApo);
        uint256 sho_tx4_apoas = SignatureHashOld(scriptCode, CTransaction(tx4To), nIn, nHashTypeApoas);

        // test that BASE signature hash ignores SIGHASH_ANYPREVOUT and SIGHASH_ANYPREVOUTANYSCRIPT
        uint256 shb = SignatureHash(scriptCode, txTo, nIn, nHashType, 0, SigVersion::BASE);
        uint256 shb_apo = SignatureHash(scriptCode, txTo, nIn, nHashTypeApo, 0, SigVersion::BASE);
        uint256 shb_apoas = SignatureHash(scriptCode, txTo, nIn, nHashTypeApoas, 0, SigVersion::BASE);
        uint256 shb_tx2 = SignatureHash(scriptCode, tx2To, nIn, nHashType, 0, SigVersion::BASE);
        uint256 shb_tx2_apo = SignatureHash(scriptCode, tx2To, nIn, nHashTypeApo, 0, SigVersion::BASE);
        uint256 shb_tx2_apoas = SignatureHash(scriptCode, tx2To, nIn, nHashTypeApoas, 0, SigVersion::BASE);
        uint256 shb_tx3 = SignatureHash(scriptCode, tx3To, nIn, nHashType, 0, SigVersion::BASE);
        uint256 shb_tx3_apo = SignatureHash(scriptCode, tx3To, nIn, nHashTypeApo, 0, SigVersion::BASE);
        uint256 shb_tx3_apoas = SignatureHash(scriptCode, tx3To, nIn, nHashTypeApoas, 0, SigVersion::BASE);
        uint256 shb_tx4 = SignatureHash(scriptCode, tx4To, nIn, nHashType, 0, SigVersion::BASE);
        uint256 shb_tx4_apo = SignatureHash(scriptCode, tx4To, nIn, nHashTypeApo, 0, SigVersion::BASE);
        uint256 shb_tx4_apoas = SignatureHash(scriptCode, tx4To, nIn, nHashTypeApoas, 0, SigVersion::BASE);

        // test that v0 signature hash ignores SIGHASH_ANYPREVOUT and SIGHASH_ANYPREVOUTANYSCRIPT
        uint256 shv0 = SignatureHash(scriptCode, txTo, nIn, nHashType, 0, SigVersion::WITNESS_V0);
        uint256 shv0_apo = SignatureHash(scriptCode, txTo, nIn, nHashTypeApo, 0, SigVersion::WITNESS_V0);
        uint256 shv0_apoas = SignatureHash(scriptCode, txTo, nIn, nHashTypeApoas, 0, SigVersion::WITNESS_V0);
        uint256 shv0_tx2 = SignatureHash(scriptCode, tx2To, nIn, nHashType, 0, SigVersion::WITNESS_V0);
        uint256 shv0_tx2_apo = SignatureHash(scriptCode, tx2To, nIn, nHashTypeApo, 0, SigVersion::WITNESS_V0);
        uint256 shv0_tx2_apoas = SignatureHash(scriptCode, tx2To, nIn, nHashTypeApoas, 0, SigVersion::WITNESS_V0);
        uint256 shv0_tx3 = SignatureHash(scriptCode, tx3To, nIn, nHashType, 0, SigVersion::WITNESS_V0);
        uint256 shv0_tx3_apo = SignatureHash(scriptCode, tx3To, nIn, nHashTypeApo, 0, SigVersion::WITNESS_V0);
        uint256 shv0_tx3_apoas = SignatureHash(scriptCode, tx3To, nIn, nHashTypeApoas, 0, SigVersion::WITNESS_V0);
        uint256 shv0_tx4 = SignatureHash(scriptCode, tx4To, nIn, nHashType, 0, SigVersion::WITNESS_V0);
        uint256 shv0_tx4_apo = SignatureHash(scriptCode, tx4To, nIn, nHashTypeApo, 0, SigVersion::WITNESS_V0);
        uint256 shv0_tx4_apoas = SignatureHash(scriptCode, tx4To, nIn, nHashTypeApoas, 0, SigVersion::WITNESS_V0);

        #if defined(PRINT_SIGHASH_JSON)
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << txTo;

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

        // with maleated input only
        BOOST_CHECK(sho != sho_tx2);
        BOOST_CHECK(sho_apo != sho_tx2_apo);
        BOOST_CHECK(sho_apoas != sho_tx2_apoas);
        BOOST_CHECK(shb != shb_tx2);
        BOOST_CHECK(shb_apo != shb_tx2_apo);
        BOOST_CHECK(shb_apoas != shb_tx2_apoas);
        BOOST_CHECK(shv0 != shv0_tx2);
        BOOST_CHECK(shv0_apo != shv0_tx2_apo);
        BOOST_CHECK(shv0_apoas != shv0_tx2_apoas);

        // with both maleated input, script and sequence 
        BOOST_CHECK(sho != sho_tx3);
        BOOST_CHECK(sho_apo != sho_tx3_apo);
        BOOST_CHECK(sho_apoas != sho_tx3_apoas);
        BOOST_CHECK(shb != shb_tx3);
        BOOST_CHECK(shb_apo != shb_tx3_apo);
        BOOST_CHECK(shb_apoas != shb_tx3_apoas);
        BOOST_CHECK(shv0 != shv0_tx3);
        BOOST_CHECK(shv0_apo != shv0_tx3_apo);
        BOOST_CHECK(shv0_apoas != shv0_tx3_apoas);

        // maleated output value of the input
        BOOST_CHECK(sho != sho_tx4);
        BOOST_CHECK(sho_apo != sho_tx4_apo);
        BOOST_CHECK(sho_apoas != sho_tx4_apoas);
        BOOST_CHECK(shb != shb_tx4);
        BOOST_CHECK(shb_apo != shb_tx4_apo);
        BOOST_CHECK(shb_apoas != shb_tx4_apoas);
        BOOST_CHECK(shv0 != shv0_tx4);
        BOOST_CHECK(shv0_apo != shv0_tx4_apo);
        BOOST_CHECK(shv0_apoas != shv0_tx4_apoas);
    }

    #if defined(PRINT_SIGHASH_JSON)
    std::cout << "]\n";
    #endif
}

// Goal: check that SignatureHashSchnorr generates the same hash when inputs are maleated with SIGHASH_ANYPREVOUT and SIGHASH_ANYPREVOUTANYSCRIPT
BOOST_AUTO_TEST_CASE(sighash_anyprevout_schnorr)
{
    #if defined(PRINT_SIGHASH_JSON)
    std::cout << "[\n";
    std::cout << "\t[\"raw_transaction, script, input_index, hashType, signature_hash (result)\"],\n";
    int nRandomTests = 500;
    #else
    int nRandomTests = 50000;
    #endif

    for (int i=0; i<nRandomTests; i++) {

        // Random SigHash, excluding sighash input flags
        int nHashType = InsecureRand32() & ~SIGHASH_INPUT_MASK;

        CMutableTransaction txTo;
        RandomTransaction(txTo, (nHashType & SIGHASH_OUTPUT_MASK) == SIGHASH_SINGLE);
        CScript scriptCode;
        RandomScript(scriptCode);
        int nIn = InsecureRandRange(txTo.vin.size());

        // tx2 is same as tx1 but mutates the input transactions
        CMutableTransaction tx2To(txTo);      
        MutateInputs(tx2To, false, false);

        // tx3 is same as tx1 but mutates the input transaction, input script and sequence
        CMutableTransaction tx3To(txTo);      
        MutateInputs(tx3To, true, false);

        // tx4 is same as tx1 but mutates the output values of the inputs
        CMutableTransaction tx4To(txTo);      
        MutateInputs(tx4To, false, true);

        // add witness to transactions
        txTo.vin[0].scriptWitness.stack.push_back({OP_TRUE});
        tx2To.vin[0].scriptWitness.stack.push_back({OP_TRUE});
        tx3To.vin[0].scriptWitness.stack.push_back({OP_TRUE});
        tx4To.vin[0].scriptWitness.stack.push_back({OP_TRUE});

        // precompute transaction caches
        PrecomputedTransactionData txdata(txTo);
        PrecomputedTransactionData tx2data(tx2To);
        PrecomputedTransactionData tx3data(tx3To);
        PrecomputedTransactionData tx4data(tx4To);

        // only check signature version of v1/TAPSCRIPT (0x3) because EvalChecksig will not allow execution of v1/TAPROOT (0x2) transactions
        SigVersion sigversion = SigVersion::TAPSCRIPT;

        // build a simple v1/TAPSCRIPT transaction
        std::vector<unsigned char> taproot_pubkey_v0(WITNESS_V1_TAPROOT_SIZE, 0);
        CScript scriptPubKey = CScript() << OP_1 << taproot_pubkey_v0;
        
        // create a tapscript p2wpk outputs for each input
        txdata.Init(txTo, std::vector<CTxOut>(txTo.vin.size(), CTxOut(0, scriptPubKey)));
        tx2data.Init(tx2To, std::vector<CTxOut>(tx2To.vin.size(), CTxOut(0, scriptPubKey)));
        tx3data.Init(tx3To, std::vector<CTxOut>(tx3To.vin.size(), CTxOut(0, scriptPubKey)));
        tx4data.Init(tx4To, std::vector<CTxOut>(tx4To.vin.size(), CTxOut(0, scriptPubKey)));

        // create random v1/TAPSCRIPT execution data
        ScriptExecutionData execdata;
        execdata.m_annex_init = true;
        execdata.m_annex_present = InsecureRandBool();
        execdata.m_annex_hash = InsecureRand256();
        execdata.m_tapleaf_hash_init = true;
        execdata.m_tapleaf_hash = InsecureRand256();
        execdata.m_codeseparator_pos_init = true;
        execdata.m_codeseparator_pos = InsecureRand32();

        // with the TAPROOT (0x0) key version, SIGHASH_DEFAULT should behave like SIGHASH_ALL
        {
            uint256 shts_trk_default, shts_trk_all;
            BOOST_CHECK(SignatureHashSchnorr(shts_trk_default, execdata, txTo, nIn, SIGHASH_DEFAULT, sigversion, KeyVersion::TAPROOT, txdata));
            BOOST_CHECK(SignatureHashSchnorr(shts_trk_all, execdata, txTo, nIn, SIGHASH_ALL, sigversion, KeyVersion::TAPROOT, txdata));
            BOOST_CHECK(shts_trk_default == shts_trk_all);
        }

        // with the ANYPREVOUT (0x1) key version, SIGHASH_DEFAULT should behave like SIGHASH_ALL
        {
            uint256 shts_trk_default, shts_trk_all, shts_apo_default, shts_apo_all;
            BOOST_CHECK(SignatureHashSchnorr(shts_apo_default, execdata, txTo, nIn, SIGHASH_DEFAULT, sigversion, KeyVersion::ANYPREVOUT, txdata));
            BOOST_CHECK(SignatureHashSchnorr(shts_apo_all, execdata, txTo, nIn, SIGHASH_ALL, sigversion, KeyVersion::ANYPREVOUT, txdata));
            BOOST_CHECK(shts_apo_default == shts_apo_all);
        }
        
        int nHashType_outmask = nHashType & SIGHASH_OUTPUT_MASK;
        int nHashType_inoutmask = nHashType & (SIGHASH_INPUT_MASK | SIGHASH_OUTPUT_MASK);

        // any sighash that sets undefined input or output flags should fail
        {
            uint256 tmp;

            if (nHashType_inoutmask != nHashType) {
                BOOST_CHECK(false == SignatureHashSchnorr(tmp, execdata, txTo, nIn, nHashType, sigversion, KeyVersion::TAPROOT, txdata));
            }
            if (nHashType_inoutmask != nHashType) {
                BOOST_CHECK(false == SignatureHashSchnorr(tmp, execdata, txTo, nIn, nHashType, sigversion, KeyVersion::ANYPREVOUT, txdata));
            }
        }

        // check transactions using the TAPROOT (0x0) key version
        {
            uint256 tmp, shts_trk_default, shts_trk_all;

            // should behave like SIGHASH_ALL when no sighash is set (SIGHASH_DEFAULT) 
            BOOST_CHECK(SignatureHashSchnorr(shts_trk_default, execdata, txTo, nIn, SIGHASH_DEFAULT, sigversion, KeyVersion::TAPROOT, txdata));
            BOOST_CHECK(SignatureHashSchnorr(shts_trk_all, execdata, txTo, nIn, SIGHASH_ALL, sigversion, KeyVersion::TAPROOT, txdata));

            // should fail unless no sighash input flag or the ANYONECANPAY input flag is set 
            uint256 shts_trk, shts_trk_acp;
            if (nHashType_outmask == SIGHASH_DEFAULT) {
                BOOST_CHECK(SignatureHashSchnorr(shts_trk, execdata, txTo, nIn, nHashType_outmask, sigversion, KeyVersion::TAPROOT, txdata));
                BOOST_CHECK(false == SignatureHashSchnorr(tmp, execdata, txTo, nIn, nHashType_outmask | SIGHASH_ANYONECANPAY, sigversion, KeyVersion::TAPROOT, txdata));
                BOOST_CHECK(false == SignatureHashSchnorr(tmp, execdata, txTo, nIn, nHashType_outmask | SIGHASH_ANYPREVOUT, sigversion, KeyVersion::TAPROOT, txdata));
                BOOST_CHECK(false == SignatureHashSchnorr(tmp, execdata, txTo, nIn, nHashType_outmask | SIGHASH_ANYPREVOUTANYSCRIPT, sigversion, KeyVersion::TAPROOT, txdata));
            }
            // otherwise all other output sighash flags should fail when any input sighash flags are set except SIGHASH_ANYONECANPAY (0x80)
            else {
                BOOST_CHECK(SignatureHashSchnorr(shts_trk_acp, execdata, txTo, nIn, nHashType_inoutmask | SIGHASH_ANYONECANPAY, sigversion, KeyVersion::TAPROOT, txdata));
                BOOST_CHECK(false == SignatureHashSchnorr(tmp, execdata, txTo, nIn, nHashType_inoutmask | SIGHASH_ANYPREVOUT, sigversion, KeyVersion::TAPROOT, txdata));
                BOOST_CHECK(false == SignatureHashSchnorr(tmp, execdata, txTo, nIn, nHashType_inoutmask | SIGHASH_ANYPREVOUTANYSCRIPT, sigversion, KeyVersion::TAPROOT, txdata));
            }
        }

        // check transactions using the ANYPREVOUT (0x1) key version
        {
            uint256 tmp, shts, shts_acp, shts_apo, shts_apoas;
            uint256 shts_tx2_acp, shts_tx2_apo, shts_tx2_apoas;
            uint256 shts_tx3_acp, shts_tx3_apo, shts_tx3_apoas;
            uint256 shts_tx4_acp, shts_tx4_apo, shts_tx4_apoas;

            // should behave like SIGHASH_ALL when no sighash is set (SIGHASH_DEFAULT), and fail if any input sighash is set any output sighash set
            if (nHashType_outmask == SIGHASH_DEFAULT) {
                BOOST_CHECK(SignatureHashSchnorr(shts, execdata, txTo, nIn, nHashType_outmask, sigversion, KeyVersion::ANYPREVOUT, txdata));
                BOOST_CHECK(false == SignatureHashSchnorr(tmp, execdata, txTo, nIn, nHashType_outmask | SIGHASH_ANYONECANPAY, sigversion, KeyVersion::ANYPREVOUT, txdata));
                BOOST_CHECK(false == SignatureHashSchnorr(tmp, execdata, txTo, nIn, nHashType_outmask | SIGHASH_ANYPREVOUT, sigversion, KeyVersion::ANYPREVOUT, txdata));
                BOOST_CHECK(false == SignatureHashSchnorr(tmp, execdata, txTo, nIn, nHashType_outmask | SIGHASH_ANYPREVOUTANYSCRIPT, sigversion, KeyVersion::ANYPREVOUT, txdata));
            }
            // otherwise any output sighash flags should succeed with any input sighash flags
            else {
                BOOST_CHECK(SignatureHashSchnorr(shts_acp, execdata, txTo, nIn, nHashType_inoutmask | SIGHASH_ANYONECANPAY, sigversion, KeyVersion::TAPROOT, txdata));
                BOOST_CHECK(SignatureHashSchnorr(shts_apo, execdata, txTo, nIn, nHashType_inoutmask | SIGHASH_ANYPREVOUT, sigversion, KeyVersion::TAPROOT, txdata));
                BOOST_CHECK(SignatureHashSchnorr(shts_apoas, execdata, txTo, nIn, nHashType_inoutmask | SIGHASH_ANYPREVOUTANYSCRIPT, sigversion, KeyVersion::TAPROOT, txdata));
                BOOST_CHECK(SignatureHashSchnorr(shts_tx2_acp, execdata, tx2To, nIn, nHashType_inoutmask | SIGHASH_ANYONECANPAY, sigversion, KeyVersion::TAPROOT, tx2data));
                BOOST_CHECK(SignatureHashSchnorr(shts_tx2_apo, execdata, tx2To, nIn, nHashType_inoutmask | SIGHASH_ANYPREVOUT, sigversion, KeyVersion::TAPROOT, tx2data));
                BOOST_CHECK(SignatureHashSchnorr(shts_tx2_apoas, execdata, tx2To, nIn, nHashType_inoutmask | SIGHASH_ANYPREVOUTANYSCRIPT, sigversion, KeyVersion::TAPROOT, tx2data));
                BOOST_CHECK(SignatureHashSchnorr(shts_tx3_acp, execdata, tx3To, nIn, nHashType_inoutmask | SIGHASH_ANYONECANPAY, sigversion, KeyVersion::TAPROOT, tx3data));
                BOOST_CHECK(SignatureHashSchnorr(shts_tx3_apo, execdata, tx3To, nIn, nHashType_inoutmask | SIGHASH_ANYPREVOUT, sigversion, KeyVersion::TAPROOT, tx3data));
                BOOST_CHECK(SignatureHashSchnorr(shts_tx3_apoas, execdata, tx3To, nIn, nHashType_inoutmask | SIGHASH_ANYPREVOUTANYSCRIPT, sigversion, KeyVersion::TAPROOT, tx3data));
                BOOST_CHECK(SignatureHashSchnorr(shts_tx4_acp, execdata, tx4To, nIn, nHashType_inoutmask | SIGHASH_ANYONECANPAY, sigversion, KeyVersion::TAPROOT, tx4data));
                BOOST_CHECK(SignatureHashSchnorr(shts_tx4_apo, execdata, tx4To, nIn, nHashType_inoutmask | SIGHASH_ANYPREVOUT, sigversion, KeyVersion::TAPROOT, tx4data));
                BOOST_CHECK(SignatureHashSchnorr(shts_tx4_apoas, execdata, tx4To, nIn, nHashType_inoutmask | SIGHASH_ANYPREVOUTANYSCRIPT, sigversion, KeyVersion::TAPROOT, tx4data));
            }

            // adding the SIGHASH_ANYONECANPAY input flag should always create unique sighash results
            BOOST_CHECK(shts != shts_tx2_acp);
            BOOST_CHECK(shts_acp != shts_tx2_acp);
            BOOST_CHECK(shts_acp != shts_tx3_acp);
            BOOST_CHECK(shts_tx2_acp != shts_tx3_acp);

            // adding the SIGHASH_ANYPREVOUT input flag should only create identical sighashes when the input script and sequence does not change
            BOOST_CHECK(shts_apo == shts_tx2_apo);
            BOOST_CHECK(shts_apo != shts_tx3_apo);
            BOOST_CHECK(shts_tx2_apo != shts_tx3_apo);
            BOOST_CHECK(shts != shts_tx2_apo);
            BOOST_CHECK(shts != shts_tx3_apo);
            BOOST_CHECK(shts_acp != shts_tx2_apo);
            BOOST_CHECK(shts_acp != shts_tx3_apo);

            // adding the SIGHASH_ANYPREVOUTANYSCRIPT input flag should create identical sighashes if the output value of the inputs do not change
            BOOST_CHECK(shts_apoas == shts_tx2_apoas);
            BOOST_CHECK(shts_apoas == shts_tx3_apoas);
            BOOST_CHECK(shts_tx2_apoas == shts_tx3_apoas);
            BOOST_CHECK(shts != shts_tx2_apoas);
            BOOST_CHECK(shts != shts_tx3_apoas);
            BOOST_CHECK(shts_acp != shts_tx2_apoas);
            BOOST_CHECK(shts_acp != shts_tx3_apoas);

            // should always create unique sighashes if the output value of the inputs change
            BOOST_CHECK(shts != shts_tx4_acp);
            BOOST_CHECK(shts != shts_tx4_apo);
            BOOST_CHECK(shts != shts_tx4_apoas);
            BOOST_CHECK(shts_acp != shts_tx4_acp);
            BOOST_CHECK(shts_acp != shts_tx4_apo);
            BOOST_CHECK(shts_acp != shts_tx4_apoas);
            BOOST_CHECK(shts_apo != shts_tx4_acp);
            BOOST_CHECK(shts_apo != shts_tx4_apo);
            BOOST_CHECK(shts_apo != shts_tx4_apoas);
            BOOST_CHECK(shts_apoas != shts_tx4_acp);
            BOOST_CHECK(shts_apoas != shts_tx4_apo);
            BOOST_CHECK(shts_apoas != shts_tx4_apoas);
        }

        #if defined(PRINT_SIGHASH_JSON)
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << txTo;

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
    }
    #if defined(PRINT_SIGHASH_JSON)
    std::cout << "]\n";
    #endif
}
BOOST_AUTO_TEST_SUITE_END()
