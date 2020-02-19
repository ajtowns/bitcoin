// Copyright (c) 2016-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <key.h>
#if defined(HAVE_CONSENSUS_LIB)
#include <script/bitcoinconsensus.h>
#endif
#include <script/script.h>
#include <script/standard.h>
#include <streams.h>
#include <test/util/transaction_utils.h>

#include <array>

// Microbenchmark for verification of a basic P2WPKH script. Can be easily
// modified to measure performance of other types of scripts.
static void VerifyScriptBench(benchmark::State& state)
{
    const int flags = SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH;
    const int witnessversion = 0;

    // Keypair.
    CKey key;
    static const std::array<unsigned char, 32> vchKey = {
        {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        }
    };
    key.Set(vchKey.begin(), vchKey.end(), false);
    CPubKey pubkey = key.GetPubKey();
    uint160 pubkeyHash;
    CHash160().Write(pubkey.begin(), pubkey.size()).Finalize(pubkeyHash.begin());

    // Script.
    CScript scriptPubKey = CScript() << witnessversion << ToByteVector(pubkeyHash);
    CScript scriptSig;
    CScript witScriptPubkey = CScript() << OP_DUP << OP_HASH160 << ToByteVector(pubkeyHash) << OP_EQUALVERIFY << OP_CHECKSIG;
    const CMutableTransaction& txCredit = BuildCreditingTransaction(scriptPubKey, 1);
    CMutableTransaction txSpend = BuildSpendingTransaction(scriptSig, CScriptWitness(), CTransaction(txCredit));
    CScriptWitness& witness = txSpend.vin[0].scriptWitness;
    witness.stack.emplace_back();
    key.Sign(SignatureHash(witScriptPubkey, txSpend, 0, SIGHASH_ALL, txCredit.vout[0].nValue, SigVersion::WITNESS_V0), witness.stack.back());
    witness.stack.back().push_back(static_cast<unsigned char>(SIGHASH_ALL));
    witness.stack.push_back(ToByteVector(pubkey));

    // Benchmark.
    while (state.KeepRunning()) {
        ScriptError err;
        bool success = VerifyScript(
            txSpend.vin[0].scriptSig,
            txCredit.vout[0].scriptPubKey,
            &txSpend.vin[0].scriptWitness,
            flags,
            MutableTransactionSignatureChecker(&txSpend, 0, txCredit.vout[0].nValue),
            &err);
        assert(err == SCRIPT_ERR_OK);
        assert(success);

#if defined(HAVE_CONSENSUS_LIB)
        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
        stream << txSpend;
        int csuccess = bitcoinconsensus_verify_script_with_amount(
            txCredit.vout[0].scriptPubKey.data(),
            txCredit.vout[0].scriptPubKey.size(),
            txCredit.vout[0].nValue,
            (const unsigned char*)stream.data(), stream.size(), 0, flags, nullptr);
        assert(csuccess == 1);
#endif
    }
}

template<int N,int X=100>
static inline void VerifyNestedIfScriptN(benchmark::State& state) {
    std::vector<std::vector<unsigned char>> stack;
    static_assert(N <= X, "can't have more than 201 ops, so 100 IF and 100 ENDIF");
    static_assert(3*X+1000 < 10000, "script is too large");
    CScript script;
    for (int i = 0; i < N; ++i) {
        script << OP_1 << OP_IF;
    }
    for (int i = N; i < X; ++i) {
        script << OP_1 << OP_DROP;
    }
    for (int i = 0; i < 1000; ++i) {
        script << OP_1;
    }
    for (int i = 0; i < N; ++i) {
        script << OP_ENDIF;
    }
    for (int i = N; i < X; ++i) {
        script << OP_NOP;
    }
    assert(script.size() < 10000);
    while (state.KeepRunning()) {
        auto stack_copy = stack;
        ScriptError error;
        bool ret = EvalScript(stack_copy, script, (1U<<17), BaseSignatureChecker(), SigVersion::BASE, &error);
        assert(ret);
    }
}
static void VerifyNestedIfScript(benchmark::State& state) {
    return VerifyNestedIfScriptN<100>(state);
}
static void VerifyNestedIfScript50(benchmark::State& state) {
    return VerifyNestedIfScriptN<50>(state);
}
static void VerifyNestedIfScript400(benchmark::State& state) {
    return VerifyNestedIfScriptN<400,400>(state);
}

BENCHMARK(VerifyScriptBench, 6300);

BENCHMARK(VerifyNestedIfScript, 100);
BENCHMARK(VerifyNestedIfScript50, 100);
BENCHMARK(VerifyNestedIfScript400, 100);
