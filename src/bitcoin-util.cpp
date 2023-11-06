// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <common/args.h>
#include <common/system.h>
#include <compat/compat.h>
#include <core_io.h>
#include <script/interpreter.h>
#include <streams.h>
#include <univalue.h>
#include <util/exception.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <version.h>

#include <atomic>
#include <cstdio>
#include <functional>
#include <memory>
#include <thread>

static const int CONTINUE_EXECUTION=-1;

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

static void SetupBitcoinUtilArgs(ArgsManager &argsman)
{
    SetupHelpOptions(argsman);

    argsman.AddArg("-version", "Print version and exit", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);

    argsman.AddCommand("grind", "Perform proof of work on hex header string");
    argsman.AddCommand("evalscript", "Interpret a bitcoin script");

    SetupChainParamsBaseOptions(argsman);
}

// This function returns either one of EXIT_ codes when it's expected to stop the process or
// CONTINUE_EXECUTION when it's expected to continue further.
static int AppInitUtil(ArgsManager& args, int argc, char* argv[])
{
    SetupBitcoinUtilArgs(args);
    std::string error;
    if (!args.ParseParameters(argc, argv, error)) {
        tfm::format(std::cerr, "Error parsing command line arguments: %s\n", error);
        return EXIT_FAILURE;
    }

    if (HelpRequested(args) || args.IsArgSet("-version")) {
        // First part of help message is specific to this utility
        std::string strUsage = PACKAGE_NAME " bitcoin-util utility version " + FormatFullVersion() + "\n";

        if (args.IsArgSet("-version")) {
            strUsage += FormatParagraph(LicenseInfo());
        } else {
            strUsage += "\n"
                "Usage:  bitcoin-util [options] [commands]  Do stuff\n";
            strUsage += "\n" + args.GetHelpMessage();
        }

        tfm::format(std::cout, "%s", strUsage);

        if (argc < 2) {
            tfm::format(std::cerr, "Error: too few parameters\n");
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }

    // Check for chain settings (Params() calls are only valid after this clause)
    try {
        SelectParams(args.GetChainType());
    } catch (const std::exception& e) {
        tfm::format(std::cerr, "Error: %s\n", e.what());
        return EXIT_FAILURE;
    }

    return CONTINUE_EXECUTION;
}

static void grind_task(uint32_t nBits, CBlockHeader header, uint32_t offset, uint32_t step, std::atomic<bool>& found, uint32_t& proposed_nonce)
{
    arith_uint256 target;
    bool neg, over;
    target.SetCompact(nBits, &neg, &over);
    if (target == 0 || neg || over) return;
    header.nNonce = offset;

    uint32_t finish = std::numeric_limits<uint32_t>::max() - step;
    finish = finish - (finish % step) + offset;

    while (!found && header.nNonce < finish) {
        const uint32_t next = (finish - header.nNonce < 5000*step) ? finish : header.nNonce + 5000*step;
        do {
            if (UintToArith256(header.GetHash()) <= target) {
                if (!found.exchange(true)) {
                    proposed_nonce = header.nNonce;
                }
                return;
            }
            header.nNonce += step;
        } while(header.nNonce != next);
    }
}

static int Grind(const std::vector<std::string>& args, std::string& strPrint)
{
    if (args.size() != 1) {
        strPrint = "Must specify block header to grind";
        return EXIT_FAILURE;
    }

    CBlockHeader header;
    if (!DecodeHexBlockHeader(header, args[0])) {
        strPrint = "Could not decode block header";
        return EXIT_FAILURE;
    }

    uint32_t nBits = header.nBits;
    std::atomic<bool> found{false};
    uint32_t proposed_nonce{};

    std::vector<std::thread> threads;
    int n_tasks = std::max(1u, std::thread::hardware_concurrency());
    threads.reserve(n_tasks);
    for (int i = 0; i < n_tasks; ++i) {
        threads.emplace_back(grind_task, nBits, header, i, n_tasks, std::ref(found), std::ref(proposed_nonce));
    }
    for (auto& t : threads) {
        t.join();
    }
    if (found) {
        header.nNonce = proposed_nonce;
    } else {
        strPrint = "Could not satisfy difficulty target";
        return EXIT_FAILURE;
    }

    DataStream ss{};
    ss << header;
    strPrint = HexStr(ss);
    return EXIT_SUCCESS;
}

static UniValue stack2uv(const std::vector<std::vector<unsigned char>>& stack)
{
    UniValue result{UniValue::VARR};
    for (const auto& v : stack) {
        result.push_back(HexStr(v));
    }
    return result;
}

static int EvalScript(const std::vector<std::string>& args, std::string& strPrint)
{
    UniValue result{UniValue::VOBJ};

    std::vector<std::vector<unsigned char> > stack{};
    CScript script{};
    uint32_t flags{0};
    BaseSignatureChecker checker;

//  CTransaction txTo;
//
//  PrecomputedTransactionData txdata;
//  std::vector<CTxOut> spent_outputs;
//  txdata.Init(txTo, std::move(spent_outputs), /*force=*/true);
//
//  unsigned int idx;  // which input is being spent
//  CAmount amountIn = spent_outputs.at(idx).nAmount; // ?  (assuming it's initialized, ofc)
//
//  GenericTransactionSignatureChecker checker(txTo, idx, amount, txdata, MissingDataBehavior::ASSERT_FAIL);

    SigVersion sigversion = SigVersion::WITNESS_V0;
    ScriptError serror{};

    if (args.size() > 0) {
        auto h = ParseHex(args[0]);
        script = CScript(h.begin(), h.end());

        for (size_t i = 1; i < args.size(); ++i) {
            stack.push_back(ParseHex(args[i]));
        }
    }

    UniValue uv_script{UniValue::VOBJ};
    ScriptToUniv(script, uv_script);
    result.pushKV("script", uv_script);

    bool success = EvalScript(stack, script, flags, checker, sigversion, &serror);

    result.pushKV("stack-after", stack2uv(stack));

    result.pushKV("success", success);
    if (!success) {
        result.pushKV("error", ScriptErrorString(serror));
    }

    strPrint = result.write(2);

    return EXIT_SUCCESS;
}

MAIN_FUNCTION
{
    ArgsManager& args = gArgs;
    SetupEnvironment();

    try {
        int ret = AppInitUtil(args, argc, argv);
        if (ret != CONTINUE_EXECUTION) {
            return ret;
        }
    } catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInitUtil()");
        return EXIT_FAILURE;
    } catch (...) {
        PrintExceptionContinue(nullptr, "AppInitUtil()");
        return EXIT_FAILURE;
    }

    const auto cmd = args.GetCommand();
    if (!cmd) {
        tfm::format(std::cerr, "Error: must specify a command\n");
        return EXIT_FAILURE;
    }

    int ret = EXIT_FAILURE;
    std::string strPrint;
    try {
        if (cmd->command == "grind") {
            ret = Grind(cmd->args, strPrint);
        } else if (cmd->command == "evalscript") {
            ret = EvalScript(cmd->args, strPrint);
        } else {
            assert(false); // unknown command should be caught earlier
        }
    } catch (const std::exception& e) {
        strPrint = std::string("error: ") + e.what();
    } catch (...) {
        strPrint = "unknown error";
    }

    if (strPrint != "") {
        tfm::format(ret == 0 ? std::cout : std::cerr, "%s\n", strPrint);
    }

    return ret;
}
