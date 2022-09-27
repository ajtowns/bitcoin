// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <deploymentinfo.h>
#include <hash.h> // for signet block challenge hash
#include <script/interpreter.h>
#include <util/string.h>
#include <util/system.h>

#include <assert.h>

CChainParams::SigNetOptions GetSigNetOptions(const ArgsManager& args)
{
    std::vector<std::string> seeds{};
    if (args.IsArgSet("-signetseednode")) {
        seeds = args.GetArgs("-signetseednode");
    }
    if (args.IsArgSet("-signetchallenge")) {
        const auto signet_challenge = args.GetArgs("-signetchallenge");
        if (signet_challenge.size() != 1) {
            throw std::runtime_error(strprintf("%s: -signetchallenge cannot be multiple values.", __func__));
        }
        return CChainParams::SigNetOptions{ParseHex(signet_challenge[0]), seeds};
    } else {
        auto opts = CChainParams::SigNetOptions::GetDefaults();
        if (!seeds.empty()) {
            opts.seeds = seeds;
        }
        return opts;
    }
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::optional<CChainParams::Activations> name4namestr(const std::string& name_str) {
    if (name_str == "segwit") {
        return CChainParams::Activations::SEGWIT;
    } else if (name_str == "bip34") {
        return CChainParams::Activations::BIP34;
    } else if (name_str == "dersig") {
        return CChainParams::Activations::DERSIG;
    } else if (name_str == "cltv") {
        return CChainParams::Activations::CLTV;
    } else if (name_str == "csv") {
        return CChainParams::Activations::CSV;
    }
    return std::nullopt;
}

CChainParams::RegTestOptions GetRegTestOptions(const ArgsManager& args)
{
    std::unordered_map<CChainParams::Activations, int> activation_heights;

    for (const std::string& arg : args.GetArgs("-testactivationheight"))
    {
        const auto found{arg.find('@')};
        if (found == std::string::npos) {
            throw std::runtime_error(strprintf("Invalid format (%s) for -testactivationheight=name@height.", arg));
        }

        const auto name_str{arg.substr(0, found)};
        std::optional<CChainParams::Activations> maybe_name{name4namestr(name_str)};
        if (!maybe_name.has_value()) {
            throw std::runtime_error(strprintf("Invalid name (%s) for -testactivationheight=name@height.", arg));
        }

        const auto value{arg.substr(found + 1)};
        int32_t height;
        if (!ParseInt32(value, &height) || height < 0 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Invalid height value (%s) for -testactivationheight=name@height.", arg));
        }

        activation_heights.insert_or_assign(*maybe_name, height);
    }

    std::unordered_map<Consensus::DeploymentPos, CChainParams::VersionBitsParameters> version_bits_parameters;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams = SplitString(strDeployment, ':');
        if (vDeploymentParams.size() < 3 || 4 < vDeploymentParams.size()) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end[:min_activation_height]");
        }
        CChainParams::VersionBitsParameters vbparams{};
        if (!ParseInt64(vDeploymentParams[1], &vbparams.start_time)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &vbparams.timeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        if (vDeploymentParams.size() >= 4) {
            if (!ParseInt32(vDeploymentParams[3], &vbparams.min_activation_height)) {
                throw std::runtime_error(strprintf("Invalid min_activation_height (%s)", vDeploymentParams[3]));
            }
        } else {
            vbparams.min_activation_height = 0;
        }

        bool found = false;
        for (int j = 0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                version_bits_parameters.insert_or_assign(Consensus::DeploymentPos(j), vbparams);
                found = true;
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }

    uint64_t prune_after_height = args.GetBoolArg("-fastprune", false) ? 100 : 1000;
    return CChainParams::RegTestOptions{version_bits_parameters, activation_heights, prune_after_height};
}

std::unique_ptr<const CChainParams> CreateChainParams(const ArgsManager& args, const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN) {
        return CChainParams::Main();
    } else if (chain == CBaseChainParams::TESTNET) {
        return CChainParams::TestNet();
    } else if (chain == CBaseChainParams::SIGNET) {
        return CChainParams::SigNet(GetSigNetOptions(args));
    } else if (chain == CBaseChainParams::REGTEST) {
        return CChainParams::RegTest(GetRegTestOptions(args));
    }
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(gArgs, network);
}
