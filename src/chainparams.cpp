// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsbase.h>
#include <common/args.h>
#include <common/argsregister.h>
#include <consensus/params.h>
#include <deploymentinfo.h>
#include <logging.h>
#include <tinyformat.h>
#include <util/chaintype.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <cassert>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>


namespace {
class SigNetArgsRegister
{
public:
    using T = CChainParams::SigNetOptions;

    static inline void GetChallenge(std::optional<std::vector<uint8_t>>& challenge, const std::vector<std::string>& arg_challenges)
    {
        if (arg_challenges.size() != 1) {
            throw std::runtime_error("-signetchallenge cannot be multiple values.");
        }

        const auto val{TryParseHex<uint8_t>(arg_challenges[0])};
        if (!val) {
            throw std::runtime_error(strprintf("-signetchallenge must be hex, not '%s'.", arg_challenges[0]));
        }
        challenge.emplace(*val);
    }

    template<typename C, typename Op>
    static inline void Register(Op& op)
    {
        return C::Do(op,
            C::Defn(&T::challenge, "-signetchallenge", "", GetChallenge,
                    "Blocks must satisfy the given script to be considered valid (only for signet networks; defaults to the global default signet test network challenge)",
                    ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION,
                    OptionsCategory::CHAINPARAMS),
            C::Defn(&T::seeds, "-signetseednode", "",
                    "Specify a seed node for the signet network, in the hostname[:port] format, e.g. sig.net:1234 (may be used multiple times to specify multiple seed nodes; defaults to the global default signet test network seed node(s))",
                    ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION,
                    OptionsCategory::CHAINPARAMS)
            );
    }
};

class RegTestArgsRegister
{
public:
    using T = CChainParams::RegTestOptions;


    static inline void GetActivationHeights(std::unordered_map<Consensus::BuriedDeployment, int>& activation_heights, const std::vector<std::string>& args)
    {
        for (const std::string& arg : args) {
            const auto found{arg.find('@')};
            if (found == std::string::npos) {
                throw std::runtime_error(strprintf("Invalid format (%s) for -testactivationheight=name@height.", arg));
            }

            const auto value{arg.substr(found + 1)};
            int32_t height;
            if (!ParseInt32(value, &height) || height < 0 || height >= std::numeric_limits<int>::max()) {
                throw std::runtime_error(strprintf("Invalid height value (%s) for -testactivationheight=name@height.", arg));
            }

            const auto deployment_name{arg.substr(0, found)};
            if (const auto buried_deployment = GetBuriedDeployment(deployment_name)) {
                activation_heights[*buried_deployment] = height;
            } else {
                throw std::runtime_error(strprintf("Invalid name (%s) for -testactivationheight=name@height.", arg));
            }
        }
    }

    static inline void GetVBParams(std::unordered_map<Consensus::DeploymentPos, CChainParams::VersionBitsParameters>& version_bits_parameters, const std::vector<std::string>& args)
    {
        for (const std::string& deployment : args) {
            std::vector<std::string> vDeploymentParams = SplitString(deployment, ':');
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
            for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
                if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                    version_bits_parameters[Consensus::DeploymentPos(j)] = vbparams;
                    found = true;
                    LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld, min_activation_height=%d\n", vDeploymentParams[0], vbparams.start_time, vbparams.timeout, vbparams.min_activation_height);
                    break;
                }
            }
            if (!found) {
                throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
            }
        }
    }

    template<typename C, typename Op>
    static inline void Register(Op& op)
    {
        return C::Do(op,
            C::Defn(&T::version_bits_parameters, "-vbparams", "=deployment:start:end[:min_activation_height]", GetVBParams,
                    "Use given start/end times and min_activation_height for specified version bits deployment (regtest-only)",
                    ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY,
                    OptionsCategory::DEBUG_TEST),
            C::Defn(&T::activation_heights, "-testactivationheight", "=name@height.", GetActivationHeights,
                    "Set the activation height of 'name' (segwit, bip34, dersig, cltv, csv). (regtest-only)",
                    ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY,
                    OptionsCategory::DEBUG_TEST),
            C::Defn(&T::fastprune, "-fastprune", "",
                    "Use smaller block files and lower minimum prune height for testing purposes",
                    ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY,
                    OptionsCategory::DEBUG_TEST)
            );
    }
};

} // anon namespace

void SetupChainParamsOptions(ArgsManager& argsman)
{
    ArgsRegister<RegTestArgsRegister>::Register(argsman);
    ArgsRegister<SigNetArgsRegister>::Register(argsman);
}


void ReadSigNetArgs(const ArgsManager& args, CChainParams::SigNetOptions& options)
{
    ArgsRegister<SigNetArgsRegister>::Update(args, options);
}

void ReadRegTestArgs(const ArgsManager& args, CChainParams::RegTestOptions& options)
{
    ArgsRegister<RegTestArgsRegister>::Update(args, options);
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const ArgsManager& args, const ChainType chain)
{
    switch (chain) {
    case ChainType::MAIN:
        return CChainParams::Main();
    case ChainType::TESTNET:
        return CChainParams::TestNet();
    case ChainType::SIGNET: {
        auto opts = CChainParams::SigNetOptions{};
        ReadSigNetArgs(args, opts);
        return CChainParams::SigNet(opts);
    }
    case ChainType::REGTEST: {
        auto opts = CChainParams::RegTestOptions{};
        ReadRegTestArgs(args, opts);
        return CChainParams::RegTest(opts);
    }
    }
    assert(false);
}

void SelectParams(const ChainType chain)
{
    SelectBaseParams(chain);
    globalChainParams = CreateChainParams(gArgs, chain);
}
