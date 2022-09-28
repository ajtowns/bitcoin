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

namespace {
class RegTestOptionsRegistration
{
public:
    using T = CChainParams::RegTestOptions;

    static inline void GetActivationHeights(std::unordered_map<Consensus::BuriedDeployment, int>& activation_heights, const std::vector<std::string>& vs)
    {
        for (const std::string& arg : vs) {
            const auto found{arg.find('@')};
            if (found == std::string::npos) {
                throw std::runtime_error(strprintf("Invalid format (%s) for -testactivationheight=name@height.", arg));
            }

            const auto maybe_dep = GetBuriedDeployment(arg.substr(0, found));
            if (!maybe_dep.has_value()) {
                throw std::runtime_error(strprintf("Invalid name (%s) for -testactivationheight=name@height.", arg));
            }

            const auto value{arg.substr(found + 1)};
            int32_t height;
            if (!ParseInt32(value, &height) || height < 0 || height >= std::numeric_limits<int>::max()) {
                throw std::runtime_error(strprintf("Invalid height value (%s) for -testactivationheight=name@height.", arg));
            }

            activation_heights.insert_or_assign(*maybe_dep, height);
        }
    }

    static inline void GetVBParams(std::unordered_map<Consensus::DeploymentPos, CChainParams::VersionBitsParameters>& version_bits_parameters, const std::vector<std::string>& vs)
    {
        for (const std::string& strDeployment : vs) {
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
    }

    template<typename C, typename Op>
    static inline void Register(Op& op)
    {
        return C::Do(op,
            C::Defn(&T::activation_heights, GetActivationHeights, "-testactivationheight", "=name@height.", "Set the activation height of 'name' (segwit, bip34, dersig, cltv, csv). (regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST),
            C::Defn(&T::version_bits_parameters, GetVBParams, "-vbparams", "=deployment:start:end[:min_activation_height]", "Use given start/end times and min_activation_height for specified version bits deployment (regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS),
            C::Defn(&T::fast_prune, "-fastprune", "", "Use smaller block files and lower minimum prune height for testing purposes", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST, false)
        );
    }
};

class SigNetOptionsRegistration
{
public:
    using T = CChainParams::SigNetOptions;

    static inline void GetChallenge(std::vector<uint8_t>& challenge, const std::string& hex)
    {
        challenge = ParseHex(hex);
    }

    template<typename C, typename Op>
    static inline void Register(Op& op)
    {
        return C::Do(op,
            C::Defn(&T::challenge, GetChallenge, "-signetchallenge", "", "Blocks must satisfy the given script to be considered valid (only for signet networks; defaults to the global default signet test network challenge)", ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION, OptionsCategory::CHAINPARAMS),
            C::Defn(&T::seeds, "-signetseednode", "", "Specify a seed node for the signet network, in the hostname[:port] format, e.g. sig.net:1234 (may be used multiple times to specify multiple seed nodes; defaults to the global default signet test network seed node(s))", ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION, OptionsCategory::CHAINPARAMS)
        );
    }
};
}

void RegisterChainParamsOptions(ArgsManager& args)
{
    SettingsRegister<SigNetOptionsRegistration>::Register(args);
    SettingsRegister<RegTestOptionsRegistration>::Register(args);
}

CChainParams::SigNetOptions GetSigNetOptions(const ArgsManager& args)
{
    return SettingsRegister<SigNetOptionsRegistration>::Get(args);
}

CChainParams::RegTestOptions GetRegTestOptions(const ArgsManager& args)
{
    return SettingsRegister<RegTestOptionsRegistration>::Get(args);
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
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
