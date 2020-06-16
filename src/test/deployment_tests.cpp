// Copyright (c) 2014-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/deployment.h>
#include <consensus/params.h>
#include <deploymentstatus.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

using namespace Consensus;

static bool operator==(const SignalledDeploymentStatus::StateHeight& l, const SignalledDeploymentStatus::StateHeight& r) {
    return l.height == r.height && l.state == r.state;
}

class DeploymentStatusTester
{
    // A fake blockchain
    std::vector<CBlockIndex*> vpblock;

    // Test counter (to identify failures)
    int num;
    int resets;

    std::vector<std::pair<const SignalledDeploymentParams, const std::vector<SignalledDeploymentStatus::StateHeight>>> unconditional_checks;

public:
    DeploymentStatusTester() : num(0), resets(0) {}

    DeploymentStatusTester& Reset() {
        for (unsigned int i = 0; i < vpblock.size(); i++) {
            delete vpblock[i];
        }
        vpblock.clear();
        ++resets;
        num = 0;
        return *this;
    }

    ~DeploymentStatusTester() {
         Reset();
    }

    DeploymentStatusTester& Mine(unsigned int height, int32_t nVersion) {
        while (vpblock.size() < height) {
            CBlockIndex* pindex = new CBlockIndex();
            pindex->nHeight = vpblock.size();
            pindex->pprev = vpblock.size() > 0 ? vpblock.back() : nullptr;
            pindex->nTime = 1415926536 + 600 * vpblock.size();
            pindex->nVersion = nVersion;
            pindex->BuildSkip();
            vpblock.push_back(pindex);
        }
        return *this;
    }


    void UnconditionalCheck(const SignalledDeploymentParams& dep, const std::vector<SignalledDeploymentStatus::StateHeight> stateheights) {
        unconditional_checks.push_back(std::make_pair(dep, stateheights));
    }

    DeploymentStatusTester& UnconditionalTests() {
        num = 100; // UnconditionalTests get reported as 101, 102, etc
        for (const auto& depsh : unconditional_checks) {
            Test(depsh.first, depsh.second);
        }
        return *this;
    }

    DeploymentStatusTester& Test(const SignalledDeploymentParams& dep, const std::vector<SignalledDeploymentStatus::StateHeight> stateheights) {
        BOOST_REQUIRE(stateheights.begin() != stateheights.end());
        BOOST_REQUIRE(!vpblock.empty());
        ++num;
        for (int skip : {dep.period}) { // {1, dep.period, 1800, 3500}) {
            for (int do_first : {0, 1, (int)stateheights.size()/2, (int)stateheights.size()}) {
                bool did_first = false;
                do_first -= (do_first % skip);

                SignalledDeploymentStatus cache;

                SignalledDeploymentStatus::StateHeight res_first = cache.GetStateHeightFor(do_first == 0 ? nullptr : vpblock[do_first-1], dep, DeploymentStatus::g_condition);

                auto exp = stateheights.begin();
                for (int h = 0; h <= (int)vpblock.size(); h += skip) {
                    while ((exp+1) != stateheights.end() && (exp+1)->height <= h) ++exp;
                    SignalledDeploymentStatus::StateHeight res = cache.GetStateHeightFor(h == 0 ? nullptr : vpblock[h-1], dep, DeploymentStatus::g_condition);
                    BOOST_CHECK_MESSAGE(res == *exp, strprintf("Test %i:%i for GetStateHeightFor (skip=%d, h=%d, %d/%d != %d/%d)", resets, num, skip, h, res.state, res.height, exp->state, exp->height));
                    if (do_first == h) {
                        did_first = true;
                        BOOST_CHECK_MESSAGE(res_first == *exp, strprintf("Test %i:%i for GetStateHeightFor (skip=%d, h=%d) did not work on first try", resets, num, skip, h));
                    }
                }
                BOOST_CHECK_MESSAGE((exp+1) == stateheights.end(), strprintf("Test %i:%i for GetStateHeightFor did not reach end of expected (skip=%d, size=%d, exp.height=%d)", resets, num, skip, vpblock.size(), exp->height));
                BOOST_CHECK_MESSAGE(did_first, strprintf("Test %i:%i failed to validate result of first query (skip=%d, do_first=%d)", resets, num, skip, do_first));
            }
        }

        return *this;
    }

    CBlockIndex * Tip() { return vpblock.size() ? vpblock.back() : nullptr; }
};

BOOST_FIXTURE_TEST_SUITE(deployment_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(deployment_test)
{
    const int BIT = 1;
    const int32_t vnone = VERSIONBITS_LAST_OLD_BLOCK_VERSION;
    const int32_t vsig = VERSIONBITS_TOP_BITS | (1l << BIT);
    const int32_t vother = VERSIONBITS_TOP_BITS | (1l << (BIT+1));
    const int32_t vboth = vsig | vother;
    const int32_t vmiss = (0x7fffffffL & (~VERSIONBITS_TOP_BITS));

    const SignalledDeploymentParams dep_disabled = DeploymentDisabled<BIT>();
    const SignalledDeploymentParams dep_always = DeploymentAlwaysActive<BIT>();
    const SignalledDeploymentParams dep_buried_5000 = DeploymentBuried<BIT,5000>();
    const SignalledDeploymentParams dep_buried_8000 = DeploymentBuried<BIT,8000>();
    const SignalledDeploymentParams dep_allsig = DeploymentAlwaysSignal<BIT,1000,900>();
    const SignalledDeploymentParams dep_sig = Deployment<BIT,3000,10,5,10,1000,900>(false);
    const SignalledDeploymentParams dep_sig_guar = Deployment<BIT,3000,10,5,10,1000,900>(true);
    const SignalledDeploymentParams dep_sig_short = Deployment<BIT,3000,20,10,20,500,450>(false);

    for (auto dep : { dep_always, dep_buried_5000, dep_buried_8000, dep_allsig, dep_sig, dep_sig_guar, dep_sig_short }) {
        BOOST_CHECK(!SignalledDeploymentStatus::AlwaysDisabled(dep));
    }
    BOOST_CHECK(SignalledDeploymentStatus::AlwaysDisabled(dep_disabled));

    const SignalledDeploymentStatus::State DEF = SignalledDeploymentStatus::State::DEFINED,
                                           PRI = SignalledDeploymentStatus::State::PRIMARY,
                                           QUI = SignalledDeploymentStatus::State::QUIET,
                                           SEC = SignalledDeploymentStatus::State::SECONDARY,
                                           LOC = SignalledDeploymentStatus::State::LOCKED_IN,
                                           ACT = SignalledDeploymentStatus::State::ACTIVE,
                                           FAI = SignalledDeploymentStatus::State::FAILED;

    DeploymentStatusTester test;
    test.UnconditionalCheck(dep_disabled,    { {DEF, 0} });
    test.UnconditionalCheck(dep_always,      { {ACT, 0} });
    test.UnconditionalCheck(dep_buried_5000, { {DEF, 0}, {LOC, 4999}, {ACT, 5000} });
    test.UnconditionalCheck(dep_buried_8000, { {DEF, 0}, {LOC, 7999}, {ACT, 8000} });

    // What happens if everyone signals?
    for (auto ver : { vsig, vboth }) {
        test.Reset()
            .Mine(40000, ver)
            .Test(dep_allsig,      { {DEF, 0}, {PRI, 1000}, {LOC, 2000}, {ACT, 3000} })
            .Test(dep_sig,         { {DEF, 0}, {PRI, 3000}, {LOC, 4000}, {ACT, 5000} })
            .Test(dep_sig_guar,    { {DEF, 0}, {PRI, 3000}, {LOC, 4000}, {ACT, 5000} })
            .Test(dep_sig_short,   { {DEF, 0}, {PRI, 3000}, {LOC, 3500}, {ACT, 4000} })
            .UnconditionalTests();
    }

    // What happens if no one signals?
    for (auto ver : { vnone, vother, vmiss }) {
        test.Reset()
            .Mine(40000, ver)
            .Test(dep_allsig,      { {DEF, 0}, {PRI, 1000} })
            .Test(dep_sig,         { {DEF, 0}, {PRI, 3000}, {FAI, 13000} })
            .Test(dep_sig_guar,    { {DEF, 0}, {PRI, 3000}, {QUI, 13000}, {SEC, 18000}, {LOC, 28000}, {ACT, 29000} })
            .Test(dep_sig_short,   { {DEF, 0}, {PRI, 3000}, {FAI, 13000} })
            .UnconditionalTests();
    }

    // What happens with mixed signals?
    test.Reset()
        .Mine(900, vsig)
        .Mine(2000, vnone)
        .Mine(3250, vsig)
        .Mine(3400, vother)
        .Mine(3950, vboth)
        .Mine(5000, vother)
        .Mine(7000, vboth)
        .Mine(30000, vnone)
        .Test(dep_allsig,      { {DEF, 0}, {PRI, 1000}, {LOC, 3000}, {ACT, 4000} })
        .Test(dep_sig,         { {DEF, 0}, {PRI, 3000}, {LOC, 6000}, {ACT, 7000} })
        .Test(dep_sig_guar,    { {DEF, 0}, {PRI, 3000}, {LOC, 6000}, {ACT, 7000} })
        .Test(dep_sig_short,   { {DEF, 0}, {PRI, 3000}, {LOC, 4000}, {ACT, 4500} })
        .UnconditionalTests();

    // Signalling in SECONDARY period only
    test.Reset()
        .Mine(18500, vnone)
        .Mine(21000, vsig)
        .Mine(30000, vnone)
        .Test(dep_sig,         { {DEF, 0}, {PRI, 3000}, {FAI, 13000} })
        .Test(dep_sig_guar,    { {DEF, 0}, {PRI, 3000}, {QUI, 13000}, {SEC, 18000}, {LOC, 20000}, {ACT, 21000} })
        .UnconditionalTests();

    // How about edge cases?
    // Signalling in last block of PRIMARY 
    test.Reset()
        .Mine(12000, vnone)
        .Mine(13000, vsig)
        .Mine(30000, vnone)
        .Test(dep_sig,         { {DEF, 0}, {PRI, 3000}, {LOC, 13000}, {ACT, 14000} })
        .Test(dep_sig_guar,    { {DEF, 0}, {PRI, 3000}, {LOC, 13000}, {ACT, 14000} })
        .UnconditionalTests();

    // Signalling in first block of QUIET
    test.Reset()
        .Mine(13000, vnone)
        .Mine(14000, vsig)
        .Mine(30000, vnone)
        .Test(dep_sig,         { {DEF, 0}, {PRI, 3000}, {FAI, 13000} })
        .Test(dep_sig_guar,    { {DEF, 0}, {PRI, 3000}, {QUI, 13000}, {SEC, 18000}, {LOC, 28000}, {ACT, 29000} })
        .UnconditionalTests();

    // Just enough blocks
    test.Reset()
        .Mine(10100, vnone)
        .Mine(11000, vsig)
        .Mine(30000, vnone)
        .Test(dep_sig,         { {DEF, 0}, {PRI, 3000}, {LOC, 11000}, {ACT, 12000} })
        .Test(dep_sig_guar,    { {DEF, 0}, {PRI, 3000}, {LOC, 11000}, {ACT, 12000} })
        .UnconditionalTests();

    // Just enough blocks, but off by one
    test.Reset()
        .Mine(10101, vnone)
        .Mine(11001, vsig)
        .Mine(30000, vnone)
        .Test(dep_sig,         { {DEF, 0}, {PRI, 3000}, {FAI, 13000} })
        .Test(dep_sig_guar,    { {DEF, 0}, {PRI, 3000}, {QUI, 13000}, {SEC, 18000}, {LOC, 28000}, {ACT, 29000} })
        .UnconditionalTests();


}

static void sanity_check_bit_overlap(const std::string& chainName)
{
    // Sanity checks of version bit deployments
    const auto chainParams = CreateChainParams(chainName);
    const Consensus::Params &params = chainParams->GetConsensus();

    const int BUFFER_PERIODS = 3; // locked in plus first two ACTIVE periods

    for (int i=0; i<(int) MAX_VERSION_BITS_DEPLOYMENTS; i++) {
        const auto& dep_i = params.vDeployments[i];
        uint32_t bitmask_i = DeploymentStatus::Mask(params, static_cast<SignalledDeployment>(i));

        // Make sure that no deployment tries to set an invalid bit.
        BOOST_CHECK_EQUAL(bitmask_i & ~(uint32_t)VERSIONBITS_TOP_MASK, bitmask_i);

        // Skip non-signalling deployments
        if (dep_i.primary_periods == 0 && dep_i.secondary_periods == 0) continue;

        int final_i = dep_i.start_height + dep_i.period * ((int) dep_i.primary_periods + (int) dep_i.quiet_periods + (int) dep_i.secondary_periods + BUFFER_PERIODS);
        BOOST_CHECK(dep_i.start_height <= final_i);

        // Verify that overlapping deployments are not using the same bit.
        for (int j=0; j < i; j++) {
            const auto& dep_j = params.vDeployments[j];

            // Skip non-signalling deployments
            if (dep_j.primary_periods == 0 && dep_j.secondary_periods == 0) continue;

            int final_j = dep_j.start_height + dep_j.period * ((int) dep_j.primary_periods + (int) dep_j.quiet_periods + (int) dep_j.secondary_periods + BUFFER_PERIODS);

            // Signalling periods don't overlap
            if (final_j < dep_i.start_height) continue;
            if (final_i < dep_j.start_height) continue;

            // otherwise must have different bits
            BOOST_CHECK(DeploymentStatus::Mask(params, static_cast<SignalledDeployment>(j)) != bitmask_i);
        }
    }
}



BOOST_AUTO_TEST_CASE(deployment_bit_overlap)
{
    sanity_check_bit_overlap(CBaseChainParams::MAIN);
    sanity_check_bit_overlap(CBaseChainParams::TESTNET);
    sanity_check_bit_overlap(CBaseChainParams::REGTEST);
}

BOOST_AUTO_TEST_CASE(deployment_height_sanity)
{
    for (const auto& chain : {CBaseChainParams::MAIN, CBaseChainParams::TESTNET, CBaseChainParams::REGTEST}) {
        const auto chainParams = CreateChainParams(chain);
        const Consensus::Params& params = chainParams->GetConsensus();
        for (const auto& dep : params.vDeployments) {
            // duplicates the compile time checks in versionbits.h Deployment<>()

            BOOST_CHECK(0 <= dep.bit && dep.bit < VERSIONBITS_NUM_BITS && ((1L << dep.bit) & VERSIONBITS_TOP_MASK) == 0);
            BOOST_CHECK(0 < dep.period && dep.period <= 52416);
            BOOST_CHECK(0 < dep.threshold && dep.threshold <= dep.period);
            BOOST_CHECK(dep.start_height >= 0 || dep.start_height + dep.period == 0);
            BOOST_CHECK(dep.start_height % dep.period == 0);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
