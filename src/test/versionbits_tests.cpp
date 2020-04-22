// Copyright (c) 2014-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <versionbits.h>

#include <boost/test/unit_test.hpp>

class TestConditionChecker : public ThresholdConditionChecker
{
private:
    mutable ThresholdConditionCache cache;

public:
    TestConditionChecker(const Consensus::ModernDeployment& dep) : ThresholdConditionChecker{ThresholdConditionChecker::FromModernDeployment(dep)} {}

    ThresholdState GetStateFor(const CBlockIndex* pindexPrev) const { return ThresholdConditionChecker::GetStateFor(pindexPrev, cache); }
    ThresholdStateHeight GetStateHeightFor(const CBlockIndex* pindexPrev) const { return ThresholdConditionChecker::GetStateHeightFor(pindexPrev, cache); }
};

static bool operator==(const ThresholdStateHeight& l, const ThresholdStateHeight& r) {
    return l.height == r.height && l.state == r.state;
}

class VersionBitsTester
{
    // A fake blockchain
    std::vector<CBlockIndex*> vpblock;

    // Test counter (to identify failures)
    int num;
    int resets;

    std::vector<std::pair<const Consensus::ModernDeployment, const std::vector<ThresholdStateHeight>>> unconditional_checks;

public:
    VersionBitsTester() : num(0), resets(0) {}

    VersionBitsTester& Reset() {
        for (unsigned int i = 0; i < vpblock.size(); i++) {
            delete vpblock[i];
        }
        vpblock.clear();
        resets++;
        num = 0;
        return *this;
    }

    ~VersionBitsTester() {
         Reset();
    }

    VersionBitsTester& Mine(unsigned int height, int32_t nVersion) {
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


    void UnconditionalCheck(const Consensus::ModernDeployment& dep, const std::vector<ThresholdStateHeight> stateheights) {
        unconditional_checks.push_back(std::make_pair(dep, stateheights));
    }

    VersionBitsTester& UnconditionalTests() {
        num = 100; // UnconditionalTests get reported as 101, 102, etc
        for (const auto& depsh : unconditional_checks) {
            Test(depsh.first, depsh.second);
        }
        return *this;
    }

    VersionBitsTester& Test(const Consensus::ModernDeployment& dep, const std::vector<ThresholdStateHeight> stateheights) {
        BOOST_REQUIRE(stateheights.begin() != stateheights.end());
        BOOST_REQUIRE(!vpblock.empty());
        ++num;
        for (int skip : {1, 1800, 3500}) {
            for (int do_first : {0, 1, (int)stateheights.size()/2, (int)stateheights.size()}) {
                bool did_first = false;
                do_first -= (do_first % skip);

                TestConditionChecker check(dep);

                ThresholdStateHeight res_first = check.GetStateHeightFor(do_first == 0 ? nullptr : vpblock[do_first-1]);

                auto exp = stateheights.begin();
                for (int h = 0; h <= (int)vpblock.size(); h += skip) {
                    while ((exp+1) != stateheights.end() && (exp+1)->height <= h) ++exp;
                    ThresholdStateHeight res = check.GetStateHeightFor(h == 0 ? nullptr : vpblock[h-1]);
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

BOOST_FIXTURE_TEST_SUITE(versionbits_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(versionbits_test)
{
    const int BIT = 1;
    const int32_t vnone = VERSIONBITS_LAST_OLD_BLOCK_VERSION;
    const int32_t vsig = VERSIONBITS_TOP_BITS | (1l << BIT);
    const int32_t vother = VERSIONBITS_TOP_BITS | (1l << (BIT+1));
    const int32_t vboth = vsig | vother;
    const int32_t vmiss = (0x7fffffffL & (~VERSIONBITS_TOP_BITS));

    const Consensus::ModernDeployment dep_disabled = DeploymentDisabled<BIT>();
    const Consensus::ModernDeployment dep_always = DeploymentAlwaysActive<BIT>();
    const Consensus::ModernDeployment dep_buried_5000 = DeploymentBuried<BIT,5000>();
    const Consensus::ModernDeployment dep_buried_8000 = DeploymentBuried<BIT,8000>();
    const Consensus::ModernDeployment dep_allsig = DeploymentAlwaysSignal<BIT,1000,900>();
    const Consensus::ModernDeployment dep_sig = Deployment<BIT,3000,10,5,10,1000,900>(false);
    const Consensus::ModernDeployment dep_sig_uasf = Deployment<BIT,3000,10,5,10,1000,900>(true);
    const Consensus::ModernDeployment dep_sig_short = Deployment<BIT,3000,20,10,20,500,450>(false);

    const ThresholdState DEF = ThresholdState::DEFINED,
                         SIG = ThresholdState::SIGNAL,
                         QUI = ThresholdState::QUIET,
                         UAS = ThresholdState::UASF,
                         LOC = ThresholdState::LOCKED_IN,
                         ACT = ThresholdState::ACTIVE,
                         FAI = ThresholdState::FAILED,
                         DIS = ThresholdState::DISABLED;

    VersionBitsTester test;
    test.UnconditionalCheck(dep_disabled,    { {DIS, 0 } });
    test.UnconditionalCheck(dep_always,      { {ACT, 0 } });
    test.UnconditionalCheck(dep_buried_5000, { {DEF, 0 }, {ACT, 5000} });
    test.UnconditionalCheck(dep_buried_8000, { {DEF, 0 }, {ACT, 8000} });

    // What happens if everyone signals?
    for (auto ver : { vsig, vboth }) {
        test.Reset()
            .Mine(30000, ver)
            .Test(dep_allsig,      { {DEF, 0 }, {SIG, 1000}, {LOC, 2000}, {ACT, 3000} })
            .Test(dep_sig,         { {DEF, 0 }, {SIG, 3000}, {LOC, 4000}, {ACT, 5000} })
            .Test(dep_sig_uasf,    { {DEF, 0 }, {SIG, 3000}, {LOC, 4000}, {ACT, 5000} })
            .Test(dep_sig_short,   { {DEF, 0 }, {SIG, 3000}, {LOC, 3500}, {ACT, 4000} })
            .UnconditionalTests();
    }

    // What happens if no one signals?
    for (auto ver : { vnone, vother, vmiss }) {
        test.Reset()
            .Mine(30000, ver)
            .Test(dep_allsig,      { {DEF, 0 }, {SIG, 1000} })
            .Test(dep_sig,         { {DEF, 0 }, {SIG, 3000}, {FAI, 13000} })
            .Test(dep_sig_uasf,    { {DEF, 0 }, {SIG, 3000}, {QUI, 13000}, {UAS, 18000}, {LOC, 27000}, {ACT, 28000} })
            .Test(dep_sig_short,   { {DEF, 0 }, {SIG, 3000}, {FAI, 13000} })
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
        .Test(dep_allsig,      { {DEF, 0 }, {SIG, 1000}, {LOC, 3000}, {ACT, 4000} })
        .Test(dep_sig,         { {DEF, 0 }, {SIG, 3000}, {LOC, 6000}, {ACT, 7000} })
        .Test(dep_sig_uasf,    { {DEF, 0 }, {SIG, 3000}, {LOC, 6000}, {ACT, 7000} })
        .Test(dep_sig_short,   { {DEF, 0 }, {SIG, 3000}, {LOC, 4000}, {ACT, 4500} })
        .UnconditionalTests();

    // Signalling in UASF period only
    test.Reset()
        .Mine(18500, vnone)
        .Mine(21000, vsig)
        .Mine(30000, vnone)
        .Test(dep_sig,         { {DEF, 0 }, {SIG, 3000}, {FAI, 13000} })
        .Test(dep_sig_uasf,    { {DEF, 0 }, {SIG, 3000}, {QUI, 13000}, {UAS, 18000}, {LOC, 20000}, {ACT, 21000} })
        .UnconditionalTests();

    // How about edge cases?
    // Signalling in last block of SIGNAL
    test.Reset()
        .Mine(12000, vnone)
        .Mine(13000, vsig)
        .Mine(30000, vnone)
        .Test(dep_sig,         { {DEF, 0 }, {SIG, 3000}, {LOC, 13000}, {ACT, 14000} })
        .Test(dep_sig_uasf,    { {DEF, 0 }, {SIG, 3000}, {LOC, 13000}, {ACT, 14000} })
        .UnconditionalTests();

    // Signalling in first block of QUIET
    test.Reset()
        .Mine(13000, vnone)
        .Mine(14000, vsig)
        .Mine(30000, vnone)
        .Test(dep_sig,         { {DEF, 0 }, {SIG, 3000}, {FAI, 13000} })
        .Test(dep_sig_uasf,    { {DEF, 0 }, {SIG, 3000}, {QUI, 13000}, {UAS, 18000}, {LOC, 27000}, {ACT, 28000} })
        .UnconditionalTests();

    // Just enough blocks
    test.Reset()
        .Mine(10100, vnone)
        .Mine(11000, vsig)
        .Mine(30000, vnone)
        .Test(dep_sig,         { {DEF, 0 }, {SIG, 3000}, {LOC, 11000}, {ACT, 12000} })
        .Test(dep_sig_uasf,    { {DEF, 0 }, {SIG, 3000}, {LOC, 11000}, {ACT, 12000} })
        .UnconditionalTests();

    // Just enough blocks, but off by one
    test.Reset()
        .Mine(10101, vnone)
        .Mine(11001, vsig)
        .Mine(30000, vnone)
        .Test(dep_sig,         { {DEF, 0 }, {SIG, 3000}, {FAI, 13000} })
        .Test(dep_sig_uasf,    { {DEF, 0 }, {SIG, 3000}, {QUI, 13000}, {UAS, 18000}, {LOC, 27000}, {ACT, 28000} })
        .UnconditionalTests();


}

static void sanity_check_bit_overlap(const std::string& chainName)
{
    // Sanity checks of version bit deployments
    const auto chainParams = CreateChainParams(chainName);
    const Consensus::Params &params = chainParams->GetConsensus();

    std::vector<ThresholdConditionChecker> checkers;

    for (int i=0; i<(int) Consensus::MAX_VERSION_BITS_DEPLOYMENTS; i++) {
        checkers.emplace_back(ThresholdConditionChecker::FromModernDeployment(params.vDeployments[i]));

        uint32_t bitmask = VersionBitsMask(params, static_cast<Consensus::DeploymentPos>(i));
        // Make sure that no deployment tries to set an invalid bit.
        BOOST_CHECK_EQUAL(bitmask & ~(uint32_t)VERSIONBITS_TOP_MASK, bitmask);

        // disabled
        if (checkers[i].signal_height == checkers[i].MAX_HEIGHT) continue;
        // buried
        if (checkers[i].signal_height == checkers[i].mandatory_height) continue;

        // Verify that overlapping deployments are not using the
        // same bit.
        for (int j=0; j < i; j++) {
            // disabled
            if (checkers[j].signal_height == checkers[j].MAX_HEIGHT) continue;
            // buried
            if (checkers[j].signal_height == checkers[i].mandatory_height) continue;

            // no overlap in signalling period
            if (checkers[i].mandatory_height < checkers[j].signal_height || checkers[j].mandatory_height < checkers[i].signal_height) continue;

            // otherwise must have different bits
            BOOST_CHECK(VersionBitsMask(params, static_cast<Consensus::DeploymentPos>(j)) != bitmask);
        }
    }
}



BOOST_AUTO_TEST_CASE(versionbits_bit_overlap_main)
{
    sanity_check_bit_overlap(CBaseChainParams::MAIN);
}
BOOST_AUTO_TEST_CASE(versionbits_bit_overlap_testnet)
{
    sanity_check_bit_overlap(CBaseChainParams::TESTNET);
}
BOOST_AUTO_TEST_CASE(versionbits_bit_overlap_regtest)
{
    sanity_check_bit_overlap(CBaseChainParams::REGTEST);
}

BOOST_AUTO_TEST_CASE(versionbits_height_sanity)
{
    for (const auto& chain : {CBaseChainParams::MAIN, CBaseChainParams::TESTNET, CBaseChainParams::REGTEST}) {
        const auto chainParams = CreateChainParams(chain);
        const Consensus::Params& params = chainParams->GetConsensus();
        for (const auto& dep : params.vDeployments) {
            // duplicates the compile time checks in versionbits.h Deployment<>()

            BOOST_CHECK(0 <= dep.bit && dep.bit < VERSIONBITS_NUM_BITS && ((1L << dep.bit) & VERSIONBITS_TOP_MASK) == 0);
            BOOST_CHECK(0 < dep.period && dep.period <= 52416);
            BOOST_CHECK(0 < dep.threshold && dep.threshold <= dep.period);
            BOOST_CHECK(0 <= dep.signal_height);
            BOOST_CHECK(dep.signal_height % dep.period == 0);
            BOOST_CHECK(dep.signal_periods >= 0 || (dep.signal_periods == -1 && dep.quiet_periods == 0 && dep.uasf_periods == 0));
            BOOST_CHECK(dep.quiet_periods >= 0 || (dep.quiet_periods == -1 && dep.uasf_periods == 0));
            BOOST_CHECK(dep.uasf_periods >= 0);
            BOOST_CHECK(dep.signal_periods != 0 || dep.uasf_periods != 0 || dep.quiet_periods <= 0);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
