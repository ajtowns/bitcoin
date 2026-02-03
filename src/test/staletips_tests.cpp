// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <staletips.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(staletips_tests, BasicTestingSetup)

// Test vector from BIP staletip: Signet stale branch at heights 287767-287785
// Fork point: height 287766, hash 00000012602fde2eaf33a90523f42fb07ca854c1d26108782dc4592a80507e1c
// Stale tip: height 287785, hash 0000000024ff924ff932668d497bba7da9157559a68d9c87d2f28d22e5e4a001
// Branch length: 19, have_block: false
static const std::string SIGNET_TEST_VECTOR_HEX =
    "1c7e50802a59c42d780861d2c154a87cb02ff42305a933af2ede2f6012000000"
    "13"
    "0000002067aa2937b235e209f1ad40f37b17dcad8ca02d1fb9cf4c4928902eab3ff853a6cda16e691658151d81ad7b04"
    "00000020721ab6f36042842bab4583f98e15181b646c47c7b9dfb07a204c4e5152e54e97fda46e691658151dd2dcec18"
    "00000020ddc6b628101b404f78d446591a623e12bb7e7cd2ae1593d0cc6ef082e19fa81014a66e691658151d46070e10"
    "000000208be5b9607b20ac0163b885881aa6018ef60a5637b93a9cd85981515a169a31c36aab6e691658151de4e10600"
    "000000206c974ef806b2e6a21cc9a53fedcbd5d5e203b4929a1bd7c5859ec77d0a755c1d64ae6e691658151d2a2e130e"
    "0000002039505fa2ee91f5e5b2540b4a9a7f02ed58d79fc387412cf2520a39ee16bf435f6eb16e691658151db29c830a"
    "00000020411bce69cda2b239c74faea1f0cfaceabd90377114dc0ace14e2a58858cd4f9a91b46e691658151d4c2d3f05"
    "0000002096464a2ec42fea8419a5c6adcc41ca7dc3f53461cd0afc880f76498aa8eedbf993b56e691658151d5e99700b"
    "00000020c3cad611ee3c7bffec3f80fc83f68192ca0a86e8c89050f8353480310d080caf08b76e691658151dbc61a615"
    "0000002079e36b5a06bb5a524a2f5bad6725451613c354cbf64f9a0283f77fe90782d59fcbba6e691658151d6c669300"
    "000000204c69fd467818994e7ff885181e7451d23869a7fd19447dad7a95398077ed7774dcba6e691658151dc9c7ff02"
    "000000208ea9a871b12cd45226ab6df280ec46b8c9ca196b98dc8adc27718cab333e19a50abc6e691658151df6bae902"
    "000000209c182979424a5c85d55d5bddbf3b9421b01b7810edf95ad2529552dd2eec80848ebd6e691658151d439e5c00"
    "00000020cfb9f6d1643613dfdd23a6e1eabadac38c392f985f5dc05b00ef682c428922c96cbe6e691658151d278b4d14"
    "00000020eea983b8d64947368de4f7626531a3134d18f20a8d87462ba011a4f56a53b6ac4fbf6e691658151ddae86408"
    "00000020140bc70b1a3282fbebf9d48ff40a9b73ab7c76ad522799cee73315e9c21aab50dcc06e691658151dedaae90f"
    "000000209b91a056fe089429f2ba4298e764acb4177249ce7d68e6883836f70d1d9218b355c16e691658151d28a43206"
    "00000020b26e80c6a12cc4595556d2318fda564ced5d2a526c7b77f57a9897a56c10539056c16e691658151dc64fb500"
    "00000020369d36495749c96d36260d839abfa703a611aad7b3016342ef05d0412f42221e6ac56e691658151d8f8bfb0f"
    "00";

BOOST_AUTO_TEST_CASE(staletip_testvector_deserialize)
{
    // Decode the test vector
    auto data = ParseHex(SIGNET_TEST_VECTOR_HEX);
    DataStream ss{data};

    // Deserialize
    StaleTipData tip_data;
    ss >> tip_data;

    // Verify fork point hash
    BOOST_CHECK_EQUAL(tip_data.m_hash_fork_point.ToString(),
        "00000012602fde2eaf33a90523f42fb07ca854c1d26108782dc4592a80507e1c");

    // Verify branch length
    BOOST_CHECK_EQUAL(tip_data.m_headers.size(), 19U);

    // Verify have_block
    BOOST_CHECK_EQUAL(tip_data.m_have_block, false);

    // Verify first header (block 287767)
    BOOST_CHECK_EQUAL(tip_data.m_headers[0].nVersion, 536870912);
    BOOST_CHECK_EQUAL(tip_data.m_headers[0].hashMerkleRoot.ToString(),
        "a653f83fab2e9028494ccfb91f2da08caddc177bf340adf109e235b23729aa67");
    BOOST_CHECK_EQUAL(tip_data.m_headers[0].nTime, 1768858061U);
    BOOST_CHECK_EQUAL(tip_data.m_headers[0].nBits, 0x1d155816U);
    BOOST_CHECK_EQUAL(tip_data.m_headers[0].nNonce, 75214209U);

    // Verify last header (block 287785, the stale tip)
    BOOST_CHECK_EQUAL(tip_data.m_headers[18].nVersion, 536870912);
    BOOST_CHECK_EQUAL(tip_data.m_headers[18].hashMerkleRoot.ToString(),
        "1e22422f41d005ef426301b3d7aa11a603a7bf9a830d26366dc9495749369d36");
    BOOST_CHECK_EQUAL(tip_data.m_headers[18].nTime, 1768867178U);
    BOOST_CHECK_EQUAL(tip_data.m_headers[18].nBits, 0x1d155816U);
    BOOST_CHECK_EQUAL(tip_data.m_headers[18].nNonce, 268143503U);

    // Reconstruct headers and verify tip hash
    auto [tip_hash, headers] = tip_data.ReconstructHeaders();
    BOOST_CHECK_EQUAL(headers.size(), 19U);
    BOOST_CHECK_EQUAL(tip_hash.ToString(),
        "0000000024ff924ff932668d497bba7da9157559a68d9c87d2f28d22e5e4a001");

    // Verify first reconstructed header has correct prevblock
    BOOST_CHECK_EQUAL(headers[0].hashPrevBlock.ToString(),
        "00000012602fde2eaf33a90523f42fb07ca854c1d26108782dc4592a80507e1c");
}

BOOST_AUTO_TEST_CASE(staletip_testvector_roundtrip)
{
    // Decode the test vector
    auto data = ParseHex(SIGNET_TEST_VECTOR_HEX);
    DataStream ss{data};

    // Deserialize
    StaleTipData tip_data;
    ss >> tip_data;

    // Re-serialize
    DataStream ss2{};
    ss2 << tip_data;

    // Verify round-trip produces identical bytes
    BOOST_CHECK_EQUAL(HexStr(ss2), SIGNET_TEST_VECTOR_HEX);
}

BOOST_AUTO_TEST_SUITE_END()
