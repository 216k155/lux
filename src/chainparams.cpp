// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The LUX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"
#include "primitives/transaction.h"

#include "random.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

using namespace std;
using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock = uint256(0);
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Main network
 */

//! Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress>& vSeedsOut, const SeedSpec6* data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7 * 24 * 60 * 60;
    for (unsigned int i = 0; i < count; i++) {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port), NODE_NETWORK);
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

//   What makes a good checkpoint block?
// + Is surrounded by blocks with reasonable timestamps
//   (no blocks before with a timestamp after, none after with
//    timestamp before)
// + Contains no strange transactions
static Checkpoints::MapCheckpoints mapCheckpoints =
    boost::assign::map_list_of
            ( 0,   uint256("0x00000759bb3da130d7c9aedae170da8335f5a0d01a9007e4c8d3ccd08ace6a42") )
            ( 175,   uint256("0x000000000002611e8e3c2e460e7fcd0a39ee210b9915fc76a5573a0704bb2b33") )
            ( 2241,   uint256("0x69e2e47fb84085c4b82b6090f701c7ac03a4e510bd1f41cc072c33061cf83a0d") )
            ( 6901,   uint256("0x0000000000034bab666179e364e0cce7c19eaa255f1e4afd2170356acfa1a3ac") )
            ( 25318,   uint256("0x092a04ee669d2d2241aba0ec9dcecb548c9cea9ff114b0ee52cdc7ddac98a1f4") )
            ( 97176,   uint256("0x000000000004e4aac7926e7dbd778f21b15b62f0e4c1d424ac9e5a9889c1724a") )
            ( 122237,   uint256("0x10f6d17326a0c439f61a21c44a172885469bb60668a0d77be82eead7209183b0") )
            ( 203690,   uint256("0x00000000000180e78502c3c952f00bf8bba2bc9ffef60e7188c8763582f26ef4") );

static const Checkpoints::CCheckpointData data = {
    &mapCheckpoints,
    1514488096, // * UNIX timestamp of last checkpoint block
    1157185,    // * total number of transactions between genesis and last checkpoint
                //   (the tx=... number in the SetBestChain debug.log lines)
    2000        // * estimated number of transactions per day after checkpoint
};

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
    boost::assign::map_list_of(0, uint256("0"));
static const Checkpoints::CCheckpointData dataTestnet = {
    &mapCheckpointsTestnet,
    0,
    0,
    0
};

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
    boost::assign::map_list_of(0, uint256("0"));
static const Checkpoints::CCheckpointData dataRegtest = {
    &mapCheckpointsRegtest,
    0,
    0,
    0
};

static Checkpoints::MapCheckpoints mapCheckpointsSegWittest =
        boost::assign::map_list_of(0, uint256("0"));
static const Checkpoints::CCheckpointData dataSegwittest = {
        &mapCheckpointsSegWittest,
        0,
        0,
        0
};

class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        //consensus.BIP34Height = 227931;
        //consensus.BIP34Hash = uint256S("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
        consensus.powLimit = ~uint256(0) >> 20; // LUX starting difficulty is 1 / 2^12
        consensus.nPowTargetTimespan = 30 * 60; //36 * 60 * 60; // LUX: 1 36hrs
        consensus.nPowTargetSpacing = 2 * 60;  // LUX: 2 minute
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1026; // 95% of 1080 is 1026
        consensus.nMinerConfirmationWindow = 1080; // nPowTargetTimespan / nPowTargetSpacing
        // Deployment of SegWit (BIP141 and BIP143)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0; //TODO: ?
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1557187200; // TODO: ?? - just some random date - 05.07.2019
        consensus.nLastPOWBlock = 6000000;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0xf9;
        pchMessageStart[1] = 0x73;
        pchMessageStart[2] = 0xc9;
        pchMessageStart[3] = 0xa7;
        vAlertPubKey = ParseHex("042d13c016ed91528241bcff222989769417eb10cdb679228c91e26e26900eb9fd053cd9f16a9a2894ad5ebbd551be1a4bd23bd55023679be17f0bd3a16e6fbeba");
        nDefaultPort = /*28666*/ 26868;
        nMaxReorganizationDepth = 100;
        nMinerThreads = 0;
        nMaturity = 79;
        nMasternodeCountDrift = 20;
        nModifierUpdateBlock = 615800;

        const char* pszTimestamp = "Lux - Implemented New PHI Algo PoW/PoS Hybird - Parallel Masternode - ThankYou - 216k155"; // Input Activation code to activate blockchain
        CMutableTransaction txNew;
        txNew.nVersion = 1;
        txNew.nTime = 1507656633;
        txNew.nLockTime = 0;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 0 << CScriptNum(42) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].SetEmpty();

        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime = 1507656633; //10/10/2017
        genesis.nBits = 0x1e0fffff;
        genesis.nNonce = 986946;

        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256("0x00000759bb3da130d7c9aedae170da8335f5a0d01a9007e4c8d3ccd08ace6a42"));
        assert(genesis.hashMerkleRoot == uint256("0xe08ae0cfc35a1d70e6764f347fdc54355206adeb382446dd54c32cd0201000d3"));

        vSeeds.push_back(CDNSSeedData("luxseed1.luxcore.io", "luxseed1.luxcore.io")); // DNSSeed
        vSeeds.push_back(CDNSSeedData("luxseed2.luxcore.io", "luxseed2.luxcore.io")); // DNSSeed
        vSeeds.push_back(CDNSSeedData("luxseed3.luxcore.io", "luxseed3.luxcore.io")); // DNSSeed
        vSeeds.push_back(CDNSSeedData("luxseed4.luxcore.io", "luxseed4.luxcore.io")); // DNSSeed
        vSeeds.push_back(CDNSSeedData("209.250.254.156", "209.250.254.156")); // Non-standard DNS request
        vSeeds.push_back(CDNSSeedData("45.76.114.209", "45.76.114.209")); // Non-standard DNS request
        vSeeds.push_back(CDNSSeedData("5.189.142.181", "5.189.142.181")); // Non-standard DNS request
        //vSeeds.push_back(CDNSSeedData("5.77.44.147", "5.77.44.147")); // Non-standard DNS request

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,48); // LUX Start letter L
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,48);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1,155);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x07)(0x28)(0xA2)(0x4E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x03)(0xD8)(0xA1)(0xE5).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;
        fHeadersFirstSyncingActive = false;

        nPoolMaxTransactions = 3;
        strSporkKey = "04a983220ea7a38a7106385003fef77896538a382a0dcc389cc45f3c98751d9af423a097789757556259351198a8aaa628a1fd644c3232678c5845384c744ff8d7";

        strDarksendPoolDummyAddress = "LgcjpYxWa5EB9KCYaRtpPgG8kgiWRvJY38";
        nStartMasternodePayments = 1507656633; // 10/10/2017

        nStakingRoundPeriod = 120; // 2 minutes a round
        nStakingInterval = 22;
        nStakingMinAge = 36 * 60 * 60;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return data;
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams
{
public:
    CTestNetParams()
    {
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 100;
        //consensus.BIP34Height = 227931;
        //consensus.BIP34Hash = uint256S("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
        consensus.powLimit = ~uint256(0) >> 1;
        consensus.nPowTargetTimespan = 24 * 60 * 60; // LUX: 1 day //TODO: change it for testnet
        consensus.nPowTargetSpacing = 60;  // LUX: 1 minute //TODO: change it for testnet
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1368; // 95% of 1440 is
        consensus.nMinerConfirmationWindow = 1440; // nPowTargetTimespan / nPowTargetSpacing
        // Deployment of SegWit (BIP141 and BIP143)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 0; // Never / undefined
        consensus.nLastPOWBlock = 6000000;

        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";
        pchMessageStart[0] = 0x54;
        pchMessageStart[1] = 0x67;
        pchMessageStart[2] = 0x56;
        pchMessageStart[3] = 0xab;
        vAlertPubKey = ParseHex("000010e83b2703ccf322f7dbd62dd5855ac7c10bd055814ce121ba32607d573b8810c02c0582aed05b4deb9c4b77b26d92428c61256cd42774babea0a073b2ed0c9");
        nDefaultPort = 28333;
        nMinerThreads = 0;
        nMaturity = 79;
        nModifierUpdateBlock = 51197; //approx Mon, 17 Apr 2017 04:00:00 GMT

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nBits  = 0x1e0fffff;
        genesis.nTime = 1504344001;
        genesis.nNonce = 1454059;

        consensus.hashGenesisBlock = genesis.GetHash();
//      assert(hashGenesisBlock == uint256("0"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("luxtest1", "88.198.192.110"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 139); // Testnet lux addresses start with 'x' or 'y'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 19);  // Testnet lux script addresses start with '8' or '9'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);     // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        // Testnet lux BIP32 pubkeys start with 'DRKV'
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x3a)(0x80)(0x61)(0xa0).convert_to_container<std::vector<unsigned char> >();
        // Testnet lux BIP32 prvkeys start with 'DRKP'
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x3a)(0x80)(0x58)(0x37).convert_to_container<std::vector<unsigned char> >();
        // Testnet lux BIP44 coin type is '1' (All coin's testnet default)
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x01)(0x00)(0x00)(0x80).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        nPoolMaxTransactions = 2;
        strSporkKey = "04348C2F50F90267E64FACC65BFDC9D0EB147D090872FB97ABAE92E9A36E6CA60983E28E741F8E7277B11A7479B626AC115BA31463AC48178A5075C5A9319D4A38";
        strDarksendPoolDummyAddress = "LPGq7DZbqZ8Vb3tfLH8Z8VHqeV4fsK68oX";
        nStartMasternodePayments = 1420837558; //Fri, 09 Jan 2015 21:05:58 GMT

        nStakingRoundPeriod = 5; // 5 seconds a round
        nStakingInterval = 30; // 30 seconds
        nStakingMinAge = 6 * 60; // 6 minutes
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams
{
public:
    CRegTestParams()
    {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";

        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        //consensus.BIP34Height = -1; // BIP34 has not necessarily activated on regtest
        //consensus.BIP34Hash = uint256();
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 24 * 60 * 60; // Lux: 1 day
        consensus.nPowTargetSpacing = 1 * 60; // Lux: 1 minutes
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;
        consensus.powLimit = ~uint256(0) >> 1;

        pchMessageStart[0] = 0xa1;
        pchMessageStart[1] = 0xcf;
        pchMessageStart[2] = 0x7e;
        pchMessageStart[3] = 0xac;
        nMinerThreads = 1;
        nMaturity = 2;
        genesis.nTime = 1454124731;
        genesis.nBits = 0x207fffff;
        genesis.nNonce = 12345;

        consensus.hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 51476;
//        assert(hashGenesisBlock == uint256("0"));

        vFixedSeeds.clear(); //! Testnet mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Testnet mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }
};
static CRegTestParams regTestParams;

/**
 * Unit test
 */
class CUnitTestParams : public CMainParams, public CModifiableParams
{
public:
    CUnitTestParams()
    {
        networkID = CBaseChainParams::UNITTEST;
        strNetworkID = "unittest";
        nDefaultPort = 51478;
        vFixedSeeds.clear(); //! Unit test mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Unit test mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        consensus.fPowAllowMinDifficultyBlocks = false;
        fMineBlocksOnDemand = true;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        // UnitTest share the same checkpoints as MAIN
        return data;
    }

    //! Published setters to allow changing values in unit test cases
    virtual void setSubsidyHalvingInterval(int anSubsidyHalvingInterval) { consensus.nSubsidyHalvingInterval = anSubsidyHalvingInterval; }
    virtual void setEnforceBlockUpgradeMajority(int anEnforceBlockUpgradeMajority) { consensus.nMajorityEnforceBlockUpgrade = anEnforceBlockUpgradeMajority; }
    virtual void setRejectBlockOutdatedMajority(int anRejectBlockOutdatedMajority) { consensus.nMajorityRejectBlockOutdated = anRejectBlockOutdatedMajority; }
    virtual void setToCheckBlockUpgradeMajority(int anToCheckBlockUpgradeMajority) { consensus.nMajorityWindow = anToCheckBlockUpgradeMajority; }
    virtual void setDefaultConsistencyChecks(bool afDefaultConsistencyChecks) { fDefaultConsistencyChecks = afDefaultConsistencyChecks; }
    virtual void setAllowMinDifficultyBlocks(bool afAllowMinDifficultyBlocks) { consensus.fPowAllowMinDifficultyBlocks = afAllowMinDifficultyBlocks; }
    virtual void setSkipProofOfWorkCheck(bool afSkipProofOfWorkCheck) { fSkipProofOfWorkCheck = afSkipProofOfWorkCheck; }
};
static CUnitTestParams unitTestParams;

bool CheckProof(uint256 hash, unsigned int nBits)
{
    bool fNegative;
    bool fOverflow;
    uint256 bnTarget;


    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow)
        return false; //error("CheckProofOfWork() : nBits below minimum work");

    // Check proof of work matches claimed amount
    if (hash > bnTarget)
        return false; //error("CheckProofOfWork() : hash doesn't match nBits");

    return true;
}

class CSegWitTestnet : public CChainParams
{
public:
    CSegWitTestnet()
    {
        networkID = CBaseChainParams::SEGWITTEST;
        strNetworkID = "segwit";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = ~uint256(0) >> 20; // LUX starting difficulty is 1 / 2^12
        consensus.nPowTargetTimespan = 10 * 60; //10 minute
        consensus.nPowTargetSpacing = 60;  // LUX: 1 minute
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 9; // 95% of 10
        consensus.nMinerConfirmationWindow = 10; // nPowTargetTimespan / nPowTargetSpacing
        // Deployment of SegWit (BIP141 and BIP143)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1524733200;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1557187200; // TODO: ?? - just some random date - 05.07.2019
        consensus.nLastPOWBlock = 6000000;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0xf9;
        pchMessageStart[1] = 0x73;
        pchMessageStart[2] = 0xc9;
        pchMessageStart[3] = 0xa7;
        vAlertPubKey = ParseHex("042d13c016ed91528241bcff222989769417eb10cdb679228c91e26e26900eb9fd053cd9f16a9a2894ad5ebbd551be1a4bd23bd55023679be17f0bd3a16e6fbeba");
        nDefaultPort = 25666;
        nMaxReorganizationDepth = 100;
        nMinerThreads = 0;
        nMaturity = 5;
        nMasternodeCountDrift = 20;
        nModifierUpdateBlock = 615800;

        const char* pszTimestamp = "Lux - Implemented New PHI Algo PoW/PoS Hybrid - Parallel Masternode - ThankYou - 216k155"; // Input Activation code to activate blockchain
        CMutableTransaction txNew;
        txNew.nVersion = 1;
        txNew.nTime = 1524645689;
        txNew.nLockTime = 0;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        const char* strPubKey = "039ec9c09ee245790849f297f8df36c3aab97335ee011250a23d35569fdab891f0";
        txNew.vin[0].scriptSig = CScript() << 0 << CScriptNum(42) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].scriptPubKey = CScript() << ParseHex(strPubKey) << OP_CHECKSIG;
        txNew.vout[0].nValue = 21000000000000;

        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime = 1524645689;
        genesis.nBits = 0x1e0fffff;
        genesis.nNonce = 729147;

        /*while (!CheckProof(genesis.GetHash(), genesis.nBits)) {
            genesis.nNonce ++;
        }

        std::cout << genesis.nNonce << std::endl;
        std::cout << genesis.GetHash().GetHex() << std::endl;
        std::cout << genesis.hashMerkleRoot.GetHex() << std::endl;*/

        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256("0x00000a1a2a728145f14f873037b5f4188c1b36d20f8187d329e412b97cdbaabf"));
        assert(genesis.hashMerkleRoot == uint256("0xb35719fbe3e4d52f06d791e938de406d48defadb83beeb1fdd10c7ef52a481c2"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,48); // LUX Start letter L
        base58Prefixes[WIT_PUBKEY_ADDRESS] = std::vector<unsigned char>(1,54);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,48);
        base58Prefixes[WIT_SCRIPT_ADDRESS] = std::vector<unsigned char>(1,55);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1,155);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x07)(0x28)(0xA2)(0x4E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x03)(0xD8)(0xA1)(0xE5).convert_to_container<std::vector<unsigned char> >();

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;
        fHeadersFirstSyncingActive = false;

        nPoolMaxTransactions = 3;
        strSporkKey = "04a983220ea7a38a7106385003fef77896538a382a0dcc389cc45f3c98751d9af423a097789757556259351198a8aaa628a1fd644c3232678c5845384c744ff8d7";

        strDarksendPoolDummyAddress = "LgcjpYxWa5EB9KCYaRtpPgG8kgiWRvJY38";
        nStartMasternodePayments = 1507656633; // 10/10/2017

        nStakingRoundPeriod = 120; // 2 minutes a round
        nStakingInterval = 22;
        nStakingMinAge = 36 * 60 * 60;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataSegwittest;
    }
};
static CSegWitTestnet segwitParams;


static CChainParams* pCurrentParams = 0;

CModifiableParams* ModifiableParams()
{
    assert(pCurrentParams);
    assert(pCurrentParams == &unitTestParams);
    return (CModifiableParams*)&unitTestParams;
}

const CChainParams& Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(CBaseChainParams::Network network)
{
    switch (network) {
    case CBaseChainParams::MAIN:
        return mainParams;
    case CBaseChainParams::TESTNET:
        return testNetParams;
    case CBaseChainParams::REGTEST:
        return regTestParams;
    case CBaseChainParams::UNITTEST:
        return unitTestParams;
    case CBaseChainParams::SEGWITTEST:
        return segwitParams;
    default:
        assert(false && "Unimplemented network");
        return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}
