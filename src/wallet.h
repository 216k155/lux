// Copyright (c) 2009-2010 Satoshi Nakamoto             -*- c++ -*-
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The LUX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_H
#define BITCOIN_WALLET_H

#include "amount.h"
#include "base58.h"
#include "crypter.h"
#include "key.h"
#include "keystore.h"
#include "main.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "ui_interface.h"
#include "util.h"
#include "uint256.h"
#include "wallet_ismine.h"
#include "validationinterface.h"
#include "walletdb.h"

#include <algorithm>
#include <atomic>
#include <map>
#include <set>
#include <stdexcept>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>

extern CWallet* pwalletMain;

/**
 * Settings
 */
extern CAmount nReserveBalance;
extern CFeeRate payTxFee;
extern CAmount maxTxFee;
extern unsigned int nTxConfirmTarget;
extern bool bSpendZeroConfChange;
extern bool bZeroBalanceAddressToken;
extern bool fSendFreeTransactions;
extern bool fPayAtLeastCustomFee;
extern bool fNotUseChangeAddress;
typedef CWallet* CWalletRef;
extern std::vector<CWalletRef> vpwallets;
//! -paytxfee default
static const CAmount DEFAULT_TRANSACTION_FEE = 1000;
//! -paytxfee will warn if called with a higher fee than this amount (in satoshis) per KB
static const CAmount nHighTransactionFeeWarning = 0.1 * COIN;
//! -maxtxfee default
static const CAmount DEFAULT_TRANSACTION_MAXFEE = 1 * COIN;
//! -maxtxfee will warn if called with a higher fee than this amount (in satoshis)
static const CAmount nHighTransactionMaxFeeWarning = 100 * nHighTransactionFeeWarning;
//! Largest (in bytes) free transaction we're willing to create
static const unsigned int MAX_FREE_TRANSACTION_CREATE_SIZE = 1000;
//! Default for -spendzeroconfchange
static const bool DEFAULT_SPEND_ZEROCONF_CHANGE = true;
//! Default for -zerobalanceaddresstoken
static const bool DEFAULT_ZERO_BALANCE_ADDRESS_TOKEN = true;

static const bool DEFAULT_NOT_USE_CHANGE_ADDRESS = false;
//! if set, all keys will be derived by using BIP32
static const bool DEFAULT_USE_HD_WALLET = true;
static const unsigned int DEFAULT_KEYPOOL_SIZE = 1000;

class CAccountingEntry;
class CCoinControl;
class COutput;
class CReserveKey;
class CScript;
class CTxMemPool;
class CWalletTx;
class CContractBookData;
class CTokenTx;

/** (client) version numbers for particular wallet features */
enum WalletFeature {
    FEATURE_BASE = 10500, // the earliest version new wallets supports (only useful for getinfo's clientversion output)

    FEATURE_WALLETCRYPT = 40000, // wallet encryption
    FEATURE_COMPRPUBKEY = 60000, // compressed public keys
    FEATURE_HD = 130000,
    FEATURE_HD_SPLIT = 139900,
    FEATURE_LATEST = FEATURE_COMPRPUBKEY // HD is optional, use FEATURE_COMPRPUBKEY as latest version

};

enum OutputType : int
{
    OUTPUT_TYPE_NONE,
    OUTPUT_TYPE_LEGACY,
    OUTPUT_TYPE_P2SH_SEGWIT,
    OUTPUT_TYPE_BECH32,

    OUTPUT_TYPE_DEFAULT = OUTPUT_TYPE_LEGACY
};

extern OutputType g_address_type;
extern OutputType g_change_type;

enum AvailableCoinsType {
    ALL_COINS = 1,
    ONLY_DENOMINATED = 2,
    ONLY_NONDENOMINATED = 3, // ONLY_NOT10000IFMN = 3,
    ONLY_NONDENOMINATED_NOTMN = 4, // ONLY_NONDENOMINATED_NOT10000IFMN = 4, ONLY_NONDENOMINATED and not 10000 LUX at the same time
};

struct CompactTallyItem {
    CTxDestination address;
    CAmount nAmount;
    std::vector<CTxIn> vecTxIn;
    CompactTallyItem()
    {
        nAmount = 0;
    }
};

/** A key pool entry */
class CKeyPool {
public:
    int64_t nTime;
    CPubKey vchPubKey;
    bool fInternal; // for change outputs

    CKeyPool();

    CKeyPool(const CPubKey &vchPubKeyIn, bool internalIn);

    ADD_SERIALIZE_METHODS;

    template<typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(VARINT(s.GetVersion()));
        READWRITE(nTime);
        READWRITE(vchPubKey);
        if (ser_action.ForRead()) { try { READWRITE(fInternal); }
            catch (std::ios_base::failure &) {
                /* flag as external address if we can't read the internal boolean */
                fInternal = false;
            }
        } else { READWRITE(fInternal); }
    }
};

/** Address book data */
class CAddressBookData {
public:
    std::string name;
    std::string purpose;

    CAddressBookData() : purpose("unknown") {}

    typedef std::map <std::string, std::string> StringMap;
    StringMap destdata;
};

typedef std::map <std::string, std::string> mapValue_t;


static void __attribute__((unused)) ReadOrderPos(int64_t &nOrderPos, mapValue_t &mapValue) {
    if (!mapValue.count("n")) {
        nOrderPos = -1; // TODO: calculate elsewhere
        return;
    }
    nOrderPos = atoi64(mapValue["n"].c_str());
}


static void __attribute__((unused)) WriteOrderPos(const int64_t& nOrderPos, mapValue_t& mapValue)
{
    if (nOrderPos == -1)
        return;
    mapValue["n"] = i64tostr(nOrderPos);
}

struct COutputEntry {
    CTxDestination destination;
    CAmount amount;
    int vout;
};

/** A transaction with a merkle branch linking it to the block chain. */
class CMerkleTx
{
private:
    int GetDepthInMainChainINTERNAL(const CBlockIndex*& pindexRet) const;
    /** Constant used in hashBlock to indicate tx has been abandoned */
    static const uint256 ABANDON_HASH;

public:
    CTransactionRef tx;
    uint256 hashBlock;
    std::vector<uint256> vMerkleBranch;
    int nIndex;

    CMerkleTx()
    {
        SetTx(MakeTransactionRef());
        Init();
    }

    CMerkleTx(CTransactionRef arg)
    {
        SetTx(std::move(arg));
        Init();
    }

    /** Helper conversion operator to allow passing CMerkleTx where CTransaction is expected.
     *  TODO: adapt callers and remove this operator. */
    operator const CTransaction&() const { return *tx; }

    void Init()
    {
        hashBlock = uint256();
        nIndex = -1;
    }

    void SetTx(CTransactionRef arg)
    {
        tx = std::move(arg);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        std::vector<uint256> vMerkleBranch; // For compatibility with older versions.
        READWRITE(tx);
        READWRITE(hashBlock);
        READWRITE(vMerkleBranch);
        READWRITE(nIndex);
    }

    int SetMerkleBranch(const CBlock& block);
    void SetMerkleBranch(const CBlockIndex* pIndex, int posInBlock);


    /**
     * Return depth of transaction in blockchain:
     * -1  : not in blockchain, and not in memory pool (conflicted transaction)
     *  0  : in memory pool, waiting to be included in a block
     * >=1 : this many blocks deep in the main chain
     */
    int GetDepthInMainChain(const CBlockIndex*& pindexRet, bool enableIX = true) const;
    int GetDepthInMainChain(bool enableIX = true) const
    {
        const CBlockIndex* pindexRet;
        return GetDepthInMainChain(pindexRet, enableIX);
    }
    bool IsInMainChain() const
    {
        const CBlockIndex* pindexRet;
        return GetDepthInMainChainINTERNAL(pindexRet) > 0;
    }
    int GetBlocksToMaturity() const;
    bool AcceptToMemoryPool(bool fLimitFree = true, bool fRejectInsaneFee = true, bool ignoreFees = false);
    bool isAbandoned() const { return (hashBlock == ABANDON_HASH); }
    bool hashUnset() const { return (hashBlock.IsNull() || hashBlock == ABANDON_HASH); }
    void setAbandoned() { hashBlock = ABANDON_HASH; }
    int GetTransactionLockSignatures() const;
    bool IsTransactionLockTimedOut() const;

    //wrappers around CTransactionRef
    bool IsNull() const { return tx->IsNull(); }

    const uint256& GetHash() const { return tx->GetHash(); }

    void UpdateHash() const { tx->UpdateHash(); }

    // Compute a hash that includes both transaction and witness data
    uint256 GetWitnessHash() const { return tx->GetWitnessHash(); }

    // Return sum of txouts.
    CAmount GetValueOut() const { return tx->GetValueOut(); }
    // GetValueIn() is a method on CCoinsViewCache, because
    // inputs must be known to compute value in.

    // Compute priority, given priority of inputs and (optionally) tx size
    double ComputePriority(double dPriorityInputs, unsigned int nTxSize=0) const { return tx->ComputePriority(dPriorityInputs, nTxSize); }

    // Compute modified tx size for priority calculation (optionally given tx size)
    unsigned int CalculateModifiedSize(unsigned int nTxSize=0) const { return tx->CalculateModifiedSize(nTxSize); }
    //////////////////////////////////////// // lux
    bool HasCreateOrCall() const { return tx->HasCreateOrCall(); }
    bool HasOpSpend() const { return tx->HasOpSpend(); }
    ////////////////////////////////////////

    /**
     * Get the total transaction size in bytes, including witness data.
     * "Total Size" defined in BIP141 and BIP144.
     * @return Total transaction size in bytes
     */
    unsigned int GetTotalSize() const { return tx->GetTotalSize(); }

    bool IsCoinBase() const { return tx->IsCoinBase(); }

    bool IsCoinStake() const { return tx->IsCoinStake(); }

    bool IsCoinGenerated() const { return tx->IsCoinGenerated(); }

    // True if only scriptSigs are different
   // bool IsEquivalentTo(const CWalletTx& tx) const;

    std::string ToString() const { return tx->ToString(); }

    // ppcoin: get transaction coin age
    bool GetCoinAge(uint64_t& nCoinAge) const { return tx->GetCoinAge(nCoinAge); }

    bool HasWitness() const { return tx->HasWitness(); }
};

/**
* A CWallet is an extension of a keystore, which also maintains a set of transactions and balances,
* and provides the ability to create new transactions.
*/
class CWallet : public CCryptoKeyStore, public CValidationInterface
{
private:
    std::atomic<bool> fAbortRescan{false};

    static std::atomic<bool> fFlushScheduled;
    CWalletDB* pwalletdbEncryption;

    //! the current wallet version: clients below this version are not able to load the wallet
    int nWalletVersion;

    //! the maximum wallet format version: memory-only variable that specifies to what version this wallet may be upgraded
    int nWalletMaxVersion;

    int64_t nNextResend;
    int64_t nLastResend;
    bool fBroadcastTransactions;

    /**
    * Select a set of coins such that nValueRet >= nTargetValue and at least
    * all coins from coinControl are selected; Never select unconfirmed coins
    * if they are not ours
    */
    bool SelectCoins(const std::string &account, const CAmount& nTargetValue, std::set<std::pair<const CWalletTx*, unsigned int> >& setCoinsRet, CAmount& nValueRet, const CCoinControl* coinControl = nullptr, AvailableCoinsType coin_type = ALL_COINS, bool useIX = true) const;

    /**
     * Used to keep track of spent outpoints, and
     * detect and report conflicts (double-spends or
     * mutated transactions where the mutant gets mined).
     */
    typedef std::multimap<COutPoint, uint256> TxSpends;
    TxSpends mapTxSpends;
    void AddToSpends(const COutPoint& outpoint, const uint256& wtxid);
    void RemoveFromSpends(const COutPoint& outpoint, const uint256& wtxid);
    void AddToSpends(const uint256& wtxid);
    void RemoveFromSpends(const uint256& wtxid);

    /* Mark a transaction (and its in-wallet descendants) as conflicting with a particular block. */
    void MarkConflicted(const uint256& hashBlock, const uint256& hashTx);

    void SyncMetaData(std::pair<TxSpends::iterator, TxSpends::iterator>);

    void DeriveNewChildKey(const CKeyMetadata& metadata, CKey& secretRet, uint32_t nAccountIndex, bool fInternal /*= false*/);

public:
    bool MintableCoins();
    bool SelectCoinsDark(int64_t nValueMin, int64_t nValueMax, std::vector<CTxIn>& setCoinsRet, int64_t& nValueRet, int nDarksendRoundsMin, int nDarksendRoundsMax) const;
    bool SelectCoinsByDenominations(int nDenom, int64_t nValueMin, int64_t nValueMax, std::vector<CTxIn>& vCoinsRet, std::vector<COutput>& vCoinsRet2, int64_t& nValueRet, int nDarksendRoundsMin, int nDarksendRoundsMax);
    bool SelectCoinsDarkDenominated(int64_t nTargetValue, std::vector<CTxIn>& setCoinsRet, int64_t& nValueRet) const;
    std::vector<uint256> vStakingWalletUpdated;
    bool HasCollateralInputs(bool fOnlyConfirmed = true) const;
    bool IsCollateralAmount(int64_t nInputAmount) const;
    int CountInputsWithAmount(int64_t nInputAmount);

    bool SelectCoinsCollateral(std::vector<CTxIn>& setCoinsRet, int64_t& nValueRet) const;

    void LoadKeyPool(int64_t nIndex, const CKeyPool &keypool);

    /* the hd chain data model (external chain counters) */
    CHDChain hdChain;

    /*
     * Main wallet lock.
     * This lock protects all the fields added by CWallet
     *   except for:
     *      fFileBacked (immutable after instantiation)
     *      strWalletFile (immutable after instantiation)
     */
    mutable CCriticalSection cs_wallet;

    bool fFileBacked;
    bool fWalletUnlockAnonymizeOnly;
    std::string strWalletFile;

    //std::set<int64_t> setKeyPool;

    std::set<int64_t> setInternalKeyPool;
    std::set<int64_t> setExternalKeyPool;
    int64_t m_max_keypool_index;
    std::map<CKeyID, int64_t> m_pool_key_to_index;
    // Map from Key ID to key metadata.
    std::map<CKeyID, CKeyMetadata> mapKeyMetadata;

    // Map from Script ID to key metadata (for watch-only keys).
    std::map<CScriptID, CKeyMetadata> m_script_metadata;

    typedef std::map<unsigned int, CMasterKey> MasterKeyMap;
    MasterKeyMap mapMasterKeys;
    unsigned int nMasterKeyMaxID;
    bool AddWatchOnly(const CScript& dest) override;
    //MultiSend
    std::vector<std::pair<std::string, int> > vMultiSend;
    bool fMultiSendStake;
    bool fMultiSendMasternodeReward;
    bool fMultiSendNotify;
    std::string strMultiSendChangeAddress;
    int nLastMultiSendHeight;
    std::vector<std::string> vDisabledAddresses;
    //Auto Combine Inputs
    bool fCombineDust;
    CAmount nAutoCombineThreshold;

    std::map<std::string, CLuxNodeConfig> mapMyLuxNodes;
    bool AddLuxNodeConfig(CLuxNodeConfig nodeConfig);

    CWallet()
    {
        SetNull();
    }

    CWallet(const std::string& strWalletFileIn)
    : strWalletFile(strWalletFileIn)
    {
        SetNull();

        fFileBacked = true;
    }

    ~CWallet()
    {
        delete pwalletdbEncryption;
        pwalletdbEncryption = NULL;
    }

    void SetNull()
    {
        nWalletVersion = FEATURE_BASE;
        nWalletMaxVersion = FEATURE_BASE;
        fFileBacked = false;
        nMasterKeyMaxID = 0;
        pwalletdbEncryption = nullptr;
        nOrderPosNext = 0;
        nAccountingEntryNumber = 0;
        nNextResend = 0;
        nLastResend = 0;
        m_max_keypool_index = 0;
        nTimeFirstKey = 0;
        fWalletUnlockAnonymizeOnly = false;

        //MultiSend
        vMultiSend.clear();
        fMultiSendStake = false;
        fMultiSendMasternodeReward = false;
        fMultiSendNotify = false;
        strMultiSendChangeAddress = "";
        nLastMultiSendHeight = 0;
        vDisabledAddresses.clear();

        //Auto Combine Dust
        fCombineDust = false;
        nAutoCombineThreshold = 0;
    }

    bool isMultiSendEnabled()
    {
        return fMultiSendMasternodeReward || fMultiSendStake;
    }

    void setMultiSendDisabled()
    {
        fMultiSendMasternodeReward = false;
        fMultiSendStake = false;
    }

    std::map<uint256, CWalletTx> mapWallet;
    std::list<CAccountingEntry> laccentries;

    typedef std::pair<CWalletTx*, CAccountingEntry*> TxPair;
    typedef std::multimap<int64_t, TxPair > TxItems;
    TxItems wtxOrdered;

    int64_t nOrderPosNext;
    uint64_t nAccountingEntryNumber;
    std::map<uint256, int> mapRequestCount;

    std::map<CTxDestination, CAddressBookData> mapAddressBook;

    std::map<std::string, CContractBookData> mapContractBook;

    CPubKey vchDefaultKey;

    std::set<COutPoint> setLockedCoins;

    std::map<uint256, CTokenInfo> mapToken;

    std::map<uint256, CTokenTx> mapTokenTx;

    int64_t nTimeFirstKey;
    int64_t nKeysLeftSinceAutoBackup;

    std::map<CKeyID, CHDPubKey> mapHdPubKeys; //<! memory map of HD extended pubkeys

    const CWalletTx* GetWalletTx(const uint256& hash) const;
    bool CanSupportFeature(enum WalletFeature wf) { return nWalletMaxVersion >= wf; }

    void AvailableCoins(std::vector<COutput>& vCoins,  bool fOnlyConfirmed = true, const CCoinControl* coinControl = nullptr, bool fIncludeZeroValue = false, AvailableCoinsType nCoinType = ALL_COINS, bool fUseIX = false) const;
    void AvailableCoinsMN(std::vector<COutput>& vCoins, bool fOnlyConfirmed=true, const CCoinControl *coinControl = nullptr, AvailableCoinsType coin_type=ALL_COINS, bool useIX = false) const;
    std::map<CTxDestination, std::vector<COutput> > AvailableCoinsByAddress(bool fConfirmed = true, CAmount maxCoinValue = 0);
    bool SelectCoinsMinConf(const std::string &account, const CAmount& nTargetValue, int nConfMine, int nConfTheirs, std::vector<COutput> vCoins, std::set<std::pair<const CWalletTx*, unsigned int> >& setCoinsRet, CAmount& nValueRet) const;
    bool SelectCoinsMinConf(const CAmount& nTargetValue, int nConfMine, int nConfTheirs, std::vector<COutput> vCoins, std::set<std::pair<const CWalletTx*, unsigned int> >& setCoinsRet, CAmount& nValueRet) const;

    /// Get 1000DASH output and keys which can be used for the Masternode
    bool GetMasternodeVinAndKeys(CTxIn& txinRet, CPubKey& pubKeyRet, CKey& keyRet, std::string strTxHash = "", std::string strOutputIndex = "");
    /// Extract txin information and keys from output
    bool GetVinAndKeysFromOutput(COutput out, CTxIn& txinRet, CPubKey& pubKeyRet, CKey& keyRet);

    bool IsSpent(const uint256& hash, unsigned int n) const;

    bool IsLockedCoin(uint256 hash, unsigned int n) const;
    void LockCoin(COutPoint& output);
    void UnlockCoin(COutPoint& output);
    void UnlockAllCoins();
    void ListLockedCoins(std::vector<COutPoint>& vOutpts);
    int64_t GetTotalValue(std::vector<CTxIn> vCoins);

     /*
     * Rescan abort properties
     */
    void AbortRescan() { fAbortRescan = true; }
    bool IsAbortingRescan() { return fAbortRescan; }

    /**
     * keystore implementation
     * Generate a new key
     */
    CPubKey GenerateNewKey(uint32_t nAccountIndex, bool internal /*= false*/);
    //! HaveKey implementation that also checks the mapHdPubKeys
    bool HaveKey(const CKeyID &address) const;
    //! GetPubKey implementation that also checks the mapHdPubKeys
    bool GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const;
    //! GetKey implementation that can derive a HD private key on the fly
    bool GetKey(const CKeyID &address, CKey& keyOut) const;
    //! Adds a HDPubKey into the wallet(database)
    bool AddHDPubKey(const CExtPubKey &extPubKey, bool fInternal);
    //! loads a HDPubKey into the wallets memory
    bool LoadHDPubKey(const CHDPubKey &hdPubKey);
    //! Adds a key to the store, and saves it to disk.
    bool AddKeyPubKey(const CKey& key, const CPubKey &pubkey) override;
    bool AddKeyPubKeyWithDB(CWalletDB &walletdb,const CKey& key, const CPubKey &pubkey);
    //! Adds a key to the store, without saving it to disk (used by LoadWallet)
    bool LoadKey(const CKey& key, const CPubKey& pubkey) { return CCryptoKeyStore::AddKeyPubKey(key, pubkey); }
    //! Load metadata (used by LoadWallet)
    bool LoadKeyMetadata(const CKeyID& keyID, const CKeyMetadata &metadata);
    bool LoadScriptMetadata(const CScriptID& script_id, const CKeyMetadata &metadata);

    bool LoadMinVersion(int nVersion)
    {
        AssertLockHeld(cs_wallet);
        nWalletVersion = nVersion;
        nWalletMaxVersion = std::max(nWalletMaxVersion, nVersion);
        return true;
    }

    void UpdateTimeFirstKey(int64_t nCreateTime);
    //! Adds an encrypted key to the store, and saves it to disk.
    bool AddCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret) override;
    //! Adds an encrypted key to the store, without saving it to disk (used by LoadWallet)
    bool LoadCryptedKey(const CPubKey& vchPubKey, const std::vector<unsigned char>& vchCryptedSecret);
    bool AddCScript(const CScript& redeemScript) override;
    bool LoadCScript(const CScript& redeemScript);

    //! Adds a destination data tuple to the store, and saves it to disk
    bool AddDestData(const CTxDestination& dest, const std::string& key, const std::string& value);
    //! Erases a destination data tuple in the store and on disk
    bool EraseDestData(const CTxDestination& dest, const std::string& key);
    //! Adds a destination data tuple to the store, without saving it to disk
    bool LoadDestData(const CTxDestination& dest, const std::string& key, const std::string& value);
    //! Look up a destination data tuple in the store, return true if found false otherwise
    bool GetDestData(const CTxDestination& dest, const std::string& key, std::string* value) const;

    //! Adds a watch-only address to the store, and saves it to disk.
    bool AddWatchOnly(const CScript& dest, int64_t nCreateTime);
    bool RemoveWatchOnly(const CScript &dest) override;
    //! Adds a watch-only address to the store, without saving it to disk (used by LoadWallet)
    bool LoadWatchOnly(const CScript& dest);

    bool Unlock(const SecureString& strWalletPassphrase, bool anonimizeOnly = false);
    bool ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase);
    bool EncryptWallet(const SecureString& strWalletPassphrase);

    void GetKeyBirthTimes(std::map<CTxDestination, int64_t> &mapKeyBirth) const;
    unsigned int ComputeTimeSmart(const CWalletTx& wtx) const;

    bool LoadToken(const CTokenInfo &token);

    bool LoadTokenTx(const CTokenTx &tokenTx);

    //! Adds a contract data tuple to the store, without saving it to disk
    bool LoadContractData(const std::string &address, const std::string &key, const std::string &value);

    /**
     * Increment the next transaction order id
     * @return next transaction order id
     */
    int64_t IncOrderPosNext(CWalletDB* pwalletdb = nullptr);
    bool GetAccountDestination(CTxDestination &dest, std::string strAccount, bool bForceNew = false);

    /**
     * Get the wallet's activity log
     * @return multimap of ordered transactions and accounting entries
     * @warning Returned pointers are *only* valid within the scope of passed acentries
     */
    TxItems OrderedTxItems(std::list<CAccountingEntry>& acentries, std::string strAccount = "");

    DBErrors ReorderTransactions();
    bool AccountMove(std::string strFrom, std::string strTo, CAmount nAmount, std::string strComment = "");
    bool GetAccountPubkey(CPubKey &pubKey, std::string strAccount, bool bForceNew = false);

    void MarkDirty();
    bool AddToWallet(const CWalletTx& wtxIn, bool fFromLoadWallet = false, bool fFlushOnClose=true);
    bool LoadToWallet(const CWalletTx& wtxIn);
    void SyncTransaction(const CTransactionRef& tx, const CBlockIndex *pindex = nullptr, int posInBlock = 0);
    bool AddToWalletIfInvolvingMe(const CTransactionRef& tx, const CBlockIndex* pIndex, int posInBlock, bool fUpdate);
    int64_t RescanFromTime(int64_t startTime, bool update);
    CBlockIndex* ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate = false);
    void EraseFromWallet(const uint256& hash);
    void ReacceptWalletTransactions();
    void ResendWalletTransactions();
    CAmount GetBalance() const;
    CAmount GetUnconfirmedBalance() const;
    CAmount GetImmatureBalance() const;
    CAmount GetAnonymizableBalance() const;
    CAmount GetAnonymizedBalance() const;
    double GetAverageAnonymizedRounds() const;
    CAmount GetNormalizedAnonymizedBalance() const;
    CAmount GetDenominatedBalance(bool unconfirmed/*=false*/) const;
    CAmount GetDenominatedBalance(bool onlyDenom/*=true*/, bool onlyUnconfirmed/*=false*/) const;
    CAmount GetWatchOnlyBalance() const;
    CAmount GetUnconfirmedWatchOnlyBalance() const;
    CAmount GetImmatureWatchOnlyBalance() const;
    CAmount GetLegacyBalance(const isminefilter& filter, int minDepth, const std::string* account) const;
    CAmount GetAvailableBalance(const CCoinControl* coinControl = nullptr) const;
    OutputType TransactionChangeType(const std::vector<std::pair<CScript, CAmount> >& vecSend);
    bool CreateTransaction(const std::vector<std::pair<CScript, CAmount> >& vecSend,
                           CWalletTx& wtxNew,
                           CReserveKey& reservekey,
                           CAmount& nFeeRet,
                           std::string& strFailReason,
                           const CCoinControl* coinControl = nullptr,
                           AvailableCoinsType coin_type = ALL_COINS,
                           bool useIX = false,
                           CAmount nFeePay = 0, CAmount nGasFee=0);
    bool CreateTransaction(CScript scriptPubKey, const CAmount& nValue, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRet, std::string& strFailReason, const CCoinControl* coinControl = nullptr, AvailableCoinsType coin_type = ALL_COINS, bool useIX = false, CAmount nFeePay = 0);
    bool CommitTransaction(CWalletTx& wtxNew, CReserveKey& reservekey, std::string strCommand = "tx");
    std::string PrepareDarksendDenominate(int minRounds, int maxRounds);
    bool CreateCollateralTransaction(CMutableTransaction& txCollateral, std::string& strReason);
    bool ConvertList(std::vector<CTxIn> vCoins, std::vector<int64_t>& vecAmounts);
    bool MultiSend();
    void AutoCombineDust();

    bool AddTokenEntry(const CTokenInfo &token, bool fFlushOnClose=true);

    bool AddTokenTxEntry(const CTokenTx& tokenTx, bool fFlushOnClose=true);

    bool GetTokenTxDetails(const CTokenTx &wtx, uint256& credit, uint256& debit, std::string& tokenSymbol, uint8_t& decimals) const;

    bool IsTokenTxMine(const CTokenTx &wtx) const;

    bool RemoveTokenEntry(const uint256& tokenHash, bool fFlushOnClose=true);

    void ListAccountCreditDebit(const std::string& strAccount, std::list<CAccountingEntry>& entries);

    bool AddAccountingEntry(const CAccountingEntry&);

    bool AddAccountingEntry(const CAccountingEntry&, CWalletDB *pwalletdb);



    static CFeeRate minTxFee;
    static CAmount GetMinimumFee(unsigned int nTxBytes, unsigned int nConfirmTarget, const CTxMemPool& pool);

    bool NewKeyPool();
    size_t KeypoolCountExternalKeys();
    size_t KeypoolCountInternalKeys();
    bool TopUpKeyPool(unsigned int kpSize = 0);
    void ReserveKeyFromKeyPool(int64_t& nIndex, CKeyPool& keypool, bool fRequestedInternal);
    void KeepKey(int64_t nIndex);
    void ReturnKey(int64_t nIndex, bool internal, const CPubKey& pubkey);
    bool GetKeyFromPool(CPubKey &key, bool internal = false);
    int64_t GetOldestKeyPoolTime();
    /**
     * Marks all keys in the keypool up to and including reserve_key as used.
     */
    void MarkReserveKeysAsUsed(int64_t keypool_id);
   // const std::map<CKeyID, int64_t>& GetAllReserveKeys() const { return m_pool_key_to_index; }
   void GetAllReserveKeys(std::set<CKeyID>& setAddress) const;

    std::set<std::set<CTxDestination> > GetAddressGroupings();
    std::map<CTxDestination, CAmount> GetAddressBalances();

    std::set<CTxDestination> GetAccountAddresses(const std::string &strAccount) const;

    bool GetBudgetSystemCollateralTX(CTransaction& tx, uint256 hash, bool useIX);
    bool GetBudgetSystemCollateralTX(CWalletTx& tx, uint256 hash, bool useIX);

    // get the DarkSend chain depth for a given input
    int GetRealInputDarkSendRounds(CTxIn in, int rounds) const;
    // respect current settings
    int GetInputDarkSendRounds(CTxIn in) const;

    bool IsDenominated(const CTxIn& txin) const;
    bool IsDenominated(const CTransaction& tx) const;
    bool IsDenominatedAmount(int64_t nInputAmount) const;

    isminetype IsMine(const CTxIn& txin) const;
    isminetype IsMine(const CTxOut& txout) const { return ::IsMine(*this, txout.scriptPubKey); }
    bool IsMine(const CTransaction& tx) const
    {
        for (const CTxOut& txout : tx.vout)
        if (IsMine(txout) != ISMINE_NO) return true;
        return false;
    }

    /** should probably be renamed to IsRelevantToMe */
    bool IsFromMe(const CTransaction& tx) const
    {
        return (GetDebit(tx, ISMINE_ALL) > 0);
    }

    CAmount GetDebit(const CTxIn& txin, const isminefilter& filter) const;
    CAmount GetDebit(const CTransaction& tx, const isminefilter& filter) const
    {
        CAmount nDebit = 0;
        for (const CTxIn& txin : tx.vin) {
            nDebit += GetDebit(txin, filter);
            if (!MoneyRange(nDebit))
                throw std::runtime_error("CWallet::GetDebit() : value out of range");
        }
        return nDebit;
    }

    CAmount GetCredit(const CTxOut& txout, const isminefilter& filter) const
    {
        if (!MoneyRange(txout.nValue))
            throw std::runtime_error("CWallet::GetCredit() : value out of range");
        return ((IsMine(txout) & filter) ? txout.nValue : 0);
    }
    CAmount GetCredit(const CTransaction& tx, const isminefilter& filter) const
    {
        CAmount nCredit = 0;
        for (const CTxOut& txout : tx.vout) {
            nCredit += GetCredit(txout, filter);
            if (!MoneyRange(nCredit))
                throw std::runtime_error("CWallet::GetCredit() : value out of range");
        }
        return nCredit;
    }

    bool IsChange(const CTxOut& txout) const;
    CAmount GetChange(const CTxOut& txout) const
    {
        if (!MoneyRange(txout.nValue))
            throw std::runtime_error("CWallet::GetChange() : value out of range");
        return (IsChange(txout) ? txout.nValue : 0);
    }
    CAmount GetChange(const CTransaction& tx) const
    {
        CAmount nChange = 0;
        for (const CTxOut& txout : tx.vout) {
            nChange += GetChange(txout);
            if (!MoneyRange(nChange))
                throw std::runtime_error("CWallet::GetChange() : value out of range");
        }
        return nChange;
    }

    void SetBestChain(const CBlockLocator& loc);

    DBErrors LoadWallet(bool& fFirstRunRet);
    DBErrors ZapWalletTx(std::vector<CWalletTx>& vWtx);
    DBErrors ZapSelectTx(std::vector<uint256>& vHashIn, std::vector<uint256>& vHashOut);

    bool SetAddressBook(const CTxDestination& address, const std::string& strName, const std::string& purpose);

    bool DelAddressBook(const CTxDestination& address);

    const std::string& GetAccountName(const CScript& scriptPubKey) const;

    bool SetContractBook(const std::string& strAddress, const std::string& strName, const std::string& strAbi);

    bool DelContractBook(const std::string& strAddress);

   bool UpdatedTransaction(const uint256& hashTx);

    void Inventory(const uint256& hash)
    {
        LOCK(cs_wallet);
        std::map<uint256, int>::iterator mi = mapRequestCount.find(hash);
        if (mi != mapRequestCount.end()) (*mi).second++;
    }

    void GetScriptForMining(std::shared_ptr<CReserveScript> &script);

    unsigned int GetKeyPoolSize()
    {
        AssertLockHeld(cs_wallet); // set{Ex,In}ternalKeyPool
        return setInternalKeyPool.size() + setExternalKeyPool.size();
    }

    bool SetDefaultKey(const CPubKey& vchPubKey);

    //! signify that a particular wallet feature is now used. this may change nWalletVersion and nWalletMaxVersion if those are lower
    bool SetMinVersion(enum WalletFeature, CWalletDB* pwalletdbIn = nullptr, bool fExplicit = false);

    //! change which version we're allowed to upgrade to (note that this does not immediately imply upgrading to that format)
    bool SetMaxVersion(int nVersion);

    //! get the current wallet format (the oldest client version guaranteed to understand this wallet)
    int GetVersion()
    {
        LOCK(cs_wallet);
        return nWalletVersion;
    }

    //! disable transaction for coinstake
    void DisableTransaction(const CTransaction &tx);

    //! Get wallet transactions that conflict with given transaction (spend same outputs)
    std::set<uint256> GetConflicts(const uint256& txid) const;

    //! Check if a given transaction has any of its outputs spent by another transaction in the wallet
    bool HasWalletSpend(const uint256& txid) const;

    //! Flush wallet (bitdb flush)
    void Flush(bool shutdown=false);

    //! Responsible for reading and validating the -wallet arguments and verifying the wallet database.
    //  This function will perform salvage on the wallet if requested, as long as only one wallet is
    //  being loaded (CWallet::ParameterInteraction forbids -salvagewallet, -zapwallettxes or -upgradewallet with multiwallet).
    static bool Verify();

    /**
     * Address book entry changed.
     * @note called with lock cs_wallet held.
     */
    boost::signals2::signal<void(CWallet* wallet, const CTxDestination& address, const std::string& label, bool isMine, const std::string& purpose, ChangeType status)> NotifyAddressBookChanged;

    /**
     * Wallet transaction added, removed or updated.
     * @note called with lock cs_wallet held.
     */

    /** Wallet transaction added, removed or updated. */
    boost::signals2::signal<void (CWallet *wallet, const uint256 &hashToken,
                                  ChangeType status)> NotifyTokenChanged;

    boost::signals2::signal<void(CWallet* wallet, const uint256& hashTx, ChangeType status)> NotifyTransactionChanged;

    /** Contract book entry changed. */
    boost::signals2::signal<void (CWallet *wallet, const std::string &address,
            const std::string &label, const std::string &abi,
            ChangeType status)> NotifyContractBookChanged;

    /**
     * Wallet token transaction added, removed or updated.
     * @note called with lock cs_wallet held.
     */
    boost::signals2::signal<void (CWallet *wallet, const uint256 &hashTx,
                                  ChangeType status)> NotifyTokenTransactionChanged;


    /** Show progress e.g. for rescan */
    boost::signals2::signal<void(const std::string& title, int nProgress)> ShowProgress;

    /** Watch-only address added */
    boost::signals2::signal<void(bool fHaveWatchOnly)> NotifyWatchonlyChanged;

    /** Inquire whether this wallet broadcasts transactions. */
    bool GetBroadcastTransactions() const { return fBroadcastTransactions; }

    /** Set whether this wallet broadcasts transactions. */
    void SetBroadcastTransactions(bool broadcast) { fBroadcastTransactions = broadcast; }

    static CWallet* InitLoadWallet(bool fDisableWallet, const std::string& strWalletFile, std::string& warningString, std::string& errorString);

    /** Return whether transaction can be abandoned */
    bool TransactionCanBeAbandoned(const uint256& hashTx) const;

    /* Mark a transaction (and it in-wallet descendants) as abandoned so its inputs may be respent. */
    bool AbandonTransaction(const uint256& hashTx);

    /** Mark a transaction as replaced by another transaction (e.g., BIP 125). */
    bool MarkReplaced(const uint256& originalHash, const uint256& newHash);

    /* Returns the wallets help message */
    static std::string GetWalletHelpString(bool showDebug);

    /* Initializes the wallet, returns a new CWallet instance or a null pointer in case of an error */
    static CWallet* CreateWalletFromFile(const std::string walletFile);
    static bool InitLoadWallet();
    bool GetStakeWeight(uint64_t& nWeight);

    /**
     * Explicitly make the wallet learn the related scripts for outputs to the
     * given key. This is purely to make the wallet file compatible with older
     * software, as CBasicKeyStore automatically does this implicitly for all
     * keys now.
     */
    void LearnRelatedScripts(const CPubKey& key, OutputType);

    /**
     * Same as LearnRelatedScripts, but when the OutputType is not known (and could
     * be anything).
     */
    void LearnAllRelatedScripts(const CPubKey& key);

    /**
     * Get a destination of the requested type (if possible) to the specified script.
     * This function will automatically add the necessary scripts to the wallet.
     */
    CTxDestination AddAndGetDestinationForScript(const CScript& script, OutputType);

    /**
     * HD Wallet Functions
     */
    bool IsHDEnabled();

    /* Generates a new HD chain */
    void GenerateNewHDChain();
    /* Set the HD chain model (chain child index counters) */
    bool SetHDChain(const CHDChain& chain, bool memonly);
    bool SetCryptedHDChain(const CHDChain& chain, bool memonly);
    bool GetDecryptedHDChain(CHDChain& hdChainRet);

    /* Set the current hd master key (will reset the chain child index counters) */
    //const CHDChain& GetHDChain() { return hdChain; }
    /* Returns true if HD is enabled */
    CPubKey GenerateNewHDMasterKey();
    bool SetHDMasterKey(const CPubKey& key, CHDChain *forOldChain = nullptr);
};

/** A key allocated from the key pool. */
class CReserveKey : public CReserveScript
{
protected:
    CWallet* pwallet;
    int64_t nIndex;
    CPubKey vchPubKey;
    bool fInternal;

public:
    CReserveKey(CWallet* pwalletIn)
    {
        nIndex = -1;
        pwallet = pwalletIn;
        fInternal = false;
    }

    CReserveKey() = default;
    CReserveKey(const CReserveKey&) = delete;
    CReserveKey& operator=(const CReserveKey&) = delete;

    ~CReserveKey()
    {
        ReturnKey();
    }

    void ReturnKey();
    bool GetReservedKey(CPubKey &pubkey, bool internal/* = false*/);
    void KeepKey();
    void KeepScript() override { KeepKey(); }
};


/**
 * Account information.
 * Stored in wallet with key "acc"+string account name.
 */
class CAccount
{
public:
    CPubKey vchPubKey;

    CAccount()
    {
        SetNull();
    }

    void SetNull()
    {
        vchPubKey = CPubKey();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vchPubKey);
    }
};

/**
 * A transaction with a bunch of additional info that only the owner cares about.
 * It includes any unrecorded transactions needed to link it back to the block chain.
 */
class CWalletTx : public CMerkleTx
{
private:
    const CWallet* pwallet;

public:
    mapValue_t mapValue;
    std::vector<std::pair<std::string, std::string> > vOrderForm;
    unsigned int fTimeReceivedIsTxTime;
    unsigned int nTimeReceived; //! time received by this node
    unsigned int nTimeSmart;
    char fFromMe;
    std::string strFromAccount;
    int64_t nOrderPos; //! position in ordered transaction list

    // memory only
    mutable bool fDebitCached;
    mutable bool fCreditCached;
    mutable bool fImmatureCreditCached;
    mutable bool fAvailableCreditCached;
    mutable bool fAnonymizableCreditCached;
    mutable bool fAnonymizedCreditCached;
    mutable bool fDenomUnconfCreditCached;
    mutable bool fDenomConfCreditCached;
    mutable bool fWatchDebitCached;
    mutable bool fWatchCreditCached;
    mutable bool fImmatureWatchCreditCached;
    mutable bool fAvailableWatchCreditCached;
    mutable bool fChangeCached;
    mutable CAmount nDebitCached;
    mutable CAmount nCreditCached;
    mutable CAmount nImmatureCreditCached;
    mutable CAmount nAvailableCreditCached;
    mutable CAmount nAnonymizableCreditCached;
    mutable CAmount nAnonymizedCreditCached;
    mutable CAmount nDenomUnconfCreditCached;
    mutable CAmount nDenomConfCreditCached;
    mutable CAmount nWatchDebitCached;
    mutable CAmount nWatchCreditCached;
    mutable CAmount nImmatureWatchCreditCached;
    mutable CAmount nAvailableWatchCreditCached;
    mutable CAmount nChangeCached;

    CWalletTx()
    {
        Init(nullptr);
    }

    CWalletTx(const CWallet* pwalletIn, const CTransactionRef arg) : CMerkleTx(std::move(arg))
    {
        Init(pwalletIn);
    }

    const CWallet* GetWallet() const { return pwallet; }

    // True if only scriptSigs are different
    bool IsEquivalentTo(const CWalletTx& tx);

    void Init(const CWallet* pwalletIn)
    {
        pwallet = pwalletIn;
        mapValue.clear();
        vOrderForm.clear();
        fTimeReceivedIsTxTime = false;
        nTimeReceived = 0;
        nTimeSmart = 0;
        fFromMe = false;
        strFromAccount.clear();
        fDebitCached = false;
        fCreditCached = false;
        fImmatureCreditCached = false;
        fAvailableCreditCached = false;
        fAnonymizableCreditCached = false;
        fAnonymizedCreditCached = false;
        fDenomUnconfCreditCached = false;
        fDenomConfCreditCached = false;
        fWatchDebitCached = false;
        fWatchCreditCached = false;
        fImmatureWatchCreditCached = false;
        fAvailableWatchCreditCached = false;
        fChangeCached = false;
        nDebitCached = 0;
        nCreditCached = 0;
        nImmatureCreditCached = 0;
        nAvailableCreditCached = 0;
        nAnonymizableCreditCached = 0;
        nAnonymizedCreditCached = 0;
        nDenomUnconfCreditCached = 0;
        nDenomConfCreditCached = 0;
        nWatchDebitCached = 0;
        nWatchCreditCached = 0;
        nAvailableWatchCreditCached = 0;
        nImmatureWatchCreditCached = 0;
        nChangeCached = 0;
        nOrderPos = -1;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        if (ser_action.ForRead())
            Init(nullptr);
        char fSpent = false;

        if (!ser_action.ForRead()) {
            mapValue["fromaccount"] = strFromAccount;

            WriteOrderPos(nOrderPos, mapValue);

            if (nTimeSmart)
                mapValue["timesmart"] = strprintf("%u", nTimeSmart);
        }

        READWRITE(*(CMerkleTx*)this);
        std::vector<CMerkleTx> vUnused; //! Used to be vtxPrev
        READWRITE(vUnused);
        READWRITE(mapValue);
        READWRITE(vOrderForm);
        READWRITE(fTimeReceivedIsTxTime);
        READWRITE(nTimeReceived);
        READWRITE(fFromMe);
        READWRITE(fSpent);

        if (ser_action.ForRead()) {
            strFromAccount = mapValue["fromaccount"];

            ReadOrderPos(nOrderPos, mapValue);

            nTimeSmart = mapValue.count("timesmart") ? (unsigned int)atoi64(mapValue["timesmart"]) : 0;
        }

        mapValue.erase("fromaccount");
        mapValue.erase("version");
        mapValue.erase("spent");
        mapValue.erase("n");
        mapValue.erase("timesmart");
    }

    //! make sure balances are recalculated
    void MarkDirty()
    {
        fCreditCached = false;
        fAvailableCreditCached = false;
        fAnonymizableCreditCached = false;
        fAnonymizedCreditCached = false;
        fDenomUnconfCreditCached = false;
        fDenomConfCreditCached = false;
        fWatchDebitCached = false;
        fWatchCreditCached = false;
        fAvailableWatchCreditCached = false;
        fImmatureWatchCreditCached = false;
        fDebitCached = false;
        fChangeCached = false;
    }

    void BindWallet(CWallet* pwalletIn)
    {
        pwallet = pwalletIn;
        MarkDirty();
    }

    //! filter decides which addresses will count towards the debit
    CAmount GetDebit(const isminefilter& filter) const
    {
        if (tx->vin.empty())
            return 0;

        CAmount debit = 0;
        if (filter & ISMINE_SPENDABLE) {
            if (fDebitCached)
                debit += nDebitCached;
            else {
                nDebitCached = pwallet->GetDebit(*tx, ISMINE_SPENDABLE);
                fDebitCached = true;
                debit += nDebitCached;
            }
        }
        if (filter & ISMINE_WATCH_ONLY) {
            if (fWatchDebitCached)
                debit += nWatchDebitCached;
            else {
                nWatchDebitCached = pwallet->GetDebit(*tx, ISMINE_WATCH_ONLY);
                fWatchDebitCached = true;
                debit += nWatchDebitCached;
            }
        }
        return debit;
    }

    CAmount GetCredit(const isminefilter& filter) const
    {
        // Must wait until coinbase is safely deep enough in the chain before valuing it
        if (IsCoinBase() && GetBlocksToMaturity() > 0)
            return 0;

        int64_t credit = 0;
        if (filter & ISMINE_SPENDABLE) {
            // GetBalance can assume transactions in mapWallet won't change
            if (fCreditCached)
                credit += nCreditCached;
            else {
                nCreditCached = pwallet->GetCredit(*tx, ISMINE_SPENDABLE);
                fCreditCached = true;
                credit += nCreditCached;
            }
        }
        if (filter & ISMINE_WATCH_ONLY) {
            if (fWatchCreditCached)
                credit += nWatchCreditCached;
            else {
                nWatchCreditCached = pwallet->GetCredit(*tx, ISMINE_WATCH_ONLY);
                fWatchCreditCached = true;
                credit += nWatchCreditCached;
            }
        }
        return credit;
    }

    CAmount GetImmatureCredit(bool fUseCache = true) const
    {
        if (IsCoinGenerated() && GetBlocksToMaturity() > 0 && IsInMainChain()) {
            if (fUseCache && fImmatureCreditCached)
                return nImmatureCreditCached;
            nImmatureCreditCached = pwallet->GetCredit(*tx, ISMINE_SPENDABLE);
            fImmatureCreditCached = true;
            return nImmatureCreditCached;
        }

        return 0;
    }

    CAmount GetAvailableCredit(bool fUseCache = true) const
    {
        if (pwallet == 0)
            return 0;

        // Must wait until coinbase is safely deep enough in the chain before valuing it
        if (IsCoinGenerated() && GetBlocksToMaturity() > 0)
            return 0;

        if (fUseCache && fAvailableCreditCached)
            return nAvailableCreditCached;

        CAmount nCredit = 0;
        uint256 hashTx = GetHash();
        for (unsigned int i = 0; i < tx->vout.size(); i++) {
            if (!pwallet->IsSpent(hashTx, i)) {
                const CTxOut& txout = tx->vout[i];
                nCredit += pwallet->GetCredit(txout, ISMINE_SPENDABLE);
                if (!MoneyRange(nCredit))
                    throw std::runtime_error(std::string(__func__) + " : value out of range");
            }
        }

        nAvailableCreditCached = nCredit;
        fAvailableCreditCached = true;
        return nCredit;
    }

    CAmount GetAnonymizableCredit(bool fUseCache = true) const
    {
        if (pwallet == 0)
            return 0;

        // Must wait until coinbase is safely deep enough in the chain before valuing it
        if (IsCoinBase() && GetBlocksToMaturity() > 0)
            return 0;

        if (fUseCache && fAnonymizableCreditCached)
            return nAnonymizableCreditCached;

        CAmount nCredit = 0;
        uint256 hashTx = GetHash();
        for (unsigned int i = 0; i < tx->vout.size(); i++) {
            const CTxOut& txout = tx->vout[i];
            const CTxIn vin = CTxIn(hashTx, i);

            if (pwallet->IsSpent(hashTx, i) || pwallet->IsLockedCoin(hashTx, i)) continue;
            if (fMasterNode && tx->vout[i].nValue == DARKSEND_COLLATERAL) continue; // do not count MN-like outputs

            const int rounds = pwallet->GetInputDarkSendRounds(vin);
            if (rounds >= -2 && rounds < nDarksendRounds) {
                nCredit += pwallet->GetCredit(txout, ISMINE_SPENDABLE);
                if (!MoneyRange(nCredit))
                    throw std::runtime_error("CWalletTx::GetAnonamizableCredit() : value out of range");
            }
        }

        nAnonymizableCreditCached = nCredit;
        fAnonymizableCreditCached = true;
        return nCredit;
    }

    CAmount GetAnonymizedCredit(bool fUseCache = true) const
    {
        if (pwallet == 0)
            return 0;

        // Must wait until coinbase is safely deep enough in the chain before valuing it
        if (IsCoinBase() && GetBlocksToMaturity() > 0)
            return 0;

        if (fUseCache && fAnonymizedCreditCached)
            return nAnonymizedCreditCached;

        CAmount nCredit = 0;
        uint256 hashTx = GetHash();
        for (unsigned int i = 0; i < tx->vout.size(); i++) {
            const CTxOut& txout = tx->vout[i];
            const CTxIn vin = CTxIn(hashTx, i);

            if (pwallet->IsSpent(hashTx, i) || !pwallet->IsDenominated(vin)) continue;

            const int rounds = pwallet->GetInputDarkSendRounds(vin);
            if (rounds >= nDarksendRounds) {
                nCredit += pwallet->GetCredit(txout, ISMINE_SPENDABLE);
                if (!MoneyRange(nCredit))
                    throw std::runtime_error("CWalletTx::GetAnonymizedCredit() : value out of range");
            }
        }

        nAnonymizedCreditCached = nCredit;
        fAnonymizedCreditCached = true;
        return nCredit;
    }

    CAmount GetDenominatedCredit(bool unconfirmed, bool fUseCache = true) const
    {
        if (pwallet == 0)
            return 0;

        // Must wait until coinbase is safely deep enough in the chain before valuing it
        if (IsCoinBase() && GetBlocksToMaturity() > 0)
            return 0;

        int nDepth = GetDepthInMainChain(false);
        if (nDepth < 0) return 0;

        bool isUnconfirmed = !IsFinalTx(*tx) || (!IsTrusted() && nDepth == 0);
        if (unconfirmed != isUnconfirmed) return 0;

        if (fUseCache) {
            if (unconfirmed && fDenomUnconfCreditCached)
                return nDenomUnconfCreditCached;
            else if (!unconfirmed && fDenomConfCreditCached)
                return nDenomConfCreditCached;
        }

        CAmount nCredit = 0;
        uint256 hashTx = GetHash();
        for (unsigned int i = 0; i < tx->vout.size(); i++) {
            const CTxOut& txout = tx->vout[i];

            if (pwallet->IsSpent(hashTx, i) || !pwallet->IsDenominatedAmount(tx->vout[i].nValue)) continue;

            nCredit += pwallet->GetCredit(txout, ISMINE_SPENDABLE);
            if (!MoneyRange(nCredit))
                throw std::runtime_error("CWalletTx::GetDenominatedCredit() : value out of range");
        }

        if (unconfirmed) {
            nDenomUnconfCreditCached = nCredit;
            fDenomUnconfCreditCached = true;
        } else {
            nDenomConfCreditCached = nCredit;
            fDenomConfCreditCached = true;
        }
        return nCredit;
    }

    CAmount GetImmatureWatchOnlyCredit(const bool& fUseCache = true) const
    {
        if (IsCoinBase() && GetBlocksToMaturity() > 0 && IsInMainChain()) {
            if (fUseCache && fImmatureWatchCreditCached)
                return nImmatureWatchCreditCached;
            nImmatureWatchCreditCached = pwallet->GetCredit(*tx, ISMINE_WATCH_ONLY);
            fImmatureWatchCreditCached = true;
            return nImmatureWatchCreditCached;
        }

        return 0;
    }

    CAmount GetAvailableWatchOnlyCredit(const bool& fUseCache = true) const
    {
        if (pwallet == 0)
            return 0;

        // Must wait until coinbase is safely deep enough in the chain before valuing it
        if (IsCoinGenerated() && GetBlocksToMaturity() > 0)
            return 0;

        if (fUseCache && fAvailableWatchCreditCached)
            return nAvailableWatchCreditCached;

        CAmount nCredit = 0;
        for (unsigned int i = 0; i < tx->vout.size(); i++) {
            if (!pwallet->IsSpent(GetHash(), i)) {
                const CTxOut& txout = tx->vout[i];
                nCredit += pwallet->GetCredit(txout, ISMINE_WATCH_ONLY);
                if (!MoneyRange(nCredit))
                    throw std::runtime_error("CWalletTx::GetAvailableCredit() : value out of range");
            }
        }

        nAvailableWatchCreditCached = nCredit;
        fAvailableWatchCreditCached = true;
        return nCredit;
    }

    CAmount GetChange() const
    {
        if (fChangeCached)
            return nChangeCached;
        nChangeCached = pwallet->GetChange(*tx);
        fChangeCached = true;
        return nChangeCached;
    }

    void GetAmounts(std::list<COutputEntry>& listReceived,
        std::list<COutputEntry>& listSent,
        CAmount& nFee,
        std::string& strSentAccount,
        const isminefilter& filter) const;

    void GetAccountAmounts(const std::string& strAccount, CAmount& nReceived, CAmount& nSent, CAmount& nFee, const isminefilter& filter) const;

    bool IsFromMe(const isminefilter& filter) const
    {
        return (GetDebit(filter) > 0);
    }

    bool InMempool() const;

    bool IsTrusted() const
    {
        // Quick answer in most cases
        if (!IsFinalTx(*tx))
            return false;
        int nDepth = GetDepthInMainChain();
        if (nDepth >= 1)
            return true;
        if (nDepth < 0)
            return false;
        if (!bSpendZeroConfChange || !IsFromMe(ISMINE_ALL)) // using wtx's cached debit
            return false;

        // Trusted if all inputs are from us and are in the mempool:
        for (const CTxIn& txin : tx->vin) {
            // Transactions not sent by us: not trusted
            const CWalletTx* parent = pwallet->GetWalletTx(txin.prevout.hash);
            if (parent == nullptr)
                return false;
            const CTxOut& parentOut = parent->tx->vout[txin.prevout.n];
            const isminetype t = pwallet->IsMine(parentOut);
            if (t != ISMINE_SPENDABLE)
                return false;
        }
        return true;
    }

    int64_t GetTxTime() const;
    int GetRequestCount() const;

    void RelayWalletTransaction(std::string strCommand = "tx");

    std::set<uint256> GetConflicts() const;
};


class COutput
{
public:
    const CWalletTx* tx;
    int i;
    int nDepth;
    bool fSpendable;

    COutput(const CWalletTx* txIn, int iIn, int nDepthIn, bool fSpendableIn)
    {
        tx = txIn;
        i = iIn;
        nDepth = nDepthIn;
        fSpendable = fSpendableIn;
    }

    //Used with DarkSend. Will return largest nondenom, then denominations, then very small inputs
    int Priority() const
    {
        for (int64_t d : darkSendDenominations)
            if (tx->tx->vout[i].nValue == d) return 10000;
        if (tx->tx->vout[i].nValue < 1 * COIN) return 20000;

        //nondenom return largest first
        return static_cast<int>(-(tx->tx->vout[i].nValue / COIN));
    }

    CAmount Value() const
    {
        return tx->tx->vout[i].nValue;
    }

    std::string ToString() const;
};


/** Private key that includes an expiration date in case it never gets used. */
class CWalletKey
{
public:
    CPrivKey vchPrivKey;
    int64_t nTimeCreated;
    int64_t nTimeExpires;
    std::string strComment;
    //! todo: add something to note what created it (user, getnewaddress, change)
    //!   maybe should have a map<string, string> property map

    CWalletKey(int64_t nExpires = 0);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vchPrivKey);
        READWRITE(nTimeCreated);
        READWRITE(nTimeExpires);
        READWRITE(LIMITED_STRING(strComment, 65536));
    }
};

/**
 * Internal transfers.
 * Database key is acentry<account><counter>.
 */
class CAccountingEntry
{
public:
    std::string strAccount;
    CAmount nCreditDebit;
    int64_t nTime;
    std::string strOtherAccount;
    std::string strComment;
    mapValue_t mapValue;
    int64_t nOrderPos; //! position in ordered transaction list
    uint64_t nEntryNo;

    CAccountingEntry()
    {
        SetNull();
    }

    void SetNull()
    {
        nCreditDebit = 0;
        nTime = 0;
        strAccount.clear();
        strOtherAccount.clear();
        strComment.clear();
        nOrderPos = -1;
        nEntryNo = 0;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        //! Note: strAccount is serialized as part of the key, not here.
        READWRITE(nCreditDebit);
        READWRITE(nTime);
        READWRITE(LIMITED_STRING(strOtherAccount, 65536));

        if (!ser_action.ForRead()) {
            WriteOrderPos(nOrderPos, mapValue);

            if (!(mapValue.empty() && _ssExtra.empty())) {
                CDataStream ss(s.GetType(), s.GetVersion());
                ss.insert(ss.begin(), '\0');
                ss << mapValue;
                ss.insert(ss.end(), _ssExtra.begin(), _ssExtra.end());
                strComment.append(ss.str());
            }
        }

        READWRITE(LIMITED_STRING(strComment, 65536));

        size_t nSepPos = strComment.find("\0", 0, 1);
        if (ser_action.ForRead()) {
            mapValue.clear();
            if (std::string::npos != nSepPos) {
                CDataStream ss(std::vector<char>(strComment.begin() + nSepPos + 1, strComment.end()), s.GetType(), s.GetVersion());
                ss >> mapValue;
                _ssExtra = std::vector<char>(ss.begin(), ss.end());
            }
            ReadOrderPos(nOrderPos, mapValue);
        }
        if (std::string::npos != nSepPos)
            strComment.erase(nSepPos);

        mapValue.erase("n");
    }

private:
    std::vector<char> _ssExtra;
};

OutputType ParseOutputType(const std::string& str, OutputType default_type = OUTPUT_TYPE_DEFAULT);
const std::string& FormatOutputType(OutputType type);

/**
 * Get a destination of the requested type (if possible) to the specified key.
 * The caller must make sure LearnRelatedScripts has been called beforehand.
 */
CTxDestination GetDestinationForKey(const CPubKey& key, OutputType);

/** Get all destinations (potentially) supported by the wallet for the given key. */
std::vector<CTxDestination> GetAllDestinationsForKey(const CPubKey& key);

/** Contract book data */
class CContractBookData
{
public:
    std::string name;
    std::string abi;

    CContractBookData()
    {}
};

class CTokenInfo
{
public:
    static const int CURRENT_VERSION=1;
    int nVersion;
    std::string strContractAddress;
    std::string strTokenName;
    std::string strTokenSymbol;
    uint8_t nDecimals;
    std::string strSenderAddress;
    int64_t nCreateTime;
    uint256 blockHash;
    int64_t blockNumber;

    CTokenInfo()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        if (!(s.GetType() & SER_GETHASH))
        {
            READWRITE(nVersion);
            READWRITE(nCreateTime);
            READWRITE(strTokenName);
            READWRITE(strTokenSymbol);
            READWRITE(blockHash);
            READWRITE(blockNumber);
        }
        READWRITE(nDecimals);
        READWRITE(strContractAddress);
        READWRITE(strSenderAddress);
    }

    void SetNull()
    {
        nVersion = CTokenInfo::CURRENT_VERSION;
        nCreateTime = 0;
        strContractAddress = "";
        strTokenName = "";
        strTokenSymbol = "";
        nDecimals = 0;
        strSenderAddress = "";
        blockHash.SetNull();
        blockNumber = -1;
    }

    uint256 GetHash() const;
};

class CTokenTx
{
public:
    static const int CURRENT_VERSION=1;
    int nVersion;
    std::string strContractAddress;
    std::string strSenderAddress;
    std::string strReceiverAddress;
    uint256 nValue;
    uint256 transactionHash;
    int64_t nCreateTime;
    uint256 blockHash;
    int64_t blockNumber;
    std::string strLabel;

    CTokenTx()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        if (!(s.GetType() & SER_GETHASH))
        {
            READWRITE(nVersion);
            READWRITE(nCreateTime);
            READWRITE(blockHash);
            READWRITE(blockNumber);
            READWRITE(LIMITED_STRING(strLabel, 65536));
        }
        READWRITE(strContractAddress);
        READWRITE(strSenderAddress);
        READWRITE(strReceiverAddress);
        READWRITE(nValue);
        READWRITE(transactionHash);
    }

    void SetNull()
    {
        nVersion = CTokenTx::CURRENT_VERSION;
        nCreateTime = 0;
        strContractAddress = "";
        strSenderAddress = "";
        strReceiverAddress = "";
        nValue.SetNull();
        transactionHash.SetNull();
        blockHash.SetNull();
        blockNumber = -1;
        strLabel = "";
    }

    uint256 GetHash() const;
};

#endif // BITCOIN_WALLET_H
