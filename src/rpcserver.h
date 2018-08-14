// Copyright (c) 2010 Satoshi Nakamoto                  -*- c++ -*-
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPCSERVER_H
#define BITCOIN_RPCSERVER_H

#include "amount.h"
#include "rpcprotocol.h"
#include "uint256.h"

#include <list>
#include <map>
#include <stdint.h>
#include <string>
#include <httpserver.h>
#include <boost/function.hpp>

#include "univalue/univalue.h"

class CRPCCommand;

namespace RPCServer
{
    void OnStarted(boost::function<void ()> slot);
    void OnStopped(boost::function<void ()> slot);
    void OnPreCommand(boost::function<void (const CRPCCommand&)> slot);
    void OnPostCommand(boost::function<void (const CRPCCommand&)> slot);
}

class CBlockIndex;
class CNetAddr;

class JSONRPCRequest
{
public:
    UniValue id;
    std::string strMethod;
    UniValue params;
    bool fHelp;
    std::string URI;
    std::string authUser;

    bool isLongPolling;

    /**
     * If using batch JSON request, this object won't get the underlying HTTPRequest.
     */
    JSONRPCRequest() {
        id = NullUniValue;
        params = NullUniValue;
        fHelp = false;
        req = nullptr;
        isLongPolling = false;
    };

    JSONRPCRequest(HTTPRequest *req);

    /**
     * Start long-polling
     */
    void PollStart();

    /**
     * Ping long-poll connection with an empty character to make sure it's still alive.
     */
    void PollPing();

    /**
     * Returns whether the underlying long-poll connection is still alive.
     */
    bool PollAlive();

    /**
     * End a long poll request.
     */
    void PollCancel();

    /**
     * Return the JSON result of a long poll request
     */
    void PollReply(const UniValue& result);

    void parse(const UniValue& valRequest);

    // FIXME: make this private?
    HTTPRequest *req;
};

/** Start RPC threads */
void StartRPCThreads();
/**
 * Alternative to StartRPCThreads for the GUI, when no server is
 * used. The RPC thread in this case is only used to handle timeouts.
 * If real RPC threads have already been started this is a no-op.
 */
void StartDummyRPCThread();
/** Stop RPC threads */
void StopRPCThreads();
/** Query whether RPC is running */
bool IsRPCRunning();

/** 
 * Set
 * the RPC warmup status.  When this is done, all RPC calls will error out
 * immediately with RPC_IN_WARMUP.
 */
void SetRPCWarmupStatus(const std::string& newStatus);
/* Mark warmup as done.  RPC calls will be processed from now on.  */
void SetRPCWarmupFinished();

/* returns the current warmup state.  */
bool RPCIsInWarmup(std::string* statusOut);

void RPCTypeCheck(const UniValue& params,
                  const std::list<UniValue::VType>& typesExpected,
                  bool fAllowNull = false);
/**
 * Type-check arguments; throws JSONRPCError if wrong type given. Does not check that
 * the right number of arguments are passed, just that any passed are the correct type.
 * Use like:  RPCTypeCheck(request.params, boost::assign::list_of(str_type)(int_type)(obj_type));
 */
void RPCTypeCheckObj(const UniValue& o, const std::map<std::string, UniValue::VType>& typesExpected, bool fAllowNull=false);

/** Opaque base class for timers returned by NewTimerFunc.
 * This provides no methods at the moment, but makes sure that delete
 * cleans up the whole state.
 */
class RPCTimerBase
{
public:
    virtual ~RPCTimerBase() {}
};

/**
* RPC timer "driver".
 */
class RPCTimerInterface
{
public:
    virtual ~RPCTimerInterface() {}
    /** Implementation name */
    virtual const char *Name() = 0;
    /** Factory function for timers.
     * RPC will call the function to create a timer that will call func in *millis* milliseconds.
     * @note As the RPC mechanism is backend-neutral, it can use different implementations of timers.
     * This is needed to cope with the case in which there is no HTTP server, but
     * only GUI RPC console, and to break the dependency of pcserver on httprpc.
     */
    virtual RPCTimerBase* NewTimer(boost::function<void(void)>& func, int64_t millis) = 0;
};

/** Register factory function for timers */
void RPCRegisterTimerInterface(RPCTimerInterface *iface);
/** Unregister factory function for timers */
void RPCUnregisterTimerInterface(RPCTimerInterface *iface);

/**
 * LUX RPC command dispatcher.
 */

void RPCRunLater(const std::string& name, boost::function<void(void)> func, int64_t nSeconds);

typedef UniValue(*rpcfn_type)(const JSONRPCRequest& jsonRequest);

class CRPCCommand
{
public:
    std::string category;
    std::string name;
    rpcfn_type actor;
    bool okSafeMode;
    bool threadSafe;
    bool reqWallet;
};

/**
 *  RPC command dispatcher.
 */

class CRPCTable
{
private:
    std::map<std::string, const CRPCCommand*> mapCommands;

public:
    CRPCTable();
    const CRPCCommand* operator[](const std::string& name) const;
    std::string help(std::string name) const;

    /**
     * Execute a method.
     * @param method   Method to execute
     * @param params   Array of arguments (JSON objects)
     * @returns Result of the call.
     * @throws an exception (UniValue) when an error happens.
     */
    UniValue execute(const JSONRPCRequest &request) const;

    /**
    * Returns a list of registered commands
    * @returns List of registered commands.
    */
    std::vector<std::string> listCommands() const;
};

extern const CRPCTable tableRPC;

/**
 * Utilities: convert hex-encoded Values
 * (throws error if not hex).
 */
extern uint256 ParseHashV(const UniValue& v, std::string strName);
extern uint256 ParseHashO(const UniValue& o, std::string strKey);
extern std::vector<unsigned char> ParseHexV(const UniValue& v, std::string strName);
extern std::vector<unsigned char> ParseHexO(const UniValue& o, std::string strKey);

extern int ParseInt(const UniValue& o, std::string strKey);
extern bool ParseBool(const UniValue& o, std::string strKey);

extern int64_t nWalletUnlockTime;
extern CAmount AmountFromValue(const UniValue& value);
extern double GetDifficulty(const CBlockIndex* blockindex = nullptr);
extern CBlockIndex* GetLastBlockOfType(const int nPoS);
extern std::string HelpRequiringPassphrase();
extern std::string HelpExampleCli(std::string methodname, std::string args);
extern std::string HelpExampleRpc(std::string methodname, std::string args);

extern void EnsureWalletIsUnlocked();

extern UniValue getconnectioncount(const JSONRPCRequest& request); // in rpcnet.cpp
extern UniValue getpeerinfo(const JSONRPCRequest& request);
extern UniValue ping(const JSONRPCRequest& request);
extern UniValue addnode(const JSONRPCRequest& request);
//extern UniValue disconnectnode(const JSONRPCRequest& request);
extern UniValue getaddednodeinfo(const JSONRPCRequest& request);
extern UniValue getnettotals(const JSONRPCRequest& request);
extern UniValue setban(const JSONRPCRequest& request);
extern UniValue listbanned(const JSONRPCRequest& request);
extern UniValue clearbanned(const JSONRPCRequest& request);

extern UniValue dumpprivkey(const JSONRPCRequest& request); // in rpcdump.cpp
extern UniValue importprivkey(const JSONRPCRequest& request);
extern UniValue importaddress(const JSONRPCRequest& request);
extern UniValue dumpwallet(const JSONRPCRequest& request);
extern UniValue importwallet(const JSONRPCRequest& request);
extern UniValue bip38encrypt(const JSONRPCRequest& request);
extern UniValue bip38decrypt(const JSONRPCRequest& request);

extern UniValue dumpprivkey(const JSONRPCRequest& request); // in rpcdump.cpp
extern UniValue importprivkey(const JSONRPCRequest& request);
extern UniValue importaddress(const JSONRPCRequest& request);
extern UniValue dumpwallet(const JSONRPCRequest& request);
extern UniValue importwallet(const JSONRPCRequest& request);
extern UniValue bip38encrypt(const JSONRPCRequest& request);
extern UniValue bip38decrypt(const JSONRPCRequest& request);
extern UniValue setstakesplitthreshold(const JSONRPCRequest& request);
extern UniValue getstakesplitthreshold(const JSONRPCRequest& request);
extern UniValue getgenerate(const JSONRPCRequest& request); // in rpcmining.cpp
extern UniValue setgenerate(const JSONRPCRequest& request);
extern UniValue getnetworkhashps(const JSONRPCRequest& request);
extern UniValue gethashespersec(const JSONRPCRequest& request);
extern UniValue getmininginfo(const JSONRPCRequest& request);
extern UniValue prioritisetransaction(const JSONRPCRequest& request);
extern UniValue getblocktemplate(const JSONRPCRequest& request);
extern UniValue getwork(const JSONRPCRequest& request);

extern UniValue submitblock(const JSONRPCRequest& request);
extern UniValue estimatefee(const JSONRPCRequest& request);
extern UniValue estimatepriority(const JSONRPCRequest& request);
extern UniValue estimatesmartfee(const JSONRPCRequest& request);
extern UniValue estimatesmartpriority(const JSONRPCRequest& request);

extern UniValue getnewaddress(const JSONRPCRequest& request); // in rpcwallet.cpp
extern UniValue getaccountaddress(const JSONRPCRequest& request);
extern UniValue getrawchangeaddress(const JSONRPCRequest& request);
extern UniValue setaccount(const JSONRPCRequest& request);
extern UniValue getaccount(const JSONRPCRequest& request);
extern UniValue getaddressesbyaccount(const JSONRPCRequest& request);
extern UniValue sendtoaddress(const JSONRPCRequest& request);
extern UniValue sendtoaddressix(const JSONRPCRequest& request);
extern UniValue signmessage(const JSONRPCRequest& request);
extern UniValue verifymessage(const JSONRPCRequest& request);
extern UniValue getreceivedbyaddress(const JSONRPCRequest& request);
extern UniValue getreceivedbyaccount(const JSONRPCRequest& request);
extern UniValue getbalance(const JSONRPCRequest& request);
extern UniValue getunconfirmedbalance(const JSONRPCRequest& request);
extern UniValue movecmd(const JSONRPCRequest& request);
extern UniValue sendfrom(const JSONRPCRequest& request);
extern UniValue sendmany(const JSONRPCRequest& request);
extern UniValue addmultisigaddress(const JSONRPCRequest& request);
extern UniValue createmultisig(const JSONRPCRequest& request);
extern UniValue createwitnessaddress(const JSONRPCRequest& request);
extern UniValue listreceivedbyaddress(const JSONRPCRequest& request);
extern UniValue listreceivedbyaccount(const JSONRPCRequest& request);
extern UniValue listtransactions(const JSONRPCRequest& request);
extern UniValue listaddressgroupings(const JSONRPCRequest& request);
extern UniValue listaccounts(const JSONRPCRequest& request);
extern UniValue listsinceblock(const JSONRPCRequest& request);
extern UniValue gettransaction(const JSONRPCRequest& request);
extern UniValue backupwallet(const JSONRPCRequest& request);
extern UniValue keypoolrefill(const JSONRPCRequest& request);
extern UniValue walletpassphrase(const JSONRPCRequest& request);
extern UniValue walletpassphrasechange(const JSONRPCRequest& request);
extern UniValue walletlock(const JSONRPCRequest& request);
extern UniValue encryptwallet(const JSONRPCRequest& request);
extern UniValue validateaddress(const JSONRPCRequest& request);
extern UniValue getinfo(const JSONRPCRequest& request);
extern UniValue getstateinfo(const JSONRPCRequest& request);
extern UniValue getwalletinfo(const JSONRPCRequest& request);
extern UniValue getblockchaininfo(const JSONRPCRequest& request);
extern UniValue getnetworkinfo(const JSONRPCRequest& request);
extern UniValue setmocktime(const JSONRPCRequest& request);
extern UniValue reservebalance(const JSONRPCRequest& request);
extern UniValue multisend(const JSONRPCRequest& request);
extern UniValue autocombinerewards(const JSONRPCRequest& request);
extern UniValue getstakingstatus(const JSONRPCRequest& request);
extern UniValue callcontract(const JSONRPCRequest& request);
extern UniValue createcontract(const JSONRPCRequest& request);
extern UniValue sendtocontract(const JSONRPCRequest& request);

extern UniValue getrawtransaction(const JSONRPCRequest& request); // in rcprawtransaction.cpp
extern UniValue listunspent(const JSONRPCRequest& request);
extern UniValue lockunspent(const JSONRPCRequest& request);
extern UniValue listlockunspent(const JSONRPCRequest& request);
extern UniValue createrawtransaction(const JSONRPCRequest& request);
extern UniValue decoderawtransaction(const JSONRPCRequest& request);
extern UniValue decodescript(const JSONRPCRequest& request);
extern UniValue signrawtransaction(const JSONRPCRequest& request);
extern UniValue sendrawtransaction(const JSONRPCRequest& request);
extern UniValue gethexaddress(const JSONRPCRequest& request);
extern UniValue fromhexaddress(const JSONRPCRequest& request);

extern UniValue getblockcount(const JSONRPCRequest& request); // in rpcblockchain.cpp
extern UniValue getblockhashes(const JSONRPCRequest& request);
extern UniValue getbestblockhash(const JSONRPCRequest& request);
extern UniValue getdifficulty(const JSONRPCRequest& request);
extern UniValue settxfee(const JSONRPCRequest& request);
extern UniValue getmempoolinfo(const JSONRPCRequest& request);
extern UniValue getrawmempool(const JSONRPCRequest& request);
extern UniValue getblockhash(const JSONRPCRequest& request);
extern UniValue getblock(const JSONRPCRequest& request);
extern UniValue getblockheader(const JSONRPCRequest& request);
extern UniValue gettxoutsetinfo(const JSONRPCRequest& request);
extern UniValue gettxout(const JSONRPCRequest& request);
extern UniValue verifychain(const JSONRPCRequest& request);
extern UniValue getchaintips(const JSONRPCRequest& request);
extern UniValue switchnetwork(const JSONRPCRequest& request);
extern UniValue invalidateblock(const JSONRPCRequest& request);
extern UniValue reconsiderblock(const JSONRPCRequest& request);
extern UniValue darksend(const JSONRPCRequest& request);
extern UniValue spork(const JSONRPCRequest& request);
extern UniValue masternode(const JSONRPCRequest& request);
extern UniValue getaccountinfo(const JSONRPCRequest& request);
//extern UniValue masternodelist(const JSONRPCRequest& request);
//extern UniValue mnbudget(const JSONRPCRequest& request);
//extern UniValue mnbudgetvoteraw(const JSONRPCRequest& request);
//extern UniValue mnfinalbudget(const JSONRPCRequest& request);
//extern UniValue mnsync(const JSONRPCRequest& request);


extern UniValue getstorage(const JSONRPCRequest& request);
extern UniValue listcontracts(const JSONRPCRequest& request);
extern UniValue gettransactionreceipt(const JSONRPCRequest& request);
extern UniValue searchlogs(const JSONRPCRequest& request);
extern UniValue pruneblockchain(const JSONRPCRequest& request);

bool StartRPC();
void InterruptRPC();
void StopRPC();
std::string JSONRPCExecBatch(const UniValue& vReq);

#endif // BITCOIN_RPCSERVER_H
