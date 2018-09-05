// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The LUX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpcblockchain.h"

#include "amount.h"
#include "base58.h"
#include "core_io.h"
#include "coins.h"
#include "consensus/validation.h"
#include "consensus/validation.h"
#include "checkpoints.h"
#include "init.h"
#include "net.h"
#include "netbase.h"
#include "main.h"
#include "libdevcore/CommonData.h"
#include "primitives/transaction.h"
#include "rpcserver.h"
#include "rbf.h"
#include "rpcwallet.cpp"
#include "sync.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/sign.h"
#include "script/standard.h"
#include "timedata.h"
#include "txdb.h"
#include "txmempool.h"
#include "util.h"
#include "utilmoneystr.h"
#include "wallet.h"
#include "walletdb.h"


#include <stdint.h>
#include <string>

#include "univalue/univalue.h"
#include <boost/thread/thread.hpp> // boost::thread::interrupt

#include <mutex>
#include <condition_variable>

using namespace std;

extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry);
void ScriptPubKeyToJSON(const CScript& scriptPubKey, UniValue& out, bool fIncludeHex);
int getBlockTimeByHeight(int nHeight);

double GetDifficulty(const CBlockIndex* blockindex)
{
    // Floating point number that is a multiple of the minimum difficulty,
    // minimum difficulty = 1.0.
    if (blockindex == nullptr) {
        if (chainActive.Tip() == nullptr)
            return 1.0;
        else
            blockindex = chainActive.Tip();
    }

    int nShift = (blockindex->nBits >> 24) & 0xff;

    double dDiff =
        (double)0x0000ffff / (double)(blockindex->nBits & 0x00ffffff);

    while (nShift < 29) {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29) {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

CBlockIndex* GetLastBlockOfType(const int nPoS) // 0: PoW; 1: PoS
{
    CBlockIndex* pBlock = chainActive.Tip();
    while (pBlock && pBlock->nHeight > 0) {
        bool isValid = false;
        isValid = (nPoS && pBlock->IsProofOfStake()) || (!nPoS && !pBlock->IsProofOfStake());
        if (isValid)
            return pBlock;

        if (pBlock->nHeight > 1)
            pBlock = chainActive[pBlock->nHeight-1];
        else
            pBlock = pBlock->pprev;
    }
    return nullptr;
}

UniValue blockToJSON(const CBlock& block, const CBlockIndex* blockindex, bool txDetails = false)
{
    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hash", block.GetHash(blockindex->nHeight >= Params().SwitchPhi2Block()).GetHex()));
    int confirmations = -1;
    // Only report confirmations if the block is on the main chain
    if (chainActive.Contains(blockindex))
        confirmations = chainActive.Height() - blockindex->nHeight + 1;
    result.push_back(Pair("confirmations", confirmations));
    result.push_back(Pair("strippedsize", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS)));
    result.push_back(Pair("size", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION)));
    result.push_back(Pair("height", blockindex->nHeight));
    result.push_back(Pair("version", block.nVersion));
    result.push_back(Pair("merkleroot", block.hashMerkleRoot.GetHex()));
    result.push_back(Pair("stateroot", block.hashStateRoot.GetHex()));
    result.push_back(Pair("utxoroot", block.hashUTXORoot.GetHex()));
    UniValue txs(UniValue::VARR);
    for (const CTransactionRef& tx : block.vtx) {
        if (txDetails) {
            UniValue objTx(UniValue::VOBJ);
            TxToJSON(*tx, uint256(), objTx);
            txs.push_back(objTx);
        } else
            txs.push_back(tx->GetHash().GetHex());
    }
    result.push_back(Pair("tx", txs));
    result.push_back(Pair("time", block.GetBlockTime()));
    result.push_back(Pair("nonce", (uint64_t)block.nNonce));
    result.push_back(Pair("bits", strprintf("%08x", block.nBits)));
    result.push_back(Pair("difficulty", GetDifficulty(blockindex)));
    result.push_back(Pair("flags", strprintf("%s%s", blockindex->IsProofOfStake()?"proof-of-stake":"proof-of-work",
            blockindex->IsProofOfStake() && blockindex->GeneratedStakeModifier()?" stake-modifier":"")));
    result.push_back(Pair("chainwork", blockindex->nChainWork.GetHex()));

    if (blockindex->pprev)
        result.push_back(Pair("previousblockhash", blockindex->pprev->GetBlockHash().GetHex()));
    CBlockIndex* pnext = chainActive.Next(blockindex);
    if (pnext)
        result.push_back(Pair("nextblockhash", pnext->GetBlockHash().GetHex()));
    return result;
}


UniValue blockheaderToJSON(const CBlock& block, const CBlockIndex* blockindex)
{
    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("version", block.nVersion));
    if (blockindex->pprev)
        result.push_back(Pair("previousblockhash", blockindex->pprev->GetBlockHash().GetHex()));
    result.push_back(Pair("merkleroot", block.hashMerkleRoot.GetHex()));
    result.push_back(Pair("time", block.GetBlockTime()));
    result.push_back(Pair("bits", strprintf("%08x", block.nBits)));
    result.push_back(Pair("nonce", (uint64_t)block.nNonce));
    return result;
}

UniValue blockheaderToJSON(const CBlockIndex* blockindex)
{
    AssertLockHeld(cs_main);
    UniValue result(UniValue::VOBJ);
    result.pushKV("hash", blockindex->GetBlockHash().GetHex());
    int confirmations = -1;
    // Only report confirmations if the block is on the main chain
    if (chainActive.Contains(blockindex))
        confirmations = chainActive.Height() - blockindex->nHeight + 1;
    result.pushKV("confirmations", confirmations);
    result.pushKV("height", blockindex->nHeight);
    result.pushKV("version", blockindex->nVersion);
    result.pushKV("versionHex", strprintf("%08x", blockindex->nVersion));
    result.pushKV("merkleroot", blockindex->hashMerkleRoot.GetHex());
    result.pushKV("time", (int64_t)blockindex->nTime);
    result.pushKV("mediantime", (int64_t)blockindex->GetMedianTimePast());
    result.pushKV("nonce", (uint64_t)blockindex->nNonce);
    result.pushKV("bits", strprintf("%08x", blockindex->nBits));
    result.pushKV("difficulty", GetDifficulty(blockindex));
    result.pushKV("chainwork", blockindex->nChainWork.GetHex());
    result.pushKV("nTx", (uint64_t)blockindex->nTx);

    if (blockindex->pprev)
        result.pushKV("previousblockhash", blockindex->pprev->GetBlockHash().GetHex());
    CBlockIndex *pnext = chainActive.Next(blockindex);
    if (pnext)
        result.pushKV("nextblockhash", pnext->GetBlockHash().GetHex());
    return result;
}

UniValue blockToDeltasJSON(const CBlock& block, const CBlockIndex* blockindex)
{
    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hash", block.GetHash().GetHex()));
    int confirmations = -1;
    // Only report confirmations if the block is on the main chain
    if (chainActive.Contains(blockindex)) {
        confirmations = chainActive.Height() - blockindex->nHeight + 1;
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block is an orphan");
    }
    result.push_back(Pair("confirmations", confirmations));
    result.push_back(Pair("size", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION)));
    result.push_back(Pair("height", blockindex->nHeight));
    result.push_back(Pair("version", block.nVersion));
    result.push_back(Pair("merkleroot", block.hashMerkleRoot.GetHex()));
    UniValue deltas(UniValue::VARR);
    for (int i = block.vtx.size() - 1; i >= 0; i--) {
        const CTransaction &tx = *(block.vtx[i]);
        const uint256 txhash = tx.GetHash();
        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("txid", txhash.GetHex()));
        entry.push_back(Pair("index", (int)i));
        UniValue inputs(UniValue::VARR);
        if (!tx.IsCoinBase()) {
            for (unsigned int i = 0; i < tx.vin.size(); i++) {
                const CTxIn input = tx.vin[i];
                UniValue delta(UniValue::VOBJ);
                CSpentIndexValue spentInfo;
                CSpentIndexKey spentKey(input.prevout.hash, input.prevout.n);
                if (GetSpentIndex(spentKey, spentInfo)) {
                    if (spentInfo.addressType == 1) {
                        delta.push_back(Pair("address", EncodeDestination(CKeyID(spentInfo.addressHash))));
                    } else if (spentInfo.addressType == 2)  {
                        delta.push_back(Pair("address", EncodeDestination(CScriptID(spentInfo.addressHash))));
                    } else {
                        continue;
                    }
                    delta.push_back(Pair("satoshis", -1 * spentInfo.satoshis));
                    delta.push_back(Pair("index", (int)i));
                    delta.push_back(Pair("prevtxid", input.prevout.hash.GetHex()));
                    delta.push_back(Pair("prevout", (int)input.prevout.n));
                    inputs.push_back(delta);
                } else {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Spent information not available");
                }
            }
        }
        entry.push_back(Pair("inputs", inputs));
        UniValue outputs(UniValue::VARR);
        for (unsigned int k = 0; k < tx.vout.size(); k++) {
            const CTxOut &out = tx.vout[k];
            UniValue delta(UniValue::VOBJ);
            if (out.scriptPubKey.IsPayToScriptHash()) {
                vector<unsigned char> hashBytes(out.scriptPubKey.begin()+2, out.scriptPubKey.begin()+22);
                delta.push_back(Pair("address", EncodeDestination (CScriptID(uint160(hashBytes)))));
            } else if (out.scriptPubKey.IsPayToPubkeyHash()) {
                vector<unsigned char> hashBytes(out.scriptPubKey.begin()+3, out.scriptPubKey.begin()+23);
                delta.push_back(Pair("address", EncodeDestination (CKeyID(uint160(hashBytes)))));
            } else {
                continue;
            }
            delta.push_back(Pair("satoshis", out.nValue));
            delta.push_back(Pair("index", (int)k));
            outputs.push_back(delta);
        }
        entry.push_back(Pair("outputs", outputs));
        deltas.push_back(entry);
    }
    result.push_back(Pair("deltas", deltas));
    result.push_back(Pair("time", block.GetBlockTime()));
    result.push_back(Pair("mediantime", (int64_t)blockindex->GetMedianTimePast()));
    result.push_back(Pair("nonce", (uint64_t)block.nNonce));
    result.push_back(Pair("bits", strprintf("%08x", block.nBits)));
    result.push_back(Pair("difficulty", GetDifficulty(blockindex)));
    result.push_back(Pair("chainwork", blockindex->nChainWork.GetHex()));
    if (blockindex->pprev)
        result.push_back(Pair("previousblockhash", blockindex->pprev->GetBlockHash().GetHex()));
    CBlockIndex *pnext = chainActive.Next(blockindex);
    if (pnext)
        result.push_back(Pair("nextblockhash", pnext->GetBlockHash().GetHex()));
    return result;
}

UniValue getblockcount(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
            "getblockcount\n"
            "\nReturns the number of blocks in the longest block chain.\n"
            "\nResult:\n"
            "n    (numeric) The current block count\n"
            "\nExamples:\n" +
            HelpExampleCli("getblockcount", "") + HelpExampleRpc("getblockcount", ""));

    LOCK(cs_main);
    return chainActive.Height();
}

UniValue getbestblockhash(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
            "getbestblockhash\n"
            "\nReturns the hash of the best (tip) block in the longest block chain.\n"
            "\nResult\n"
            "\"hex\"      (string) the block hash hex encoded\n"
            "\nExamples\n" +
            HelpExampleCli("getbestblockhash", "") + HelpExampleRpc("getbestblockhash", ""));

    LOCK(cs_main);
    return chainActive.Tip()->GetBlockHash().GetHex();
}

void RPCNotifyBlockChange(bool ibd, const CBlockIndex * pindex)
{
    if(pindex) {
        std::lock_guard<std::mutex> lock(cs_blockchange);
        latestblock.hash = pindex->GetBlockHash();
        latestblock.height = pindex->nHeight;
    }
    cond_blockchange.notify_all();
}

UniValue waitfornewblock(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "waitfornewblock (timeout)\n"
            "\nWaits for a specific new block and returns useful info about it.\n"
            "\nReturns the current block on timeout or exit.\n"
            "\nArguments:\n"
            "1. timeout (int, optional, default=0) Time in milliseconds to wait for a response. 0 indicates no timeout.\n"
            "\nResult:\n"
            "{                           (json object)\n"
            "  \"hash\" : {       (string) The blockhash\n"
            "  \"height\" : {     (int) Block height\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("waitfornewblock", "1000")
            + HelpExampleRpc("waitfornewblock", "1000")
        );
    int timeout = 0;
    if (!request.params[0].isNull())
        timeout = request.params[0].get_int();

    CUpdatedBlock block;
    {
        std::unique_lock<std::mutex> lock(cs_blockchange);
        block = latestblock;
        if(timeout)
            cond_blockchange.wait_for(lock, std::chrono::milliseconds(timeout), [&block]{return latestblock.height != block.height || latestblock.hash != block.hash || !IsRPCRunning(); });
        else
            cond_blockchange.wait(lock, [&block]{return latestblock.height != block.height || latestblock.hash != block.hash || !IsRPCRunning(); });
        block = latestblock;
    }
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("hash", block.hash.GetHex()));
    ret.push_back(Pair("height", block.height));
    return ret;
}

UniValue waitforblock(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "waitforblock <blockhash> (timeout)\n"
            "\nWaits for a specific new block and returns useful info about it.\n"
            "\nReturns the current block on timeout or exit.\n"
            "\nArguments:\n"
            "1. \"blockhash\" (required, string) Block hash to wait for.\n"
            "2. timeout       (int, optional, default=0) Time in milliseconds to wait for a response. 0 indicates no timeout.\n"
            "\nResult:\n"
            "{                           (json object)\n"
            "  \"hash\" : {       (string) The blockhash\n"
            "  \"height\" : {     (int) Block height\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("waitforblock", "\"0000000000079f8ef3d2c688c244eb7a4570b24c9ed7b4a8c619eb02596f8862\", 1000")
            + HelpExampleRpc("waitforblock", "\"0000000000079f8ef3d2c688c244eb7a4570b24c9ed7b4a8c619eb02596f8862\", 1000")
        );
    int timeout = 0;

    uint256 hash = uint256S(request.params[0].get_str());

    if (!request.params[1].isNull())
        timeout = request.params[1].get_int();

    CUpdatedBlock block;
    {
        std::unique_lock<std::mutex> lock(cs_blockchange);
        if(timeout)
            cond_blockchange.wait_for(lock, std::chrono::milliseconds(timeout), [&hash]{return latestblock.hash == hash || !IsRPCRunning();});
        else
            cond_blockchange.wait(lock, [&hash]{return latestblock.hash == hash || !IsRPCRunning(); });
        block = latestblock;
    }

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("hash", block.hash.GetHex()));
    ret.push_back(Pair("height", block.height));
    return ret;
}

UniValue waitforblockheight(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "waitforblockheight <height> (timeout)\n"
            "\nWaits for (at least) block height and returns the height and hash\n"
            "of the current tip.\n"
            "\nReturns the current block on timeout or exit.\n"
            "\nArguments:\n"
            "1. height  (required, int) Block height to wait for (int)\n"
            "2. timeout (int, optional, default=0) Time in milliseconds to wait for a response. 0 indicates no timeout.\n"
            "\nResult:\n"
            "{                           (json object)\n"
            "  \"hash\" : {       (string) The blockhash\n"
            "  \"height\" : {     (int) Block height\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("waitforblockheight", "\"100\", 1000")
            + HelpExampleRpc("waitforblockheight", "\"100\", 1000")
        );
    int timeout = 0;

    int height = request.params[0].get_int();

    if (!request.params[1].isNull())
        timeout = request.params[1].get_int();

    CUpdatedBlock block;
    {
        std::unique_lock<std::mutex> lock(cs_blockchange);
        if(timeout)
            cond_blockchange.wait_for(lock, std::chrono::milliseconds(timeout), [&height]{return latestblock.height >= height || !IsRPCRunning();});
        else
            cond_blockchange.wait(lock, [&height]{return latestblock.height >= height || !IsRPCRunning(); });
        block = latestblock;
    }
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("hash", block.hash.GetHex()));
    ret.push_back(Pair("height", block.height));
    return ret;
}

UniValue getdifficulty(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
            "getdifficulty\n"
            "\nReturns the proof-of-work difficulty as a multiple of the minimum difficulty.\n"
            "\nResult:\n"
            "n.nnn       (numeric) the proof-of-work difficulty as a multiple of the minimum difficulty.\n"
            "\nExamples:\n" +
            HelpExampleCli("getdifficulty", "") + HelpExampleRpc("getdifficulty", ""));

    LOCK(cs_main);

    CBlockIndex* powTip = GetLastBlockOfType(0);
    return GetDifficulty(powTip);
}

UniValue getrawmempool(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1)
        throw runtime_error(
            "getrawmempool ( verbose )\n"
            "\nReturns all transaction ids in memory pool as a json array of string transaction ids.\n"
            "\nArguments:\n"
            "1. verbose           (boolean, optional, default=false) true for a json object, false for array of transaction ids\n"
            "\nResult: (for verbose = false):\n"
            "[                     (json array of string)\n"
            "  \"transactionid\"     (string) The transaction id\n"
            "  ,...\n"
            "]\n"
            "\nResult: (for verbose = true):\n"
            "{                           (json object)\n"
            "  \"transactionid\" : {       (json object)\n"
            "    \"size\" : n,             (numeric) transaction size in bytes\n"
            "    \"fee\" : n,              (numeric) transaction fee in lux\n"
            "    \"time\" : n,             (numeric) local time transaction entered pool in seconds since 1 Jan 1970 GMT\n"
            "    \"height\" : n,           (numeric) block height when transaction entered pool\n"
            "    \"startingpriority\" : n, (numeric) priority when transaction entered pool\n"
            "    \"currentpriority\" : n,  (numeric) transaction priority now\n"
            "    \"depends\" : [           (array) unconfirmed transactions used as inputs for this transaction\n"
            "        \"transactionid\",    (string) parent transaction id\n"
            "       ... ]\n"
            "  }, ...\n"
            "]\n"
            "\nExamples\n" +
            HelpExampleCli("getrawmempool", "true") + HelpExampleRpc("getrawmempool", "true"));

    LOCK(cs_main);

    bool fVerbose = false;
    if (request.params.size() > 0)
        fVerbose = request.params[0].get_bool();

    if (fVerbose) {
        LOCK(mempool.cs);
        UniValue o(UniValue::VOBJ);
        for (const CTxMemPoolEntry& e : mempool.mapTx) {
            const uint256& hash = e.GetTx().GetHash();
            UniValue info(UniValue::VOBJ);
            info.push_back(Pair("size", (int)e.GetTxSize()));
            info.push_back(Pair("fee", ValueFromAmount(e.GetFee())));
            info.push_back(Pair("time", e.GetTime()));
            info.push_back(Pair("height", (int)e.GetHeight()));
            info.push_back(Pair("startingpriority", e.GetPriority(e.GetHeight())));
            info.push_back(Pair("currentpriority", e.GetPriority(chainActive.Height())));
            const CTransaction& tx = e.GetTx();
            set<string> setDepends;
            for (const CTxIn& txin : tx.vin) {
                if (mempool.exists(txin.prevout.hash))
                    setDepends.insert(txin.prevout.hash.ToString());
            }
            UniValue depends(UniValue::VARR);

            for (const std::string& dep : setDepends)
            {
                  depends.push_back(dep);
            }

            info.push_back(Pair("depends", depends));
            o.push_back(Pair(hash.ToString(), info));
        }
        return o;
    } else {
        vector<uint256> vtxid;
        mempool.queryHashes(vtxid);

        UniValue a(UniValue::VARR);
        for (const uint256& hash : vtxid)
            a.push_back(hash.ToString());

        return a;
    }
}

UniValue getblockdeltas(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error("");
    std::string strHash = request.params[0].get_str();
    uint256 hash(uint256S(strHash));
    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hash];
    if (fHavePruned && !(pblockindex->nStatus & BLOCK_HAVE_DATA) && pblockindex->nTx > 0)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Block not available (pruned data)");
    if(!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus()))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");
    return blockToDeltasJSON(block, pblockindex);
}

UniValue getmempoolancestors(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2) {
        throw runtime_error(
                "getmempoolancestors txid (verbose)\n"
                "\nIf txid is in the mempool, returns all in-mempool ancestors.\n"
                "\nArguments:\n"
                "1. \"txid\"                 (string, required) The transaction id (must be in mempool)\n"
                "2. verbose                  (boolean, optional, default=false) True for a json object, false for array of transaction ids\n"
                "\nResult (for verbose=false):\n"
                "[                       (json array of strings)\n"
                "  \"transactionid\"           (string) The transaction id of an in-mempool ancestor transaction\n"
                "  ,...\n"
                "]\n"
                "\nResult (for verbose=true):\n"
                "{                           (json object)\n"
                "  \"transactionid\" : {       (json object)\n"

                "  }, ...\n"
                "}\n"
                "\nExamples:\n"
                + HelpExampleCli("getmempoolancestors", "\"mytxid\"")
        );
    }

    bool fVerbose = false;
    if (request.params.size() > 1)
        fVerbose = request.params[1].get_bool();

    uint256 hash = ParseHashV(request.params[0], "parameter 1");

    LOCK(mempool.cs);

    CTxMemPool::txiter it = mempool.mapTx.find(hash);
    if (it == mempool.mapTx.end()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not in mempool");
    }

    CTxMemPool::setEntries setAncestors;
    uint64_t noLimit = std::numeric_limits<uint64_t>::max();
    std::string dummy;
    mempool.CalculateMemPoolAncestors(*it, setAncestors, noLimit, noLimit, noLimit, noLimit, dummy, false);

    if (!fVerbose) {
        UniValue o(UniValue::VARR);
        for (CTxMemPool::txiter ancestorIt : setAncestors) {
            o.push_back(ancestorIt->GetTx().GetHash().ToString());
        }

        return o;
    } else {
        UniValue o(UniValue::VOBJ);
        for (CTxMemPool::txiter ancestorIt : setAncestors) {
            const CTxMemPoolEntry &e = *ancestorIt;
            const uint256& _hash = e.GetTx().GetHash();
            UniValue info(UniValue::VOBJ);
           // entryToJSON(info, e);
            o.push_back(Pair(_hash.ToString(), info));
        }
        return o;
    }
}

UniValue getmempooldescendants(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2) {
        throw runtime_error(
                "getmempooldescendants txid (verbose)\n"
                "\nIf txid is in the mempool, returns all in-mempool descendants.\n"
                "\nArguments:\n"
                "1. \"txid\"                 (string, required) The transaction id (must be in mempool)\n"
                "2. verbose                  (boolean, optional, default=false) True for a json object, false for array of transaction ids\n"
                "\nResult (for verbose=false):\n"
                "[                       (json array of strings)\n"
                "  \"transactionid\"           (string) The transaction id of an in-mempool descendant transaction\n"
                "  ,...\n"
                "]\n"
                "\nResult (for verbose=true):\n"
                "{                           (json object)\n"
                "  \"transactionid\" : {       (json object)\n"
                "  }, ...\n"
                "}\n"
                "\nExamples:\n"
                + HelpExampleCli("getmempooldescendants", "\"mytxid\"")
        );
    }

    bool fVerbose = false;
    if (request.params.size() > 1)
        fVerbose = request.params[1].get_bool();

    uint256 hash = ParseHashV(request.params[0], "parameter 1");

    LOCK(mempool.cs);

    CTxMemPool::txiter it = mempool.mapTx.find(hash);
    if (it == mempool.mapTx.end()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not in mempool");
    }

    CTxMemPool::setEntries setDescendants;
    mempool.CalculateDescendants(it, setDescendants);
    // CTxMemPool::CalculateDescendants will include the given tx
    setDescendants.erase(it);

    if (!fVerbose) {
        UniValue o(UniValue::VARR);
        for (CTxMemPool::txiter descendantIt : setDescendants) {
            o.push_back(descendantIt->GetTx().GetHash().ToString());
        }

        return o;
    } else {
        UniValue o(UniValue::VOBJ);
       for (CTxMemPool::txiter descendantIt : setDescendants) {
            const CTxMemPoolEntry &e = *descendantIt;
            const uint256& _hash = e.GetTx().GetHash();
            UniValue info(UniValue::VOBJ);
           // entryToJSON(info, e);
            o.push_back(Pair(_hash.ToString(), info));
        }
        return o;
    }
}

UniValue getmempoolentry(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1) {
        throw runtime_error(
                "getmempoolentry txid\n"
                "\nReturns mempool data for given transaction\n"
                "\nArguments:\n"
                "1. \"txid\"                   (string, required) The transaction id (must be in mempool)\n"
                "\nResult:\n"
                "{                           (json object)\n"
                "}\n"
                "\nExamples:\n"
                + HelpExampleCli("getmempoolentry", "\"mytxid\"")
        );
    }

    uint256 hash = ParseHashV(request.params[0], "parameter 1");

    LOCK(mempool.cs);

    CTxMemPool::txiter it = mempool.mapTx.find(hash);
    if (it == mempool.mapTx.end()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not in mempool");
    }
#if 0
    const CTxMemPoolEntry &e = *it;
#endif
    UniValue info(UniValue::VOBJ);
    //entryToJSON(info, e);
    return info;
}

void entryToJSON(UniValue &info, const CTxMemPoolEntry &e)
{
    AssertLockHeld(mempool.cs);

    info.push_back(Pair("size", (int)e.GetTxSize()));
    info.push_back(Pair("fee", ValueFromAmount(e.GetFee())));
    info.push_back(Pair("modifiedfee", ValueFromAmount(e.GetModifiedFee())));
    info.push_back(Pair("time", e.GetTime()));
    info.push_back(Pair("height", (int)e.GetHeight()));
    info.push_back(Pair("startingpriority", e.GetPriority(e.GetHeight())));
    info.push_back(Pair("currentpriority", e.GetPriority(chainActive.Height())));
    info.push_back(Pair("descendantcount", e.GetCountWithDescendants()));
    info.push_back(Pair("descendantsize", e.GetSizeWithDescendants()));
    info.push_back(Pair("descendantfees", e.GetModFeesWithDescendants()));
    info.push_back(Pair("ancestorcount", e.GetCountWithAncestors()));
    info.push_back(Pair("ancestorsize", e.GetSizeWithAncestors()));
    info.push_back(Pair("ancestorfees", e.GetModFeesWithAncestors()));
    const CTransaction& tx = e.GetTx();
    set<string> setDepends;
    for (const CTxIn& txin : tx.vin) {
        if (mempool.exists(txin.prevout.hash))
            setDepends.insert(txin.prevout.hash.ToString());
    }

    UniValue depends(UniValue::VARR);
    for (const string& dep : setDepends) {
        depends.push_back(dep);
    }

    info.push_back(Pair("depends", depends));
}

UniValue mempoolToJSON(bool fVerbose)
{
    if (fVerbose)
    {
        LOCK(mempool.cs);
        UniValue o(UniValue::VOBJ);
        for (const CTxMemPoolEntry& e : mempool.mapTx)
        {
            const uint256& hash = e.GetTx().GetHash();
            UniValue info(UniValue::VOBJ);
           // entryToJSON(info, e);
            o.push_back(Pair(hash.ToString(), info));
        }
        return o;
    }
    else
    {
        std::vector<uint256> vtxid;
        mempool.queryHashes(vtxid);

        UniValue a(UniValue::VARR);
        for (const uint256& hash : vtxid)
            a.push_back(hash.ToString());

        return a;
    }
}

UniValue getblockhashes(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2)
        throw runtime_error(
                "getblockhashes timestamp\n"
                        "\nReturns array of hashes of blocks within the timestamp range provided.\n"
                        "\nArguments:\n"
                        "1. high         (numeric, required) The newer block timestamp\n"
                        "2. low          (numeric, required) The older block timestamp\n"
                        "3. options      (string, required) A json object\n"
                        "    {\n"
                        "      \"noOrphans\":true   (boolean) will only include blocks on the main chain\n"
                        "      \"logicalTimes\":true   (boolean) will include logical timestamps with hashes\n"
                        "    }\n"
                        "\nResult:\n"
                        "[\n"
                        "  \"hash\"         (string) The block hash\n"
                        "]\n"
                        "[\n"
                        "  {\n"
                        "    \"blockhash\": (string) The block hash\n"
                        "    \"logicalts\": (numeric) The logical timestamp\n"
                        "  }\n"
                        "]\n"
                        "\nExamples:\n"
                + HelpExampleCli("getblockhashes", "1522073246 1521473246")
                + HelpExampleRpc("getblockhashes", "1522073246, 1521473246")
                + HelpExampleCli("getblockhashes", "1522073246 1521473246 '{\"noOrphans\":false, \"logicalTimes\":true}'")
        );

    LOCK(cs_main);

    unsigned int high = request.params[0].get_int();
    unsigned int low = request.params[1].get_int();
    UniValue a(UniValue::VARR);
    int nHeight = chainActive.Height();

    for (int i = 0; i <= nHeight; i++) {
        unsigned int blockTime = getBlockTimeByHeight(i);
        if (blockTime > low && blockTime < high) {
            CBlockIndex* pblockindex =chainActive[i];
            a.push_back(pblockindex->GetBlockHash().GetHex());
        }
    }
    return a;
}

int getBlockTimeByHeight(int nHeight){
    CBlock block;
    CBlockIndex* pblockindex =chainActive[nHeight];
    std::string strHash = pblockindex->GetBlockHash().GetHex();
    uint256 hash(strHash);
    CBlockIndex* pblockindex2 = mapBlockIndex[hash];
        return pblockindex2->GetBlockTime();
    }

UniValue getblockhash(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "getblockhash index\n"
            "\nReturns hash of block in best-block-chain at index provided.\n"
            "\nArguments:\n"
            "1. index         (numeric, required) The block index\n"
            "\nResult:\n"
            "\"hash\"         (string) The block hash\n"
            "\nExamples:\n" +
            HelpExampleCli("getblockhash", "1000") + HelpExampleRpc("getblockhash", "1000"));

    LOCK(cs_main);

    int nHeight = request.params[0].get_int();
    if (nHeight < 0 || nHeight > chainActive.Height())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");

    CBlockIndex* pblockindex = chainActive[nHeight];
    return pblockindex->GetBlockHash().GetHex();
}

UniValue getblock(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw runtime_error(
            "getblock \"hash\" ( verbose )\n"
            "\nIf verbose is false, returns a string that is serialized, hex-encoded data for block 'hash'.\n"
            "If verbose is true, returns an Object with information about block <hash>.\n"
            "\nArguments:\n"
            "1. \"hash\"          (string, required) The block hash\n"
            "2. verbose           (boolean, optional, default=true) true for a json object, false for the hex encoded data\n"
            "\nResult (for verbose = true):\n"
            "{\n"
            "  \"hash\" : \"hash\",     (string) the block hash (same as provided)\n"
            "  \"confirmations\" : n,   (numeric) The number of confirmations, or -1 if the block is not on the main chain\n"
            "  \"size\" : n,            (numeric) The block size\n"
            "  \"height\" : n,          (numeric) The block height or index\n"
            "  \"version\" : n,         (numeric) The block version\n"
            "  \"merkleroot\" : \"xxxx\", (string) The merkle root\n"
            "  \"tx\" : [               (array of string) The transaction ids\n"
            "     \"transactionid\"     (string) The transaction id\n"
            "     ,...\n"
            "  ],\n"
            "  \"time\" : ttt,          (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"nonce\" : n,           (numeric) The nonce\n"
            "  \"bits\" : \"1d00ffff\", (string) The bits\n"
            "  \"difficulty\" : x.xxx,  (numeric) The difficulty\n"
            "  \"previousblockhash\" : \"hash\",  (string) The hash of the previous block\n"
            "  \"nextblockhash\" : \"hash\"       (string) The hash of the next block\n"
            "}\n"
            "\nResult (for verbose=false):\n"
            "\"data\"             (string) A string that is serialized, hex-encoded data for block 'hash'.\n"
            "\nExamples:\n" +
            HelpExampleCli("getblock", "\"00000000000fd08c2fb661d2fcb0d49abb3a91e5f27082ce64feed3b4dede2e2\"") + HelpExampleRpc("getblock", "\"00000000000fd08c2fb661d2fcb0d49abb3a91e5f27082ce64feed3b4dede2e2\""));

    LOCK(cs_main);

    std::string strHash = request.params[0].get_str();
    uint256 hash(strHash);

    bool fVerbose = true;
    if (request.params.size() > 1)
        fVerbose = request.params[1].get_bool();

    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hash];

    if (!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus()))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");

    if (!fVerbose) {
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
        ssBlock << block;
        std::string strHex = HexStr(ssBlock.begin(), ssBlock.end());
        return strHex;
    }

    return blockToJSON(block, pblockindex);
}

//////////////////////////////////////////////////////////////////////////// // lux
UniValue executionResultToJSON(const dev::eth::ExecutionResult& exRes)
{
    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("gasUsed", CAmount(exRes.gasUsed)));
    std::stringstream ss;
    ss << exRes.excepted;
    result.push_back(Pair("excepted", ss.str()));
    result.push_back(Pair("newAddress", exRes.newAddress.hex()));
    result.push_back(Pair("output", HexStr(exRes.output)));
    result.push_back(Pair("codeDeposit", static_cast<int32_t>(exRes.codeDeposit)));
    result.push_back(Pair("gasRefunded", CAmount(exRes.gasRefunded)));
    result.push_back(Pair("depositSize", static_cast<int32_t>(exRes.depositSize)));
    result.push_back(Pair("gasForDeposit", CAmount(exRes.gasForDeposit)));
    return result;
}

UniValue transactionReceiptToJSON(const dev::eth::TransactionReceipt& txRec)
{
    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("stateRoot", txRec.stateRoot().hex()));
    result.push_back(Pair("gasUsed", CAmount(txRec.gasUsed())));
    result.push_back(Pair("bloom", txRec.bloom().hex()));
    UniValue logEntries(UniValue::VARR);
    dev::eth::LogEntries logs = txRec.log();
    for(dev::eth::LogEntry log : logs){
        UniValue logEntrie(UniValue::VOBJ);
        logEntrie.push_back(Pair("address", log.address.hex()));
        UniValue topics(UniValue::VARR);
        for(dev::h256 l : log.topics){
            topics.push_back(l.hex());
        }
        logEntrie.push_back(Pair("topics", topics));
        logEntrie.push_back(Pair("data", HexStr(log.data)));
        logEntries.push_back(logEntrie);
    }
    result.push_back(Pair("log", logEntries));
    return result;
}

void assignJSON(UniValue& entry, const TransactionReceiptInfo& resExec) {
    entry.push_back(Pair("blockHash", resExec.blockHash.GetHex()));
    entry.push_back(Pair("blockNumber", uint64_t(resExec.blockNumber)));
    entry.push_back(Pair("transactionHash", resExec.transactionHash.GetHex()));
    entry.push_back(
            Pair("transactionIndex", uint64_t(resExec.transactionIndex)));
    entry.push_back(Pair("from", resExec.from.hex()));
    entry.push_back(Pair("to", resExec.to.hex()));
    entry.push_back(
            Pair("cumulativeGasUsed", CAmount(resExec.cumulativeGasUsed)));
    entry.push_back(Pair("gasUsed", CAmount(resExec.gasUsed)));
    entry.push_back(Pair("contractAddress", resExec.contractAddress.hex()));
    std::stringstream ss;
    ss << resExec.excepted;
    entry.push_back(Pair("excepted",ss.str()));
}

void assignJSON(UniValue& logEntry, const dev::eth::LogEntry& log,
                bool includeAddress) {
    if (includeAddress) {
        logEntry.push_back(Pair("address", log.address.hex()));
    }

    UniValue topics(UniValue::VARR);
    for (dev::h256 hash : log.topics) {
        topics.push_back(hash.hex());
    }
    logEntry.push_back(Pair("topics", topics));
    logEntry.push_back(Pair("data", HexStr(log.data)));
}

void transactionReceiptInfoToJSON(const TransactionReceiptInfo& resExec, UniValue& entry) {
    assignJSON(entry, resExec);

    const auto& logs = resExec.logs;
    UniValue logEntries(UniValue::VARR);
    for(const auto&log : logs){
        UniValue logEntry(UniValue::VOBJ);
        assignJSON(logEntry, log, true);
        logEntries.push_back(logEntry);
    }
    entry.push_back(Pair("log", logEntries));
}

size_t parseUInt(const UniValue& val, size_t defaultVal) {
    if (val.isNull()) {
        return defaultVal;
    } else {
        int n = val.get_int();
        if (n < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Expects unsigned integer");
        }

        return n;
    }
}

int parseBlockHeight(const UniValue& val) {
    if (val.isStr()) {
        auto blockKey = val.get_str();

        if (blockKey == "latest") {
            return latestblock.height;
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMS, "invalid block number");
        }
    }

    if (val.isNum()) {
        int blockHeight = val.get_int();

        if (blockHeight < 0) {
            return latestblock.height;
        }

        return blockHeight;
    }

    throw JSONRPCError(RPC_INVALID_PARAMS, "invalid block number");
}

int parseBlockHeight(const UniValue& val, int defaultVal) {
    if (val.isNull()) {
        return defaultVal;
    } else {
        return parseBlockHeight(val);
    }
}

dev::h160 parseParamH160(const UniValue& val) {
    if (!val.isStr()) {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid hex 160");
    }

    auto addrStr = val.get_str();

    if (addrStr.length() != 40 || !CheckHex(addrStr)) {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid hex 160 string");
    }
    return dev::h160(addrStr);
}

void parseParam(const UniValue& val, std::vector<dev::h160> &h160s) {
    if (val.isNull()) {
        return;
    }

    // Treat a string as an array of length 1
    if (val.isStr()) {
        h160s.push_back(parseParamH160(val.get_str()));
        return;
    }

    if (!val.isArray()) {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Expect an array of hex 160 strings");
    }

    auto vals = val.getValues();
    h160s.resize(vals.size());

    std::transform(vals.begin(), vals.end(), h160s.begin(), [](UniValue val) -> dev::h160 {
        return parseParamH160(val);
    });
}

void parseParam(const UniValue& val, std::set<dev::h160> &h160s) {
    std::vector<dev::h160> v;
    parseParam(val, v);
    h160s.insert(v.begin(), v.end());
}

void parseParam(const UniValue& val, std::vector<boost::optional<dev::h256>> &h256s) {
    if (val.isNull()) {
        return;
    }

    if (!val.isArray()) {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Expect an array of hex 256 strings");
    }

    auto vals = val.getValues();
    h256s.resize(vals.size());

    std::transform(vals.begin(), vals.end(), h256s.begin(), [](UniValue val) -> boost::optional<dev::h256> {
        if (val.isNull()) {
            return boost::optional<dev::h256>();
        }

        if (!val.isStr()) {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid hex 256 string");
        }

        auto addrStr = val.get_str();

        if (addrStr.length() != 64 || !CheckHex(addrStr)) {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid hex 256 string");
        }

        return boost::optional<dev::h256>(dev::h256(addrStr));
    });
}

class WaitForLogsParams {
public:
    int fromBlock;
    int toBlock;

    int minconf;

    std::set<dev::h160> addresses;
    std::vector<boost::optional<dev::h256>> topics;

    // bool wait;

    WaitForLogsParams(const UniValue& params) {
        std::unique_lock<std::mutex> lock(cs_blockchange);

        fromBlock = parseBlockHeight(params[0], latestblock.height + 1);
        toBlock = parseBlockHeight(params[1], -1);

        parseFilter(params[2]);
        minconf = parseUInt(params[3], 6);
    }

private:
    void parseFilter(const UniValue& val) {
        if (val.isNull()) {
            return;
        }

        parseParam(val["addresses"], addresses);
        parseParam(val["topics"], topics);
    }
};

UniValue waitforlogs(const JSONRPCRequest& request_) {
    JSONRPCRequest& request = (JSONRPCRequest&) request_;
    if (request.fHelp) {
        throw runtime_error(
                "waitforlogs (fromBlock) (toBlock) (filter) (minconf)\n"
                "requires -logevents to be enabled\n"
                "\nWaits for a new logs and return matching log entries. When the call returns, it also specifies the next block number to start waiting for new logs.\n"
                "By calling waitforlogs repeatedly using the returned `nextBlock` number, a client can receive a stream of up-to-date log entires.\n"
                "\nThis call is different from the similarly named `waitforlogs`. This call returns individual matching log entries, `searchlogs` returns a transaction receipt if one of the log entries of that transaction matches the filter conditions.\n"
                "\nArguments:\n"
                "1. fromBlock (int | \"latest\", optional, default=null) The block number to start looking for logs. ()\n"
                "2. toBlock   (int | \"latest\", optional, default=null) The block number to stop looking for logs. If null, will wait indefinitely into the future.\n"
                "3. filter    ({ addresses?: Hex160String[], topics?: Hex256String[] }, optional default={}) Filter conditions for logs. Addresses and topics are specified as array of hexadecimal strings\n"
                "4. minconf   (uint, optional, default=6) Minimal number of confirmations before a log is returned\n"
                "\nResult:\n"
                "An object with the following properties:\n"
                "1. logs (LogEntry[]) Array of matchiing log entries. This may be empty if `filter` removed all entries."
                "2. count (int) How many log entries are returned."
                "3. nextBlock (int) To wait for new log entries haven't seen before, use this number as `fromBlock`"
                "\nUsage:\n"
                "`waitforlogs` waits for new logs, starting from the tip of the chain.\n"
                "`waitforlogs 600` waits for new logs, but starting from block 600. If there are logs available, this call will return immediately.\n"
                "`waitforlogs 600 700` waits for new logs, but only up to 700th block\n"
                "`waitforlogs null null` this is equivalent to `waitforlogs`, using default parameter values\n"
                "`waitforlogs null null` { \"addresses\": [ \"ff0011...\" ], \"topics\": [ \"c0fefe\"] }` waits for logs in the future matching the specified conditions\n"
                "\nSample Output:\n"
                "{\n  \"entries\": [\n    {\n      \"blockHash\": \"56d5f1f5ec239ef9c822d9ed600fe9aa63727071770ac7c0eabfc903bf7316d4\",\n      \"blockNumber\": 3286,\n      \"transactionHash\": \"00aa0f041ce333bc3a855b2cba03c41427cda04f0334d7f6cb0acad62f338ddc\",\n      \"transactionIndex\": 2,\n      \"from\": \"3f6866e2b59121ada1ddfc8edc84a92d9655675f\",\n      \"to\": \"8e1ee0b38b719abe8fa984c986eabb5bb5071b6b\",\n      \"cumulativeGasUsed\": 23709,\n      \"gasUsed\": 23709,\n      \"contractAddress\": \"8e1ee0b38b719abe8fa984c986eabb5bb5071b6b\",\n      \"topics\": [\n        \"f0e1159fa6dc12bb31e0098b7a1270c2bd50e760522991c6f0119160028d9916\",\n        \"0000000000000000000000000000000000000000000000000000000000000002\"\n      ],\n      \"data\": \"00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000003\"\n    }\n  ],\n\n  \"count\": 7,\n  \"nextblock\": 801\n}\n"
        );
    }

    if (!fLogEvents)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Events indexing disabled");

    if(!request.req)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No HTTP connection");

    WaitForLogsParams params(request.params);

    request.PollStart();

    std::vector<std::vector<uint256>> hashesToBlock;

    int curheight = 0;

    auto& addresses = params.addresses;
    auto& filterTopics = params.topics;

    while (curheight == 0) {
        {
            LOCK(cs_main);
            curheight = pblocktree->ReadHeightIndex(params.
                                                    fromBlock,
                                                    params.
                                                    toBlock,
                                                    params.
                                                    minconf,
                                                    hashesToBlock,
                                                    addresses);
        }
        if (curheight > 0) { break; }
        if (curheight == -1) { break; }

        // wait for a new block to arrive
        {
            while (true) {
                std::unique_lock<std::mutex> lock(cs_blockchange);
                auto blockHeight = latestblock.height;

                request.PollPing();

                cond_blockchange.wait_for(lock, std::chrono::milliseconds(1000));
                if (latestblock.height > blockHeight) {
                    break;
                }

                // TODO: maybe just merge `IsRPCRunning` this into PollAlive
                if (!request.PollAlive() || !IsRPCRunning()) {
                    LogPrintf("waitforlogs client disconnected\n");
                    return NullUniValue;
                }
            }
        }
    }

    LOCK(cs_main);
    std::set<uint256> dupes;
    if (pstorageresult == nullptr) { return NullUniValue; }
    UniValue jsonLogs(UniValue::VARR);
    for (const auto& txHashes : hashesToBlock) {
        for (const auto& txHash : txHashes) {
            if(dupes.find(txHash) != dupes.end()) { continue; }
            dupes.insert(txHash);
            std::vector<TransactionReceiptInfo> receipts = pstorageresult->getResult(uintToh256(txHash));
            for (const auto& receipt : receipts) {
                for (const auto& log : receipt.logs) {
                    bool includeLog = true;
                    if (!filterTopics.empty()) {
                        for (size_t i = 0; i < filterTopics.size(); i++) {
                            auto filterTopic = filterTopics[i];
                            if (!filterTopic) { continue; }
                            auto filterTopicContent = filterTopic.get();
                            auto topicContent = log.topics[i];
                            if (topicContent != filterTopicContent) {
                                includeLog = false;
                                break;
                            }
                        }
                    }
                    if (!includeLog) { continue; }
                    UniValue jsonLog(UniValue::VOBJ);
                    assignJSON(jsonLog, receipt);
                    assignJSON(jsonLog, log, false);
                    jsonLogs.push_back(jsonLog);
                }
            }
        }
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("entries", jsonLogs));
    result.push_back(Pair("count", (int) jsonLogs.size()));
    result.push_back(Pair("nextblock", curheight + 1));

    return result;
}

class SearchLogsParams {
public:
    size_t fromBlock;
    size_t toBlock;
    size_t minconf;

    std::set<dev::h160> addresses;
    std::vector<boost::optional<dev::h256>> topics;

    SearchLogsParams(const UniValue& params) {
        std::unique_lock<std::mutex> lock(cs_blockchange);

        setFromBlock(params[0]);
        setToBlock(params[1]);

        parseParam(params[2]["addresses"], addresses);
        parseParam(params[3]["topics"], topics);

        minconf = parseUInt(params[4], 0);
    }

private:
    void setFromBlock(const UniValue& val) {
        if (!val.isNull()) {
            fromBlock = parseBlockHeight(val);
        } else {
            fromBlock = latestblock.height;
        }
    }

    void setToBlock(const UniValue& val) {
        if (!val.isNull()) {
            toBlock = parseBlockHeight(val);
        } else {
            toBlock = latestblock.height;
        }
    }

};

UniValue searchlogs(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2)
        throw std::runtime_error(
                "searchlogs <fromBlock> <toBlock> (address) (topics)\n"
                "requires -logevents to be enabled"
                "\nArgument:\n"
                "1. \"fromBlock\"        (numeric, required) The number of the earliest block (latest may be given to mean the most recent block).\n"
                "2. \"toBlock\"          (string, required) The number of the latest block (-1 may be given to mean the most recent block).\n"
                "3. \"address\"          (string, optional) An address or a list of addresses to only get logs from particular account(s).\n"
                "4. \"topics\"           (string, optional) An array of values from which at least one must appear in the log entries. The order is important, if you want to leave topics out use null, e.g. [\"null\", \"0x00...\"]. \n"
                "5. \"minconf\"          (uint, optional, default=0) Minimal number of confirmations before a log is returned\n"
                "\nExamples:\n"
                + HelpExampleCli("searchlogs", "0 100 '{\"addresses\": [\"12ae42729af478ca92c8c66773a3e32115717be4\"]}' '{\"topics\": [\"null\",\"b436c2bf863ccd7b8f63171201efd4792066b4ce8e543dde9c3e9e9ab98e216c\"]}'")
                + HelpExampleRpc("searchlogs", "0 100 {\"addresses\": [\"12ae42729af478ca92c8c66773a3e32115717be4\"]} {\"topics\": [\"null\",\"b436c2bf863ccd7b8f63171201efd4792066b4ce8e543dde9c3e9e9ab98e216c\"]}")
        );

    if(!fLogEvents)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Events indexing disabled");

    int curheight = 0;

    LOCK(cs_main);
    SearchLogsParams logsParams(request.params);
    std::vector<std::vector<uint256>> hashesToBlock;
    curheight = pblocktree->ReadHeightIndex(logsParams.fromBlock,
                                            logsParams.toBlock,
                                            logsParams.minconf,
                                            hashesToBlock,
                                            logsParams.addresses);

    if (curheight == -1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Incorrect params");
    }

    UniValue result(UniValue::VARR);

    auto topics = logsParams.topics;

    for(const auto& hashesTx : hashesToBlock)
    {
        for(const auto& e : hashesTx)
        {
            std::vector<TransactionReceiptInfo> receipts = pstorageresult->getResult(uintToh256(e));

            for(const auto& receipt : receipts) {
                if(receipt.logs.empty()) {
                    continue;
                }

                if (!topics.empty()) {
                    for (size_t i = 0; i < topics.size(); i++) {
                        const auto& tc = topics[i];

                        if (!tc) {
                            continue;
                        }

                        for (const auto& log: receipt.logs) {
                            auto filterTopicContent = tc.get();

                            if (i >= log.topics.size()) {
                                continue;
                            }

                            if (filterTopicContent == log.topics[i]) {
                                goto push;
                            }
                        }
                    }

                    // Skip the log if none of the topics are matched
                    continue;
                }

                push:

                UniValue tri(UniValue::VOBJ);
                transactionReceiptInfoToJSON(receipt, tri);
                result.push_back(tri);
            }
        }
    }

    return result;
}

UniValue getstorage(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1)
        throw std::runtime_error(
                "getstorage \"address\"\n"
                "\nArgument:\n"
                "1. \"address\"          (string, required) The address to get the storage from\n"
                "2. \"blockNum\"         (string, optional) Number of block to get state from, \"latest\" keyword supported. Latest if not passed.\n"
                "3. \"index\"            (number, optional) Zero-based index position of the storage\n"
        );

    LOCK(cs_main);

    std::string strAddr = request.params[0].get_str();
    if(strAddr.size() != 40 || !CheckHex(strAddr))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Incorrect address");

    TemporaryState ts(globalState);
    if (request.params.size() > 1)
    {
        if (request.params[1].isNum())
        {
            auto blockNum = request.params[1].get_int();
            if((blockNum < 0 && blockNum != -1) || blockNum > chainActive.Height())
                throw JSONRPCError(RPC_INVALID_PARAMS, "Incorrect block number");

            if(blockNum != -1)
                ts.SetRoot(uintToh256(chainActive[blockNum]->hashStateRoot), uintToh256(chainActive[blockNum]->hashUTXORoot));

        } else {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Incorrect block number");
        }
    }

    dev::Address addrAccount(strAddr);
    if(!globalState->addressInUse(addrAccount))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Address does not exist");

    UniValue result(UniValue::VOBJ);

    bool onlyIndex = request.params.size() > 2;
    unsigned index = 0;
    if (onlyIndex)
        index = request.params[2].get_int();

    auto storage(globalState->storage(addrAccount));

    if (onlyIndex)
    {
        if (index >= storage.size())
        {
            std::ostringstream stringStream;
            stringStream << "Storage size: " << storage.size() << " got index: " << index;
            throw JSONRPCError(RPC_INVALID_PARAMS, stringStream.str());
        }
        auto elem = std::next(storage.begin(), index);
        UniValue e(UniValue::VOBJ);

        storage = {{elem->first, {elem->second.first, elem->second.second}}};
    }
    for (const auto& j: storage)
    {
        UniValue e(UniValue::VOBJ);
        e.push_back(Pair(dev::toHex(j.second.first), dev::toHex(j.second.second)));
        result.push_back(Pair(j.first.hex(), e));
    }
    return result;
}

UniValue listcontracts(const JSONRPCRequest& request)
{
    if (request.fHelp)
        throw std::runtime_error(
                "listcontracts       (start maxDisplay)\n"
                "\nArgument:\n"
                "1. start            (numeric or string, optional) The starting account index, default 1\n"
                "2. maxDisplay       (numeric or string, optional) Max accounts to list, default 20\n"
        );

    LOCK(cs_main);

    int start=1;
    if (request.params.size() > 0){
        start = request.params[0].get_int();
        if (start<= 0)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid start, min=1");
    }

    int maxDisplay=20;
    if (request.params.size() > 1){
        maxDisplay = request.params[1].get_int();
        if (maxDisplay <= 0)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid maxDisplay");
    }

    UniValue result(UniValue::VOBJ);

    auto map = globalState->addresses();
    int contractsCount=(int)map.size();

    if (contractsCount>0 && start > contractsCount)
        throw JSONRPCError(RPC_TYPE_ERROR, "start greater than max index "+ itostr(contractsCount));

    int itStartPos=std::min(start-1,contractsCount);
    int i=0;
    for (auto it = std::next(map.begin(),itStartPos); it!=map.end(); it++)
    {
        result.push_back(Pair(it->first.hex(),ValueFromAmount(CAmount(globalState->balance(it->first)))));
        i++;
        if(i==maxDisplay)break;
    }

    return result;
}

UniValue callcontract(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2)
        throw runtime_error(
                "callcontract \"address\" \"data\" ( address )\n"
                "\nArgument:\n"
                "1. \"address\"          (string, required) The account address\n"
                "2. \"data\"             (string, required) The data hex string\n"
                "3. address              (string, optional) The sender address hex string\n"
                "4. gasLimit             (string, optional) The gas limit for executing the contract\n"
        );

    if (chainActive.Height() < Params().FirstSCBlock()) {
        throw JSONRPCError(RPC_VERIFY_ERROR, "Smart contracts hardfork is not active yet. Activation block number - " + std::to_string(Params().FirstSCBlock()));
    }

    LOCK(cs_main);

    std::string strAddr = request.params[0].get_str();
    std::string data = request.params[1].get_str();

    if(data.size() % 2 != 0 || !CheckHex(data))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid data (data not hex)");

    if(strAddr.size() != 40 || !CheckHex(strAddr))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Incorrect address");

    dev::Address addrAccount(strAddr);
    if(!globalState->addressInUse(addrAccount))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Address does not exist");

    dev::Address senderAddress;
    if(request.params.size() == 3){
        CTxDestination luxSenderAddress = DecodeDestination(request.params[2].get_str());
        if(IsValidDestination(luxSenderAddress)) {
            CKeyID *keyid = boost::get<CKeyID>(&luxSenderAddress);

            senderAddress = dev::Address(HexStr(valtype(keyid->begin(),keyid->end())));
        }else{
            senderAddress = dev::Address(request.params[2].get_str());
        }

    }
    uint64_t gasLimit=0;
    if(request.params.size() == 4){
        gasLimit = request.params[3].get_int();
    }


    std::vector<ResultExecute> execResults = CallContract(addrAccount, ParseHex(data), senderAddress, gasLimit);

    if(fRecordLogOpcodes){
        writeVMlog(execResults);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("address", strAddr));
    result.push_back(Pair("executionResult", executionResultToJSON(execResults[0].execRes)));
    result.push_back(Pair("transactionReceipt", transactionReceiptToJSON(execResults[0].txRec)));

    return result;
}

UniValue createcontract(const JSONRPCRequest& request){

    if (!EnsureWalletIsAvailable(request.fHelp))
        return NullUniValue;

    LOCK2(cs_main, pwalletMain->cs_wallet);
    LuxDGP luxDGP(globalState.get(), fGettingValuesDGP);
    uint64_t blockGasLimit = luxDGP.getBlockGasLimit(chainActive.Height());
    uint64_t minGasPrice = CAmount(luxDGP.getMinGasPrice(chainActive.Height()));
    CAmount nGasPrice = (minGasPrice>DEFAULT_GAS_PRICE)?minGasPrice:DEFAULT_GAS_PRICE;

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 6)
        throw runtime_error(
                "createcontract \"bytecode\" (gaslimit gasprice \"senderaddress\" broadcast)"
                "\nCreate a contract with bytcode.\n"
                + HelpRequiringPassphrase() +
                "\nArguments:\n"
                "1. \"bytecode\"  (string, required) contract bytcode.\n"
                "2. gasLimit  (numeric or string, optional) gasLimit, default: "+i64tostr(DEFAULT_GAS_LIMIT_OP_CREATE)+", max: "+i64tostr(blockGasLimit)+"\n""3. gasPrice  (numeric or string, optional) gasPrice LUX price per gas unit, default: "+FormatMoney(nGasPrice)+", min:"+FormatMoney(minGasPrice)+"\n"
                                                                                                                                                                                                                                                                                                              "4. \"senderaddress\" (string, optional) The quantum address that will be used to create the contract.\n"
                                                                                                                                                                                                                                                                                                              "5. \"broadcast\" (bool, optional, default=true) Whether to broadcast the transaction or not.\n"
                                                                                                                                                                                                                                                                                                              "6. \"changeToSender\" (bool, optional, default=true) Return the change to the sender.\n"
                                                                                                                                                                                                                                                                                                              "\nResult:\n"
                                                                                                                                                                                                                                                                                                              "[\n"
                                                                                                                                                                                                                                                                                                              "  {\n"
                                                                                                                                                                                                                                                                                                              "    \"txid\" : (string) The transaction id.\n"
                                                                                                                                                                                                                                                                                                              "    \"sender\" : (string) " + CURRENCY_UNIT + " address of the sender.\n"
                                                                                                                                                                                                                                                                                                                                                             "    \"hash160\" : (string) ripemd-160 hash of the sender.\n"
                                                                                                                                                                                                                                                                                                                                                             "    \"address\" : (string) expected contract address.\n"
                                                                                                                                                                                                                                                                                                                                                             "  }\n"
                                                                                                                                                                                                                                                                                                                                                             "]\n"
                                                                                                                                                                                                                                                                                                                                                             "\nExamples:\n"
                + HelpExampleCli("createcontract", "\"60606040525b33600060006101000a81548173ffffffffffffffffffffffffffffffffffffffff02191690836c010000000000000000000000009081020402179055506103786001600050819055505b600c80605b6000396000f360606040526008565b600256\"")
                + HelpExampleCli("createcontract", "\"60606040525b33600060006101000a81548173ffffffffffffffffffffffffffffffffffffffff02191690836c010000000000000000000000009081020402179055506103786001600050819055505b600c80605b6000396000f360606040526008565b600256\" 6000000 "+FormatMoney(minGasPrice)+" \"LgAskSorXfCYUweZcCTpGNtpcFotS2rqDF\" true")
        );

    if (chainActive.Height() < Params().FirstSCBlock()) {
        throw JSONRPCError(RPC_VERIFY_ERROR, "Smart contracts hardfork is not active yet. Activation block number - " + std::to_string(Params().FirstSCBlock()));
    }

    string bytecode=request.params[0].get_str();

    if(bytecode.size() % 2 != 0 || !CheckHex(bytecode))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid data (data not hex)");

    uint64_t nGasLimit=DEFAULT_GAS_LIMIT_OP_CREATE;

    if (request.params.size() > 1) {
        nGasLimit = request.params[1].get_int64();
        if (nGasLimit > blockGasLimit)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid value for gasLimit (Maximum is: "+i64tostr(blockGasLimit)+")");
        if (nGasLimit < MINIMUM_GAS_LIMIT)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid value for gasLimit (Minimum is: "+i64tostr(MINIMUM_GAS_LIMIT)+")");
        if (nGasLimit <= 0)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid value for gasLimit");
    }

    if (request.params.size() > 2){
        UniValue uGasPrice = request.params[2];
        if(!ParseMoney(uGasPrice.getValStr(), nGasPrice))
        {
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid value for gasPrice");
        }
        CAmount maxRpcGasPrice = GetArg("-rpcmaxgasprice", MAX_RPC_GAS_PRICE);
        if (nGasPrice > (int64_t)maxRpcGasPrice)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid value for gasPrice, Maximum allowed in RPC calls is: "+FormatMoney(maxRpcGasPrice)+" (use -rpcmaxgasprice to change it)");
        if (nGasPrice < (int64_t)minGasPrice)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid value for gasPrice (Minimum is: "+FormatMoney(minGasPrice)+")");
        if (nGasPrice <= 0)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid value for gasPrice");
    }

    bool fHasSender=false;
    CTxDestination senderAddress;
    if (request.params.size() > 3){
        senderAddress = DecodeDestination(request.params[3].get_str());
        if (!IsValidDestination(senderAddress))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Lux address to send from");
        else
            fHasSender=true;
    }

    bool fBroadcast=true;
    if (request.params.size() > 4){
        fBroadcast=request.params[4].get_bool();
    }

    bool fChangeToSender=true;
    if (request.params.size() > 5){
        fChangeToSender=request.params[5].get_bool();
    }

    CCoinControl coinControl;

    if(fHasSender){
        //find a UTXO with sender address

        UniValue results(UniValue::VARR);
        vector<COutput> vecOutputs;

        coinControl.fAllowOtherInputs=true;

        assert(pwalletMain != nullptr);
        pwalletMain->AvailableCoins(vecOutputs, false, nullptr, true);

        for (const COutput& out : vecOutputs) {
            CTxDestination address;
            const CScript& scriptPubKey = out.tx->tx->vout[out.i].scriptPubKey;
            bool fValidAddress = ExtractDestination(scriptPubKey, address);

            if (!fValidAddress || senderAddress != address)
                continue;

            coinControl.Select(COutPoint(out.tx->GetHash(),out.i));

            break;

        }

        if(!coinControl.HasSelected()){
            throw JSONRPCError(RPC_TYPE_ERROR, "Sender address does not have any unspent outputs");
        }
        if(fChangeToSender){
            coinControl.destChange=senderAddress;
        }
    }
    EnsureWalletIsUnlocked();

    CWalletTx wtx;

    wtx.nTimeSmart = GetAdjustedTime();

    CAmount nGasFee=nGasPrice*nGasLimit;

    CAmount curBalance = pwalletMain->GetBalance();

    // Check amount
    if (nGasFee <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount");

    if (nGasFee > curBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

    // Build OP_EXEC script
    CScript scriptPubKey = CScript() << CScriptNum(VersionVM::GetEVMDefault().toRaw()) << CScriptNum(nGasLimit) << CScriptNum(nGasPrice) << ParseHex(bytecode) << OP_CREATE;

    // Create and send the transaction
    CReserveKey reservekey(pwalletMain);
    CAmount nFeeRequired;
    std::string strError;
    vector<pair<CScript, CAmount> > vecSend;
    vecSend.push_back(make_pair(scriptPubKey, 0));

    if (!pwalletMain->CreateTransaction(vecSend, wtx, reservekey, nFeeRequired, strError, &coinControl,  ALL_COINS,
                                        false, (CAmount)0, nGasFee)) {
        if (nFeeRequired > pwalletMain->GetBalance())
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!", FormatMoney(nFeeRequired));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    CTxDestination txSenderDest;
    ExtractDestination(pwalletMain->mapWallet[wtx.tx->vin[0].prevout.hash].tx->vout[wtx.tx->vin[0].prevout.n].scriptPubKey,txSenderDest);

    if (fHasSender && !(senderAddress == txSenderDest)){
        throw JSONRPCError(RPC_TYPE_ERROR, "Sender could not be set, transaction was not committed!");
    }

    UniValue result(UniValue::VOBJ);
    if (fBroadcast) {
        CValidationState state;
        if (!pwalletMain->CommitTransaction(wtx, reservekey))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of the wallet and coins were spent in the copy but not marked as spent here.");

        std::string txId=wtx.GetHash().GetHex();
        result.push_back(Pair("txid", txId));

        CKeyID *keyid = boost::get<CKeyID>(&txSenderDest);

        result.push_back(Pair("sender", EncodeDestination(txSenderDest)));
        result.push_back(Pair("hash160", HexStr(valtype(keyid->begin(),keyid->end()))));

        std::vector<unsigned char> SHA256TxVout(32);
        vector<unsigned char> contractAddress(20);
        vector<unsigned char> txIdAndVout(wtx.GetHash().begin(), wtx.GetHash().end());
        uint32_t voutNumber=0;
        for (const CTxOut& txout : wtx.tx->vout) {
            if (txout.scriptPubKey.HasOpCreate()) {
                std::vector<unsigned char> voutNumberChrs;
                if (voutNumberChrs.size() < sizeof(voutNumber))voutNumberChrs.resize(sizeof(voutNumber));
                std::memcpy(voutNumberChrs.data(), &voutNumber, sizeof(voutNumber));
                txIdAndVout.insert(txIdAndVout.end(),voutNumberChrs.begin(),voutNumberChrs.end());
                break;
            }
            voutNumber++;
        }
        CSHA256().Write(txIdAndVout.data(), txIdAndVout.size()).Finalize(SHA256TxVout.data());
        CRIPEMD160().Write(SHA256TxVout.data(), SHA256TxVout.size()).Finalize(contractAddress.data());
        result.push_back(Pair("address", HexStr(contractAddress)));
    } else {
        string strHex = EncodeHexTx(*wtx.tx);
        result.push_back(Pair("raw transaction", strHex));
    }
    return result;
}

UniValue sendtocontract(const JSONRPCRequest& request){

    if (!EnsureWalletIsAvailable(request.fHelp))
        return NullUniValue;

    LOCK2(cs_main, pwalletMain->cs_wallet);
    LuxDGP luxDGP(globalState.get(), fGettingValuesDGP);
    uint64_t blockGasLimit = luxDGP.getBlockGasLimit(chainActive.Height());
    uint64_t minGasPrice = CAmount(luxDGP.getMinGasPrice(chainActive.Height()));
    CAmount nGasPrice = (minGasPrice>DEFAULT_GAS_PRICE)?minGasPrice:DEFAULT_GAS_PRICE;

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 8)
        throw runtime_error(
                "sendtocontract \"contractaddress\" \"data\" (amount gaslimit gasprice senderaddress broadcast)"
                "\nSend funds and data to a contract.\n"
                + HelpRequiringPassphrase() +
                "\nArguments:\n"
                "1. \"contractaddress\" (string, required) The contract address that will receive the funds and data.\n"
                "2. \"datahex\"  (string, required) data to send.\n"
                "3. \"amount\"      (numeric or string, optional) The amount in " + CURRENCY_UNIT + " to send. eg 0.1, default: 0\n"
                                                                                                    "4. gasLimit  (numeric or string, optional) gasLimit, default: "+i64tostr(DEFAULT_GAS_LIMIT_OP_SEND)+", max: "+i64tostr(blockGasLimit)+"\n"
                                                                                                                                                                                                                                           "5. gasPrice  (numeric or string, optional) gasPrice Lux price per gas unit, default: "+FormatMoney(nGasPrice)+", min:"+FormatMoney(minGasPrice)+"\n"
                                                                                                                                                                                                                                                                                                                                                                                            "6. \"senderaddress\" (string, optional) The quantum address that will be used as sender.\n"
                                                                                                                                                                                                                                                                                                                                                                                            "7. \"broadcast\" (bool, optional, default=true) Whether to broadcast the transaction or not.\n"
                                                                                                                                                                                                                                                                                                                                                                                            "8. \"changeToSender\" (bool, optional, default=true) Return the change to the sender.\n"
                                                                                                                                                                                                                                                                                                                                                                                            "\nResult:\n"
                                                                                                                                                                                                                                                                                                                                                                                            "[\n"
                                                                                                                                                                                                                                                                                                                                                                                            "  {\n"
                                                                                                                                                                                                                                                                                                                                                                                            "    \"txid\" : (string) The transaction id.\n"
                                                                                                                                                                                                                                                                                                                                                                                            "    \"sender\" : (string) " + CURRENCY_UNIT + " address of the sender.\n"
                                                                                                                                                                                                                                                                                                                                                                                                                                           "    \"hash160\" : (string) ripemd-160 hash of the sender.\n"
                                                                                                                                                                                                                                                                                                                                                                                                                                           "  }\n"
                                                                                                                                                                                                                                                                                                                                                                                                                                           "]\n"
                                                                                                                                                                                                                                                                                                                                                                                                                                           "\nExamples:\n"
                + HelpExampleCli("sendtocontract", "\"c6ca2697719d00446d4ea51f6fac8fd1e9310214\" \"54f6127f\"")
                + HelpExampleCli("sendtocontract", "\"c6ca2697719d00446d4ea51f6fac8fd1e9310214\" \"54f6127f\" 12.0015 6000000 "+FormatMoney(minGasPrice)+" \"LgAskSorXfCYUweZcCTpGNtpcFotS2rqDF\"")
        );

    if (chainActive.Height() < Params().FirstSCBlock()) {
        throw JSONRPCError(RPC_VERIFY_ERROR, "Smart contracts hardfork is not active yet. Activation block number - " + std::to_string(Params().FirstSCBlock()));
    }

    std::string contractaddress = request.params[0].get_str();
    if(contractaddress.size() != 40 || !CheckHex(contractaddress))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Incorrect contract address");

    dev::Address addrAccount(contractaddress);
    if(!globalState->addressInUse(addrAccount))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "contract address does not exist");

    string datahex = request.params[1].get_str();
    if(datahex.size() % 2 != 0 || !CheckHex(datahex))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid data (data not hex)");

    CAmount nAmount = 0;
    if (request.params.size() > 2) {
        UniValue uAmount = request.params[2];
        if(!ParseMoney(uAmount.getValStr(), nAmount)) {
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid value for Amount");
        }
    }

    uint64_t nGasLimit=DEFAULT_GAS_LIMIT_OP_SEND;
    if (request.params.size() > 3){
        nGasLimit = request.params[3].get_int64();
        if (nGasLimit > blockGasLimit)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid value for gasLimit (Maximum is: "+i64tostr(blockGasLimit)+")");
        if (nGasLimit < MINIMUM_GAS_LIMIT)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid value for gasLimit (Minimum is: "+i64tostr(MINIMUM_GAS_LIMIT)+")");
        if (nGasLimit <= 0)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid value for gasLimit");
    }

    if (request.params.size() > 4){
        UniValue uGasPrice = request.params[4];
        if(!ParseMoney(uGasPrice.getValStr(), nGasPrice))
        {
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid value for gasPrice");
        }
        CAmount maxRpcGasPrice = GetArg("-rpcmaxgasprice", MAX_RPC_GAS_PRICE);
        if (nGasPrice > (int64_t)maxRpcGasPrice)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid value for gasPrice, Maximum allowed in RPC calls is: "+FormatMoney(maxRpcGasPrice)+" (use -rpcmaxgasprice to change it)");
        if (nGasPrice < (int64_t)minGasPrice)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid value for gasPrice (Minimum is: "+FormatMoney(minGasPrice)+")");
        if (nGasPrice <= 0)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid value for gasPrice");
    }

    bool fHasSender=false;
    CTxDestination senderAddress;
    if (request.params.size() > 5){
        senderAddress = DecodeDestination(request.params[5].get_str());
        if (!IsValidDestination(senderAddress))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Lux address to send from");
        else
            fHasSender=true;
    }

    bool fBroadcast=true;
    if (request.params.size() > 6){
        fBroadcast=request.params[6].get_bool();
    }

    bool fChangeToSender=true;
    if (request.params.size() > 7){
        fChangeToSender=request.params[7].get_bool();
    }

    CCoinControl coinControl;

    if(fHasSender){

        UniValue results(UniValue::VARR);
        vector<COutput> vecOutputs;

        coinControl.fAllowOtherInputs=true;

        assert(pwalletMain != nullptr);
        pwalletMain->AvailableCoins(vecOutputs, false, nullptr, true);

        for (const COutput& out : vecOutputs) {

            CTxDestination address;
            const CScript& scriptPubKey = out.tx->tx->vout[out.i].scriptPubKey;
            bool fValidAddress = ExtractDestination(scriptPubKey, address);

            if (!fValidAddress || senderAddress != address)
                continue;

            coinControl.Select(COutPoint(out.tx->GetHash(),out.i));

            break;

        }

        if(!coinControl.HasSelected()){
            throw JSONRPCError(RPC_TYPE_ERROR, "Sender address does not have any unspent outputs");
        }
        if(fChangeToSender){
            coinControl.destChange=senderAddress;
        }
    }

    EnsureWalletIsUnlocked();

    CWalletTx wtx;

    wtx.nTimeSmart = GetAdjustedTime();

    CAmount nGasFee=nGasPrice*nGasLimit;

    CAmount curBalance = pwalletMain->GetBalance();

    // Check amount
    if (nGasFee <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount for gas fee");

    if (nAmount+nGasFee > curBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

    // Build OP_EXEC_ASSIGN script
    CScript scriptPubKey = CScript() << CScriptNum(VersionVM::GetEVMDefault().toRaw()) << CScriptNum(nGasLimit) << CScriptNum(nGasPrice) << ParseHex(datahex) << ParseHex(contractaddress) << OP_CALL;

    // Create and send the transaction
    CReserveKey reservekey(pwalletMain);
    CAmount nFeeRequired;
    std::string strError;
    vector<pair<CScript, CAmount> > vecSend;
//    int nChangePosRet = -1;
    vecSend.push_back(make_pair(scriptPubKey, nAmount));


    if (!pwalletMain->CreateTransaction(vecSend, wtx, reservekey, nFeeRequired, strError, &coinControl, ALL_COINS,
                                        false, (CAmount)0, nGasFee)) {
        if (nFeeRequired > pwalletMain->GetBalance())
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!", FormatMoney(nFeeRequired));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    CTxDestination txSenderDest;
    ExtractDestination(pwalletMain->mapWallet[wtx.tx->vin[0].prevout.hash].tx->vout[wtx.tx->vin[0].prevout.n].scriptPubKey,txSenderDest);

    if (fHasSender && !(senderAddress == txSenderDest)){
        throw JSONRPCError(RPC_TYPE_ERROR, "Sender could not be set, transaction was not committed!");
    }

    UniValue result(UniValue::VOBJ);

    if (fBroadcast) {


        CValidationState state;
        if (!pwalletMain->CommitTransaction(wtx, reservekey))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of the wallet and coins were spent in the copy but not marked as spent here.");

        std::string txId=wtx.GetHash().GetHex();
        result.push_back(Pair("txid", txId));

        CKeyID *keyid = boost::get<CKeyID>(&txSenderDest);

        result.push_back(Pair("sender", EncodeDestination(txSenderDest)));
        result.push_back(Pair("hash160", HexStr(valtype(keyid->begin(),keyid->end()))));
    } else {
        string strHex = EncodeHexTx(*wtx.tx);
        result.push_back(Pair("raw transaction", strHex));
    }

    return result;
}

bool getContractAddressesFromParams(const UniValue& params, std::vector<dev::h160> &addresses)
{
    if (params[2].isStr()) {
        auto addrStr(params[2].get_str());
        if (addrStr.length() != 40)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
        dev::h160 address(params[2].get_str());
        addresses.push_back(address);
    } else if (params[2].isObject()) {

        UniValue addressValues = find_value(params[2].get_obj(), "addresses");
        if (!addressValues.isArray()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Addresses is expected to be an array");
        }

        std::vector<UniValue> values = addressValues.getValues();

        for (std::vector<UniValue>::iterator it = values.begin(); it != values.end(); ++it) {
            auto addrStr(it->get_str());
            if (addrStr.length() != 40)
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
            addresses.push_back(dev::h160(addrStr));
        }
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    return true;
}

bool getTopicsFromParams(const UniValue& params, std::vector<std::pair<unsigned, dev::h256>> &topics)
{
    if (params[3].isObject()) {

        UniValue topicValues = find_value(params[3].get_obj(), "topics");
        if (!topicValues.isArray()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Topics is expected to be an array");
        }

        std::vector<UniValue> values = topicValues.getValues();

        for (size_t i = 0; i < values.size(); ++i) {
            auto topicStr(values[i].get_str());
            if (topicStr == "null")
                continue;
            if (topicStr.length() != 64)
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid topic");
            topics.push_back({i, dev::h256(topicStr)});
        }
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid topic");
    }

    return true;
}
////////////////////////////////////////////////////////////////////////////


UniValue gettransactionreceipt(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1)
        throw std::runtime_error(
            "gettransactionreceipt \"txid\"\n"
            "\nNOTE: This function requires -logevents enabled.\n"

            "\nReturns an array of objects with smart contract transaction execution results.\n"

            "\nArgument:\n"
            "1. \"txid\"      (string, required) The transaction id\n"

            "\nResult:\n"
            "[{\n"
            "  \"blockHash\": \"data\",      (string)  The block hash containing the 'txid'\n"
            "  \"blockNumber\": n,         (numeric) The block height\n"
            "  \"transactionHash\": \"id\",  (string)  The transaction id (same as provided)\n"
            "  \"transactionIndex\": n,    (numeric) The transaction index in block\n"
            "  \"from\": \"address\",        (string)  The hexadecimal address from\n"
            "  \"to\": \"address\",          (string)  The hexadecimal address to\n"
            "  \"cumulativeGasUsed\": n,   (numeric) The gas used during execution\n"
            "  \"gasUsed\": n,             (numeric) The gas used during execution\n"
            "  \"contractAddress\": \"hex\", (string)  The hexadecimal contract address\n"
            "  \"excepted\": \"None\",       (string)\n"
            "  \"log\": []                 (array)\n"
            "}]\n"
        );

    if(!fLogEvents)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Events indexing disabled");

    LOCK(cs_main);

    std::string hashTemp = request.params[0].get_str();
    if(hashTemp.size() != 64){
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Incorrect hash");
    }

    uint256 hash(uint256S(hashTemp));

    if (pstorageresult == nullptr) {
        return NullUniValue;
    }

    std::vector<TransactionReceiptInfo> transactionReceiptInfo = pstorageresult->getResult(uintToh256(hash));

    UniValue result(UniValue::VARR);
    for(TransactionReceiptInfo& t : transactionReceiptInfo){
        UniValue tri(UniValue::VOBJ);
        transactionReceiptInfoToJSON(t, tri);
        result.push_back(tri);
    }
    return result;
}

UniValue pruneblockchain(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "pruneblockchain\n"
            "\nArguments:\n"
            "1. \"height\"       (numeric, required) The block height to prune up to. May be set to a discrete height, or a unix timestamp\n"
            "                  to prune blocks whose block time is at least 2 hours older than the provided timestamp.\n"
            "\nResult:\n"
            "n    (numeric) Height of the last block pruned.\n"
            "\nExamples:\n"
            + HelpExampleCli("pruneblockchain", "1000")
            + HelpExampleRpc("pruneblockchain", "1000"));

    if (!fPruneMode)
        throw JSONRPCError(RPC_MISC_ERROR, "Cannot prune blocks because node is not in prune mode.");

    LOCK(cs_main);

    int heightParam = request.params[0].get_int();
    if (heightParam < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative block height.");

    // Height value more than a billion is too high to be a block height, and
    // too low to be a block time (corresponds to timestamp from Sep 2001).
    if (heightParam > 1000000000) {
        // Add a 2 hour buffer to include blocks which might have had old timestamps
        CBlockIndex* pindex = chainActive.FindEarliestAtLeast(heightParam - TIMESTAMP_WINDOW);
        if (!pindex) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Could not find block with at least the specified timestamp.");
        }
        heightParam = pindex->nHeight;
    }

    unsigned int height = (unsigned int) heightParam;
    unsigned int chainHeight = (unsigned int) chainActive.Height();
    if (height < Params().PruneAfterHeight() || chainHeight < Params().PruneAfterHeight())
        throw JSONRPCError(RPC_MISC_ERROR, "Blockchain is too short for pruning.");
    else if (height > chainHeight)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Blockchain is shorter than the attempted prune height.");
    else if (height > chainHeight - MIN_BLOCKS_TO_KEEP) {
        LogPrintf("pruneblockchain: %s\n", "Attempt to prune blocks close to the tip.  Retaining the minimum number of blocks.");
        height = chainHeight - MIN_BLOCKS_TO_KEEP;
    }

    PruneBlockFilesManual(height);
    return uint64_t(height);
}

UniValue getaccountinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1)
        throw std::runtime_error(
                "getaccountinfo \"address\"\n"
                "\nArgument:\n"
                "1. \"address\"          (string, required) The account address\n"
        );

    LOCK(cs_main);

    std::string strAddr = request.params[0].get_str();
    if(strAddr.size() != 40 || !CheckHex(strAddr))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Incorrect address");

    dev::Address addrAccount(strAddr);
    if(!globalState->addressInUse(addrAccount))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Address does not exist");

    UniValue result(UniValue::VOBJ);

    result.push_back(Pair("address", strAddr));
    result.push_back(Pair("balance", CAmount(globalState->balance(addrAccount))));
    std::vector<uint8_t> code(globalState->code(addrAccount));
    auto storage(globalState->storage(addrAccount));

    UniValue storageUV(UniValue::VOBJ);
    for (auto j: storage)
    {
        UniValue e(UniValue::VOBJ);
        e.push_back(Pair(dev::toHex(j.second.first), dev::toHex(j.second.second)));
        storageUV.push_back(Pair(j.first.hex(), e));
    }

    result.push_back(Pair("storage", storageUV));

    result.push_back(Pair("code", HexStr(code.begin(), code.end())));

    std::unordered_map<dev::Address, Vin> vins = globalState->vins();
    if(vins.count(addrAccount)){
        UniValue vin(UniValue::VOBJ);
        valtype vchHash(vins[addrAccount].hash.asBytes());
        vin.push_back(Pair("hash", HexStr(vchHash.rbegin(), vchHash.rend())));
        vin.push_back(Pair("nVout", uint64_t(vins[addrAccount].nVout)));
        vin.push_back(Pair("value", uint64_t(vins[addrAccount].value)));
        result.push_back(Pair("vin", vin));
    }
    return result;
}

UniValue getblockheader(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw runtime_error(
            "getblockheader \"hash\" ( verbose )\n"
            "\nIf verbose is false, returns a string that is serialized, hex-encoded data for block 'hash' header.\n"
            "If verbose is true, returns an Object with information about block <hash> header.\n"
            "\nArguments:\n"
            "1. \"hash\"          (string, required) The block hash\n"
            "2. verbose           (boolean, optional, default=true) true for a json object, false for the hex encoded data\n"
            "\nResult (for verbose = true):\n"
            "{\n"
            "  \"version\" : n,         (numeric) The block version\n"
            "  \"previousblockhash\" : \"hash\",  (string) The hash of the previous block\n"
            "  \"merkleroot\" : \"xxxx\", (string) The merkle root\n"
            "  \"time\" : ttt,          (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"bits\" : \"1d00ffff\", (string) The bits\n"
            "  \"nonce\" : n,           (numeric) The nonce\n"
            "}\n"
            "\nResult (for verbose=false):\n"
            "\"data\"             (string) A string that is serialized, hex-encoded data for block 'hash' header.\n"
            "\nExamples:\n" +
            HelpExampleCli("getblockheader", "\"00000000000fd08c2fb661d2fcb0d49abb3a91e5f27082ce64feed3b4dede2e2\"") + HelpExampleRpc("getblockheader", "\"00000000000fd08c2fb661d2fcb0d49abb3a91e5f27082ce64feed3b4dede2e2\""));

    LOCK(cs_main);

    std::string strHash = request.params[0].get_str();
    uint256 hash(strHash);

    bool fVerbose = true;
    if (request.params.size() > 1)
        fVerbose = request.params[1].get_bool();

    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hash];

    if (!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus()))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");

    if (!fVerbose) {
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
        ssBlock << block.GetBlockHeader();
        std::string strHex = HexStr(ssBlock.begin(), ssBlock.end());
        return strHex;
    }

    return blockheaderToJSON(block, pblockindex);
}

UniValue gettxoutsetinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
            "gettxoutsetinfo\n"
            "\nReturns statistics about the unspent transaction output set.\n"
            "Note this call may take some time.\n"
            "\nResult:\n"
            "{\n"
            "  \"height\":n,     (numeric) The current block height (index)\n"
            "  \"bestblock\": \"hex\",   (string) the best block hash hex\n"
            "  \"transactions\": n,      (numeric) The number of transactions\n"
            "  \"txouts\": n,            (numeric) The number of output transactions\n"
            "  \"bytes_serialized\": n,  (numeric) The serialized size\n"
            "  \"hash_serialized\": \"hash\",   (string) The serialized hash\n"
            "  \"total_amount\": x.xxx          (numeric) The total amount\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("gettxoutsetinfo", "") + HelpExampleRpc("gettxoutsetinfo", ""));

    LOCK(cs_main);

    UniValue ret(UniValue::VOBJ);

    CCoinsStats stats;
    FlushStateToDisk();
    if (pcoinsTip->GetStats(stats)) {
        ret.push_back(Pair("height", (int64_t)stats.nHeight));
        ret.push_back(Pair("bestblock", stats.hashBlock.GetHex()));
        ret.push_back(Pair("transactions", (int64_t)stats.nTransactions));
        ret.push_back(Pair("txouts", (int64_t)stats.nTransactionOutputs));
        ret.push_back(Pair("bytes_serialized", (int64_t)stats.nSerializedSize));
        ret.push_back(Pair("hash_serialized", stats.hashSerialized.GetHex()));
        ret.push_back(Pair("total_amount", ValueFromAmount(stats.nTotalAmount)));
    }
    return ret;
}

UniValue gettxout(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
        throw runtime_error(
            "gettxout \"txid\" n ( includemempool )\n"
            "\nReturns details about an unspent transaction output.\n"
            "\nArguments:\n"
            "1. \"txid\"       (string, required) The transaction id\n"
            "2. n              (numeric, required) vout value\n"
            "3. includemempool  (boolean, optional) Whether to included the mem pool\n"
            "\nResult:\n"
            "{\n"
            "  \"bestblock\" : \"hash\",    (string) the block hash\n"
            "  \"confirmations\" : n,       (numeric) The number of confirmations\n"
            "  \"value\" : x.xxx,           (numeric) The transaction value in btc\n"
            "  \"scriptPubKey\" : {         (json object)\n"
            "     \"asm\" : \"code\",       (string) \n"
            "     \"hex\" : \"hex\",        (string) \n"
            "     \"reqSigs\" : n,          (numeric) Number of required signatures\n"
            "     \"type\" : \"pubkeyhash\", (string) The type, eg pubkeyhash\n"
            "     \"addresses\" : [          (array of string) array of lux addresses\n"
            "     \"luxaddress\"   	 	(string) lux address\n"
            "        ,...\n"
            "     ]\n"
            "  },\n"
            "  \"version\" : n,            (numeric) The version\n"
            "  \"coinbase\" : true|false   (boolean) Coinbase or not\n"
            "}\n"

            "\nExamples:\n"
            "\nGet unspent transactions\n" +
            HelpExampleCli("listunspent", "") +
            "\nView the details\n" + HelpExampleCli("gettxout", "\"txid\" 1") +
            "\nAs a json rpc call\n" + HelpExampleRpc("gettxout", "\"txid\", 1"));

    LOCK(cs_main);

    UniValue ret(UniValue::VOBJ);

    std::string strHash = request.params[0].get_str();
    uint256 hash(strHash);
    int n = request.params[1].get_int();
    COutPoint out(hash, n);
    bool fMempool = true;
    if (request.params.size() > 2)
        fMempool = request.params[2].get_bool();

    CCoins coins;
    if (fMempool) {
        //LOCK(mempool.cs);
        CCoinsViewMemPool view(pcoinsTip, mempool);
        if (!view.GetCoin(out, coins) || mempool.isSpent(out)) { // TODO: filtering spent coins should be done by the CCoinsViewMemPool
            return NullUniValue;
        }
    } else {
        if (!pcoinsTip->GetCoin(hash, coins)) {
            return NullUniValue;
        }
    }

    if ((unsigned int) n >= coins.vout.size()) {
        return NullUniValue;
    }

    CBlockIndex* pindex = LookupBlockIndex(pcoinsTip->GetBestBlock());
    ret.push_back(Pair("bestblock", pindex->GetBlockHash().GetHex()));
    if ((unsigned int)coins.nHeight == MEMPOOL_HEIGHT)
        ret.push_back(Pair("confirmations", 0));
    else
        ret.push_back(Pair("confirmations", pindex->nHeight - coins.nHeight + 1));
    ret.push_back(Pair("value", ValueFromAmount(coins.vout[n].nValue)));
    UniValue o(UniValue::VOBJ);
    ScriptPubKeyToJSON(coins.vout[n].scriptPubKey, o, true);
    ret.push_back(Pair("scriptPubKey", o));
    ret.push_back(Pair("version", coins.nVersion));
    ret.push_back(Pair("coinbase", coins.fCoinBase));

    return ret;
}

UniValue verifychain(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 2)
        throw runtime_error(
            "verifychain ( checklevel numblocks )\n"
            "\nVerifies blockchain database.\n"
            "\nArguments:\n"
            "1. checklevel   (numeric, optional, 0-4, default=3) How thorough the block verification is.\n"
            "2. numblocks    (numeric, optional, default=288, 0=all) The number of blocks to check.\n"
            "\nResult:\n"
            "true|false       (boolean) Verified or not\n"
            "\nExamples:\n" +
            HelpExampleCli("verifychain", "") + HelpExampleRpc("verifychain", ""));

    LOCK(cs_main);

    int nCheckLevel = GetArg("-checklevel", 3);
    int nCheckDepth = GetArg("-checkblocks", 288);
    if (request.params.size() > 0)
        nCheckLevel = request.params[0].get_int();
    if (request.params.size() > 1)
        nCheckDepth = request.params[1].get_int();

    return CVerifyDB().VerifyDB(Params(), pcoinsTip, nCheckLevel, nCheckDepth);
}

static UniValue BIP9SoftForkDesc(const Consensus::Params& consensusParams, Consensus::DeploymentPos id)
{
    UniValue rv(UniValue::VOBJ);
    const ThresholdState thresholdState = VersionBitsTipState(consensusParams, id);
    switch (thresholdState) {
        case THRESHOLD_DEFINED: rv.push_back(Pair("status", "defined")); break;
        case THRESHOLD_STARTED: rv.push_back(Pair("status", "started")); break;
        case THRESHOLD_LOCKED_IN: rv.push_back(Pair("status", "locked_in")); break;
        case THRESHOLD_ACTIVE: rv.push_back(Pair("status", "active")); break;
        case THRESHOLD_FAILED: rv.push_back(Pair("status", "failed")); break;
    }
    if (THRESHOLD_STARTED == thresholdState)
    {
        rv.push_back(Pair("bit", consensusParams.vDeployments[id].bit));
    }
    rv.push_back(Pair("startTime", consensusParams.vDeployments[id].nStartTime));
    rv.push_back(Pair("timeout", consensusParams.vDeployments[id].nTimeout));
    return rv;
}

UniValue getblockchaininfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
            "getblockchaininfo\n"
            "Returns an object containing various state info regarding block chain processing.\n"
            "\nResult:\n"
            "{\n"
            "  \"chain\": \"xxxx\",        (string) current network name as defined in BIP70 (main, test, regtest)\n"
            "  \"blocks\": xxxxxx,         (numeric) the current number of blocks processed in the server\n"
            "  \"headers\": xxxxxx,        (numeric) the current number of headers we have validated\n"
            "  \"bestblockhash\": \"...\", (string) the hash of the currently best block\n"
            "  \"difficulty\": xxxxxx,     (numeric) the current difficulty\n"
            "  \"mediantime\": xxxxxx,     (numeric) median time for the current best block\n"
            "  \"verificationprogress\": xxxx, (numeric) estimate of verification progress [0..1]\n"
            "  \"chainwork\": \"xxxx\"     (string) total amount of work in active chain, in hexadecimal\n"
            "  \"bip9_softforks\": {          (object) status of BIP9 softforks in progress\n"
            "     \"xxxx\" : {                (string) name of the softfork\n"
            "        \"status\": \"xxxx\",    (string) one of \"defined\", \"started\", \"lockedin\", \"active\", \"failed\"\n"
            "        \"bit\": xx,             (numeric) the bit, 0-28, in the block version field used to signal this soft fork\n"
            "        \"startTime\": xx,       (numeric) the minimum median time past of a block at which the bit gains its meaning\n"
            "        \"timeout\": xx          (numeric) the median time past of a block at which the deployment is considered failed if not yet locked in\n"
            "     }\n"
            "  }\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getblockchaininfo", "")
            + HelpExampleRpc("getblockchaininfo", "")
        );

    LOCK(cs_main);
    CBlockIndex* powTip = GetLastBlockOfType(0);
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("chain",                 Params().NetworkIDString()));
    obj.push_back(Pair("blocks",                chainActive.Height()));
    obj.push_back(Pair("headers",               pindexBestHeader ? pindexBestHeader->nHeight : -1));
    obj.push_back(Pair("bestblockhash",         chainActive.Tip()->GetBlockHash().GetHex()));
    obj.push_back(Pair("difficulty",            (double)GetDifficulty(powTip)));
    obj.push_back(Pair("mediantime",            (int64_t)chainActive.Tip()->GetMedianTimePast()));
    obj.push_back(Pair("verificationprogress",  Checkpoints::GuessVerificationProgress(Params().Checkpoints(), chainActive.Tip())));
    obj.push_back(Pair("chainwork",             chainActive.Tip()->nChainWork.GetHex()));

    const Consensus::Params& consensusParams = Params().GetConsensus();
    UniValue bip9_softforks(UniValue::VOBJ);
    bip9_softforks.push_back(Pair("csv", BIP9SoftForkDesc(consensusParams, Consensus::DEPLOYMENT_CSV)));
    bip9_softforks.push_back(Pair("segwit", BIP9SoftForkDesc(consensusParams, Consensus::DEPLOYMENT_SEGWIT)));
    obj.push_back(Pair("bip9_softforks", bip9_softforks));

    return obj;
}

/** Comparison function for sorting the getchaintips heads.  */
struct CompareBlocksByHeight {
    bool operator()(const CBlockIndex* a, const CBlockIndex* b) const
    {
        /* Make sure that unequal blocks with the same height do not compare
           equal. Use the pointers themselves to make a distinction. */

        if (a->nHeight != b->nHeight)
            return (a->nHeight > b->nHeight);

        return a < b;
    }
};

UniValue getchaintips(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
            "getchaintips\n"
            "Return information about all known tips in the block tree,"
            " including the main chain as well as orphaned branches.\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"height\": xxxx,         (numeric) height of the chain tip\n"
            "    \"hash\": \"xxxx\",         (string) block hash of the tip\n"
            "    \"branchlen\": 0          (numeric) zero for main chain\n"
            "    \"status\": \"active\"      (string) \"active\" for the main chain\n"
            "  },\n"
            "  {\n"
            "    \"height\": xxxx,\n"
            "    \"hash\": \"xxxx\",\n"
            "    \"branchlen\": 1          (numeric) length of branch connecting the tip to the main chain\n"
            "    \"status\": \"xxxx\"        (string) status of the chain (active, valid-fork, valid-headers, headers-only, invalid)\n"
            "  }\n"
            "]\n"
            "Possible values for status:\n"
            "1.  \"invalid\"               This branch contains at least one invalid block\n"
            "2.  \"headers-only\"          Not all blocks for this branch are available, but the headers are valid\n"
            "3.  \"valid-headers\"         All blocks are available for this branch, but they were never fully validated\n"
            "4.  \"valid-fork\"            This branch is not part of the active chain, but is fully validated\n"
            "5.  \"active\"                This is the tip of the active main chain, which is certainly valid\n"
            "\nExamples:\n" +
            HelpExampleCli("getchaintips", "") + HelpExampleRpc("getchaintips", ""));

    LOCK(cs_main);

    /* Build up a list of chain tips.  We start with the list of all
       known blocks, and successively remove blocks that appear as pprev
       of another block.  */
    std::set<const CBlockIndex*, CompareBlocksByHeight> setTips;
    std::set<const CBlockIndex*> setOrphans;
    std::set<const CBlockIndex*> setPrevs;

    for (const PAIRTYPE(const uint256, CBlockIndex*)& item : mapBlockIndex) {
        if (!chainActive.Contains(item.second)) {
            setOrphans.insert(item.second);
            setPrevs.insert(item.second->pprev);
        }
    }

    for (std::set<const CBlockIndex*>::iterator it = setOrphans.begin(); it != setOrphans.end(); ++it) {
        if (setPrevs.erase(*it) == 0) {
            setTips.insert(*it);
        }
    }

    // Always report the currently active tip.
    setTips.insert(chainActive.Tip());

    /* Construct the output array.  */
    UniValue res(UniValue::VARR);
    for (const CBlockIndex* block : setTips) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("height", block->nHeight));
        obj.push_back(Pair("hash", block->phashBlock->GetHex()));

        const int branchLen = block->nHeight - chainActive.FindFork(block)->nHeight;
        obj.push_back(Pair("branchlen", branchLen));

        string status;
        if (chainActive.Contains(block)) {
            // This block is part of the currently active chain.
            status = "active";
        } else if (block->nStatus & BLOCK_FAILED_MASK) {
            // This block or one of its ancestors is invalid.
            status = "invalid";
        } else if (block->nChainTx == 0) {
            // This block cannot be connected because full block data for it or one of its parents is missing.
            status = "headers-only";
        } else if (block->IsValid(BLOCK_VALID_SCRIPTS)) {
            // This block is fully validated, but no longer part of the active chain. It was probably the active block once, but was reorganized.
            status = "valid-fork";
        } else if (block->IsValid(BLOCK_VALID_TREE)) {
            // The headers for this block are valid, but it has not been validated. It was probably never part of the most-work chain.
            status = "valid-headers";
        } else {
            // No clue.
            status = "unknown";
        }
        obj.push_back(Pair("status", status));

        res.push_back(obj);
    }

    return res;
}

UniValue mempoolInfoToJSON() {
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("size", (int64_t) mempool.size()));
    ret.push_back(Pair("bytes", (int64_t) mempool.GetTotalTxSize()));
    ret.push_back(Pair("usage", (int64_t) mempool.DynamicMemoryUsage()));
    size_t maxmempool = GetBoolArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000;
    ret.push_back(Pair("maxmempool", (int64_t) maxmempool));
    ret.push_back(Pair("mempoolminfee", ValueFromAmount(mempool.GetMinFee(maxmempool).GetFeePerK())));

    return ret;
}

UniValue getmempoolinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
            "getmempoolinfo\n"
            "\nReturns details on the active state of the TX memory pool.\n"
            "\nResult:\n"
            "{\n"
            "  \"size\": xxxxx                (numeric) Current tx count\n"
            "  \"bytes\": xxxxx               (numeric) Sum of all tx sizes\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getmempoolinfo", "") + HelpExampleRpc("getmempoolinfo", ""));

    LOCK(cs_main);

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("size", (int64_t)mempool.size()));
    ret.push_back(Pair("bytes", (int64_t)mempool.GetTotalTxSize()));

    return ret;
}

UniValue invalidateblock(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "invalidateblock \"hash\"\n"
            "\nPermanently marks a block as invalid, as if it violated a consensus rule.\n"
            "\nArguments:\n"
            "1. hash   (string, required) the hash of the block to mark as invalid\n"
            "\nResult:\n"
            "\nExamples:\n" +
            HelpExampleCli("invalidateblock", "\"blockhash\"") + HelpExampleRpc("invalidateblock", "\"blockhash\""));

    std::string strHash = request.params[0].get_str();
    uint256 hash(strHash);
    CValidationState state;

    {
        LOCK(cs_main);
        if (mapBlockIndex.count(hash) == 0)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

        CBlockIndex* pblockindex = mapBlockIndex[hash];
        InvalidateBlock(state, Params(), pblockindex);
    }

    if (state.IsValid()) {
        ActivateBestChain(state, Params(), nullptr);
    }

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.GetRejectReason());
    }

    return NullUniValue;
}

UniValue reconsiderblock(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "reconsiderblock \"hash\"\n"
            "\nRemoves invalidity status of a block and its descendants, reconsider them for activation.\n"
            "This can be used to undo the effects of invalidateblock.\n"
            "\nArguments:\n"
            "1. hash   (string, required) the hash of the block to reconsider\n"
            "\nResult:\n"
            "\nExamples:\n" +
            HelpExampleCli("reconsiderblock", "\"blockhash\"") + HelpExampleRpc("reconsiderblock", "\"blockhash\""));

    std::string strHash = request.params[0].get_str();
    uint256 hash(strHash);
    CValidationState state;

    {
        LOCK(cs_main);
        if (mapBlockIndex.count(hash) == 0)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

        CBlockIndex* pblockindex = mapBlockIndex[hash];
        ReconsiderBlock(state, pblockindex);
    }

    if (state.IsValid()) {
        ActivateBestChain(state, Params(), nullptr);
    }

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.GetRejectReason());
    }

    return NullUniValue;
}

std::string EntryDescriptionString()
{
    return "    \"size\" : n,             (numeric) virtual transaction size as defined in BIP 141. This is different from actual serialized size for witness transactions as witness data is discounted.\n"
           "    \"fee\" : n,              (numeric) transaction fee in " + CURRENCY_UNIT + "\n"
                                                                                           "    \"modifiedfee\" : n,      (numeric) transaction fee with fee deltas used for mining priority\n"
                                                                                           "    \"time\" : n,             (numeric) local time transaction entered pool in seconds since 1 Jan 1970 GMT\n"
                                                                                           "    \"height\" : n,           (numeric) block height when transaction entered pool\n"
                                                                                           "    \"startingpriority\" : n, (numeric) DEPRECATED. Priority when transaction entered pool\n"
                                                                                           "    \"currentpriority\" : n,  (numeric) DEPRECATED. Transaction priority now\n"
                                                                                           "    \"descendantcount\" : n,  (numeric) number of in-mempool descendant transactions (including this one)\n"
                                                                                           "    \"descendantsize\" : n,   (numeric) virtual transaction size of in-mempool descendants (including this one)\n"
                                                                                           "    \"descendantfees\" : n,   (numeric) modified fees (see above) of in-mempool descendants (including this one)\n"
                                                                                           "    \"ancestorcount\" : n,    (numeric) number of in-mempool ancestor transactions (including this one)\n"
                                                                                           "    \"ancestorsize\" : n,     (numeric) virtual transaction size of in-mempool ancestors (including this one)\n"
                                                                                           "    \"ancestorfees\" : n,     (numeric) modified fees (see above) of in-mempool ancestors (including this one)\n"
                                                                                           "    \"depends\" : [           (array) unconfirmed transactions used as inputs for this transaction\n"
                                                                                           "        \"transactionid\",    (string) parent transaction id\n"
                                                                                           "       ... ]\n";
}
