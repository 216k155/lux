
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <util.h>
#include <tinyformat.h>
#include <script/standard.h>
#include <chainparams.h>
#include <main.h>
#include <pubkey.h>
#include "luxtransaction.h"


bool ContractOutputParser::parseOutput(ContractOutput& output){
    try{
        std::vector<uint8_t> receiveAddress;
        valtype vecAddr;
        if (opcode == OP_CALL)
        {
            vecAddr = stack.back();
            stack.pop_back();
            receiveAddress = vecAddr;
        }
        if(stack.size() < 4)
            return false;

        if(stack.back().size() < 1){
            return false;
        }
        valtype code(stack.back());
        stack.pop_back();
        uint64_t gasPrice = CScriptNum::vch_to_uint64(stack.back());
        stack.pop_back();
        uint64_t gasLimit = CScriptNum::vch_to_uint64(stack.back());
        stack.pop_back();
        if(gasPrice > INT64_MAX || gasLimit > INT64_MAX){
            return false;
        }
        //we track this as CAmount in some places, which is an int64_t, so constrain to INT64_MAX
        if(gasPrice !=0 && gasLimit > INT64_MAX / gasPrice){
            //overflows past 64bits, reject this tx
            return false;
        }
        if(stack.back().size() > 4){
            return false;
        }
        VersionVM version = VersionVM::fromRaw((uint32_t)CScriptNum::vch_to_uint64(stack.back()));
        stack.pop_back();
        output.version = version;
        output.gasPrice = gasPrice;
        if(version.rootVM == EVM_VM) {
            output.address = UniversalAddress(AddressVersion ::EVM, receiveAddress);
        }else if(version.rootVM == LUX_VM){
            output.address = UniversalAddress(AddressVersion::LUX, receiveAddress);
        }else{
            LogPrintf("Invalid contract address!");
            return false;
        }
        output.data = code;
        output.gasLimit = gasLimit;
        return true;
    }
    catch(const scriptnum_error& err){
        LogPrintf("Incorrect parameters to VM.");
        return false;
    }
}

bool ContractOutputParser::receiveStack(const CScript& scriptPubKey){
    EvalScript(stack, scriptPubKey, SCRIPT_EXEC_BYTE_CODE, BaseSignatureChecker(), SIGVERSION_BASE, nullptr);
    if (stack.empty())
        return false;

    CScript scriptRest(stack.back().begin(), stack.back().end());
    stack.pop_back();

    opcode = (opcodetype)(*scriptRest.begin());
    if((opcode == OP_CREATE && stack.size() < 4) || (opcode == OP_CALL && stack.size() < 5)){
        stack.clear();
        return false;
    }

    return true;
}

UniversalAddress ContractOutputParser::getSenderAddress(){
    if(coinsView == NULL || blockTransactions == NULL){
        return UniversalAddress();
    }
    CScript script;
    bool scriptFilled=false; //can't use script.empty() because an empty script is technically valid
    const CChainParams& chainparams = Params();
    // First check the current (or in-progress) block for zero-confirmation change spending that won't yet be in txindex
    if(blockTransactions){
        for(auto btx : *blockTransactions){
            if(btx.GetHash() == tx.vin[0].prevout.hash){
                script = btx.vout[tx.vin[0].prevout.n].scriptPubKey;
                scriptFilled=true;
                break;
            }
        }
    }

    if(!scriptFilled && coinsView){    // view.AccessCoins(prevHash);
        script = coinsView->AccessCoins(tx.vin[0].prevout.hash)->vout[0].scriptPubKey;
        scriptFilled = true;
    }
    if(!scriptFilled)
    {
        CTransaction txPrevout;
        uint256 hashBlock;
        if(GetTransaction(tx.vin[0].prevout.hash, txPrevout, chainparams.GetConsensus(), hashBlock, true)){
            script = txPrevout.vout[tx.vin[0].prevout.n].scriptPubKey;
        } else {
            LogPrintf("Error fetching transaction details of tx %s. This will probably cause more errors", tx.vin[0].prevout.hash.ToString());
            return UniversalAddress();
        }
    }

    CTxDestination addressBit;
    txnouttype txType=TX_NONSTANDARD;
    if(ExtractDestination(script, addressBit, &txType)){
        if ((txType == TX_PUBKEY || txType == TX_PUBKEYHASH) &&
            addressBit.type() == typeid(CKeyID)){
            CKeyID senderAddress(boost::get<CKeyID>(addressBit));
            return UniversalAddress(AddressVersion::PUBKEYHASH, senderAddress.begin(), senderAddress.end());
        }
    }

    //prevout is not a standard transaction format, so just return 0
    return UniversalAddress();
}

ContractEnvironment ContractExecutor::buildEnv() {
    ContractEnvironment env;
    CBlockIndex *tip = chainActive.Tip();
    //assert(*tip->phashBlock == block.GetHash());
    env.blockNumber = tip->nHeight;
#if 0
    env.blockTime = block.nTime;

    env.difficulty = block.nBits;
#endif
    env.gasLimit = blockGasLimit;
    env.blockHashes.resize(256);
    for (int i = 0; i < 256; i++) {
        if (!tip)
            break;
        env.blockHashes[i] = *tip->phashBlock;
        tip = tip->pprev;
    }
    return env;
}
#if 0
    if(block.IsProofOfStake()){
        env.blockCreator = UniversalAddress::FromScript(block.vtx[1].vout[1].scriptPubKey);
    }else {
        env.blockCreator = UniversalAddress::FromScript(block.vtx[0].vout[0].scriptPubKey);
    }
    return env;
}

UniversalAddress UniversalAddress::FromScript(const CScript& script){
    CTxDestination addressBit;
    txnouttype txType=TX_NONSTANDARD;
    if(ExtractDestination(script, addressBit, &txType)){
        if ((txType == TX_PUBKEY || txType == TX_PUBKEYHASH) &&
            addressBit.type() == typeid(CKeyID)){
            CKeyID addressKey(boost::get<CKeyID>(addressBit));
            return UniversalAddress(AddressVersion::PUBKEYHASH, addressKey.begin(), addressKey.end());
        }
    }
    //if not standard or not a pubkey or pubkeyhash output, then return 0
    return UniversalAddress();
}

ContractExecutor::ContractExecutor(const CBlock &_block, ContractOutput _output, uint64_t _blockGasLimit)
        : block(_block), output(_output), blockGasLimit(_blockGasLimit) {}


bool ContractExecutor::execute(ContractExecutionResult &result, bool commit)
{
    ContractEnvironment env=buildEnv();
    LuxDB db;
    if(output.version.rootVM == EVM_VM){
        EVMContractVM evm(db, env, blockGasLimit);
        evm.execute(output, result, commit);
    }
    return true;
}


bool EVMContractVM::execute(ContractOutput &output, ContractExecutionResult &result, bool commit)
{
    dev::eth::EnvInfo envInfo(buildEthEnv());
    if (output.address.version != AddressVersion::UNKNOWN &&
        !globalState->addressInUse(dev::Address(output.address.data))) {
        //contract is not in database
        result.usedGas = output.gasLimit;
        result.refundSender = 0;
        result.status = ContractStatus::DOESNT_EXIST;
        return false;
    }
    dev::eth::Permanence p = commit ? dev::eth::Permanence::Committed : dev::eth::Permanence::Reverted;
    ResultExecute ethres = globalState->execute(envInfo, *globalSealEngine.get(), buildLuxTx(output), p, OnOpFunc());

    //TODO, make proper status
    switch(ethres.execRes.excepted){
        case dev::eth::TransactionException::None:
            result.status = ContractStatus::SUCCESS;
            break;
        default:
            result.status = ContractStatus ::CODE_ERROR;
            break;
    }

    //todo: error checking here for overflow
    result.refundSender = (uint64_t) ethres.execRes.gasRefunded;
    result.usedGas = (uint64_t) ethres.execRes.gasUsed;
    //result.push_back(globalState->execute(envInfo, *globalSealEngine.get(), tx, type, OnOpFunc()));
    globalState->db().commit();
    globalState->dbUtxo().commit();
    globalSealEngine.get()->deleteAddresses.clear();
    return true;
}

dev::eth::EnvInfo EVMContractVM::buildEthEnv(){
    dev::eth::EnvInfo eth;
    eth.setAuthor(dev::Address(env.blockCreator.data));
    eth.setDifficulty(dev::u256(env.difficulty));
    eth.setGasLimit(env.gasLimit);
    eth.setNumber(dev::u256(env.blockNumber));
    eth.setTimestamp(dev::u256(env.blockTime));
    dev::eth::LastHashes lh;
    lh.resize(256);
    for(int i=0;i<256;i++){
        lh[i]= uintToh256(env.blockHashes[i]);
    }
    eth.setLastHashes(std::move(lh));
    return eth;
}


UniversalAddress UniversalAddress::FromOutput(AddressVersion v, uint256 txid, uint32_t vout){
    std::vector<unsigned char> txIdAndVout(txid.begin(), txid.end());
    std::vector<unsigned char> voutNumberChrs;
    if (voutNumberChrs.size() < sizeof(vout))voutNumberChrs.resize(sizeof(vout));
    std::memcpy(voutNumberChrs.data(), &vout, sizeof(vout));
    txIdAndVout.insert(txIdAndVout.end(),voutNumberChrs.begin(),voutNumberChrs.end());

    std::vector<unsigned char> SHA256TxVout(32);
    CSHA256().Write(txIdAndVout.data(), txIdAndVout.size()).Finalize(SHA256TxVout.data());

    std::vector<unsigned char> hashTxIdAndVout(20);
    CRIPEMD160().Write(SHA256TxVout.data(), SHA256TxVout.size()).Finalize(hashTxIdAndVout.data());

    return UniversalAddress(v, hashTxIdAndVout);
}

LuxTransaction EVMContractVM::buildLuxTx(const ContractOutput &output)
{
    LuxTransaction txEth;
    if (output.address.version == AddressVersion::UNKNOWN && output.OpCreate) {
        txEth = LuxTransaction(output.value, output.gasPrice, output.gasLimit, output.data, dev::u256(0));
        //txEth = LuxTransaction(txBit.vout[nOut].nValue, etp.gasPrice, etp.gasLimit, etp.code, dev::u256(0));
    } else {
        txEth = LuxTransaction(output.value, output.gasPrice, output.gasLimit, dev::Address(output.address.data),
                                output.data, dev::u256(0));
        //txEth = LuxTransaction(txBit.vout[nOut].nValue, etp.gasPrice, etp.gasLimit, etp.receiveAddress, etp.code,
        //                        dev::u256(0));
    }
    //todo cross-contract communication?
    dev::Address sender(output.sender.data);
    txEth.forceSender(sender);
    txEth.setHashWith(uintToh256(output.vout.hash));
    txEth.setNVout(output.vout.n);
    txEth.setVersion(output.version);

    return txEth;
}
#endif

