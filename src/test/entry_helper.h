// Copyright (c) 2011-2013 The Bitcoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/filesystem.hpp>
#include <boost/thread.hpp>

class CTxMemPoolEntry;

struct TestMemPoolEntryHelper
{
    // Default values
    CAmount nFee;
    int64_t nTime;
    unsigned int nHeight;
    double priority;
    CAmount inChainInputValue;
    bool spendsCoinbase;
    int64_t sigOpCost;
    LockPoints lp;
    bool poolHasNoInputsOf;
    CAmount minGasPrice;

    TestMemPoolEntryHelper() :
            nFee(0), nTime(0), nHeight(1), priority(0.0), inChainInputValue(0),
            spendsCoinbase(false), sigOpCost(4), poolHasNoInputsOf(false), minGasPrice(0) { }

    CTxMemPoolEntry FromTx(const CMutableTransaction& tx) {
        return FromTx(MakeTransactionRef(tx));
    }
    CTxMemPoolEntry FromTx(const CTransactionRef& tx) {
        return CTxMemPoolEntry(tx, nFee, nTime, priority, nHeight, inChainInputValue,
                               spendsCoinbase, sigOpCost, lp, poolHasNoInputsOf, minGasPrice);
    }

    // Change the default value
    TestMemPoolEntryHelper &Fee(CAmount _fee) { nFee = _fee; return *this; }
    TestMemPoolEntryHelper &Time(int64_t _time) { nTime = _time; return *this; }
    TestMemPoolEntryHelper &Height(unsigned int _height) { nHeight = _height; return *this; }
    TestMemPoolEntryHelper &Priority(double _priority) { priority = _priority; return *this; }
    TestMemPoolEntryHelper &InChainInputValue(CAmount _inputValue) { inChainInputValue = _inputValue; return *this; }
    TestMemPoolEntryHelper &SpendsCoinbase(bool _flag) { spendsCoinbase = _flag; return *this; }
    TestMemPoolEntryHelper &SigOpsCost(int64_t _sigopsCost) { sigOpCost = _sigopsCost; return *this; }
    TestMemPoolEntryHelper &PoolHasNoInputs(bool _poolHasNoInputsOf) { poolHasNoInputsOf = _poolHasNoInputsOf; return *this; }
    TestMemPoolEntryHelper &MinGasPrice(CAmount _minGasPrice) { minGasPrice = _minGasPrice; return *this; }
};
