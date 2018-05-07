// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "consensus/validation.h"
#include "validationinterface.h"

static CMainSignals g_signals;

CMainSignals &GetMainSignals() {
    return g_signals;
}

void RegisterValidationInterface(CValidationInterface *pwalletIn) {
    g_signals.UpdatedBlockTip.connect(boost::bind(&CValidationInterface::UpdatedBlockTip, pwalletIn, _1));
    g_signals.SyncTransaction.connect(boost::bind(&CValidationInterface::SyncTransaction, pwalletIn, _1, _2));
    g_signals.NotifyTransactionLock.connect(boost::bind(&CValidationInterface::NotifyTransactionLock, pwalletIn, _1));
    g_signals.UpdatedTransaction.connect(boost::bind(&CValidationInterface::UpdatedTransaction, pwalletIn, _1));
    g_signals.SetBestChain.connect(boost::bind(&CValidationInterface::SetBestChain, pwalletIn, _1));
    g_signals.Inventory.connect(boost::bind(&CValidationInterface::Inventory, pwalletIn, _1));
    g_signals.Broadcast.connect(boost::bind(&CValidationInterface::ResendWalletTransactions, pwalletIn));
    g_signals.BlockChecked.connect(boost::bind(&CValidationInterface::BlockChecked, pwalletIn, _1, _2));
    g_signals.ScriptForMining.connect(boost::bind(&CValidationInterface::GetScriptForMining, pwalletIn, _1));
    g_signals.BlockFound.connect(boost::bind(&CValidationInterface::ResetRequestCount, pwalletIn, _1));
}

void UnregisterValidationInterface(CValidationInterface *pwalletIn) {
    g_signals.BlockFound.disconnect(boost::bind(&CValidationInterface::ResetRequestCount, pwalletIn, _1));
    g_signals.ScriptForMining.disconnect(boost::bind(&CValidationInterface::GetScriptForMining, pwalletIn, _1));
    g_signals.BlockChecked.disconnect(boost::bind(&CValidationInterface::BlockChecked, pwalletIn, _1, _2));
    g_signals.Broadcast.disconnect(boost::bind(&CValidationInterface::ResendWalletTransactions, pwalletIn));
    g_signals.Inventory.disconnect(boost::bind(&CValidationInterface::Inventory, pwalletIn, _1));
    g_signals.SetBestChain.disconnect(boost::bind(&CValidationInterface::SetBestChain, pwalletIn, _1));
    g_signals.UpdatedTransaction.disconnect(boost::bind(&CValidationInterface::UpdatedTransaction, pwalletIn, _1));
    g_signals.NotifyTransactionLock.disconnect(boost::bind(&CValidationInterface::NotifyTransactionLock, pwalletIn, _1));
    g_signals.SyncTransaction.disconnect(boost::bind(&CValidationInterface::SyncTransaction, pwalletIn, _1, _2));
    g_signals.UpdatedBlockTip.disconnect(boost::bind(&CValidationInterface::UpdatedBlockTip, pwalletIn, _1));
}

void UnregisterAllValidationInterfaces() {
    g_signals.BlockFound.disconnect_all_slots();
    g_signals.ScriptForMining.disconnect_all_slots();
    g_signals.BlockChecked.disconnect_all_slots();
    g_signals.Broadcast.disconnect_all_slots();
    g_signals.Inventory.disconnect_all_slots();
    g_signals.SetBestChain.disconnect_all_slots();
    g_signals.UpdatedTransaction.disconnect_all_slots();
    g_signals.NotifyTransactionLock.disconnect_all_slots();
    g_signals.SyncTransaction.disconnect_all_slots();
    g_signals.UpdatedBlockTip.disconnect_all_slots();
}

void SyncWithWallets(const CTransaction &tx, const CBlock *pblock = NULL) {
    g_signals.SyncTransaction(tx, pblock);
}


//namespace
//{
//    struct CMainSignals {
//        /** Notifies listeners of updated transaction data (transaction, and optionally the block it is found in. */
//        boost::signals2::signal<void(const CTransaction&, const CBlock*)> SyncTransaction;
//        /** Notifies listeners of an updated transaction without new data (for now: a coinbase potentially becoming visible). */
//        boost::signals2::signal<void(const uint256&)> UpdatedTransaction;
//        /** Notifies listeners of a new active block chain. */
//        boost::signals2::signal<void(const CBlockLocator&)> SetBestChain;
//        /** Notifies listeners about an inventory item being seen on the network. */
//        boost::signals2::signal<void(const uint256&)> Inventory;
//        /** Tells listeners to broadcast their data. */
//        boost::signals2::signal<void()> Broadcast;
//        /** Notifies listeners of a block validation result */
 //       boost::signals2::signal<void(const CBlock&, const CValidationState&)> BlockChecked;
 //   } g_signals;

//}

//void RegisterValidationInterface(CValidationInterface* pwalletIn)
//{
  //  g_signals.SyncTransaction.connect(boost::bind(&CValidationInterface::SyncTransaction, pwalletIn, _1, _2));
  //  g_signals.UpdatedTransaction.connect(boost::bind(&CValidationInterface::UpdatedTransaction, pwalletIn, _1));
//    g_signals.SetBestChain.connect(boost::bind(&CValidationInterface::SetBestChain, pwalletIn, _1));
 //   g_signals.Inventory.connect(boost::bind(&CValidationInterface::Inventory, pwalletIn, _1));
 //   g_signals.Broadcast.connect(boost::bind(&CValidationInterface::ResendWalletTransactions, pwalletIn));
 //   g_signals.BlockChecked.connect(boost::bind(&CValidationInterface::BlockChecked, pwalletIn, _1, _2));
//}

//void UnregisterValidationInterface(CValidationInterface* pwalletIn)
//{
  //  g_signals.BlockChecked.disconnect(boost::bind(&CValidationInterface::BlockChecked, pwalletIn, _1, _2));
   // g_signals.Broadcast.disconnect(boost::bind(&CValidationInterface::ResendWalletTransactions, pwalletIn));
    //g_signals.Inventory.disconnect(boost::bind(&CValidationInterface::Inventory, pwalletIn, _1));
   // g_signals.SetBestChain.disconnect(boost::bind(&CValidationInterface::SetBestChain, pwalletIn, _1));
    //g_signals.UpdatedTransaction.disconnect(boost::bind(&CValidationInterface::UpdatedTransaction, pwalletIn, _1));
    //g_signals.SyncTransaction.disconnect(boost::bind(&CValidationInterface::SyncTransaction, pwalletIn, _1, _2));
//}

//void UnregisterAllValidationInterfaces()
//{
//    g_signals.BlockChecked.disconnect_all_slots();
//    g_signals.Broadcast.disconnect_all_slots();
//    g_signals.Inventory.disconnect_all_slots();
//    g_signals.SetBestChain.disconnect_all_slots();
//    g_signals.UpdatedTransaction.disconnect_all_slots();
//    g_signals.SyncTransaction.disconnect_all_slots();
///}

//void SyncWithWallets(const CTransaction& tx, const CBlock* pblock)
//{
//    g_signals.SyncTransaction(tx, pblock);
//}