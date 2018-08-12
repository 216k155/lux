//
// Created by k155 on 10/08/18.
//

#ifndef LUX_RPCBLOCKCHAIN_H
#define LUX_RPCBLOCKCHAIN_H

class CBlock;
class CBlockIndex;
class UniValue;

/** Block header to JSON */
UniValue blockheaderToJSON(const CBlockIndex* blockindex);

#endif //LUX_RPCBLOCKCHAIN_H
