// Copyright (c) 2018 The Luxcore developers

#ifndef LUX_SEEDER_LUX_H
#define LUX_SEEDER_LUX_H

#include "protocol.h"

#include <string>
#include <vector>

/**
 * The seeder do not use the Params facility.
 *
 * While this is sorted out, we need a replacement.
 */
extern bool fTestNet;
static inline unsigned short GetDefaultPort(const bool testnet = fTestNet) {
    return testnet ? 28333 : 9777;
}

// The network magic to use.
extern CMessageHeader::MessageMagic netMagic;

bool TestNode(const CService &cip, int &ban, int &client, std::string &clientSV,
              int &blocks, std::vector<CAddress> *vAddr);

#endif
