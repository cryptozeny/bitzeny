// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "crypto/common.h"

#include <stdlib.h>
#include "crypto/yespower/yespower.h"
#include "streams.h"
#include "version.h"

uint256 CBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

uint256 CBlockHeader::GetPoWHash() const
{
    uint256 thash;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << *this;
    // yespower_params_t yespower_0_5_bitzeny = {YESPOWER_0_5, 2048, 8, "Client Key", 10};
    yespower_params_t yespower_0_5_bitzeny = {
        .version = YESPOWER_0_5, 
        .N = 2048, 
        .r = 8, 
        .pers = (const uint8_t *)"Client Key",
        .perslen = 10
    };
    if (yespower_tls((unsigned char *)&ss[0], ss.size(), &yespower_0_5_bitzeny, (yespower_binary_t *)&thash)) {
        abort();
    }
    return thash;
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
