// Copyright (c) 2018 The PIVX developers
// Copyright (c) 2018-2019 The UNIGRID organization
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef UNIGRID_ACCUMULATORCHECKPOINTS_H
#define UNIGRID_ACCUMULATORCHECKPOINTS_H

#include "robinhood.h"

#include <libzerocoin/bignum.h>
#include <univalue/include/univalue.h>

namespace AccumulatorCheckpoints
{
    typedef robin_hood::unordered_node_map<libzerocoin::CoinDenomination, CBigNum> Checkpoint;
    extern robin_hood::unordered_node_map<int, Checkpoint> mapCheckpoints;

    UniValue read_json(const std::string& jsondata);
    bool LoadCheckpoints(const std::string& strNetwork);
    Checkpoint GetClosestCheckpoint(const int& nHeight, int& nHeightCheckpoint);
}

#endif //UNIGRID_ACCUMULATORCHECKPOINTS_H
