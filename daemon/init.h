// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2017 The PIVX developers
// Copyright (c) 2018-2019 The UNIGRID organization
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INIT_H
#define BITCOIN_INIT_H

#include <string>
#include <vector>

#include "supplycache.h"

class CScheduler;
class CWallet;
class CzUNIGRIDWallet;

namespace boost
{
class thread_group;
} // namespace boost

extern CWallet* pwalletMain;
extern CzUNIGRIDWallet* zwalletMain;
extern SupplyCache supplyCache;

void StartShutdown();
bool ShutdownRequested();
/** Interrupt threads */
void Interrupt(boost::thread_group& threadGroup);
void Shutdown();
void PrepareShutdown();
bool AppInit2(boost::thread_group& threadGroup, CScheduler& scheduler);

/** The help message mode determines what help message to show */
enum HelpMessageMode {
    HMM_BITCOIND,
    HMM_BITCOIN_QT
};

/** Help for options shared between UI and daemon (for -help) */
std::string HelpMessage(HelpMessageMode mode);
/** Returns licensing information (for -version) */
std::string LicenseInfo();

#endif // BITCOIN_INIT_H
