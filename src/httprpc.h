// Copyright (c) 2015-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HTTPRPC_H
#define BITCOIN_HTTPRPC_H

#include <any>
#include <set>
#include <string>
#include <util/fs.h>

/** Start HTTP RPC subsystem.
 * Precondition; HTTP and RPC has been started.
 */
bool StartHTTPRPC(const std::any& context);
/** Interrupt HTTP RPC subsystem.
 */
void InterruptHTTPRPC();
/** Stop HTTP RPC subsystem.
 * Precondition; HTTP and RPC has been stopped.
 */
void StopHTTPRPC();

/** Default permissions for cookie file.
 * Set to owner read/write, which on Windows sets the write permission.
 */
const fs::perms DEFAULT_COOKIE_PERMS{fs::perms::owner_read | fs::perms::owner_write};

/** Start HTTP REST subsystem.
 * Precondition; HTTP and RPC has been started.
 */
void StartREST(const std::any& context);
/** Interrupt RPC REST subsystem.
 */
void InterruptREST();
/** Stop HTTP REST subsystem.
 * Precondition; HTTP and RPC has been stopped.
 */
void StopREST();

/** Returns a collection of whitelisted RPCs for the given user
 */
std::set<std::string> GetWhitelistedRpcs(const std::string& user_name);

#endif // BITCOIN_HTTPRPC_H
