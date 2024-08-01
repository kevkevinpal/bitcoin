// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/request.h>

#include <util/fs.h>

#include <common/args.h>
#include <logging.h>
#include <random.h>
#include <rpc/protocol.h>
#include <util/fs_helpers.h>
#include <util/strencodings.h>

#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

/**
 * JSON-RPC protocol.  Bitcoin speaks version 1.0 for maximum compatibility,
 * but uses JSON-RPC 1.1/2.0 standards for parts of the 1.0 standard that were
 * unspecified (HTTP errors and contents of 'error').
 *
 * 1.0 spec: http://json-rpc.org/wiki/specification
 * 1.2 spec: http://jsonrpc.org/historical/json-rpc-over-http.html
 */

UniValue JSONRPCRequestObj(const std::string& strMethod, const UniValue& params, const UniValue& id)
{
    UniValue request(UniValue::VOBJ);
    request.pushKV("method", strMethod);
    request.pushKV("params", params);
    request.pushKV("id", id);
    return request;
}

UniValue JSONRPCReplyObj(const UniValue& result, const UniValue& error, const UniValue& id)
{
    UniValue reply(UniValue::VOBJ);
    if (!error.isNull())
        reply.pushKV("result", NullUniValue);
    else
        reply.pushKV("result", result);
    reply.pushKV("error", error);
    reply.pushKV("id", id);
    return reply;
}

std::string JSONRPCReply(const UniValue& result, const UniValue& error, const UniValue& id)
{
    UniValue reply = JSONRPCReplyObj(result, error, id);
    return reply.write() + "\n";
}

UniValue JSONRPCError(int code, const std::string& message)
{
    UniValue error(UniValue::VOBJ);
    error.pushKV("code", code);
    error.pushKV("message", message);
    return error;
}

/** Username used when cookie authentication is in use (arbitrary, only for
 * recognizability in debugging/logging purposes)
 */
static const std::string COOKIEAUTH_USER = "__cookie__";
/** Default name for auth cookie file */
static const char* const COOKIEAUTH_FILE = ".cookie";

/** Get name of RPC authentication cookie file */
static fs::path GetAuthCookieFile(bool temp=false)
{
    fs::path arg = gArgs.GetPathArg("-rpccookiefile", COOKIEAUTH_FILE);
    if (temp) {
        arg += ".tmp";
    }
    return AbsPathForConfigVal(gArgs, arg);
}

static std::optional<std::string> g_generated_cookie;

bool GenerateAuthCookie(std::string* cookie_out, const std::pair<std::optional<fs::perms>, bool>& cookie_perms)
{
    const size_t COOKIE_SIZE = 32;
    unsigned char rand_pwd[COOKIE_SIZE];
    GetRandBytes(rand_pwd);
    std::string cookie = COOKIEAUTH_USER + ":" + HexStr(rand_pwd);

    /** the umask determines what permissions are used to create this file -
     * these are set to 0077 in common/system.cpp.
     */
    std::ofstream file;
    fs::path filepath_tmp = GetAuthCookieFile(true);
    try {
        fs::remove(filepath_tmp);
    } catch (const fs::filesystem_error& e) {
        // ignore
    }
    file.open(filepath_tmp);
    if (!file.is_open()) {
        LogPrintf("Unable to open cookie authentication file %s for writing\n", fs::PathToString(filepath_tmp));
        return false;
    }

    if (cookie_perms.first) {
        std::error_code code;
        fs::permissions(filepath_tmp, *(cookie_perms.first), fs::perm_options::replace, code);
        if (code) {
            LogInfo("Unable to set permissions on cookie authentication file %s\n", fs::PathToString(filepath_tmp));
#ifdef WIN32
            // Allow default permission assignment to fail on Windows
            if (cookie_perms.second) return false;
#else
            return false;
#endif
        }
    }

    file << cookie;
    file.close();

    fs::path filepath = GetAuthCookieFile(false);
    try {
        fs::remove(filepath);
    } catch (const fs::filesystem_error& e) {
        // ignore
    }
    if (!RenameOver(filepath_tmp, filepath)) {
        LogPrintf("Unable to rename cookie authentication file %s to %s\n", fs::PathToString(filepath_tmp), fs::PathToString(filepath));
        return false;
    }

    g_generated_cookie = cookie;
    LogPrintf("Generated RPC authentication cookie %s\n", fs::PathToString(filepath));
    LogInfo("Permissions used for cookie%s: %s\n",
              (cookie_perms.first && cookie_perms.second) ? " (set by -rpccookieperms)" : "",
              PermsToString(fs::status(filepath).permissions()));

    if (cookie_out)
        *cookie_out = cookie;
    return true;
}

bool GetAuthCookie(std::string *cookie_out)
{
    std::ifstream file;
    std::string cookie;
    fs::path filepath = GetAuthCookieFile();
    file.open(filepath);
    if (!file.is_open())
        return false;
    std::getline(file, cookie);
    file.close();

    if (cookie_out)
        *cookie_out = cookie;
    return true;
}

void DeleteAuthCookie()
{
    try {
        std::string existing_cookie;
        if (GetAuthCookie(&existing_cookie) && g_generated_cookie == existing_cookie) {
            // Delete the cookie file if it exists and was generated by this process
            fs::remove(GetAuthCookieFile());
        }
    } catch (const fs::filesystem_error& e) {
        LogPrintf("%s: Unable to remove random auth cookie file: %s\n", __func__, fsbridge::get_filesystem_error_message(e));
    }
}

std::vector<UniValue> JSONRPCProcessBatchReply(const UniValue& in)
{
    if (!in.isArray()) {
        throw std::runtime_error("Batch must be an array");
    }
    const size_t num {in.size()};
    std::vector<UniValue> batch(num);
    for (const UniValue& rec : in.getValues()) {
        if (!rec.isObject()) {
            throw std::runtime_error("Batch member must be an object");
        }
        size_t id = rec["id"].getInt<int>();
        if (id >= num) {
            throw std::runtime_error("Batch member id is larger than batch size");
        }
        batch[id] = rec;
    }
    return batch;
}

void JSONRPCRequest::parse(const UniValue& valRequest)
{
    // Parse request
    if (!valRequest.isObject())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Invalid Request object");
    const UniValue& request = valRequest.get_obj();

    // Parse id now so errors from here on will have the id
    id = request.find_value("id");

    // Parse method
    const UniValue& valMethod{request.find_value("method")};
    if (valMethod.isNull())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Missing method");
    if (!valMethod.isStr())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Method must be a string");
    strMethod = valMethod.get_str();
    if (fLogIPs)
        LogPrint(BCLog::RPC, "ThreadRPCServer method=%s user=%s peeraddr=%s\n", SanitizeString(strMethod),
            this->authUser, this->peerAddr);
    else
        LogPrint(BCLog::RPC, "ThreadRPCServer method=%s user=%s\n", SanitizeString(strMethod), this->authUser);

    // Parse params
    const UniValue& valParams{request.find_value("params")};
    if (valParams.isArray() || valParams.isObject())
        params = valParams;
    else if (valParams.isNull())
        params = UniValue(UniValue::VARR);
    else
        throw JSONRPCError(RPC_INVALID_REQUEST, "Params must be an array or object");
}
