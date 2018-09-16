// Copyright (c) 2009-2010 Satoshi Nakamoto             -*- c++ -*-
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The LUX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Server/client environment: argument handling, config file parsing,
 * logging, thread wrappers
 */
#ifndef BITCOIN_UTIL_H
#define BITCOIN_UTIL_H

#if defined(HAVE_CONFIG_H)
#include "config/lux-config.h"
#endif

#include "compat.h"
#include "fs.h"
#include "sync.h"
#include "tinyformat.h"
#include "utiltime.h"

#include <atomic>
#include <exception>
#include <map>
#include <stdint.h>
#include <string>
#include <vector>

#include <boost/thread/exceptions.hpp>
#include <boost/signals2/signal.hpp>

#ifndef WIN32
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#endif

int64_t GetStartupTime();

static const bool DEFAULT_LOGTIMEMICROS = false;
static const bool DEFAULT_LOGIPS        = false;
static const bool DEFAULT_LOGTIMESTAMPS = true;

/** Translate a message to the native language of the user. */
class CTranslationInterface {
public:
    boost::signals2::signal<std::string (const char* psz)> Translate;
};

//LUX only features
extern CTranslationInterface translationInterface;
extern int64_t enforceMasternodePaymentsTime;
extern std::atomic<bool> hideLogMessage;
extern std::string strMasterNodeAddr;
extern std::vector<int64_t> darkSendDenominations;
extern std::string strBudgetMode;
extern std::map<std::string, std::string> mapArgs;
extern std::map<std::string, std::vector<std::string> > mapMultiArgs;
extern std::string strMiscWarning;
extern std::atomic<bool> fReopenDebugLog;
extern std::atomic<uint32_t> logCategories;

extern int nLogFile;
extern int nInstanTXDepth;
extern int nDarksendRounds;
extern int nWalletBackups;
extern int nAnonymizeLuxAmount;
extern int nLiquidityProvider;
extern int keysLoaded;

extern bool fDebug;
extern bool fDebugMnSecurity;
extern bool fPrintToConsole;
extern bool fPrintToDebugLog;
extern bool fLogTimestamps;
extern bool fLogTimeMicros;
extern bool fLogIPs;
extern bool fServer;
extern bool fSucessfullyLoaded;
extern bool fEnableDarksend;
extern bool fMasterNode;
extern bool fEnableInstanTX;

void SetupEnvironment();
bool SetupNetworking();

struct CLogCategoryActive {
    std::string category;
    bool active;
};

namespace BCLog {
    enum LogFlags : uint32_t {
        NONE        = 0,
        NET         = (1 <<  0),
        TOR         = (1 <<  1),
        MEMPOOL     = (1 <<  2),
        HTTP        = (1 <<  3),
        BENCH       = (1 <<  4),
        ZMQ         = (1 <<  5),
        DB          = (1 <<  6),
        RPC         = (1 <<  7),
        ESTIMATEFEE = (1 <<  8),
        ADDRMAN     = (1 <<  9),
        SELECTCOINS = (1 << 10),
        REINDEX     = (1 << 11),
        CMPCTBLOCK  = (1 << 12),
        RAND        = (1 << 13),
        PRUNE       = (1 << 14),
        PROXY       = (1 << 15),
        MEMPOOLREJ  = (1 << 16),
        LIBEVENT    = (1 << 17),
        COINDB      = (1 << 18),
        QT          = (1 << 19),
        LEVELDB     = (1 << 20),
        ALERT       = (1 << 21),
        HTTPPOLL    = (1 << 22),
        DARKSEND    = (1 << 23),
        LDEBUG      = (1 << 24),
        LUX         = (1 << 25),
        ALL         = ~(uint32_t)0,
    };
}
/** Return true if log accepts specified category */
static inline bool LogAcceptCategory(uint32_t category) {
    return (logCategories.load(std::memory_order_relaxed) & category) != 0;
}

/** Returns a string with the supported log categories */
std::string ListLogCategories();

/** Returns a vector of the active log categories. */
std::vector<CLogCategoryActive> ListActiveLogCategories();

/** Return true if str parses as a log category and set the flags in f */
bool GetLogCategory(uint32_t *f, const std::string *str);

/** Send a string to the log output */
int LogPrintStr(const std::string& str, bool useVMLog = false);

/** Push debug files */
void pushDebugLog(std::string pathDebugStr, int debugNum);

/** Get format string from VA_ARGS for error reporting */
template<typename... Args> std::string FormatStringFromLogArgs(const char *fmt, const Args&... args) { return fmt; }

static inline void MarkUsed() {}
template<typename T, typename... Args> static inline void MarkUsed(const T& t, const Args&... args) { (void)t; MarkUsed(args...); }

#ifdef USE_COVERAG
#define LogPrintf(...) do { MarkUsed(__VA_ARGS__); } while(0)
#define LogPrint(category, ...) do { MarkUsed(__VA_ARGS__); } while(0)

#else

#define LogPrintf(...) do { \
    std::string _log_msg_; /* Unlikely name to avoid shadowing variables */ \
    try { \
        _log_msg_ = tfm::format(__VA_ARGS__); \
    } catch (tinyformat::format_error &fmterr) { \
        /* Original format string will have newline so don't add one here */ \
        _log_msg_ = "Error \"" + std::string(fmterr.what()) + "\" while formatting log message: " + FormatStringFromLogArgs(__VA_ARGS__); \
    } \
    LogPrintStr(_log_msg_); \
} while(0)

#define LogPrint(category, ...) do { \
    if (LogAcceptCategory((category))) { \
        LogPrintf(__VA_ARGS__); \
    } \
} while(0)

#endif

template<typename... Args>
bool error(const char* fmt, const Args&... args) {
    LogPrintStr("ERROR: " + tfm::format(fmt, args...) + "\n");
    return false;
}

void AllocateFileRange(FILE* file, unsigned int offset, unsigned int length);
void PrintExceptionContinue(std::exception* pex, const char* pszThread);
void ParseParameters(int argc, const char* const argv[]);
void FileCommit(FILE* fileout);
void ClearDatadirCache();

bool TruncateFile(FILE* file, unsigned int length);
bool RenameOver(fs::path src, fs::path dest);
bool TryCreateDirectory(const fs::path& p);

int RaiseFileDescriptorLimit(int nMinFD);

const fs::path& GetDataDir(bool fNetSpecific = true);

fs::path GetConfigFile();
fs::path GetMasternodeConfigFile();
fs::path GetDefaultDataDir();

#ifndef WIN32

fs::path GetPidFile();
void CreatePidFile(const fs::path& path, pid_t pid);

#endif

void ReadConfigFile(std::map<std::string, std::string>& mapSettingsRet, std::map<std::string, std::vector<std::string> >& mapMultiSettingsRet);
void WriteConfigToFile(std::string strKey, std::string strValue);

#ifdef WIN32

fs::path GetSpecialFolderPath(int nFolder, bool fCreate = true);
#endif
fs::path GetTempPath();
void OpenDebugLog();
void ShrinkDebugFile();
void runCommand(std::string strCommand);

inline bool IsSwitchChar(char c)
{
#ifdef WIN32
    return c == '-' || c == '/';
#else
    return c == '-';
#endif
}

/**
 * Return true if the given argument has been manually set
 *
 * @param strArg Argument to get (e.g. "-foo")
 * @return true if the argument has been set
 */
bool IsArgSet(const std::string& strArg);

/**
 * Return string argument or default value
 *
 * @param strArg Argument to get (e.g. "-foo")
 * @param default (e.g. "1")
 * @return command-line argument or default value
 */
std::string GetArg(const std::string& strArg, const std::string& strDefault);

/**
 * Return integer argument or default value
 *
 * @param strArg Argument to get (e.g. "-foo")
 * @param default (e.g. 1)
 * @return command-line argument (0 if invalid number) or default value
 */
int64_t GetArg(const std::string& strArg, int64_t nDefault);

/**
 * Return boolean argument or default value
 *
 * @param strArg Argument to get (e.g. "-foo")
 * @param default (true or false)
 * @return command-line argument or default value
 */
bool GetBoolArg(const std::string& strArg, bool fDefault);

/**
 * Set an argument if it doesn't already have a value
 *
 CBlock block;
    CBlockIndex* pblockindex =chainActive[nHeight];
    std::string strHash =  pblockindex->GetBlockHash().GetHex();
    uint256 hash(strHash);
    CBlockIndex* pblockindex2 = mapBlockIndex[hash];
    //  a.push_back();
    return pblockindex2;
} to set (e.g. "-foo")
 * @param strValue Value (e.g. "1")
 * @return true if argument gets set, false if it already had a value
 */

bool SoftSetArg(const std::string& strArg, const std::string& strValue);

/**
 * Set a boolean argument if it doesn't already have a value
 *
 * @param strArg Argument to set (e.g. "-foo")
 * @param fValue Value (e.g. false)
 * @return true if argument gets set, false if it already had a value
 */
bool SoftSetBoolArg(const std::string& strArg, bool fValue);

// Forces a arg setting
void ForceSetArg(const std::string& strArg, const std::string& strValue);
void SetThreadPriority(int nPriority);
void RenameThread(const char* name);

inline uint32_t ByteReverse(uint32_t value)
{
    value = ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8);
    return (value<<16) | (value>>16);
}

/**
 * .. and a wrapper that just calls func once
 */
template <typename Callable>
void TraceThread(const char* name, Callable func)
{
    std::string s = strprintf("lux-%s", name);
    RenameThread(s.c_str());
    try {
        LogPrintf("%s thread start\n", name);
        func();
        LogPrintf("%s thread exit\n", name);
    } catch (boost::thread_interrupted) {
        LogPrintf("%s thread interrupt\n", name);
        // rethrow exception if current thread is not the "net" thread
        if (strcmp(name, "net")) throw;
    } catch (std::exception& e) {
        PrintExceptionContinue(&e, name);
        // rethrow exception if current thread is not the "net" thread
        if (strcmp(name, "net")) throw;
    } catch (...) {
        PrintExceptionContinue(NULL, name);
        // rethrow exception if current thread is not the "net" thread
        if (strcmp(name, "net")) throw;
    }
}

bool CheckHex(const std::string& str);

#endif // BITCOIN_UTIL_H
