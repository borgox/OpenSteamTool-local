#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace Config {

    enum class LogLevel { Trace, Debug, Info, Warn, Error };

    struct ManifestTimeouts {
        uint32_t resolve = 5000;
        uint32_t connect = 5000;
        uint32_t send    = 10000;
        uint32_t recv    = 10000;
    };

    struct InjectionSettings {
        bool enabled = false;
        std::string libraryX86;
        std::string libraryX64;
    };

    struct CloudSettings {
        bool enabled = false;
        std::string library;
    };

    struct LoadResult {
        bool applied = false;
        bool luaPathsChanged = false;
    };

    LoadResult Load(const std::string& configPath);

    ManifestTimeouts GetManifestTimeouts();
    LogLevel GetLogLevel();
    std::string GetLogDir();
    std::vector<std::string> GetLuaPaths();
    std::string GetRemoteUrlTemplate();
    bool        GetRemoteEnabled();
    std::string GetLocalTomlPath();
    InjectionSettings GetInjectionSettings();
<<<<<<< HEAD

    // [manifest] — provider selection lives in ManifestClient (table-driven).
=======
    CloudSettings GetCloudSettings();
>>>>>>> 00984b41cc9713a278d87b5fcb7b6766be1948d8
    bool GetStatsEnableApi();

    // [manifest] — provider selection lives in ManifestClient (table-driven).
    inline uint32_t manifestTimeoutResolve = 5000;
    inline uint32_t manifestTimeoutConnect = 5000;
    inline uint32_t manifestTimeoutSend    = 10000;
    inline uint32_t manifestTimeoutRecv    = 10000;
<<<<<<< HEAD
    
=======

>>>>>>> 00984b41cc9713a278d87b5fcb7b6766be1948d8
    // [log]
    inline LogLevel logLevel = LogLevel::Debug;

    // derived from configPath: <steam>/opensteamtool/
    inline std::string logDir;

    // [lua]
    inline std::vector<std::string> luaPaths;

    // [remote]
    inline std::string remoteUrlTemplate;

    // If false, the HTTP mirror chain is skipped entirely; only the local
    // cache (or localTomlPath, if set) is consulted.
    inline bool remoteEnabled = true;

    // Optional directory that is searched for <sha256>.toml files before
    // the auto-managed cache. Useful for fully offline/air-gapped setups.
    inline std::string localTomlPath;

    // [stats]
    inline bool statsEnableApi = true;

    // [inject] - optional library injection into game processes.
    inline bool injectEnabled = false;
    inline std::string injectLibraryX86;
    inline std::string injectLibraryX64;

    // [cloud] - optional Steam Cloud save redirection via CloudRedirect.
    inline bool cloudEnabled = false;
    inline std::string cloudLibrary;

}
