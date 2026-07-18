#include "IRansomwareDetector.hpp"
#include <spdlog/spdlog.h>

#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <algorithm>
#include <chrono>
#include <thread>
#include <mutex>
#include <map>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <filesystem>

#pragma comment(lib, "psapi.lib")

namespace fs = std::filesystem;

// ------------------------------------------------------------
// NtQuerySystemInformation / NtQueryObject — dynamically loaded
// from ntdll.dll for process handle enumeration.
// ------------------------------------------------------------
typedef NTSTATUS (NTAPI *pNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *pNtQueryObject)(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
);

// ------------------------------------------------------------
// SYSTEM_HANDLE_TABLE_ENTRY_INFO — not always in winternl.h,
// defined here for portability across SDK versions.
// ------------------------------------------------------------
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    ULONG  ProcessId;
    UCHAR  ObjectTypeNumber;
    UCHAR  Flags;
    USHORT Handle;
    PVOID  Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX;

// ------------------------------------------------------------
// WindowsRansomwareDetector
// ------------------------------------------------------------
class WindowsRansomwareDetector : public IRansomwareDetector {
private:
    // --- Heuristics ---
    static constexpr double ENTROPY_THRESHOLD = 7.0;
    static constexpr int RATE_THRESHOLD = 20;
    static constexpr int RATE_WINDOW_SECONDS = 5;
    static constexpr int PROC_CACHE_TTL_SECONDS = 2;

    // Extensions commonly targeted by ransomware.
    // Used as a severity BOOSTER — NOT as a standalone alert trigger.
    const std::vector<std::string> TARGET_EXTENSIONS = {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".bmp",
        ".txt", ".csv", ".log", ".xml", ".json",
        ".zip", ".rar", ".7z", ".tar", ".gz",
        ".mp3", ".mp4", ".avi", ".mkv"
    };

    // --- Watcher state ---
    std::string watch_root;
    HANDLE directory_handle = INVALID_HANDLE_VALUE;
    HANDLE completion_event = nullptr;
    std::thread watch_thread;
    std::atomic<bool> watching{false};
    AlertCallback callback;

    // --- Rate-of-modification tracking ---
    std::vector<std::chrono::steady_clock::time_point> modification_timestamps;
    std::mutex timestamps_mutex;

    // --- Process identification cache ---
    struct ProcCacheEntry {
        std::string process_name;
        int pid;
        std::chrono::steady_clock::time_point cached_at;
    };
    std::map<std::string, ProcCacheEntry> proc_cache;
    std::mutex proc_cache_mutex;

    // --- Dynamically loaded ntdll functions ---
    pNtQuerySystemInformation NtQuerySystemInformation_fn = nullptr;
    pNtQueryObject NtQueryObject_fn = nullptr;
    bool nt_functions_loaded = false;

    // ------------------------------------------------------------
    // Lazy-load ntdll functions (called once)
    // ------------------------------------------------------------
    bool load_nt_functions() {
        if (nt_functions_loaded) return true;
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (!ntdll) return false;
        NtQuerySystemInformation_fn = reinterpret_cast<pNtQuerySystemInformation>(
            GetProcAddress(ntdll, "NtQuerySystemInformation"));
        NtQueryObject_fn = reinterpret_cast<pNtQueryObject>(
            GetProcAddress(ntdll, "NtQueryObject"));
        nt_functions_loaded = (NtQuerySystemInformation_fn && NtQueryObject_fn);
        return nt_functions_loaded;
    }

    // ------------------------------------------------------------
    // Enable SeDebugPrivilege so NtQuerySystemInformation can
    // enumerate handles from other processes.
    // ------------------------------------------------------------
    bool enable_debug_privilege() {
        HANDLE hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
            return false;

        TOKEN_PRIVILEGES tp;
        LUID luid;
        if (!LookupPrivilegeValueA(nullptr, SE_DEBUG_NAME, &luid)) {
            CloseHandle(hToken);
            return false;
        }
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        CloseHandle(hToken);
        return GetLastError() == ERROR_SUCCESS;
    }

    // ------------------------------------------------------------
    // Check if the file extension is in the ransomware target list.
    // ------------------------------------------------------------
    bool is_target_extension(const std::string& path) {
        for (const auto& ext : TARGET_EXTENSIONS) {
            if (path.length() >= ext.length() &&
                _stricmp(path.c_str() + path.length() - ext.length(), ext.c_str()) == 0) {
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------
    // Track modification rate.
    // Returns true if >RATE_THRESHOLD files were modified within
    // the last RATE_WINDOW_SECONDS.
    // ------------------------------------------------------------
    bool is_rate_exceeded() {
        std::lock_guard<std::mutex> lock(timestamps_mutex);
        auto now = std::chrono::steady_clock::now();
        auto window = std::chrono::seconds(RATE_WINDOW_SECONDS);
        auto cutoff = now - window;

        modification_timestamps.erase(
            std::remove_if(modification_timestamps.begin(), modification_timestamps.end(),
                           [cutoff](const auto& ts) { return ts < cutoff; }),
            modification_timestamps.end()
        );
        modification_timestamps.push_back(now);
        return modification_timestamps.size() > RATE_THRESHOLD;
    }

    // ------------------------------------------------------------
    // Identify which process has a given file open via
    // NtQuerySystemInformation handle enumeration.
    //
    // NOTE: This requires SeDebugPrivilege (run as admin). Without
    // it, only handles belonging to the current process are visible.
    //
    // NOTE: NT object names use \Device\HarddiskVolume... paths.
    // We compare only the filename portion as a simplification.
    // In production, use QueryDosDevice + volume path mapping.
    //
    // Performance: scanning 500K+ system handles is expensive.
    // A 2-second cache is used to avoid repeated scans per event.
    // ------------------------------------------------------------
    std::string get_process_for_file(const std::string& file_path) {
        auto now = std::chrono::steady_clock::now();

        // --- Check cache first ---
        {
            std::lock_guard<std::mutex> lock(proc_cache_mutex);
            auto it = proc_cache.find(file_path);
            if (it != proc_cache.end()) {
                auto age = std::chrono::duration_cast<std::chrono::seconds>(
                    now - it->second.cached_at).count();
                if (age < PROC_CACHE_TTL_SECONDS) {
                    return it->second.process_name;
                }
            }
        }

        if (!load_nt_functions()) return "unknown";

        // --- Query system handle table ---
        ULONG bufferSize = 0x100000;  // 1 MB initial
        SYSTEM_HANDLE_INFORMATION_EX* handleInfo =
            reinterpret_cast<SYSTEM_HANDLE_INFORMATION_EX*>(malloc(bufferSize));
        if (!handleInfo) return "unknown";

        NTSTATUS status;
        while (true) {
            ULONG needed = 0;
            status = NtQuerySystemInformation_fn(
                static_cast<SYSTEM_INFORMATION_CLASS>(16),  // SystemHandleInformation
                handleInfo, bufferSize, &needed);
            if (status == 0) break;  // STATUS_SUCCESS
            if (status != 0xC0000004) {  // STATUS_INFO_LENGTH_MISMATCH
                free(handleInfo);
                return "unknown";
            }
            free(handleInfo);
            bufferSize = needed + 0x10000;
            handleInfo = reinterpret_cast<SYSTEM_HANDLE_INFORMATION_EX*>(malloc(bufferSize));
            if (!handleInfo) return "unknown";
        }

        std::string target_filename = fs::path(file_path).filename().string();
        std::string result = "unknown";

        for (ULONG i = 0; i < handleInfo->NumberOfHandles && result == "unknown"; ++i) {
            const auto& entry = handleInfo->Handles[i];

            // Skip system process (PID 4) and our own process
            if (entry.ProcessId == 0 || entry.ProcessId == 4) continue;
            if (entry.ProcessId == GetCurrentProcessId()) continue;

            HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, entry.ProcessId);
            if (!hProcess) continue;

            HANDLE dupHandle = nullptr;
            if (DuplicateHandle(hProcess, reinterpret_cast<HANDLE>(entry.Handle),
                                GetCurrentProcess(), &dupHandle,
                                0, FALSE, DUPLICATE_SAME_ACCESS)) {

                // Query object name
                ULONG nameLen = 0;
                NtQueryObject_fn(dupHandle, static_cast<OBJECT_INFORMATION_CLASS>(1),  // ObjectNameInformation
                                 nullptr, 0, &nameLen);

                if (nameLen > 0) {
                    void* nameBuf = malloc(nameLen);
                    if (nameBuf) {
                        if (NtQueryObject_fn(dupHandle, static_cast<OBJECT_INFORMATION_CLASS>(1),
                                            nameBuf, nameLen, &nameLen) == 0) {
                            auto* objName = reinterpret_cast<UNICODE_STRING*>(nameBuf);
                            if (objName->Buffer && objName->Length > 0) {
                                // Convert UNICODE_STRING to ANSI
                                int len = WideCharToMultiByte(CP_ACP, 0,
                                    objName->Buffer, objName->Length / sizeof(WCHAR),
                                    nullptr, 0, nullptr, nullptr);
                                if (len > 0) {
                                    std::string objPath(len, '\0');
                                    WideCharToMultiByte(CP_ACP, 0,
                                        objName->Buffer, objName->Length / sizeof(WCHAR),
                                        &objPath[0], len, nullptr, nullptr);

                                    // Compare filename portion only
                                    // (full NT path is \Device\HarddiskVolumeX\...)
                                    if (objPath.find(target_filename) != std::string::npos) {
                                        char procName[MAX_PATH];
                                        DWORD size = sizeof(procName);
                                        if (QueryFullProcessImageNameA(hProcess, 0, procName, &size)) {
                                            result = fs::path(procName).filename().string();
                                        } else {
                                            result = std::to_string(entry.ProcessId);
                                        }
                                    }
                                }
                            }
                        }
                        free(nameBuf);
                    }
                }
                CloseHandle(dupHandle);
            }
            CloseHandle(hProcess);
        }

        free(handleInfo);

        // --- Update cache ---
        if (result != "unknown") {
            std::lock_guard<std::mutex> lock(proc_cache_mutex);
            proc_cache[file_path] = {result, 0, now};
        }
        return result;
    }

    // ------------------------------------------------------------
    // Process a file modification/creation event.
    //
    // Alert logic (same as Linux):
    //   TRIGGER = high entropy (>7.0) OR rate-of-modification exceeded.
    //   Target extension acts as a severity BOOSTER label.
    // ------------------------------------------------------------
    void process_event(const std::string& file_path) {
        if (!fs::exists(file_path)) return;
        if (fs::is_directory(file_path)) return;

        spdlog::debug("File modified/created: {}", file_path);

        // --- Gather signals ---
        double entropy = calculate_entropy(file_path);
        bool is_high_entropy = entropy > ENTROPY_THRESHOLD;
        bool rate_exceeded = is_rate_exceeded();
        bool is_target = is_target_extension(file_path);

        // --- Alert decision: entropy OR rate triggers the alert ---
        if (is_high_entropy || rate_exceeded) {
            RansomwareAlert alert;
            alert.timestamp = std::chrono::system_clock::now();
            alert.process_name = get_process_for_file(file_path);
            alert.pid = 0;

            std::stringstream desc;
            desc << "Suspicious activity detected!";
            if (is_high_entropy) {
                desc << " [High entropy: " << std::fixed
                     << std::setprecision(2) << entropy << "]";
            }
            if (rate_exceeded) {
                desc << " [High modification rate: >" << RATE_THRESHOLD
                     << " files in " << RATE_WINDOW_SECONDS << "s]";
            }
            if (is_target) {
                desc << " [Target extension]";
            }
            alert.description = desc.str();

            SuspiciousFile sus;
            sus.path = file_path;
            sus.entropy = entropy;
            sus.size = fs::file_size(file_path);
            sus.timestamp = alert.timestamp;
            alert.suspicious_files.push_back(sus);

            if (callback) callback(alert);
        }
    }

    // ------------------------------------------------------------
    // Watcher thread — overlapped ReadDirectoryChangesW loop
    // ------------------------------------------------------------
    void watch_loop() {
        std::vector<BYTE> buffer(65536);
        DWORD bytesReturned;
        OVERLAPPED overlapped = {};
        overlapped.hEvent = completion_event;

        while (watching) {
            BOOL success = ReadDirectoryChangesW(
                directory_handle,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                TRUE,  // watch subtree
                FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_CREATION | FILE_NOTIFY_CHANGE_FILE_NAME,
                &bytesReturned,
                &overlapped,
                nullptr
            );

            if (!success) {
                if (GetLastError() == ERROR_IO_PENDING) {
                    DWORD wait = WaitForSingleObject(completion_event, 1000);
                    if (wait == WAIT_OBJECT_0) {
                        if (!GetOverlappedResult(directory_handle, &overlapped, &bytesReturned, FALSE)) {
                            spdlog::error("GetOverlappedResult failed: {}", GetLastError());
                            continue;
                        }
                    } else if (wait == WAIT_TIMEOUT) {
                        continue;
                    } else {
                        break;
                    }
                } else {
                    spdlog::error("ReadDirectoryChangesW failed: {}", GetLastError());
                    break;
                }
            }

            if (bytesReturned > 0) {
                FILE_NOTIFY_INFORMATION* notify =
                    reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer.data());
                while (true) {
                    // Convert UTF-16 filename to ANSI
                    std::wstring wname(notify->FileName, notify->FileNameLength / sizeof(WCHAR));
                    int len = WideCharToMultiByte(CP_ACP, 0, wname.c_str(), -1,
                                                  nullptr, 0, nullptr, nullptr);
                    if (len > 0) {
                        std::string name(len, '\0');
                        WideCharToMultiByte(CP_ACP, 0, wname.c_str(), -1,
                                           &name[0], len, nullptr, nullptr);
                        // Strip null terminator
                        if (!name.empty() && name.back() == '\0') name.pop_back();
                        std::string full_path = watch_root + "\\" + name;
                        process_event(full_path);
                    }

                    if (notify->NextEntryOffset == 0) break;
                    notify = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(
                        reinterpret_cast<BYTE*>(notify) + notify->NextEntryOffset);
                }
            }
        }
    }

public:
    // ------------------------------------------------------------
    // Constructor / Destructor
    // ------------------------------------------------------------
    WindowsRansomwareDetector() {
        completion_event = CreateEvent(nullptr, TRUE, FALSE, nullptr);
        if (!completion_event) {
            spdlog::error("Failed to create completion event.");
        }
    }

    ~WindowsRansomwareDetector() {
        stop_watch();
        if (completion_event) {
            CloseHandle(completion_event);
            completion_event = nullptr;
        }
    }

    // ------------------------------------------------------------
    // 1. Shannon entropy calculation via ReadFile
    //    H = -Σ p(x) * log2(p(x))
    // ------------------------------------------------------------
    double calculate_entropy(const std::string& file_path) override {
        HANDLE hFile = CreateFileA(file_path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            spdlog::error("Could not open file: {}", file_path);
            return 0.0;
        }

        const int BYTE_RANGE = 256;
        std::vector<size_t> freq(BYTE_RANGE, 0);
        size_t total_bytes = 0;

        char buffer[4096];
        DWORD bytesRead;
        while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0) {
            total_bytes += bytesRead;
            for (DWORD i = 0; i < bytesRead; ++i) {
                unsigned char byte = static_cast<unsigned char>(buffer[i]);
                freq[byte]++;
            }
        }
        CloseHandle(hFile);

        if (total_bytes == 0) return 0.0;

        double entropy = 0.0;
        for (int i = 0; i < BYTE_RANGE; ++i) {
            if (freq[i] == 0) continue;
            double p = static_cast<double>(freq[i]) / total_bytes;
            entropy -= p * std::log2(p);
        }
        return entropy;
    }

    // ------------------------------------------------------------
    // 2. Directory scanning — recursively iterates a directory,
    //    computes entropy for each file, and returns those above
    //    the threshold. Consistent with Linux behavior.
    // ------------------------------------------------------------
    std::vector<SuspiciousFile> scan_directory(const std::string& root_directory) override {
        std::vector<SuspiciousFile> suspicious;

        try {
            for (const auto& entry : fs::recursive_directory_iterator(root_directory)) {
                if (!fs::is_regular_file(entry)) continue;
                std::string path = entry.path().string();
                double entropy = calculate_entropy(path);
                if (entropy > ENTROPY_THRESHOLD) {
                    SuspiciousFile file;
                    file.path = path;
                    file.size = fs::file_size(entry);
                    file.entropy = entropy;
                    file.timestamp = std::chrono::system_clock::now();
                    suspicious.push_back(file);
                    spdlog::warn("Suspicious file: {} (entropy: {:.2f})", path, entropy);
                }
            }
        } catch (const fs::filesystem_error& e) {
            spdlog::error("Error scanning directory: {}", e.what());
        }
        return suspicious;
    }

    // ------------------------------------------------------------
    // 3. Real-time watcher using ReadDirectoryChangesW
    // ------------------------------------------------------------
    bool start_watch(const std::string& root_directory, AlertCallback cb) override {
        if (watching) {
            spdlog::warn("Monitoring is already active.");
            return false;
        }

        watch_root = root_directory;
        callback = cb;

        directory_handle = CreateFileA(
            root_directory.c_str(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            nullptr
        );

        if (directory_handle == INVALID_HANDLE_VALUE) {
            spdlog::error("Could not open directory: {}", root_directory);
            return false;
        }

        // Try to enable SeDebugPrivilege for process identification
        if (!enable_debug_privilege()) {
            spdlog::warn("SeDebugPrivilege not available — process attribution may be limited."
                         " Run as Administrator for full functionality.");
        }

        watching = true;
        watch_thread = std::thread(&WindowsRansomwareDetector::watch_loop, this);

        spdlog::info("Windows monitoring started for: {}", root_directory);
        return true;
    }

    void stop_watch() override {
        if (!watching) return;
        watching = false;
        if (completion_event) SetEvent(completion_event);  // unblock WaitForSingleObject
        if (watch_thread.joinable()) watch_thread.join();
        if (directory_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(directory_handle);
            directory_handle = INVALID_HANDLE_VALUE;
        }
        spdlog::info("Monitoring stopped.");
    }

    bool is_watching() const override {
        return watching;
    }
};

// ------------------------------------------------------------
// Factory
// ------------------------------------------------------------
std::unique_ptr<IRansomwareDetector> create_ransomware_detector() {
    spdlog::info("🛠️ Creating Ransomware Detector for Windows");
    return std::make_unique<WindowsRansomwareDetector>();
}
