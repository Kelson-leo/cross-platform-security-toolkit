#include "IRansomwareDetector.hpp"
#include <spdlog/spdlog.h>

#include <fstream>
#include <cmath>
#include <filesystem>
#include <thread>
#include <atomic>
#include <algorithm>
#include <mutex>
#include <map>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <sys/inotify.h>
#include <climits>
#include <unistd.h>
#include <dirent.h>

namespace fs = std::filesystem;

class LinuxRansomwareDetector : public IRansomwareDetector {
private:
    // --- inotify state ---
    int inotify_fd = -1;
    int watch_descriptor = -1;
    std::atomic<bool> watching{false};
    std::thread watch_thread;
    AlertCallback callback;
    std::string watch_root;

    // --- Heuristics ---
    static constexpr double ENTROPY_THRESHOLD = 7.0;
    static constexpr int RATE_THRESHOLD = 20;                // 20 files modified
    static constexpr int RATE_WINDOW_SECONDS = 5;            // within 5 seconds
    static constexpr int PROC_CACHE_TTL_SECONDS = 2;         // /proc scan cache TTL

    // Extensions commonly targeted by ransomware.
    // Used as a severity booster — NOT as a standalone alert trigger.
    const std::vector<std::string> TARGET_EXTENSIONS = {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".bmp",
        ".txt", ".csv", ".log", ".xml", ".json",
        ".zip", ".rar", ".7z", ".tar", ".gz",
        ".mp3", ".mp4", ".avi", ".mkv"
    };

    // --- Rate-of-modification tracking ---
    std::vector<std::chrono::steady_clock::time_point> modification_timestamps;
    std::mutex timestamps_mutex;

    // --- /proc scan cache ---
    // Maps file_path -> {process_name, pid, cache_time}
    struct ProcCacheEntry {
        std::string process_name;
        int pid;
        std::chrono::steady_clock::time_point cached_at;
    };
    std::map<std::string, ProcCacheEntry> proc_cache;
    std::mutex proc_cache_mutex;

    // ------------------------------------------------------------
    // Check if the file extension is in the ransomware target list.
    // ------------------------------------------------------------
    bool is_target_extension(const std::string& path) {
        for (const auto& ext : TARGET_EXTENSIONS) {
            if (path.length() >= ext.length() &&
                path.compare(path.length() - ext.length(), ext.length(), ext) == 0) {
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------
    // Track modification rate.
    // Returns true if more than RATE_THRESHOLD files were modified
    // within the last RATE_WINDOW_SECONDS.
    // ------------------------------------------------------------
    bool is_rate_exceeded() {
        std::lock_guard<std::mutex> lock(timestamps_mutex);
        auto now = std::chrono::steady_clock::now();
        auto window = std::chrono::seconds(RATE_WINDOW_SECONDS);

        // Prune timestamps older than the window
        auto cutoff = now - window;
        modification_timestamps.erase(
            std::remove_if(modification_timestamps.begin(), modification_timestamps.end(),
                           [cutoff](const auto& ts) { return ts < cutoff; }),
            modification_timestamps.end()
        );

        // Record current modification
        modification_timestamps.push_back(now);
        return modification_timestamps.size() > RATE_THRESHOLD;
    }

    // ------------------------------------------------------------
    // Identify which process has a given file open by scanning
    // /proc/*/fd/*. Includes a short-lived cache to avoid rescanning
    // on repeated events for the same file path.
    //
    // NOTE: In production, use fanotify (FAN_REPORT_TID) for O(1)
    // PID attribution. This /proc scan is a proof-of-concept.
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

        // --- Scan /proc ---
        DIR* proc_dir = opendir("/proc");
        if (!proc_dir) return "unknown";

        struct dirent* entry;
        while ((entry = readdir(proc_dir)) != nullptr) {
            if (entry->d_type != DT_DIR) continue;

            std::string name = entry->d_name;
            if (!std::all_of(name.begin(), name.end(), ::isdigit)) continue;

            int pid = std::stoi(name);
            std::string fd_path = "/proc/" + name + "/fd";
            DIR* fd_dir = opendir(fd_path.c_str());
            if (!fd_dir) continue;

            struct dirent* fd_entry;
            while ((fd_entry = readdir(fd_dir)) != nullptr) {
                if (fd_entry->d_type != DT_LNK) continue;

                // Read symlink target to get the file path
                std::string link_path = fd_path + "/" + fd_entry->d_name;
                char target[PATH_MAX];
                ssize_t len = readlink(link_path.c_str(), target, sizeof(target) - 1);
                if (len == -1) continue;
                target[len] = '\0';

                if (file_path == target) {
                    // Found the process — get its name from /proc/<pid>/comm
                    std::string comm_path = "/proc/" + name + "/comm";
                    std::ifstream comm_file(comm_path);
                    std::string comm;
                    if (comm_file.is_open()) {
                        std::getline(comm_file, comm);
                    }
                    closedir(fd_dir);
                    closedir(proc_dir);

                    std::string result = comm.empty() ? name : comm;

                    // Update cache
                    {
                        std::lock_guard<std::mutex> lock(proc_cache_mutex);
                        proc_cache[file_path] = {result, pid, now};
                    }
                    return result;
                }
            }
            closedir(fd_dir);
        }
        closedir(proc_dir);
        return "unknown";
    }

    // ------------------------------------------------------------
    // Process a single inotify event.
    //
    // Alert logic:
    //   TRIGGER = high entropy (>7.0) OR rate-of-modification exceeded.
    //   Target extension acts as a severity BOOSTER (label), not a trigger.
    // ------------------------------------------------------------
    void process_event(const struct inotify_event* event) {
        if (event->mask & IN_ISDIR) return;

        std::string file_path = watch_root + "/" + event->name;

        if (event->mask & (IN_MODIFY | IN_CREATE | IN_CLOSE_WRITE)) {
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

                // Attribute process via /proc scan
                alert.process_name = get_process_for_file(file_path);
                alert.pid = 0; // /proc scan returns name but PID is cached internally

                // Build detailed description
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
    }

public:
    ~LinuxRansomwareDetector() {
        stop_watch();
    }

    // ------------------------------------------------------------
    // 1. Shannon entropy calculation
    //    H = -Σ p(x) * log2(p(x))
    // ------------------------------------------------------------
    double calculate_entropy(const std::string& file_path) override {
        std::ifstream file(file_path, std::ios::binary);
        if (!file.is_open()) {
            spdlog::error("Could not open file: {}", file_path);
            return 0.0;
        }

        const int BYTE_RANGE = 256;
        std::vector<size_t> freq(BYTE_RANGE, 0);
        size_t total_bytes = 0;

        char buffer[4096];
        while (file.good() && !file.eof()) {
            file.read(buffer, sizeof(buffer));
            std::streamsize bytes_read = file.gcount();
            if (bytes_read == 0) break;
            total_bytes += bytes_read;
            for (std::streamsize i = 0; i < bytes_read; ++i) {
                unsigned char byte = static_cast<unsigned char>(buffer[i]);
                freq[byte]++;
            }
        }
        file.close();

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
    // 2. Directory scanning
    // ------------------------------------------------------------
    std::vector<SuspiciousFile> scan_directory(const std::string& root_directory) override {
        std::vector<SuspiciousFile> suspicious;
        const double ENTROPY_THRESHOLD = 7.0;

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
    // 3. Real-time watcher using inotify
    // ------------------------------------------------------------
    bool start_watch(const std::string& root_directory, AlertCallback cb) override {
        if (watching) {
            spdlog::warn("Monitoring is already active.");
            return false;
        }

        callback = cb;
        watch_root = root_directory;

        inotify_fd = inotify_init1(IN_NONBLOCK);
        if (inotify_fd == -1) {
            spdlog::error("Failed to initialize inotify.");
            return false;
        }

        watch_descriptor = inotify_add_watch(inotify_fd, root_directory.c_str(),
                                             IN_MODIFY | IN_CREATE | IN_CLOSE_WRITE);
        if (watch_descriptor == -1) {
            spdlog::error("Failed to add watch on directory: {}", root_directory);
            close(inotify_fd);
            inotify_fd = -1;
            return false;
        }

        watching = true;
        watch_thread = std::thread([this]() {
            const size_t EVENT_SIZE = sizeof(struct inotify_event) + NAME_MAX + 1;
            char buffer[EVENT_SIZE * 10];

            while (watching) {
                int len = read(inotify_fd, buffer, sizeof(buffer));
                if (len == -1 && errno != EAGAIN) {
                    spdlog::error("Error reading inotify event.");
                    break;
                }
                if (len <= 0) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                }

                int offset = 0;
                while (offset < len) {
                    struct inotify_event* event =
                        reinterpret_cast<struct inotify_event*>(buffer + offset);
                    process_event(event);
                    offset += EVENT_SIZE + event->len;
                }
            }
        });

        spdlog::info("inotify monitoring started for: {}", root_directory);
        return true;
    }

    void stop_watch() override {
        if (!watching) return;
        watching = false;
        if (watch_thread.joinable()) watch_thread.join();
        if (inotify_fd != -1) {
            close(inotify_fd);
            inotify_fd = -1;
        }
        watch_descriptor = -1;
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
    spdlog::info("🛠️ Creating Ransomware Detector for Linux");
    return std::make_unique<LinuxRansomwareDetector>();
}
