#include "IRansomwareDetector.hpp"
#include <spdlog/spdlog.h>

#include <fstream>
#include <cmath>
#include <filesystem>
#include <thread>
#include <atomic>
#include <cstring>
#include <sys/inotify.h>
#include <climits>
#include <unistd.h>

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
    double entropy_threshold = 7.0;

    // ------------------------------------------------------------
    // Process a single inotify event
    // ------------------------------------------------------------
    void process_event(const struct inotify_event* event) {
        // Build the full file path
        std::string file_path = watch_root + "/" + event->name;

        // Skip directories
        if (event->mask & IN_ISDIR) return;

        // Check for modification or creation events
        if (event->mask & (IN_MODIFY | IN_CREATE | IN_CLOSE_WRITE)) {
            spdlog::debug("File modified/created: {}", file_path);

            // Calculate entropy of the modified file
            double entropy = calculate_entropy(file_path);
            if (entropy > entropy_threshold) {
                // Trigger alert
                RansomwareAlert alert;
                alert.timestamp = std::chrono::system_clock::now();
                alert.process_name = "unknown"; // TODO: obtain via /proc or fanotify
                alert.pid = 0;
                alert.description = "High entropy file detected!";

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
    // ------------------------------------------------------------
    // Destructor: ensure watcher is stopped
    // ------------------------------------------------------------
    ~LinuxRansomwareDetector() {
        stop_watch();
    }

    // ------------------------------------------------------------
    // 1. Shannon entropy calculation
    //
    // H = -Σ p(x) * log2(p(x))
    //
    // A value near 8.0 indicates compressed/encrypted data.
    // ------------------------------------------------------------
    double calculate_entropy(const std::string& file_path) override {
        std::ifstream file(file_path, std::ios::binary);
        if (!file.is_open()) {
            spdlog::error("Could not open file: {}", file_path);
            return 0.0;
        }

        // Count frequency of each byte (0-255)
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

        // Compute entropy
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
    //    the threshold.
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

        // Initialize inotify
        inotify_fd = inotify_init1(IN_NONBLOCK);
        if (inotify_fd == -1) {
            spdlog::error("Failed to initialize inotify.");
            return false;
        }

        // Add watch on the root directory
        watch_descriptor = inotify_add_watch(inotify_fd, root_directory.c_str(),
                                             IN_MODIFY | IN_CREATE | IN_CLOSE_WRITE);
        if (watch_descriptor == -1) {
            spdlog::error("Failed to add watch on directory: {}", root_directory);
            close(inotify_fd);
            inotify_fd = -1;
            return false;
        }

        // Start background watcher thread
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
