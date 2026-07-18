#include "IRansomwareDetector.hpp"
#include <spdlog/spdlog.h>

#include <fstream>
#include <cmath>
#include <filesystem>

namespace fs = std::filesystem;

class WindowsRansomwareDetector : public IRansomwareDetector {
public:
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
    // 3. Watcher (placeholder — future ReadDirectoryChangesW)
    // ------------------------------------------------------------
    bool start_watch(const std::string& root_directory, AlertCallback callback) override {
        spdlog::info("[Windows] Starting monitoring on: {}", root_directory);
        // Placeholder: future ReadDirectoryChangesW implementation
        return true;
    }

    void stop_watch() override {
        spdlog::info("[Windows] Stopping monitoring");
    }

    bool is_watching() const override {
        return false;
    }
};

// ------------------------------------------------------------
// Factory
// ------------------------------------------------------------
std::unique_ptr<IRansomwareDetector> create_ransomware_detector() {
    spdlog::info("🛠️ Creating Ransomware Detector for Windows");
    return std::make_unique<WindowsRansomwareDetector>();
}
