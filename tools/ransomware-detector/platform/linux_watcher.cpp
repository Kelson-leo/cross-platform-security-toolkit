#include "IRansomwareDetector.hpp"
#include <spdlog/spdlog.h>

class LinuxRansomwareDetector : public IRansomwareDetector {
public:
    bool start_watch(const std::string& root_directory, AlertCallback callback) override {
        spdlog::info("[Linux] Starting monitoring on: {}", root_directory);
        // Placeholder: future inotify implementation
        return true;
    }

    void stop_watch() override {
        spdlog::info("[Linux] Stopping monitoring");
    }

    bool is_watching() const override {
        return false;
    }

    double calculate_entropy(const std::string& file_path) override {
        // Placeholder: returns fixed entropy for testing
        return 4.5;
    }

    std::vector<SuspiciousFile> scan_directory(const std::string& root_directory) override {
        spdlog::info("[Linux] Scanning directory: {}", root_directory);
        // Placeholder: returns empty list
        return {};
    }
};

std::unique_ptr<IRansomwareDetector> create_ransomware_detector() {
    spdlog::info("🛠️ Creating Ransomware Detector for Linux");
    return std::make_unique<LinuxRansomwareDetector>();
}
