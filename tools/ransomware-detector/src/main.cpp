#include "IRansomwareDetector.hpp"
#include <spdlog/spdlog.h>
#include <iostream>
#include <string>
#include <thread>
#include <csignal>
#include <atomic>

std::atomic<bool> running{true};

void signal_handler(int signal) {
    spdlog::info("Received signal {}, shutting down...", signal);
    running = false;
}

void on_alert(const RansomwareAlert& alert) {
    std::cout << "\n🚨 RANSOMWARE ALERT DETECTED!\n";
    std::cout << "================================\n";
    std::cout << "Time: " << std::chrono::system_clock::to_time_t(alert.timestamp) << "\n";
    std::cout << "Process: " << alert.process_name << " (PID: " << alert.pid << ")\n";
    std::cout << "Description: " << alert.description << "\n";
    std::cout << "Suspicious files:\n";
    for (const auto& file : alert.suspicious_files) {
        std::cout << "  - " << file.path << " (entropy: " << file.entropy << ")\n";
    }
    std::cout << "================================\n" << std::endl;
}

void print_usage(const char* prog_name) {
    std::cout << "Usage:\n";
    std::cout << "  " << prog_name << " --watch <directory>      # Monitor a directory in real time\n";
    std::cout << "  " << prog_name << " --scan <directory>       # Scan a directory once\n";
}

int main(int argc, char* argv[]) {
    spdlog::info("🚀 Ransomware Detector v1.0");

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    auto detector = create_ransomware_detector();
    if (!detector) {
        spdlog::error("❌ Failed to create detector.");
        return 1;
    }

    std::string mode = argv[1];

    if (mode == "--watch") {
        if (argc < 3) {
            spdlog::error("❌ Provide directory to monitor.");
            return 1;
        }
        std::string target_dir = argv[2];
        spdlog::info("👀 Monitoring directory: {}", target_dir);

        if (detector->start_watch(target_dir, on_alert)) {
            spdlog::info("Monitoring started. Press Ctrl+C to stop.");
            while (running) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            detector->stop_watch();
            spdlog::info("✅ Monitoring finished.");
        } else {
            spdlog::error("❌ Failed to start monitoring.");
            return 1;
        }
    } else if (mode == "--scan") {
        if (argc < 3) {
            spdlog::error("❌ Provide directory to scan.");
            return 1;
        }
        std::string target_dir = argv[2];
        spdlog::info("🔍 Scanning directory: {}", target_dir);

        auto suspicious = detector->scan_directory(target_dir);
        std::cout << "\n📊 Scan report:\n";
        std::cout << "================================\n";
        if (suspicious.empty()) {
            std::cout << "✅ No suspicious files found.\n";
        } else {
            std::cout << "⚠️ Found " << suspicious.size() << " suspicious files:\n";
            for (const auto& file : suspicious) {
                std::cout << "  - " << file.path << " (entropy: " << file.entropy << ")\n";
            }
        }
        std::cout << "================================\n";
    } else {
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}
