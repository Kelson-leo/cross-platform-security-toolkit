#include "IMemoryScanner.hpp"
#include <spdlog/spdlog.h>
#include <iostream>
#include <string>

void print_usage(const char* prog_name) {
    std::cout << "Usage:\n";
    std::cout << "  " << prog_name << " --list                  # List all processes\n";
    std::cout << "  " << prog_name << " --scan <PID>            # Scan a specific process\n";
}

int main(int argc, char* argv[]) {
    spdlog::info("🚀 Anti-Cheat Memory Scanner v1.0");

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    auto scanner = create_memory_scanner();
    if (!scanner) {
        spdlog::error("❌ Failed to create scanner.");
        return 1;
    }

    std::string mode = argv[1];

    if (mode == "--list") {
        auto processes = scanner->list_processes();
        std::cout << "📋 Running processes:\n";
        for (const auto& p : processes) {
            std::cout << "  PID: " << p.pid << " | Name: " << p.name << "\n";
        }
    } else if (mode == "--scan") {
        if (argc < 3) {
            spdlog::error("❌ Provide PID to scan.");
            return 1;
        }
        int pid = std::stoi(argv[2]);
        spdlog::info("🔍 Scanning process PID: {}", pid);
        auto report = scanner->scan_process(pid);
        std::cout << "📊 Report:\n";
        std::cout << "  Process: " << report.process_name << " (PID: " << report.pid << ")\n";
        std::cout << "  .text integrity: " << (report.text_section_integrity_ok ? "✅ OK" : "🚨 Compromised!") << "\n";

        // 🔥 NEW: print suspicious regions (RWX)
        if (!report.injected_regions.empty()) {
            std::cout << "  Suspicious regions:\n";
            for (const auto& region : report.injected_regions) {
                std::cout << "    - " << region << "\n";
            }
        } else {
            std::cout << "  No suspicious regions found.\n";
        }
    } else {
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}
