#include "INids.hpp"
#include <spdlog/spdlog.h>
#include <iostream>
#include <string>
#include <csignal>
#include <atomic>
#include <thread>

std::atomic<bool> running{true};

void signal_handler(int signal) {
    spdlog::info("Received signal {}, shutting down...", signal);
    running = false;
}

void on_alert(const NidsAlert& alert) {
    std::cout << "\nNIDS ALERT!\n";
    std::cout << "================================\n";
    std::cout << "Time: " << std::chrono::system_clock::to_time_t(alert.timestamp) << "\n";
    std::cout << "Classification: " << alert.classification
              << " (confidence: " << alert.confidence << ")\n";
    std::cout << "Description: " << alert.description << "\n";
    std::cout << "Flow:\n";
    std::cout << "  Source: " << alert.flow.src_ip << ":" << alert.flow.src_port << "\n";
    std::cout << "  Destination: " << alert.flow.dst_ip << ":" << alert.flow.dst_port << "\n";
    std::cout << "  Protocol: " << static_cast<int>(alert.flow.protocol) << "\n";
    std::cout << "  Packets: " << alert.flow.packet_count << "\n";
    std::cout << "  Bytes: " << alert.flow.byte_count << "\n";
    std::cout << "  Duration: " << alert.flow.duration_seconds() << "s\n";
    std::cout << "================================\n\n";
}

void print_usage(const char* prog_name) {
    std::cout << "Usage:\n";
    std::cout << "  " << prog_name << " --interface <eth0> [--filter 'tcp']\n";
    std::cout << "  " << prog_name << " --load-model <model.json>\n";
}

int main(int argc, char* argv[]) {
    spdlog::info("ML-NIDS v1.0");

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    auto nids = create_nids();
    if (!nids) {
        spdlog::error("Failed to create NIDS engine.");
        return 1;
    }

    // Load model (placeholder)
    nids->load_model("");

    // Set alert callback
    nids->set_alert_callback(on_alert);

    // Parse CLI arguments
    std::string interface = "eth0";
    std::string filter = "";
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--interface" && i + 1 < argc) {
            interface = argv[++i];
        } else if (arg == "--filter" && i + 1 < argc) {
            filter = argv[++i];
        }
    }

    if (nids->start_capture(interface, filter)) {
        spdlog::info("NIDS running on interface: {}", interface);
        while (running) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        nids->stop_capture();
        spdlog::info("NIDS finished.");
    } else {
        spdlog::error("Failed to start NIDS.");
        return 1;
    }

    return 0;
}
