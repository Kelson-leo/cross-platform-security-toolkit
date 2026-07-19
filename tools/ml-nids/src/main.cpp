#include "INids.hpp"
#include <spdlog/spdlog.h>
#include <iostream>
#include <string>
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>
#include <pthread.h>

std::atomic<bool> running{true};

// Dedicated signal-handling thread using sigwait().
// SIGINT/SIGTERM are BLOCKED in all threads via pthread_sigmask().
// Only this thread receives them via sigwait(), a normal function
// with no async-signal-safety restrictions.
void signal_thread_func() {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);

    int sig = 0;
    sigwait(&set, &sig);

    std::cerr << "\n[SIGNAL] Caught signal " << sig << ", shutting down..." << std::endl;
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
    std::cout << "  " << prog_name << " --interface <iface> [--filter 'tcp'] [--model <path>]\n";
    std::cout << "  " << prog_name << " --model <path>  (dry-run: loads model only)\n";
    std::cout << "Options:\n";
    std::cout << "  --flow-timeout <sec>    Idle seconds before finalizing a flow (default: 60)\n";
    std::cout << "  --cleanup-interval <sec> How often to check for triggers (default: 10)\n";
    std::cout << "  --max-duration <sec>    Max flow age before forced classify, 0=off (default: 0)\n";
    std::cout << "  --packet-threshold <N>  Classify if flow exceeds N packets, 0=off (default: 0)\n";
    std::cout << "  --byte-threshold <N>    Classify if flow exceeds N bytes, 0=off (default: 0)\n";
    std::cout << "  --periodic-classify <N> Classify all active flows every N secs, 0=off (default: 0)\n";
}

int main(int argc, char* argv[]) {
    spdlog::info("ML-NIDS v1.0");

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    // Block SIGINT and SIGTERM in the main thread.
    // Child threads inherit the signal mask, so signals are blocked
    // everywhere except in the dedicated sigwait() thread.
    sigset_t block_set;
    sigemptyset(&block_set);
    sigaddset(&block_set, SIGINT);
    sigaddset(&block_set, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &block_set, nullptr);

    // Spawn signal-handling thread — the ONLY thread that can receive signals.
    std::thread sig_thread(signal_thread_func);

    auto nids = create_nids();
    if (!nids) {
        spdlog::error("Failed to create NIDS engine.");
        running = false;
        sig_thread.join();
        return 1;
    }

    // Parse CLI arguments
    std::string interface;
    std::string filter;
    std::string model_path;
    int flow_timeout = 0;       // 0 = use default (60s)
    int cleanup_interval = 0;   // 0 = use default (10s)
    int max_duration = 0;       // 0 = disabled
    int packet_threshold = 0;   // 0 = disabled
    int byte_threshold = 0;     // 0 = disabled
    int periodic_classify = 0;  // 0 = disabled

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--interface" && i + 1 < argc) {
            interface = argv[++i];
        } else if (arg == "--filter" && i + 1 < argc) {
            filter = argv[++i];
        } else if (arg == "--model" && i + 1 < argc) {
            model_path = argv[++i];
        } else if (arg == "--flow-timeout" && i + 1 < argc) {
            flow_timeout = std::stoi(argv[++i]);
        } else if (arg == "--cleanup-interval" && i + 1 < argc) {
            cleanup_interval = std::stoi(argv[++i]);
        } else if (arg == "--max-duration" && i + 1 < argc) {
            max_duration = std::stoi(argv[++i]);
        } else if (arg == "--packet-threshold" && i + 1 < argc) {
            packet_threshold = std::stoi(argv[++i]);
        } else if (arg == "--byte-threshold" && i + 1 < argc) {
            byte_threshold = std::stoi(argv[++i]);
        } else if (arg == "--periodic-classify" && i + 1 < argc) {
            periodic_classify = std::stoi(argv[++i]);
        }
    }

    // Load ML model
    if (!model_path.empty()) {
        if (!nids->load_model(model_path)) {
            spdlog::error("Failed to load model. Continuing with heuristic fallback.");
        }
    } else {
        spdlog::warn("No model specified (use --model). Falling back to heuristic only.");
    }

    // Apply configurable timeouts
    nids->set_config(flow_timeout, cleanup_interval, max_duration,
                     packet_threshold, byte_threshold, periodic_classify);

    // Set alert callback
    nids->set_alert_callback(on_alert);

    // If no interface given but model was loaded, just exit (dry-run mode)
    if (interface.empty()) {
        spdlog::info("No interface specified. Model loaded. Exiting (dry-run).");
        running = false;
        sig_thread.join();
        return 0;
    }

    if (nids->start_capture(interface, filter)) {
        spdlog::info("NIDS running on interface: {}", interface);
        spdlog::info("Press Ctrl+C to stop.");

        // Signals are blocked here, so sleep_for is never interrupted.
        while (running) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        nids->stop_capture();
        spdlog::info("NIDS finished.");
    } else {
        spdlog::error("Failed to start NIDS.");
        running = false;
        sig_thread.join();
        return 1;
    }

    sig_thread.join();
    return 0;
}
