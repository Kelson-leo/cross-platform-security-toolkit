#include "INids.hpp"
#include <spdlog/spdlog.h>
#include <iostream>
#include <string>
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>
#include <pthread.h>
#include <unistd.h>

std::atomic<bool> running{true};

#define TRACE(msg) do { write(STDERR_FILENO, msg "\n", sizeof(msg)); } while(0)

// Dedicated signal-handling thread using sigwait().
// SIGINT/SIGTERM are BLOCKED in the main thread and inherited by all threads.
// Only this thread can receive them, and sigwait() is a normal (non-async)
// function — no restrictions, no deadlocks, no kernel weirdness.
void signal_thread_func() {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);

    int sig = 0;
    sigwait(&set, &sig);

    TRACE("[TRACE] signal_thread: sigwait returned, setting running=false");
    running = false;
    TRACE("[TRACE] signal_thread: running=false set, thread exiting");
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
    TRACE("[TRACE] main: signals blocked, spawning signal thread");

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

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--interface" && i + 1 < argc) {
            interface = argv[++i];
        } else if (arg == "--filter" && i + 1 < argc) {
            filter = argv[++i];
        } else if (arg == "--model" && i + 1 < argc) {
            model_path = argv[++i];
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

        TRACE("[TRACE] main: entering main loop (sleep_for 100ms)");
        // Signals are blocked here, so sleep_for is never interrupted.
        while (running) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            // Uncomment below to see every wakeup (very verbose):
            // TRACE("[TRACE] main: sleep_for returned, checking running");
        }
        TRACE("[TRACE] main: while(running) exited (running=false)");

        TRACE("[TRACE] main: calling nids->stop_capture()...");
        nids->stop_capture();
        TRACE("[TRACE] main: nids->stop_capture() returned");
        spdlog::info("NIDS finished.");
    } else {
        spdlog::error("Failed to start NIDS.");
        running = false;
        sig_thread.join();
        return 1;
    }

    TRACE("[TRACE] main: joining signal thread...");
    sig_thread.join();
    TRACE("[TRACE] main: exiting normally");
    return 0;
}
