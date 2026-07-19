#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <memory>
#include <chrono>

// 5-tuple network flow with statistics
struct NetworkFlow {
    // Identification
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol; // TCP=6, UDP=17, ICMP=1

    // Statistics
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;
    size_t packet_count;
    size_t byte_count;
    size_t src_packet_count;
    size_t dst_packet_count;
    size_t src_byte_count;
    size_t dst_byte_count;

    // TCP flags
    bool syn_flag;
    bool ack_flag;
    bool fin_flag;
    bool rst_flag;

    // Timestamp of last classification (for periodic classify dedup)
    std::chrono::steady_clock::time_point last_classified;

    // Duration in seconds
    double duration_seconds() const {
        auto duration = end_time - start_time;
        return std::chrono::duration<double>(duration).count();
    }
};

// Alert produced when a flow is classified
struct NidsAlert {
    std::chrono::system_clock::time_point timestamp;
    NetworkFlow flow;
    std::string classification; // "Malicious" or "Normal"
    double confidence;          // 0.0 to 1.0
    std::string description;
};

// Callback for alerts
using NidsCallback = std::function<void(const NidsAlert&)>;

class INids {
public:
    virtual ~INids() = default;

    // Start packet capture on a network interface
    virtual bool start_capture(const std::string& interface, const std::string& filter = "") = 0;

    // Stop packet capture
    virtual void stop_capture() = 0;

    // Check if capture is running
    virtual bool is_running() const = 0;

    // Load an ML model (Random Forest) from a file
    virtual bool load_model(const std::string& model_path) = 0;

    // Configure detection parameters. Pass 0 to keep the default.
    //   flow_timeout_sec:    idle seconds before finalizing a flow (default: 60)
    //   cleanup_interval_sec: how often to check for triggers (default: 10)
    //   max_duration_sec:    max flow age before forced classify, 0=off (default: 0)
    //   packet_threshold:    classify flow if > N packets, 0=off (default: 0)
    //   byte_threshold:      classify flow if > N bytes, 0=off (default: 0)
    //   periodic_classify_sec: classify ALL active flows every N sec, 0=off (default: 0)
    virtual void set_config(int flow_timeout_sec, int cleanup_interval_sec,
                            int max_duration_sec = 0,
                            int packet_threshold = 0,
                            int byte_threshold = 0,
                            int periodic_classify_sec = 0) = 0;

    // Filter options: show all alerts (verbose) and ignore a specific IP
    virtual void set_filter_options(bool verbose, const std::string& ignore_ip = "") = 0;

    // Output options: alert log file and cross-flow scan threshold
    virtual void set_output_options(const std::string& alert_log = "",
                                    int scan_threshold = 10,
                                    int cross_flow_interval = 30) = 0;

    // Set the alert callback
    virtual void set_alert_callback(NidsCallback callback) = 0;

    // Extract features from a flow into a vector (for ML classification)
    virtual std::vector<double> extract_features(const NetworkFlow& flow) const = 0;

    // Classify a flow (returns label and confidence)
    virtual std::pair<std::string, double> classify_flow(const NetworkFlow& flow) = 0;
};

// Free function for feature extraction (used by NidsEngine and tests)
std::vector<double> extract_flow_features(const NetworkFlow& flow);

// Factory
std::unique_ptr<INids> create_nids();
