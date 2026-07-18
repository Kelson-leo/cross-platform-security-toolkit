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
