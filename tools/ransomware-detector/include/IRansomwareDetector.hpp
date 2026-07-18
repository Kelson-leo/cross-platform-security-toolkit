#pragma once

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <functional>

// Structure representing a suspicious file
struct SuspiciousFile {
    std::string path;
    size_t size;
    double entropy;          // 0.0 to 8.0 (high = encrypted)
    std::chrono::system_clock::time_point timestamp;
};

// Structure for alerts
struct RansomwareAlert {
    std::chrono::system_clock::time_point timestamp;
    std::string process_name;   // Process that is writing the files
    int pid;
    std::vector<SuspiciousFile> suspicious_files;
    std::string description;
};

// Callback for alert notifications
using AlertCallback = std::function<void(const RansomwareAlert&)>;

class IRansomwareDetector {
public:
    virtual ~IRansomwareDetector() = default;

    // Start real-time monitoring of a directory
    // Parameters:
    //   - root_directory: folder to monitor (e.g. "/home/user/Documents")
    //   - callback: function called when an alert is triggered
    // Returns: true on success, false on error (e.g. folder does not exist)
    virtual bool start_watch(const std::string& root_directory, AlertCallback callback) = 0;

    // Stop monitoring
    virtual void stop_watch() = 0;

    // Check if monitoring is active
    virtual bool is_watching() const = 0;

    // Scan a single file and return its entropy
    virtual double calculate_entropy(const std::string& file_path) = 0;

    // Scan an entire directory (single scan) and return suspicious files
    virtual std::vector<SuspiciousFile> scan_directory(const std::string& root_directory) = 0;
};

// Factory
std::unique_ptr<IRansomwareDetector> create_ransomware_detector();
