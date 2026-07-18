#include "FeatureExtractor.hpp"
#include <cmath>

// ------------------------------------------------------------
// Extract numerical features from a network flow for ML classification.
// Returns 14 features: duration, packet/byte counts (log scale),
// ratios, packet rate, avg size, TCP flags (4), protocol one-hot (3).
// ------------------------------------------------------------
std::vector<double> extract_flow_features(const NetworkFlow& flow) {
    std::vector<double> features;

    // 1. Duration (seconds)
    features.push_back(flow.duration_seconds());

    // 2. Total packet count (log scale for normalization)
    features.push_back(std::log1p(flow.packet_count));

    // 3. Total byte count (log scale)
    features.push_back(std::log1p(flow.byte_count));

    // 4. Source/destination packet ratio
    features.push_back(static_cast<double>(flow.src_packet_count) / (flow.dst_packet_count + 1));

    // 5. Source/destination byte ratio
    features.push_back(static_cast<double>(flow.src_byte_count) / (flow.dst_byte_count + 1));

    // 6. Packets per second
    double duration = flow.duration_seconds();
    features.push_back(duration > 0 ? flow.packet_count / duration : 0.0);

    // 7. Average packet size (bytes / packets)
    features.push_back(flow.packet_count > 0 ? flow.byte_count / flow.packet_count : 0.0);

    // 8-11. TCP flags
    if (flow.protocol == 6) { // TCP
        features.push_back(flow.syn_flag ? 1.0 : 0.0);
        features.push_back(flow.ack_flag ? 1.0 : 0.0);
        features.push_back(flow.fin_flag ? 1.0 : 0.0);
        features.push_back(flow.rst_flag ? 1.0 : 0.0);
    } else {
        // Non-TCP: fill with zero
        features.push_back(0.0); // syn
        features.push_back(0.0); // ack
        features.push_back(0.0); // fin
        features.push_back(0.0); // rst
    }

    // 12-14. Protocol one-hot encoding (TCP, UDP, ICMP)
    if (flow.protocol == 6) {
        features.push_back(1.0);
        features.push_back(0.0);
        features.push_back(0.0);
    } else if (flow.protocol == 17) {
        features.push_back(0.0);
        features.push_back(1.0);
        features.push_back(0.0);
    } else if (flow.protocol == 1) {
        features.push_back(0.0);
        features.push_back(0.0);
        features.push_back(1.0);
    } else {
        features.push_back(0.0);
        features.push_back(0.0);
        features.push_back(0.0);
    }

    return features;
}
