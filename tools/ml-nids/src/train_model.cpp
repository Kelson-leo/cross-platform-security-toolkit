#include <mlpack.hpp>
#include <armadillo>
#include <spdlog/spdlog.h>
#include <iostream>
#include <random>
#include <cmath>
#include <fstream>
#include <string>

// ------------------------------------------------------------
// Standalone utility to train a Random Forest model.
// Generates realistic synthetic data with 3 traffic profiles
// (Normal, Port Scanning, DoS/DDoS) matching the 14 features
// extracted by FeatureExtractor.
//
// Usage: ./train_model [output_path]
//   Default output: models/nids_model.bin
// ------------------------------------------------------------

namespace {

// Generate one flow sample with 14 features matching the NIDS extractor.
// type: 0 = Normal, 1 = Port Scanning, 2 = DoS/DDoS
arma::vec generate_flow(int type, std::mt19937& rng) {
    std::uniform_real_distribution<double> unif(0.0, 1.0);
    std::exponential_distribution<double> exp_dist(1.0);
    std::poisson_distribution<int> poisson(15);

    double duration;
    double packet_count;
    double byte_count;
    double syn_flag, ack_flag, fin_flag, rst_flag;
    int protocol = 6; // TCP

    if (type == 0) {
        // ---- Normal traffic ----
        duration     = exp_dist(rng) * 1.5;
        packet_count = static_cast<double>(std::max(1, poisson(rng)));
        byte_count   = packet_count * (200.0 + unif(rng) * 600.0);
        syn_flag     = unif(rng) < 0.3 ? 1.0 : 0.0;
        ack_flag     = unif(rng) < 0.7 ? 1.0 : 0.0;
        fin_flag     = unif(rng) < 0.2 ? 1.0 : 0.0;
        rst_flag     = unif(rng) < 0.1 ? 1.0 : 0.0;

    } else if (type == 1) {
        // ---- Port Scanning ----
        duration     = 0.1 + unif(rng) * 1.9;
        packet_count = static_cast<double>(poisson(rng) * 2 + 5);
        byte_count   = packet_count * (100.0 + unif(rng) * 200.0);
        syn_flag     = unif(rng) < 0.9 ? 1.0 : 0.0;   // 90% SYN
        ack_flag     = unif(rng) < 0.2 ? 1.0 : 0.0;
        fin_flag     = 0.0;
        rst_flag     = unif(rng) < 0.4 ? 1.0 : 0.0;

    } else {
        // ---- DoS / DDoS ----
        duration     = 0.5 + unif(rng) * 9.5;
        packet_count = static_cast<double>(poisson(rng) * 15 + 50);
        byte_count   = packet_count * (400.0 + unif(rng) * 1100.0);
        syn_flag     = unif(rng) < 0.7 ? 1.0 : 0.0;
        ack_flag     = unif(rng) < 0.6 ? 1.0 : 0.0;
        fin_flag     = unif(rng) < 0.3 ? 1.0 : 0.0;
        rst_flag     = unif(rng) < 0.2 ? 1.0 : 0.0;
    }

    // Source/destination packet and byte ratios
    double ratio       = 0.3 + unif(rng) * 0.4;
    double src_packets = packet_count * ratio;
    double dst_packets = packet_count - src_packets;
    double src_bytes   = byte_count * ratio;
    double dst_bytes   = byte_count - src_bytes;

    // Derived features
    double packet_rate  = packet_count / (duration + 0.01);
    double avg_pkt_size = byte_count / (packet_count + 1.0);

    // Protocol one-hot encoding
    double tcp  = (protocol == 6)  ? 1.0 : 0.0;
    double udp  = (protocol == 17) ? 1.0 : 0.0;
    double icmp = (protocol == 1)  ? 1.0 : 0.0;

    arma::vec features(14);
    features(0)  = duration;
    features(1)  = std::log1p(packet_count);
    features(2)  = std::log1p(byte_count);
    features(3)  = src_packets / (dst_packets + 1.0);
    features(4)  = src_bytes / (dst_bytes + 1.0);
    features(5)  = packet_rate;
    features(6)  = avg_pkt_size;
    features(7)  = syn_flag;
    features(8)  = ack_flag;
    features(9)  = fin_flag;
    features(10) = rst_flag;
    features(11) = tcp;
    features(12) = udp;
    features(13) = icmp;

    return features;
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    constexpr size_t num_samples  = 10000;
    constexpr size_t num_features = 14;
    constexpr size_t num_classes  = 2;   // 0 = Normal, 1 = Malicious
    constexpr size_t num_trees    = 50;

    std::string output_path = "models/nids_model.bin";
    if (argc > 1) {
        output_path = argv[1];
    }

    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_real_distribution<double> type_roll(0.0, 1.0);

    spdlog::info("Generating {} synthetic training samples (3 profiles)...",
                 num_samples);

    arma::mat features(num_features, num_samples);
    arma::Row<size_t> labels(num_samples);

    int count_normal = 0, count_scan = 0, count_dos = 0;

    for (size_t i = 0; i < num_samples; ++i) {
        double roll = type_roll(rng);
        int type;
        if (roll < 0.50) {
            type = 0; // 50% Normal
            count_normal++;
        } else if (roll < 0.75) {
            type = 1; // 25% Port Scanning
            count_scan++;
        } else {
            type = 2; // 25% DoS/DDoS
            count_dos++;
        }

        features.col(i) = generate_flow(type, rng);
        labels(i) = (type == 0) ? 0 : 1;
    }

    spdlog::info("Distribution: Normal={}, Scanning={}, DoS={}",
                 count_normal, count_scan, count_dos);

    spdlog::info("Training Random Forest ({} trees, {} classes)...",
                 num_trees, num_classes);

    try {
        mlpack::tree::RandomForest<> model(features, labels,
                                           num_classes, num_trees);

        spdlog::info("Saving model to: {}", output_path);
        mlpack::data::Save(output_path, "nids_model", model);

        // Quick validation
        arma::Row<size_t> predictions;
        model.Classify(features, predictions);

        size_t correct = 0;
        for (size_t i = 0; i < num_samples; ++i) {
            if (predictions(i) == labels(i)) correct++;
        }
        double accuracy = 100.0 * correct / num_samples;

        spdlog::info("Training accuracy: {:.1f}% ({}/{})",
                     accuracy, correct, num_samples);
        spdlog::info("Model saved successfully ({} bytes).",
                     std::to_string(static_cast<int>(
                         std::ifstream(output_path, std::ios::ate).tellg())));
        return 0;

    } catch (const std::exception& e) {
        spdlog::error("Training failed: {}", e.what());
        return 1;
    }
}
