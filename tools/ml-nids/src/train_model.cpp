#include <mlpack.hpp>
#include <armadillo>
#include <spdlog/spdlog.h>
#include <iostream>
#include <cstdlib>
#include <ctime>
#include <cmath>

// ------------------------------------------------------------
// Standalone utility to train a Random Forest model.
// Generates synthetic data matching the 14 features extracted
// by FeatureExtractor, trains the model, and saves it via
// mlpack's native serialization so load_model() can read it.
//
// Usage: ./train_model [output_path]
//   Default output: models/nids_model.bin
// ------------------------------------------------------------

int main(int argc, char* argv[]) {
    std::srand(static_cast<unsigned>(std::time(nullptr)));

    const size_t num_samples = 5000;
    const size_t num_features = 14;
    const size_t num_trees = 50;
    const size_t num_classes = 2;

    std::string output_path = "models/nids_model.bin";
    if (argc > 1) {
        output_path = argv[1];
    }

    spdlog::info("Generating {} synthetic training samples ({} features)...",
                 num_samples, num_features);

    arma::mat features(num_features, num_samples);
    arma::Row<size_t> labels(num_samples);

    for (size_t i = 0; i < num_samples; ++i) {
        bool malicious = (std::rand() % 100) < 40; // 40% malicious
        labels(i) = malicious ? 1 : 0;

        double duration, packet_count, byte_count;
        double src_packets, dst_packets, src_bytes, dst_bytes;
        double syn, ack, fin, rst, proto_tcp, proto_udp, proto_icmp;
        int proto;

        if (malicious) {
            // ---- Malicious traffic patterns ----
            duration      = 0.1 + 4.9 * (static_cast<double>(std::rand()) / RAND_MAX);
            packet_count  = 100.0 + 4900.0 * (static_cast<double>(std::rand()) / RAND_MAX);
            byte_count    = packet_count * (100.0 + 1400.0 * (static_cast<double>(std::rand()) / RAND_MAX));
            src_packets   = packet_count * (0.6 + 0.3 * (static_cast<double>(std::rand()) / RAND_MAX));
            dst_packets   = packet_count - src_packets;
            src_bytes     = byte_count * (0.6 + 0.3 * (static_cast<double>(std::rand()) / RAND_MAX));
            dst_bytes     = byte_count - src_bytes;
            proto         = (std::rand() % 10 < 7) ? 6 : ((std::rand() % 10 < 8) ? 17 : 1);
            syn           = (std::rand() % 100 < 90) ? 1.0 : 0.0;
            ack           = (std::rand() % 100 < 80) ? 1.0 : 0.0;
            fin           = (std::rand() % 100 < 40) ? 1.0 : 0.0;
            rst           = (std::rand() % 100 < 50) ? 1.0 : 0.0;
        } else {
            // ---- Normal traffic patterns ----
            duration      = 0.01 + 1.99 * (static_cast<double>(std::rand()) / RAND_MAX);
            packet_count  = 1.0 + 99.0 * (static_cast<double>(std::rand()) / RAND_MAX);
            byte_count    = packet_count * (100.0 + 700.0 * (static_cast<double>(std::rand()) / RAND_MAX));
            src_packets   = packet_count * (0.3 + 0.4 * (static_cast<double>(std::rand()) / RAND_MAX));
            dst_packets   = packet_count - src_packets;
            src_bytes     = byte_count * (0.3 + 0.4 * (static_cast<double>(std::rand()) / RAND_MAX));
            dst_bytes     = byte_count - src_bytes;
            proto         = (std::rand() % 10 < 8) ? 6 : ((std::rand() % 10 < 9) ? 17 : 1);
            syn           = (std::rand() % 100 < 30) ? 1.0 : 0.0;
            ack           = (std::rand() % 100 < 70) ? 1.0 : 0.0;
            fin           = (std::rand() % 100 < 20) ? 1.0 : 0.0;
            rst           = (std::rand() % 100 < 10) ? 1.0 : 0.0;
        }

        // Feature vector (same order as FeatureExtractor::extract_flow_features)
        features(0, i)  = duration;
        features(1, i)  = std::log1p(packet_count);
        features(2, i)  = std::log1p(byte_count);
        features(3, i)  = src_packets / (dst_packets + 1.0);
        features(4, i)  = src_bytes / (dst_bytes + 1.0);
        features(5, i)  = packet_count / (duration + 0.01);
        features(6, i)  = byte_count / (packet_count + 1.0);
        features(7, i)  = syn;
        features(8, i)  = ack;
        features(9, i)  = fin;
        features(10, i) = rst;
        features(11, i) = (proto == 6)  ? 1.0 : 0.0;  // TCP
        features(12, i) = (proto == 17) ? 1.0 : 0.0;  // UDP
        features(13, i) = (proto == 1)  ? 1.0 : 0.0;  // ICMP
    }

    spdlog::info("Training Random Forest ({} trees, {} classes)...",
                 num_trees, num_classes);

    try {
        mlpack::tree::RandomForest<> model(
            features, labels, num_classes, num_trees);

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
        spdlog::info("Model saved successfully.");
        return 0;

    } catch (const std::exception& e) {
        spdlog::error("Training failed: {}", e.what());
        return 1;
    }
}
