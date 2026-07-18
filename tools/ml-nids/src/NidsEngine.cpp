#include "INids.hpp"
#include "FeatureExtractor.hpp"
#include <spdlog/spdlog.h>
#include <mlpack.hpp>
#include <armadillo>
#include <thread>

class NidsEngine : public INids {
private:
    bool running = false;
    NidsCallback callback;
    mlpack::tree::RandomForest<> model;
    bool model_loaded = false;

    // Placeholder capture loop — replaced by platform/ at build time
    void dummy_capture_loop() {
        spdlog::info("Starting dummy capture loop (placeholder)");
        // Simulate 5 test flows
        for (int i = 0; i < 5; ++i) {
            NetworkFlow flow;
            flow.src_ip = "192.168.1.1";
            flow.dst_ip = "8.8.8.8";
            flow.src_port = 54321 + i;
            flow.dst_port = 80 + i;
            flow.protocol = 6; // TCP
            flow.packet_count = 100 + i * 10;
            flow.byte_count = flow.packet_count * 1200;
            flow.src_packet_count = flow.packet_count / 2;
            flow.dst_packet_count = flow.packet_count / 2;
            flow.src_byte_count = flow.byte_count / 2;
            flow.dst_byte_count = flow.byte_count / 2;
            flow.syn_flag = true;
            flow.ack_flag = true;
            flow.fin_flag = false;
            flow.rst_flag = false;
            flow.start_time = std::chrono::steady_clock::now();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            flow.end_time = std::chrono::steady_clock::now();

            auto [label, confidence] = classify_flow(flow);
            NidsAlert alert;
            alert.timestamp = std::chrono::system_clock::now();
            alert.flow = flow;
            alert.classification = label;
            alert.confidence = confidence;
            alert.description = "Flow classified as " + label
                + " (confidence: " + std::to_string(confidence) + ")";
            if (callback) callback(alert);

            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

public:
    bool start_capture(const std::string& interface, const std::string& filter = "") override {
        if (running) {
            spdlog::warn("Capture is already running.");
            return false;
        }
        running = true;
        spdlog::info("Starting NIDS (placeholder) on interface: {}", interface);
        std::thread([this]() { dummy_capture_loop(); running = false; }).detach();
        return true;
    }

    void stop_capture() override {
        running = false;
        spdlog::info("Stopping NIDS");
    }

    bool is_running() const override {
        return running;
    }

    bool load_model(const std::string& model_path) override {
        spdlog::info("Loading ML model from: {}", model_path);
        // Train a simple Random Forest on synthetic data as placeholder.
        // In production this would deserialize a pre-trained model from disk.
        try {
            arma::mat features(14, 100); // 14 features, 100 samples
            arma::Row<size_t> labels(100);
            for (size_t i = 0; i < 100; ++i) {
                labels(i) = (i < 50) ? 0 : 1; // 0 = normal, 1 = malicious
                for (size_t f = 0; f < 14; ++f) {
                    features(f, i) = arma::randn() * (labels(i) == 0 ? 0.5 : 1.5)
                                     + (labels(i) == 0 ? 1 : 5);
                }
            }
            model = mlpack::tree::RandomForest<>(features, labels, 2, 5);
            model_loaded = true;
            spdlog::info("ML model trained on synthetic data (placeholder)");
            return true;
        } catch (const std::exception& e) {
            spdlog::error("Failed to train model: {}", e.what());
            return false;
        }
    }

    void set_alert_callback(NidsCallback cb) override {
        callback = cb;
    }

    std::vector<double> extract_features(const NetworkFlow& flow) const override {
        return extract_flow_features(flow);
    }

    std::pair<std::string, double> classify_flow(const NetworkFlow& flow) override {
        if (!model_loaded) {
            // Heuristic fallback when no model is loaded
            if (flow.packet_count > 1000 && flow.duration_seconds() < 5.0) {
                return {"Malicious", 0.9};
            }
            return {"Normal", 0.8};
        }

        // Extract features and convert to Armadillo matrix
        auto features_vec = extract_features(flow);
        arma::mat features_mat(features_vec.data(), features_vec.size(), 1);

        // Classify
        arma::Row<size_t> predictions;
        model.Classify(features_mat, predictions);

        // Simplified confidence (placeholder)
        double confidence = 0.7 + 0.3 * arma::randu();

        std::string label = (predictions(0) == 1) ? "Malicious" : "Normal";
        return {label, confidence};
    }
};

// ------------------------------------------------------------
// Factory — creates a dummy NIDS engine (used only by tests)
// ------------------------------------------------------------
std::unique_ptr<INids> create_nids() {
    spdlog::info("Creating NIDS Engine (dummy for tests)");
    return std::make_unique<NidsEngine>();
}
