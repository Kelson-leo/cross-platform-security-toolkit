#include <mlpack.hpp>
#include <armadillo>
#include <spdlog/spdlog.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cmath>
#include <set>
#include <random>
#include <algorithm>

// ------------------------------------------------------------
// Train a Random Forest model using the NSL-KDD dataset.
// Maps NSL-KDD's 41 features → our 14-feature extractor format.
//
// Usage: ./train_model [kdd_train_path] [output_path]
//   Defaults: data/KDDTrain+.txt → models/nids_model.bin
// ------------------------------------------------------------

namespace {

// Split CSV line by comma, respecting the NSL-KDD format
std::vector<std::string> split_csv(const std::string& line) {
    std::vector<std::string> cols;
    std::string field;
    for (char c : line) {
        if (c == ',') {
            cols.push_back(field);
            field.clear();
        } else {
            field += c;
        }
    }
    if (!field.empty()) cols.push_back(field);
    return cols;
}

// NSL-KDD flag → TCP flag mapping
struct TcpFlags {
    double syn = 0.0;
    double ack = 0.0;
    double fin = 0.0;
    double rst = 0.0;
};

TcpFlags flag_to_tcp(const std::string& flag) {
    // SF  = normal (SYN → ACK → FIN)
    // S0  = connection attempt, no reply (SYN only)
    // S1  = established (SYN, ACK)
    // S2  = originator closed (SYN, ACK, FIN)
    // S3  = responder closed (SYN, ACK, FIN)
    // REJ = rejected (SYN, RST)
    // RSTO = originator aborted (SYN, ACK, RST)
    // RSTOS0 = originator sent SYN, responder sent RST (SYN, RST)
    // OTH = no SYN seen (mid-stream)
    if (flag == "SF")  return {1.0, 1.0, 1.0, 0.0};
    if (flag == "S0")  return {1.0, 0.0, 0.0, 0.0};
    if (flag == "S1")  return {1.0, 1.0, 0.0, 0.0};
    if (flag == "S2")  return {1.0, 1.0, 1.0, 0.0};
    if (flag == "S3")  return {1.0, 1.0, 1.0, 0.0};
    if (flag == "REJ") return {1.0, 0.0, 0.0, 1.0};
    if (flag == "RSTO") return {1.0, 1.0, 0.0, 1.0};
    if (flag == "RSTOS0") return {1.0, 0.0, 0.0, 1.0};
    // OTH and unknown
    return {0.0, 0.0, 0.0, 0.0};
}

// Map one NSL-KDD row to our 14-feature vector.
// Returns empty vector on parse failure.
std::vector<double> nsl_kdd_to_features(const std::vector<std::string>& cols) {
    if (cols.size() < 42) return {};

    try {
        double duration   = std::stod(cols[0]);
        std::string proto = cols[1];
        std::string flag  = cols[3];
        double src_bytes  = std::stod(cols[4]);
        double dst_bytes  = std::stod(cols[5]);
        double count      = std::stod(cols[22]);
        double srv_count  = std::stod(cols[23]);
        double same_srv   = std::stod(cols[28]);
        double diff_srv   = std::stod(cols[29]);

        double byte_count    = src_bytes + dst_bytes;
        // Estimate directional packet counts using count and service distribution
        double src_pkt_est   = count * (0.3 + 0.4 * diff_srv); // more diff_srv = more outbound scanning
        double dst_pkt_est   = std::max(1.0, count - src_pkt_est);
        double src_byte_est  = std::max(0.0, src_bytes);
        double dst_byte_est  = std::max(0.0, dst_bytes);

        auto flags = flag_to_tcp(flag);

        // One-hot protocol
        double is_tcp  = (proto == "tcp")  ? 1.0 : 0.0;
        double is_udp  = (proto == "udp")  ? 1.0 : 0.0;
        double is_icmp = (proto == "icmp") ? 1.0 : 0.0;

        std::vector<double> feats(14);
        feats[0]  = duration;
        feats[1]  = std::log1p(count);                       // log1p(packet_count)
        feats[2]  = std::log1p(byte_count);                  // log1p(byte_count)
        feats[3]  = src_pkt_est / (dst_pkt_est + 1.0);       // src/dst packet ratio
        feats[4]  = src_byte_est / (dst_byte_est + 1.0);     // src/dst byte ratio
        feats[5]  = count / (duration + 0.01);               // packets/sec
        feats[6]  = byte_count / (count + 1.0);              // avg packet size
        feats[7]  = flags.syn;
        feats[8]  = flags.ack;
        feats[9]  = flags.fin;
        feats[10] = flags.rst;
        feats[11] = is_tcp;
        feats[12] = is_udp;
        feats[13] = is_icmp;

        return feats;
    } catch (...) {
        return {};
    }
}

// NSL-KDD attack categories → binary label
// normal=0, attack=1
int label_to_binary(const std::string& label) {
    if (label == "normal") return 0;
    return 1;
}

// Attack categories for reporting
std::string get_attack_category(const std::string& label) {
    static const std::set<std::string> dos_set = {
        "back","land","neptune","pod","smurf","teardrop",
        "apache2","udpstorm","processtable","mailbomb"
    };
    static const std::set<std::string> probe_set = {
        "ipsweep","nmap","portsweep","satan","mscan","saint"
    };
    static const std::set<std::string> r2l_set = {
        "ftp_write","guess_passwd","imap","multihop","phf","spy",
        "warezclient","warezmaster","sendmail","named",
        "snmpgetattack","snmpguess","xlock","xsnoop","worm"
    };
    static const std::set<std::string> u2r_set = {
        "buffer_overflow","loadmodule","perl","rootkit",
        "httptunnel","ps","sqlattack","xterm"
    };

    if (label == "normal") return "Normal";
    if (dos_set.count(label)) return "DoS";
    if (probe_set.count(label)) return "Probe";
    if (r2l_set.count(label)) return "R2L";
    if (u2r_set.count(label)) return "U2R";
    return "Other";
}

// Synthetic training fallback — used when NSL-KDD dataset is not available (CI, etc.)
int train_synthetic(const std::string& output_path) {
    constexpr size_t num_samples  = 5000;
    constexpr size_t num_features = 14;
    constexpr size_t num_trees    = 20;

    std::mt19937 rng(std::random_device{}());
    std::uniform_real_distribution<double> unif(0.0, 1.0);
    std::exponential_distribution<double> exp_dist(1.0);
    std::poisson_distribution<int> poisson(15);

    spdlog::info("Generating {} synthetic samples (3 profiles)...", num_samples);

    arma::mat features(num_features, num_samples);
    arma::Row<size_t> labels(num_samples);
    int count_normal = 0, count_scan = 0, count_dos = 0;

    for (size_t i = 0; i < num_samples; ++i) {
        double roll = unif(rng);
        int type;
        if (roll < 0.50)       { type = 0; count_normal++; }
        else if (roll < 0.75)  { type = 1; count_scan++; }
        else                   { type = 2; count_dos++; }

        double duration, packet_count, byte_count;
        double syn_f, ack_f, fin_f, rst_f;

        if (type == 0) {
            duration     = exp_dist(rng) * 1.5;
            packet_count = static_cast<double>(std::max(1, poisson(rng)));
            byte_count   = packet_count * (200.0 + unif(rng) * 600.0);
            syn_f = 0.3; ack_f = 0.7; fin_f = 0.2; rst_f = 0.1;
        } else if (type == 1) {
            duration     = 0.1 + unif(rng) * 1.9;
            packet_count = static_cast<double>(poisson(rng) * 2 + 5);
            byte_count   = packet_count * (100.0 + unif(rng) * 200.0);
            syn_f = 0.9; ack_f = 0.2; fin_f = 0.0; rst_f = 0.4;
        } else {
            duration     = 0.5 + unif(rng) * 9.5;
            packet_count = static_cast<double>(poisson(rng) * 15 + 50);
            byte_count   = packet_count * (400.0 + unif(rng) * 1100.0);
            syn_f = 0.7; ack_f = 0.6; fin_f = 0.3; rst_f = 0.2;
        }

        double ratio = 0.3 + unif(rng) * 0.4;
        double src_pkt = packet_count * ratio;
        double dst_pkt = packet_count - src_pkt;
        double src_bytes = byte_count * ratio;
        double dst_bytes = byte_count - src_bytes;

        arma::vec feat(14);
        feat(0)  = duration;
        feat(1)  = std::log1p(packet_count);
        feat(2)  = std::log1p(byte_count);
        feat(3)  = src_pkt / (dst_pkt + 1.0);
        feat(4)  = src_bytes / (dst_bytes + 1.0);
        feat(5)  = packet_count / (duration + 0.01);
        feat(6)  = byte_count / (packet_count + 1.0);
        feat(7)  = (unif(rng) < syn_f) ? 1.0 : 0.0;
        feat(8)  = (unif(rng) < ack_f) ? 1.0 : 0.0;
        feat(9)  = (unif(rng) < fin_f) ? 1.0 : 0.0;
        feat(10) = (unif(rng) < rst_f) ? 1.0 : 0.0;
        feat(11) = 1.0;  // TCP
        feat(12) = 0.0;
        feat(13) = 0.0;

        features.col(i) = feat;
        labels(i) = (type == 0) ? 0 : 1;
    }

    spdlog::info("Distribution: Normal={}, Scanning={}, DoS={}",
                 count_normal, count_scan, count_dos);
    spdlog::info("Training Random Forest ({} trees)...", num_trees);

    mlpack::tree::RandomForest<> model(features, labels, 2, num_trees);

    arma::Row<size_t> predictions;
    model.Classify(features, predictions);
    size_t correct = 0;
    for (size_t i = 0; i < num_samples; ++i)
        if (predictions(i) == labels(i)) correct++;
    spdlog::info("Synthetic training accuracy: {:.1f}%", 100.0 * correct / num_samples);

    spdlog::info("Saving model to: {}", output_path);
    mlpack::data::Save(output_path, "nids_model", model);
    spdlog::info("Model saved.");
    return 0;
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    std::string kdd_path = "data/KDDTrain+.txt";
    std::string output_path = "models/nids_model.bin";
    if (argc > 1) kdd_path = argv[1];
    if (argc > 2) output_path = argv[2];

    // -------------------------------------------------------------------
    // Load and parse NSL-KDD
    // -------------------------------------------------------------------
    spdlog::info("Loading NSL-KDD from: {}", kdd_path);
    std::ifstream file(kdd_path);
    if (!file.is_open()) {
        spdlog::warn("{} not found. Falling back to synthetic data.", kdd_path);
        // ---------- Synthetic fallback (for CI / no-dataset environments) ----------
        return train_synthetic(output_path);
    }

    std::vector<std::vector<double>> all_features;
    std::vector<int> all_labels;
    std::vector<std::string> all_categories;
    size_t skipped = 0;

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;
        auto cols = split_csv(line);
        if (cols.size() < 42) { skipped++; continue; }

        auto feats = nsl_kdd_to_features(cols);
        if (feats.empty()) { skipped++; continue; }

        int label = label_to_binary(cols[41]);
        all_features.push_back(feats);
        all_labels.push_back(label);
        all_categories.push_back(cols[41]);
    }

    spdlog::info("Parsed {} samples ({} skipped)", all_features.size(), skipped);
    if (all_features.empty()) {
        spdlog::error("No valid samples parsed.");
        return 1;
    }

    // -------------------------------------------------------------------
    // Report distribution
    // -------------------------------------------------------------------
    size_t count_normal = 0, count_attack = 0;
    std::map<std::string, size_t> cat_counts;
    for (size_t i = 0; i < all_labels.size(); ++i) {
        if (all_labels[i] == 0) count_normal++;
        else count_attack++;
        cat_counts[get_attack_category(all_categories[i])]++;
    }
    spdlog::info("Labels: Normal={}, Malicious={} (ratio {:.1f}:1)",
                 count_normal, count_attack,
                 static_cast<double>(count_normal) / std::max(size_t(1), count_attack));
    for (auto& [cat, cnt] : cat_counts) {
        spdlog::info("  {}: {} ({:.1f}%)", cat, cnt, 100.0 * cnt / all_labels.size());
    }

    // -------------------------------------------------------------------
    // Train/test split (80/20, stratified)
    // -------------------------------------------------------------------
    constexpr size_t num_features = 14;
    constexpr size_t num_trees    = 100;
    constexpr double test_ratio   = 0.20;

    // Collect indices per class for stratification
    std::vector<size_t> normal_idx, attack_idx;
    for (size_t i = 0; i < all_labels.size(); ++i) {
        if (all_labels[i] == 0) normal_idx.push_back(i);
        else attack_idx.push_back(i);
    }

    std::mt19937 rng(std::random_device{}());
    std::shuffle(normal_idx.begin(), normal_idx.end(), rng);
    std::shuffle(attack_idx.begin(), attack_idx.end(), rng);

    size_t train_n = static_cast<size_t>(normal_idx.size() * (1.0 - test_ratio));
    size_t train_a = static_cast<size_t>(attack_idx.size() * (1.0 - test_ratio));

    size_t train_size = train_n + train_a;
    size_t test_size  = (normal_idx.size() - train_n) + (attack_idx.size() - train_a);

    arma::mat train_feat(num_features, train_size);
    arma::Row<size_t> train_labels(train_size);
    arma::mat test_feat(num_features, test_size);
    arma::Row<size_t> test_labels(test_size);

    size_t idx = 0;
    for (size_t i = 0; i < train_n; ++i) {
        for (size_t f = 0; f < num_features; ++f)
            train_feat(f, idx) = all_features[normal_idx[i]][f];
        train_labels(idx) = 0;
        idx++;
    }
    for (size_t i = 0; i < train_a; ++i) {
        for (size_t f = 0; f < num_features; ++f)
            train_feat(f, idx) = all_features[attack_idx[i]][f];
        train_labels(idx) = 1;
        idx++;
    }

    idx = 0;
    for (size_t i = train_n; i < normal_idx.size(); ++i) {
        for (size_t f = 0; f < num_features; ++f)
            test_feat(f, idx) = all_features[normal_idx[i]][f];
        test_labels(idx) = 0;
        idx++;
    }
    for (size_t i = train_a; i < attack_idx.size(); ++i) {
        for (size_t f = 0; f < num_features; ++f)
            test_feat(f, idx) = all_features[attack_idx[i]][f];
        test_labels(idx) = 1;
        idx++;
    }

    spdlog::info("Train: {} samples, Test: {} samples", train_size, test_size);

    // -------------------------------------------------------------------
    // Train Random Forest
    // -------------------------------------------------------------------
    spdlog::info("Training Random Forest ({} trees)...", num_trees);

    try {
        mlpack::tree::RandomForest<> model(train_feat, train_labels, 2, num_trees);

        // -------------------------------------------------------------------
        // Evaluate on test set
        // -------------------------------------------------------------------
        arma::Row<size_t> predictions;
        model.Classify(test_feat, predictions);

        size_t tp = 0, tn = 0, fp = 0, fn = 0;
        for (size_t i = 0; i < test_size; ++i) {
            bool pred_mal = (predictions(i) == 1);
            bool true_mal = (test_labels(i) == 1);
            if (pred_mal && true_mal) tp++;
            else if (pred_mal && !true_mal) fp++;
            else if (!pred_mal && true_mal) fn++;
            else tn++;
        }

        double accuracy  = 100.0 * (tp + tn) / test_size;
        double precision = tp > 0 ? 100.0 * tp / (tp + fp) : 0.0;
        double recall    = tp > 0 ? 100.0 * tp / (tp + fn) : 0.0;
        double f1        = (precision + recall) > 0
                           ? 2.0 * precision * recall / (precision + recall) : 0.0;

        spdlog::info("========================================");
        spdlog::info("Test Results ({} samples):", test_size);
        spdlog::info("  Accuracy:  {:.2f}%", accuracy);
        spdlog::info("  Precision: {:.2f}%", precision);
        spdlog::info("  Recall:    {:.2f}%", recall);
        spdlog::info("  F1 Score:  {:.2f}%", f1);
        spdlog::info("  TP={}  TN={}  FP={}  FN={}", tp, tn, fp, fn);
        spdlog::info("========================================");

        // -------------------------------------------------------------------
        // Train on FULL dataset for final model
        // -------------------------------------------------------------------
        spdlog::info("Retraining on full dataset for deployment model...");
        arma::mat full_feat(num_features, all_features.size());
        arma::Row<size_t> full_labels(all_features.size());
        for (size_t i = 0; i < all_features.size(); ++i) {
            for (size_t f = 0; f < num_features; ++f)
                full_feat(f, i) = all_features[i][f];
            full_labels(i) = all_labels[i];
        }

        mlpack::tree::RandomForest<> final_model(full_feat, full_labels, 2, num_trees);

        // Quick in-sample check
        arma::Row<size_t> final_pred;
        final_model.Classify(full_feat, final_pred);
        size_t final_correct = 0;
        for (size_t i = 0; i < all_features.size(); ++i)
            if (final_pred(i) == full_labels(i)) final_correct++;
        spdlog::info("Full model training accuracy: {:.2f}%",
                     100.0 * final_correct / all_features.size());

        // -------------------------------------------------------------------
        // Save model
        // -------------------------------------------------------------------
        spdlog::info("Saving model to: {}", output_path);
        mlpack::data::Save(output_path, "nids_model", final_model);

        // Verify file was written
        std::ifstream check(output_path);
        if (check.good()) {
            check.seekg(0, std::ios::end);
            spdlog::info("Model saved: {} bytes", static_cast<long>(check.tellg()));
        }
        spdlog::info("Done. Deploy with: --model {}", output_path);

        return 0;

    } catch (const std::exception& e) {
        spdlog::error("Training failed: {}", e.what());
        return 1;
    }
}
