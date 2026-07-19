#include "INids.hpp"
#include "FeatureExtractor.hpp"
#include <spdlog/spdlog.h>

// Windows networking — winsock2 MUST come before windows.h
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

// Npcap/WinPcap (libpcap API for Windows)
#include <pcap/pcap.h>

#include <unordered_map>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <memory>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <tuple>
#include <filesystem>
#include <vector>
#include <string>
#include <algorithm>

// Forward declare mlpack types
#include <mlpack.hpp>

// ------------------------------------------------------------
// WindowsNidsEngine — Full INids implementation for Windows
// using Npcap/WinPcap. Feature parity with Linux version:
//   - Bidirectional flow aggregation (5-tuple)
//   - 6 classification triggers (RST/FIN, idle, max_dur, pkt/byte threshold, periodic)
//   - Cross-flow scanner (port scan, network scan, C2 beaconing)
//   - Alert logging (JSON append)
//   - Configurable thresholds and filters
//   - Recursive mutex (prevents deadlock in packet_handler → cleanup_flows)
// ------------------------------------------------------------
class WindowsNidsEngine : public INids {
private:
    // Capture state
    std::atomic<bool> running{false};
    pcap_t* pcap_handle = nullptr;
    std::string interface;
    std::string filter;
    std::thread capture_thread;
    NidsCallback callback;
    mlpack::tree::RandomForest<> model;
    bool model_loaded = false;

    // Windows event for shutdown signaling (equivalent to Linux self-pipe)
    HANDLE shutdown_event = nullptr;

    // Flow key: 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol)
    struct FlowKey {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        uint8_t protocol;

        bool operator==(const FlowKey& other) const {
            return src_ip == other.src_ip &&
                   dst_ip == other.dst_ip &&
                   src_port == other.src_port &&
                   dst_port == other.dst_port &&
                   protocol == other.protocol;
        }
    };

    struct FlowKeyHash {
        size_t operator()(const FlowKey& k) const {
            return std::hash<uint32_t>()(k.src_ip) ^
                   (std::hash<uint32_t>()(k.dst_ip) << 1) ^
                   (std::hash<uint16_t>()(k.src_port) << 2) ^
                   (std::hash<uint16_t>()(k.dst_port) << 3) ^
                   (std::hash<uint8_t>()(k.protocol) << 4);
        }
    };

    std::unordered_map<FlowKey, NetworkFlow, FlowKeyHash> active_flows;
    // recursive_mutex: packet_handler holds the lock and calls cleanup_flows()
    // which also needs the lock. std::mutex would deadlock (non-recursive).
    std::recursive_mutex flows_mutex;
    std::chrono::steady_clock::time_point last_cleanup;

    // Configurable thresholds
    int flow_timeout_sec = 60;
    int cleanup_interval_sec = 10;
    int max_duration_sec = 0;       // 0 = disabled
    int packet_threshold = 0;       // 0 = disabled
    int byte_threshold = 0;         // 0 = disabled
    int periodic_classify_sec = 0;  // 0 = disabled
    std::chrono::steady_clock::time_point last_periodic_classify;

    // Alert filtering
    bool verbose_alerts = false;
    uint32_t ignore_ip = 0;

    // Cross-flow scanner
    int scan_threshold = 10;
    int cross_flow_interval_sec = 30;
    std::chrono::steady_clock::time_point last_cross_flow_scan;

    // C2 beaconing history
    struct BeaconEntry {
        std::chrono::steady_clock::time_point first_seen;
        std::chrono::steady_clock::time_point last_seen;
        int connection_count = 0;
    };
    std::map<std::tuple<uint32_t, uint32_t, uint16_t>, BeaconEntry> beacon_history;

    // Alert log file
    std::string alert_log_path;
    std::mutex alert_log_mutex;

    // ------------------------------------------------------------
    // IP header parsing (portable: winsock structures)
    // ------------------------------------------------------------
    struct IpHeader {
        uint8_t  ver_ihl;   // Version (4 bits) + IHL (4 bits)
        uint8_t  tos;
        uint16_t total_len;
        uint16_t id;
        uint16_t frag_off;
        uint8_t  ttl;
        uint8_t  protocol;
        uint16_t checksum;
        uint32_t src_addr;
        uint32_t dst_addr;
    };

    struct TcpHeader {
        uint16_t src_port;
        uint16_t dst_port;
        uint32_t seq_num;
        uint32_t ack_num;
        uint16_t data_offset_flags;
        uint16_t window;
        uint16_t checksum;
        uint16_t urgent_ptr;
    };

    struct UdpHeader {
        uint16_t src_port;
        uint16_t dst_port;
        uint16_t length;
        uint16_t checksum;
    };

    // ------------------------------------------------------------
    // pcap callback — invoked for each captured packet
    // ------------------------------------------------------------
    void packet_handler(const struct pcap_pkthdr* header, const unsigned char* packet) {
        auto now = std::chrono::steady_clock::now();

        // Skip Ethernet header (14 bytes)
        if (header->len < 14) return;
        const IpHeader* ip = reinterpret_cast<const IpHeader*>(packet + 14);
        uint8_t protocol = ip->protocol;
        uint32_t src_ip_raw = ip->src_addr;
        uint32_t dst_ip_raw = ip->dst_addr;

        // Skip traffic to/from the ignored IP (our own device)
        if (ignore_ip != 0 && (src_ip_raw == ignore_ip || dst_ip_raw == ignore_ip)) {
            return;
        }

        uint16_t src_port = 0;
        uint16_t dst_port = 0;
        int ip_hdr_len = (ip->ver_ihl & 0x0F) * 4;

        // Parse TCP/UDP ports
        if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
            const uint16_t* ports = reinterpret_cast<const uint16_t*>(
                reinterpret_cast<const unsigned char*>(ip) + ip_hdr_len);
            src_port = ntohs(ports[0]);
            dst_port = ntohs(ports[1]);
        }

        std::lock_guard<std::recursive_mutex> lock(flows_mutex);

        // Bidirectional: check both forward and reverse flow keys
        FlowKey key{src_ip_raw, dst_ip_raw, src_port, dst_port, protocol};
        auto it = active_flows.find(key);
        bool is_reverse = false;

        if (it == active_flows.end()) {
            FlowKey rev_key{dst_ip_raw, src_ip_raw, dst_port, src_port, protocol};
            it = active_flows.find(rev_key);
            is_reverse = (it != active_flows.end());
        }

        if (it == active_flows.end()) {
            // New flow
            NetworkFlow flow;
            flow.src_ip = ip_to_string(src_ip_raw);
            flow.dst_ip = ip_to_string(dst_ip_raw);
            flow.src_port = src_port;
            flow.dst_port = dst_port;
            flow.protocol = protocol;
            flow.start_time = now;
            flow.end_time = now;
            flow.packet_count = 1;
            flow.byte_count = header->len;
            flow.src_packet_count = 1;
            flow.dst_packet_count = 0;
            flow.src_byte_count = header->len;
            flow.dst_byte_count = 0;
            flow.syn_flag = false;
            flow.ack_flag = false;
            flow.fin_flag = false;
            flow.rst_flag = false;
            flow.last_classified = now;

            if (protocol == IPPROTO_TCP) {
                const TcpHeader* tcp = reinterpret_cast<const TcpHeader*>(
                    reinterpret_cast<const unsigned char*>(ip) + ip_hdr_len);
                uint16_t flags = ntohs(tcp->data_offset_flags);
                flow.syn_flag = (flags & 0x0002) != 0;  // SYN
                flow.ack_flag = (flags & 0x0010) != 0;  // ACK
                flow.fin_flag = (flags & 0x0001) != 0;  // FIN
                flow.rst_flag = (flags & 0x0004) != 0;  // RST
            }

            active_flows[key] = flow;
        } else {
            // Update existing flow (forward or reverse)
            NetworkFlow& flow = it->second;
            flow.end_time = now;
            flow.packet_count++;
            flow.byte_count += header->len;

            if (is_reverse) {
                flow.dst_packet_count++;
                flow.dst_byte_count += header->len;
            } else {
                flow.src_packet_count++;
                flow.src_byte_count += header->len;
            }

            // OR-accumulate TCP flags
            if (protocol == IPPROTO_TCP) {
                const TcpHeader* tcp = reinterpret_cast<const TcpHeader*>(
                    reinterpret_cast<const unsigned char*>(ip) + ip_hdr_len);
                uint16_t flags = ntohs(tcp->data_offset_flags);
                flow.syn_flag = flow.syn_flag || ((flags & 0x0002) != 0);
                flow.ack_flag = flow.ack_flag || ((flags & 0x0010) != 0);
                flow.fin_flag = flow.fin_flag || ((flags & 0x0001) != 0);
                flow.rst_flag = flow.rst_flag || ((flags & 0x0004) != 0);
            }
        }

        // Periodic cleanup
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - last_cleanup).count();
        if (elapsed > cleanup_interval_sec) {
            cleanup_flows(now);
        }
    }

    // ------------------------------------------------------------
    // Fire an alert (called from cleanup_flows and cross_flow_scan)
    // ------------------------------------------------------------
    void fire_alert(const NetworkFlow& flow, const std::string& label,
                    double confidence, const std::string& trigger) {
        if (!callback) return;
        // Malicious-only by default. Use --verbose for all alerts.
        if (!verbose_alerts && label != "Malicious") return;
        NidsAlert alert;
        alert.timestamp = std::chrono::system_clock::now();
        alert.flow = flow;
        alert.classification = label;
        alert.confidence = confidence;
        alert.description = "[" + trigger + "] " + label
            + " (confidence: " + std::to_string(confidence) + ")";
        callback(alert);
        write_alert_log(alert);
    }

    // ------------------------------------------------------------
    // Cross-flow scanner: port scan, network scan, C2 beaconing
    // ------------------------------------------------------------
    void cross_flow_scan(std::chrono::steady_clock::time_point now) {
        std::map<uint32_t, std::map<uint32_t, std::set<uint16_t>>> port_scan_map;
        std::map<uint32_t, std::map<uint16_t, std::set<uint32_t>>> net_scan_map;

        for (const auto& [key, flow] : active_flows) {
            port_scan_map[key.src_ip][key.dst_ip].insert(key.dst_port);
            net_scan_map[key.src_ip][key.dst_port].insert(key.dst_ip);

            auto beacon_key = std::make_tuple(key.src_ip, key.dst_ip, key.dst_port);
            auto& entry = beacon_history[beacon_key];
            if (entry.connection_count == 0) {
                entry.first_seen = now;
            }
            entry.last_seen = now;
            entry.connection_count++;
        }

        // Port scan detection
        for (const auto& [src_ip, dst_map] : port_scan_map) {
            for (const auto& [dst_ip, ports] : dst_map) {
                if (static_cast<int>(ports.size()) >= scan_threshold) {
                    NetworkFlow synth;
                    synth.src_ip = ip_to_string(src_ip);
                    synth.dst_ip = ip_to_string(dst_ip);
                    synth.protocol = 6;
                    synth.packet_count = ports.size();
                    synth.start_time = now;
                    synth.end_time = now;

                    std::string desc = "Port scan: " + synth.src_ip + " -> "
                        + synth.dst_ip + " (" + std::to_string(ports.size()) + " ports)";
                    NidsAlert alert;
                    alert.timestamp = std::chrono::system_clock::now();
                    alert.flow = synth;
                    alert.classification = "Malicious";
                    alert.confidence = std::min(0.99, 0.7 + ports.size() * 0.01);
                    alert.description = "[cross-flow] " + desc;
                    if (callback) callback(alert);
                    write_alert_log(alert);
                }
            }
        }

        // Network scan detection
        for (const auto& [src_ip, port_map] : net_scan_map) {
            for (const auto& [dport, dst_ips] : port_map) {
                if (static_cast<int>(dst_ips.size()) >= scan_threshold) {
                    NetworkFlow synth;
                    synth.src_ip = ip_to_string(src_ip);
                    synth.dst_port = dport;
                    synth.protocol = 6;
                    synth.packet_count = dst_ips.size();
                    synth.start_time = now;
                    synth.end_time = now;

                    std::string desc = "Network scan: " + synth.src_ip
                        + " scanning port " + std::to_string(dport)
                        + " on " + std::to_string(dst_ips.size()) + " hosts";
                    NidsAlert alert;
                    alert.timestamp = std::chrono::system_clock::now();
                    alert.flow = synth;
                    alert.classification = "Malicious";
                    alert.confidence = std::min(0.99, 0.7 + dst_ips.size() * 0.01);
                    alert.description = "[cross-flow] " + desc;
                    if (callback) callback(alert);
                    write_alert_log(alert);
                }
            }
        }

        // C2 beaconing detection
        for (auto& [bkey, entry] : beacon_history) {
            if (entry.connection_count >= 5) {
                auto total_span = std::chrono::duration_cast<std::chrono::seconds>(
                    entry.last_seen - entry.first_seen).count();
                if (total_span > 0) {
                    double avg_interval = static_cast<double>(total_span) / entry.connection_count;
                    if (avg_interval > 30.0 && avg_interval < 3600.0) {
                        auto [src_ip, dst_ip, dst_port] = bkey;
                        NetworkFlow synth;
                        synth.src_ip = ip_to_string(src_ip);
                        synth.dst_ip = ip_to_string(dst_ip);
                        synth.dst_port = dst_port;
                        synth.protocol = 6;
                        synth.packet_count = entry.connection_count;
                        synth.start_time = entry.first_seen;
                        synth.end_time = entry.last_seen;

                        std::string desc = "C2 beaconing: " + synth.src_ip + " -> "
                            + synth.dst_ip + ":" + std::to_string(dst_port)
                            + " (" + std::to_string(entry.connection_count)
                            + " connections, ~" + std::to_string((int)avg_interval) + "s interval)";
                        NidsAlert alert;
                        alert.timestamp = std::chrono::system_clock::now();
                        alert.flow = synth;
                        alert.classification = "Malicious";
                        alert.confidence = std::min(0.95, 0.6 + entry.connection_count * 0.05);
                        alert.description = "[cross-flow] " + desc;
                        if (callback) callback(alert);
                        write_alert_log(alert);

                        entry.connection_count = 0;
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------
    // Write alert to JSON log file (thread-safe, append)
    // ------------------------------------------------------------
    void write_alert_log(const NidsAlert& alert) {
        if (alert_log_path.empty()) return;
        std::lock_guard<std::mutex> lock(alert_log_mutex);

        std::ofstream f(alert_log_path, std::ios::app);
        if (!f.is_open()) return;

        auto t = std::chrono::system_clock::to_time_t(alert.timestamp);
        f << "{"
          << "\"time\":" << t << ","
          << "\"classification\":\"" << alert.classification << "\","
          << "\"confidence\":" << alert.confidence << ","
          << "\"src_ip\":\"" << alert.flow.src_ip << "\","
          << "\"src_port\":" << alert.flow.src_port << ","
          << "\"dst_ip\":\"" << alert.flow.dst_ip << "\","
          << "\"dst_port\":" << alert.flow.dst_port << ","
          << "\"protocol\":" << static_cast<int>(alert.flow.protocol) << ","
          << "\"packets\":" << alert.flow.packet_count << ","
          << "\"bytes\":" << alert.flow.byte_count << ","
          << "\"duration\":" << alert.flow.duration_seconds() << ","
          << "\"description\":\"" << alert.description << "\""
          << "}\n";
    }

    static std::string ip_to_string(uint32_t ip_raw) {
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_raw, buf, sizeof(buf));
        return std::string(buf);
    }

    // ------------------------------------------------------------
    // Finalize and classify flows using multiple triggers
    // ------------------------------------------------------------
    void cleanup_flows(std::chrono::steady_clock::time_point now) {
        std::lock_guard<std::recursive_mutex> lock(flows_mutex);

        // Pass 1: removal-based triggers
        auto it = active_flows.begin();
        while (it != active_flows.end()) {
            NetworkFlow& flow = it->second;
            auto idle = std::chrono::duration_cast<std::chrono::seconds>(
                now - flow.end_time).count();
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(
                flow.end_time - flow.start_time).count();

            bool should_remove = false;
            std::string trigger;

            if (flow.fin_flag || flow.rst_flag) {
                should_remove = true;
                trigger = flow.rst_flag ? "RST" : "FIN";
            } else if (packet_threshold > 0
                       && static_cast<int>(flow.packet_count) > packet_threshold) {
                should_remove = true;
                trigger = "packets(" + std::to_string(flow.packet_count)
                        + ">" + std::to_string(packet_threshold) + ")";
            } else if (byte_threshold > 0
                       && static_cast<int>(flow.byte_count) > byte_threshold) {
                should_remove = true;
                trigger = "bytes(" + std::to_string(flow.byte_count)
                        + ">" + std::to_string(byte_threshold) + ")";
            } else if (max_duration_sec > 0 && duration > max_duration_sec) {
                should_remove = true;
                trigger = "max_duration(" + std::to_string(max_duration_sec) + "s)";
            } else if (idle > flow_timeout_sec) {
                should_remove = true;
                trigger = "idle(" + std::to_string(flow_timeout_sec) + "s)";
            }

            if (should_remove) {
                NetworkFlow flow_copy = flow;
                auto [label, confidence] = classify_flow(flow_copy);
                fire_alert(flow_copy, label, confidence, trigger);
                it = active_flows.erase(it);
            } else {
                ++it;
            }
        }

        // Pass 2: periodic classify (keep flows alive)
        if (periodic_classify_sec > 0) {
            auto since_last = std::chrono::duration_cast<std::chrono::seconds>(
                now - last_periodic_classify).count();
            if (since_last >= periodic_classify_sec) {
                for (auto& [key, flow] : active_flows) {
                    auto since_classified = std::chrono::duration_cast<std::chrono::seconds>(
                        now - flow.last_classified).count();
                    if (since_classified >= periodic_classify_sec) {
                        auto [label, confidence] = classify_flow(flow);
                        fire_alert(flow, label, confidence,
                                   "periodic(" + std::to_string(periodic_classify_sec) + "s)");
                        flow.last_classified = now;
                    }
                }
                last_periodic_classify = now;
            }
        }

        last_cleanup = now;

        // Cross-flow scan (periodic, independent of cleanup cycle)
        auto since_cross = std::chrono::duration_cast<std::chrono::seconds>(
            now - last_cross_flow_scan).count();
        if (since_cross >= cross_flow_interval_sec) {
            cross_flow_scan(now);
            last_cross_flow_scan = now;
        }
    }

    // ------------------------------------------------------------
    // Static callback wrapper for pcap (C callback → C++ method)
    // ------------------------------------------------------------
    static void pcap_callback(u_char* user, const struct pcap_pkthdr* header,
                              const u_char* packet) {
        auto* self = reinterpret_cast<WindowsNidsEngine*>(user);
        self->packet_handler(header, packet);
    }

public:
    WindowsNidsEngine() {
        auto now = std::chrono::steady_clock::now();
        last_cleanup = now;
        last_periodic_classify = now;
        last_cross_flow_scan = now;
        shutdown_event = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    }

    ~WindowsNidsEngine() {
        stop_capture();
        if (shutdown_event) {
            CloseHandle(shutdown_event);
            shutdown_event = nullptr;
        }
    }

    // ------------------------------------------------------------
    // Start capture on a network interface
    // ------------------------------------------------------------
    bool start_capture(const std::string& iface, const std::string& filter_str = "") override {
        if (running) {
            spdlog::warn("Capture is already running.");
            return false;
        }

        interface = iface;
        filter = filter_str;
        char errbuf[PCAP_ERRBUF_SIZE];

        // Windows: pcap_open_live is the most compatible (all WinPcap/Npcap versions).
        // Immediate mode is enabled by pcap_open_live's timeout parameter.
        // For Npcap, pcap_create + pcap_set_immediate_mode + pcap_activate also works.
        pcap_handle = pcap_open_live(interface.c_str(), 65536, 1, 500, errbuf);
        if (!pcap_handle) {
            spdlog::error("Failed to open interface '{}': {}", interface, errbuf);
            return false;
        }

        // Apply BPF filter if provided
        if (!filter.empty()) {
            struct bpf_program bpf;
            if (pcap_compile(pcap_handle, &bpf, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
                spdlog::error("Failed to compile filter: {}", pcap_geterr(pcap_handle));
                pcap_close(pcap_handle);
                pcap_handle = nullptr;
                return false;
            }
            if (pcap_setfilter(pcap_handle, &bpf) == -1) {
                spdlog::error("Failed to apply filter: {}", pcap_geterr(pcap_handle));
                pcap_freecode(&bpf);
                pcap_close(pcap_handle);
                pcap_handle = nullptr;
                return false;
            }
            pcap_freecode(&bpf);
        }

        running = true;
        ResetEvent(shutdown_event);

        capture_thread = std::thread([this]() {
            spdlog::info("Starting capture loop on {}", interface);
            while (running) {
                // Wait on shutdown event with timeout (100ms).
                // During this time, pcap_dispatch processes packets via callback.
                // pcap_dispatch returns on: packets processed, timeout (500ms), or breakloop.
                int ret = pcap_dispatch(pcap_handle, -1, pcap_callback,
                                        reinterpret_cast<u_char*>(this));
                if (ret < 0) {
                    spdlog::error("pcap_dispatch error: {}", pcap_geterr(pcap_handle));
                    break;
                }
                // ret >= 0: processed some packets or timeout
                // Check shutdown every iteration
                if (WaitForSingleObject(shutdown_event, 0) == WAIT_OBJECT_0) {
                    break;
                }
            }
            spdlog::info("Capture loop finished.");
        });

        spdlog::info("Capture started on interface: {}", interface);
        return true;
    }

    void stop_capture() override {
        if (!running) return;
        running = false;

        // Signal shutdown event + break pcap loop
        SetEvent(shutdown_event);
        if (pcap_handle) {
            pcap_breakloop(pcap_handle);
        }

        // Finalize pending flows
        cleanup_flows(std::chrono::steady_clock::now());

        // Join capture thread (Windows: pcap_breakloop + event ensures it exits)
        if (capture_thread.joinable()) {
            capture_thread.join();
        }

        if (pcap_handle) {
            pcap_close(pcap_handle);
            pcap_handle = nullptr;
        }

        spdlog::info("Capture stopped.");
    }

    bool is_running() const override {
        return running;
    }

    bool load_model(const std::string& model_path) override {
        spdlog::info("Loading ML model from: {}", model_path);

        if (!model_path.empty() && std::filesystem::exists(model_path)) {
            try {
                mlpack::data::Load(model_path, "nids_model", model);
                model_loaded = true;
                spdlog::info("Model loaded successfully ({} trees)", model.NumTrees());
                return true;
            } catch (const std::exception& e) {
                spdlog::error("Failed to load model file: {}", e.what());
            }
        }

        // No model file — use heuristic fallback
        spdlog::warn("No model file found. Using heuristic fallback.");
        model_loaded = false;
        return false;
    }

    void set_config(int flow_timeout, int cleanup_interval,
                    int max_duration = 0, int packet_thresh = 0,
                    int byte_thresh = 0, int periodic = 0) override {
        if (flow_timeout > 0) flow_timeout_sec = flow_timeout;
        if (cleanup_interval > 0) cleanup_interval_sec = cleanup_interval;
        max_duration_sec = max_duration;
        packet_threshold = packet_thresh;
        byte_threshold = byte_thresh;
        periodic_classify_sec = periodic;
        spdlog::info("Config: idle={}s cleanup={}s max_dur={}s "
                     "pkt_thresh={} byte_thresh={} periodic={}s",
                     flow_timeout_sec, cleanup_interval_sec, max_duration_sec,
                     packet_threshold, byte_threshold, periodic_classify_sec);
    }

    void set_filter_options(bool verbose, const std::string& ip = "") override {
        verbose_alerts = verbose;
        if (!ip.empty()) {
            ignore_ip = inet_addr(ip.c_str());
            spdlog::info("Filter: verbose={} ignore_ip={}", verbose, ip);
        } else {
            spdlog::info("Filter: verbose={}", verbose);
        }
    }

    void set_output_options(const std::string& alert_log = "",
                            int scan_thresh = 10,
                            int cross_interval = 30) override {
        alert_log_path = alert_log;
        scan_threshold = scan_thresh;
        cross_flow_interval_sec = cross_interval;
        if (!alert_log.empty()) {
            spdlog::info("Alert log: {} (scan_thresh={}, cross_interval={}s)",
                         alert_log, scan_threshold, cross_flow_interval_sec);
        } else {
            spdlog::info("Scan options: threshold={} interval={}s",
                         scan_threshold, cross_flow_interval_sec);
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
            // Heuristic fallback
            if (flow.packet_count > 1000 && flow.duration_seconds() < 5.0) {
                return {"Malicious", 0.9};
            }
            return {"Normal", 0.8};
        }

        try {
            auto features_vec = extract_features(flow);
            arma::mat features_mat(features_vec.data(), features_vec.size(), 1);

            arma::Row<size_t> predictions;
            model.Classify(features_mat, predictions);

            // Use per-tree voting proportion as confidence
            arma::mat probabilities;
            model.Classify(features_mat, predictions, probabilities);

            double confidence;
            if (probabilities.n_rows == 2) {
                // Two classes: row 0 = Normal, row 1 = Malicious
                confidence = probabilities(1, 0);
            } else {
                confidence = 0.8;
            }

            std::string label = (predictions(0) == 1) ? "Malicious" : "Normal";
            return {label, confidence};
        } catch (const std::exception& e) {
            spdlog::error("Classification error: {}", e.what());
            return {"Normal", 0.5};
        }
    }
};

// ------------------------------------------------------------
// Factory
// ------------------------------------------------------------
std::unique_ptr<INids> create_nids() {
    spdlog::info("Creating NIDS Engine (Windows with Npcap/WinPcap)");
    return std::make_unique<WindowsNidsEngine>();
}
