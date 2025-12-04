// NERVA.cpp
// Networked Engine Resilience & Verification Agent (NERVA)
// Single-file reference implementation (header + implementation) intended
// as an integration stub for a game engine networking layer.
//
// This file is designed to be self-contained as a starting point. Replace
// placeholder crypto / signature / transport calls with your platform
// specific implementations (HSM, OS crypto, engine transport API).

#include <cstdint>
#include <vector>
#include <string>
#include <unordered_map>
#include <deque>
#include <mutex>
#include <shared_mutex>
#include <chrono>
#include <functional>
#include <atomic>
#include <thread>
#include <optional>
#include <sstream>
#include <iomanip>
#include <iostream>

// ----------------------------- Configuration --------------------------------
struct NervaConfig {
    // Max number of snapshots to keep per connection
    size_t maxSnapshots = 128;
    // Time window for anomaly scoring (ms)
    uint32_t anomalyWindowMs = 2000;
    // Threshold above which an anomaly triggers quarantine (0..1)
    double anomalyThreshold = 0.75;
    // Max bytes to buffer for replay per connection
    size_t maxReplayBufferBytes = 4 * 1024 * 1024; // 4 MB
    // Whether to enable signature verification
    bool enableSignatures = true;
    // HMAC key identifier (engine-managed key store)
    std::string hmacKeyId = "nerva.default.hmac";
    // Interval for telemetry reporting (ms)
    uint32_t telemetryIntervalMs = 1000;
};

// ----------------------------- Utility Types --------------------------------
using Timestamp = std::chrono::steady_clock::time_point;
inline Timestamp Now() { return std::chrono::steady_clock::now(); }
inline uint64_t DurationMs(const Timestamp &a, const Timestamp &b) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count();
}

struct PacketView {
    uint64_t sequenceNumber = 0;
    std::vector<uint8_t> payload;
    Timestamp arriveTime = Now();
    // optional signature bytes sent with packet
    std::vector<uint8_t> signature;
};

// Snapshot of engine/network state associated with a sequence number
struct NervaSnapshot {
    uint64_t sequenceNumber = 0;
    Timestamp timestamp = Now();
    // A small binary blob representing determinism-relevant state
    std::vector<uint8_t> stateBlob;
};

// ----------------------------- Crypto Stubs ----------------------------------
// NOTE: Replace these with secure implementations (HSM, libsodium, OpenSSL, etc.)
namespace crypto {

inline std::vector<uint8_t> HMAC_SHA256(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data) {
    // Placeholder: this returns a trivial checksum (do NOT use in production)
    // Implement proper HMAC-SHA256 or keyed hash.
    std::vector<uint8_t> out(32, 0);
    uint8_t acc = 0;
    for (auto b : key) acc ^= b;
    for (auto d : data) acc = (acc + d) ^ 0x5A;
    out[0] = acc;
    out[1] = static_cast<uint8_t>(data.size() & 0xFF);
    return out;
}

inline bool Verify_HMAC_SHA256(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature) {
    auto expected = HMAC_SHA256(key, data);
    if (expected.size() != signature.size()) return false;
    // constant-time compare recommended
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < expected.size() && i < signature.size(); ++i) diff |= expected[i] ^ signature[i];
    return diff == 0;
}

} // namespace crypto

// --------------------------- Telemetry / Logging -----------------------------
struct NervaTelemetry {
    std::atomic<uint64_t> totalPackets{0};
    std::atomic<uint64_t> badSignatures{0};
    std::atomic<uint64_t> anomalies{0};
    std::atomic<uint64_t> quarantines{0};

    void Reset() {
        totalPackets = 0;
        badSignatures = 0;
        anomalies = 0;
        quarantines = 0;
    }
};

// --------------------------- Connection State --------------------------------
class ConnectionState {
public:
    ConnectionState(const std::string& id, const NervaConfig& cfg) : connId(id), config(cfg) {}

    // Push an incoming packet into the buffer
    void PushIncoming(const PacketView& p) {
        std::unique_lock lock(mutex);
        packets.push_back(p);
        telemetry.totalPackets++;
        replayBufferBytes += p.payload.size();
        if (replayBufferBytes > config.maxReplayBufferBytes) {
            // trim oldest payloads (simple policy)
            while (!packets.empty() && replayBufferBytes > config.maxReplayBufferBytes) {
                replayBufferBytes -= packets.front().payload.size();
                packets.pop_front();
            }
        }
    }

    // Create a snapshot for the given sequence
    void StoreSnapshot(const NervaSnapshot& s) {
        std::unique_lock lock(mutex);
        snapshots.push_back(s);
        // trim history
        while (snapshots.size() > config.maxSnapshots) snapshots.erase(snapshots.begin());
    }

    // Query recent snapshots (safe copy)
    std::vector<NervaSnapshot> GetSnapshots() const {
        std::shared_lock lock(mutex);
        return snapshots;
    }

    std::string ConnId() const { return connId; }

    NervaTelemetry telemetry;

    // Mark connection as quarantined
    void Quarantine(const std::string& reason) {
        std::unique_lock lock(mutex);
        quarantined = true;
        quarantineReason = reason;
        telemetry.quarantines++;
    }

    bool IsQuarantined() const {
        std::shared_lock lock(mutex);
        return quarantined;
    }

    std::optional<std::string> GetQuarantineReason() const {
        std::shared_lock lock(mutex);
        if (quarantined) return quarantineReason;
        return std::nullopt;
    }

    // Basic anomaly scoring by checking inter-arrival jitter & bad signatures
    double ComputeAnomalyScore() {
        std::shared_lock lock(mutex);
        if (packets.size() < 4) return 0.0;
        // compute simple jitter & signature-failure ratio in window
        auto now = Now();
        uint64_t windowMs = config.anomalyWindowMs;
        size_t total = 0, badSig = 0;
        Timestamp oldest = now;
        for (auto it = packets.rbegin(); it != packets.rend(); ++it) {
            auto &pv = *it;
            uint64_t age = DurationMs(pv.arriveTime, now);
            if (age > windowMs) break;
            ++total;
            if (!pv.signature.empty()) {
                // signature verification is done elsewhere; we store a small flag in payload[0] if set (convention)
                if (pv.payload.empty() || pv.payload[0] == 0xFF) ++badSig; // convention: 0xFF == marked bad
            }
            if (pv.arriveTime < oldest) oldest = pv.arriveTime;
        }
        double jitterScore = 0.0;
        // naive jitter metric: variation of arrival spacing
        std::vector<uint64_t> intervals;
        intervals.reserve(64);
        for (size_t i = 1; i < packets.size(); ++i) {
            auto a = packets[i-1].arriveTime;
            auto b = packets[i].arriveTime;
            intervals.push_back(DurationMs(a,b));
            if (DurationMs(a, now) > windowMs) break;
        }
        if (intervals.size() >= 2) {
            uint64_t minv = UINT64_MAX, maxv = 0;
            for (auto v : intervals) { minv = std::min(minv, v); maxv = std::max(maxv, v); }
            jitterScore = (double)(maxv - minv) / (double)(1 + maxv);
        }
        double sigScore = total == 0 ? 0.0 : (double)badSig / (double)total;
        // final composed score (weights tunable)
        double score = 0.6 * jitterScore + 0.4 * sigScore;
        return score;
    }

private:
    std::string connId;
    NervaConfig config;

    mutable std::shared_mutex mutex;
    std::deque<PacketView> packets; // recent incoming packets for analysis
    std::vector<NervaSnapshot> snapshots;
    bool quarantined = false;
    std::string quarantineReason;
    size_t replayBufferBytes = 0;
};

// --------------------------- NERVA Agent ------------------------------------
class NervaAgent {
public:
    using AlertCallback = std::function<void(const std::string& connId, const std::string& message)>;

    NervaAgent(const NervaConfig& cfg) : config(cfg), stopFlag(false) {
        telemetryReporterThread = std::thread(&NervaAgent::TelemetryThread, this);
    }

    ~NervaAgent() {
        stopFlag = true;
        if (telemetryReporterThread.joinable()) telemetryReporterThread.join();
    }

    // Register a new connection
    void RegisterConnection(const std::string& connId) {
        std::unique_lock lock(globalMutex);
        if (connections.find(connId) != connections.end()) return;
        connections.emplace(connId, std::make_shared<ConnectionState>(connId, config));
    }

    // Unregister connection
    void UnregisterConnection(const std::string& connId) {
        std::unique_lock lock(globalMutex);
        connections.erase(connId);
    }

    // Hook called by network stack when a packet arrives
    void OnIncomingPacket(const std::string& connId, PacketView packet) {
        auto cs = GetConn(connId);
        if (!cs) return;

        // Basic signature verification (if enabled)
        bool sigOk = true;
        if (config.enableSignatures && !packet.signature.empty()) {
            // fetch key (engine must provide key material securely)
            auto key = ResolveKey(config.hmacKeyId);
            sigOk = crypto::Verify_HMAC_SHA256(key, packet.payload, packet.signature);
            if (!sigOk) {
                // mark packet as logically bad (we avoid modifying payload in place in production; here we use convenction)
                packet.payload.insert(packet.payload.begin(), 0xFF);
                cs->telemetry.badSignatures++;
            }
        }

        cs->PushIncoming(packet);

        // run a light anomaly check
        double score = cs->ComputeAnomalyScore();
        if (score >= config.anomalyThreshold) {
            // escalate
            cs->Quarantine("AnomalyScore:" + ToString(score));
            cs->telemetry.anomalies++;
            if (alertCb) alertCb(connId, "Quarantined due to anomaly score: " + ToString(score));
        }
    }

    // Store deterministic snapshot from engine (game should call this regularly)
    void StoreSnapshot(const std::string& connId, const NervaSnapshot& snapshot) {
        auto cs = GetConn(connId);
        if (!cs) return;
        cs->StoreSnapshot(snapshot);
    }

    // Register callback for alerts
    void SetAlertCallback(AlertCallback cb) { alertCb = cb; }

    // Request a replay verify for a connection: compare snapshot vs reconstructed state
    bool VerifyReplay(const std::string& connId, uint64_t verifySequence) {
        auto cs = GetConn(connId);
        if (!cs) return false;
        auto snapshots = cs->GetSnapshots();
        // find matching snapshot
        std::optional<NervaSnapshot> target;
        for (auto &s : snapshots) if (s.sequenceNumber == verifySequence) target = s;
        if (!target) return false;

        // Reconstruct state from replay buffer (placeholder: in production use deterministic replay)
        // Here we just demonstrate the API and return success/failure based on simple hash.
        std::vector<uint8_t> reconstructed = ReconstructStateFromPackets(cs.get(), verifySequence);
        if (reconstructed.empty()) return false;

        bool equal = (reconstructed == target->stateBlob);
        if (!equal) {
            std::stringstream ss;
            ss << "Replay verification failed for " << connId << " seq=" << verifySequence;
            if (alertCb) alertCb(connId, ss.str());
        }
        return equal;
    }

    // Query telemetry aggregated across connections
    NervaTelemetry AggregateTelemetry() const {
        NervaTelemetry out;
        std::shared_lock lock(globalMutex);
        for (auto &kv : connections) {
            auto cs = kv.second;
            out.totalPackets += cs->telemetry.totalPackets.load();
            out.badSignatures += cs->telemetry.badSignatures.load();
            out.anomalies += cs->telemetry.anomalies.load();
            out.quarantines += cs->telemetry.quarantines.load();
        }
        return out;
    }

    // Manual quarantine function
    void QuarantineConnection(const std::string& connId, const std::string& reason) {
        auto cs = GetConn(connId);
        if (!cs) return;
        cs->Quarantine(reason);
        if (alertCb) alertCb(connId, "Quarantined by operator: " + reason);
    }

private:
    NervaConfig config;
    mutable std::shared_mutex globalMutex;
    std::unordered_map<std::string, std::shared_ptr<ConnectionState>> connections;
    AlertCallback alertCb = nullptr;

    // telemetry thread
    std::thread telemetryReporterThread;
    std::atomic<bool> stopFlag;

    std::shared_ptr<ConnectionState> GetConn(const std::string& connId) const {
        std::shared_lock lock(globalMutex);
        auto it = connections.find(connId);
        if (it == connections.end()) return nullptr;
        return it->second;
    }

    // Convert double to string with 3 decimals
    static std::string ToString(double v) {
        std::ostringstream ss; ss << std::fixed << std::setprecision(3) << v; return ss.str();
    }

    // Resolve HMAC key by id (placeholder)
    static std::vector<uint8_t> ResolveKey(const std::string& keyId) {
        // In production, this must query a secure key store. Here we return a deterministic pseudo-key.
        std::vector<uint8_t> k(32, 0);
        for (size_t i = 0; i < keyId.size() && i < k.size(); ++i) k[i] = static_cast<uint8_t>(keyId[i]);
        return k;
    }

    // Very simple reconstruction using packet payloads (DEMO only)
    static std::vector<uint8_t> ReconstructStateFromPackets(ConnectionState* cs, uint64_t sequenceHint) {
        // In real engine, this runs deterministic inputs through the same simulation path.
        // Here we create a simple aggregate hash of recent packets up to the sequence.
        // This is only a placeholder to show the verification API.
        auto snaps = cs->GetSnapshots();
        std::vector<uint8_t> out;
        uint64_t startSeq = sequenceHint > 64 ? sequenceHint - 64 : 0;
        // collect last 64 packet payload bytes XOR
        std::vector<uint8_t> xoracc(32,0);
        // Accessing internal packets is not exposed in this simplified demo; return empty to mark unimplemented
        return out; // unimplemented placeholder
    }

    void TelemetryThread() {
        using namespace std::chrono_literals;
        while (!stopFlag) {
            std::this_thread::sleep_for(std::chrono::milliseconds(config.telemetryIntervalMs));
            if (stopFlag) break;
            auto agg = AggregateTelemetry();
            // Send telemetry to engine logger / PASS-Net / metrics backend
            std::stringstream ss;
            ss << "[NERVA] packets=" << agg.totalPackets
               << " badSig=" << agg.badSignatures
               << " anomalies=" << agg.anomalies
               << " quarantines=" << agg.quarantines << "\n";
            std::cout << ss.str();
        }
    }
};

// --------------------------- Example Usage ----------------------------------
#ifdef NERVA_DEMO_MAIN
int main() {
    NervaConfig cfg;
    cfg.maxSnapshots = 64;
    NervaAgent agent(cfg);
    agent.RegisterConnection("player_1");

    agent.SetAlertCallback([](const std::string& connId, const std::string& msg){
        std::cerr << "ALERT: [" << connId << "] " << msg << std::endl;
    });

    // Simulate incoming packets (demo)
    for (int i = 0; i < 100; ++i) {
        PacketView p;
        p.sequenceNumber = i;
        p.payload = std::vector<uint8_t>{static_cast<uint8_t>(i & 0xFF)};
        // simple fake signature on even packets
        if ((i % 10) == 0) p.signature = crypto::HMAC_SHA256(ResolveKey(cfg.hmacKeyId), p.payload);
        agent.OnIncomingPacket("player_1", p);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // allow telemetry print
    std::this_thread::sleep_for(std::chrono::seconds(2));
    return 0;
}

#endif
