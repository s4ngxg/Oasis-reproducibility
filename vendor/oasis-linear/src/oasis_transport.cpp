#include "oasis/core.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <climits>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <numeric>
#include <queue>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

using oasis::Bytes;
using oasis::Crypto;
using oasis::Digest;
using oasis::ItemTranscript;
using oasis::NoncePair;
using oasis::Point;
using oasis::PreSignature;
using oasis::Scalar;
using oasis::Variant;
using oasis::Workload;

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

Digest verifier_salt(const Crypto& crypto, const Digest& sid,
                     const Digest& batch, const std::string& purpose) {
    return crypto.hash(
        "OASIS-VERIFIER-SALT-v1",
        {Bytes(purpose.begin(), purpose.end()), oasis::bytes(sid),
         oasis::bytes(batch), oasis::bytes(crypto.random_scalar())});
}

struct Config {
    std::string command;
    std::string host = "127.0.0.1";
    std::string bind = "0.0.0.0";
    std::string out;
    std::string server_metrics;
    std::string tls_cert;
    std::string tls_key;
    std::string tls_ca;
    std::string server_name;
    std::string campaign_id = "unspecified";
    std::string route = "local";
    std::string fault_profile = "none";
    std::string fault_scope = "none";
    double loss_pct = 0.0;
    std::vector<std::uint32_t> n_values{3, 5, 8, 16};
    std::vector<Variant> variants{
        Variant::B0FreshSequential,
        Variant::B1PersistentSequential,
        Variant::B2PersistentPipelined,
        Variant::B3BatchedItemwise,
        Variant::B4BatchedVerification,
        Variant::B5IndependentBatchVerification,
        Variant::B6PhaseCoalescedItemwise};
    int port = 9300;
    int trials = 30;
    int warmup = 5;
    int pairs = 1;
    int inject_bad_partials = 0;
    int inject_bad_openings = 0;
    int inject_bad_client_partials = 0;
    int io_timeout_seconds = 30;
    int listen_backlog = 512;
    int pair_thread_stack_kb = 128;
    int session_cache_capacity = 65536;
    int replay_retention_capacity = 262144;
    int threads =
        std::max(2u, std::thread::hardware_concurrency());
    std::uint64_t vectors = 100000;
    std::uint64_t vector_offset = 0;
    std::string context_seed_hex;
    std::uint64_t context_key_epoch = 1;
    std::uint64_t context_expiry = 3600;
    std::uint64_t context_pair_id = 0;
    std::uint64_t context_execution_id = 0;
    std::uint32_t context_arc_index = 1;
    bool tls = false;
    bool mutual_tls = false;
    bool allow_failures = false;
    bool replay_probe = false;
    bool reconnect_probe = false;
    bool eviction_replay_probe = false;
};

std::vector<std::string> split(const std::string& value, char delimiter) {
    std::vector<std::string> parts;
    std::stringstream stream(value);
    std::string part;
    while (std::getline(stream, part, delimiter)) {
        if (!part.empty()) {
            parts.push_back(part);
        }
    }
    return parts;
}

std::string objective_variant_name(Variant variant) {
    switch (variant) {
        case Variant::B0FreshSequential:
            return "fresh-connection-sequential";
        case Variant::B1PersistentSequential:
            return "persistent-sequential";
        case Variant::B2PersistentPipelined:
            return "persistent-pipelined-itemwise";
        case Variant::B3BatchedItemwise:
            return "batch-joint-presigning-itemwise";
        case Variant::B4BatchedVerification:
            return "batch-joint-presigning-batch-verification";
        case Variant::B5IndependentBatchVerification:
            return "phase-coalesced-batch-verification";
        case Variant::B6PhaseCoalescedItemwise:
            return "phase-coalesced-itemwise";
    }
    throw std::runtime_error("unknown benchmark configuration");
}

Variant parse_objective_variant(const std::string& name) {
    if (name == "fresh-connection-sequential") {
        return Variant::B0FreshSequential;
    }
    if (name == "persistent-sequential") {
        return Variant::B1PersistentSequential;
    }
    if (name == "persistent-pipelined-itemwise") {
        return Variant::B2PersistentPipelined;
    }
    if (name == "batch-joint-presigning-itemwise") {
        return Variant::B3BatchedItemwise;
    }
    if (name == "batch-joint-presigning-batch-verification") {
        return Variant::B4BatchedVerification;
    }
    if (name == "phase-coalesced-batch-verification") {
        return Variant::B5IndependentBatchVerification;
    }
    if (name == "phase-coalesced-itemwise") {
        return Variant::B6PhaseCoalescedItemwise;
    }

    throw std::runtime_error("unknown benchmark configuration: " + name);
}

Config parse_args(int argc, char** argv) {
    require(argc >= 2, "missing command; use --help");
    Config config;
    config.command = argv[1];
    for (int i = 2; i < argc; ++i) {
        const std::string argument = argv[i];
        auto value = [&]() {
            require(i + 1 < argc,
                    "missing value for " + argument);
            return std::string(argv[++i]);
        };
        if (argument == "--host") {
            config.host = value();
        } else if (argument == "--bind") {
            config.bind = value();
        } else if (argument == "--port") {
            config.port = std::stoi(value());
        } else if (argument == "--out") {
            config.out = value();
        } else if (argument == "--server-metrics") {
            config.server_metrics = value();
        } else if (argument == "--tls") {
            config.tls = true;
        } else if (argument == "--mutual-tls") {
            config.tls = true;
            config.mutual_tls = true;
        } else if (argument == "--allow-failures") {
            config.allow_failures = true;
        } else if (argument == "--replay-probe") {
            config.replay_probe = true;
        } else if (argument == "--reconnect-probe") {
            config.reconnect_probe = true;
        } else if (argument == "--eviction-replay-probe") {
            config.eviction_replay_probe = true;
        } else if (argument == "--cert") {
            config.tls_cert = value();
        } else if (argument == "--key") {
            config.tls_key = value();
        } else if (argument == "--ca") {
            config.tls_ca = value();
        } else if (argument == "--server-name") {
            config.server_name = value();
        } else if (argument == "--campaign-id") {
            config.campaign_id = value();
        } else if (argument == "--route") {
            config.route = value();
        } else if (argument == "--fault-profile") {
            config.fault_profile = value();
        } else if (argument == "--fault-scope") {
            config.fault_scope = value();
        } else if (argument == "--loss-pct") {
            config.loss_pct = std::stod(value());
        } else if (argument == "--trials") {
            config.trials = std::stoi(value());
        } else if (argument == "--warmup") {
            config.warmup = std::stoi(value());
        } else if (argument == "--pairs") {
            config.pairs = std::stoi(value());
        } else if (argument == "--inject-bad-partials") {
            config.inject_bad_partials = std::stoi(value());
        } else if (argument == "--inject-bad-client-partials") {
            config.inject_bad_client_partials = std::stoi(value());
        } else if (argument == "--inject-bad-openings") {
            config.inject_bad_openings = std::stoi(value());
        } else if (argument == "--io-timeout-seconds") {
            config.io_timeout_seconds = std::stoi(value());
        } else if (argument == "--listen-backlog") {
            config.listen_backlog = std::stoi(value());
        } else if (argument == "--pair-thread-stack-kb") {
            config.pair_thread_stack_kb = std::stoi(value());
        } else if (argument == "--session-cache-capacity") {
            config.session_cache_capacity = std::stoi(value());
        } else if (argument == "--replay-retention-capacity") {
            config.replay_retention_capacity = std::stoi(value());
        } else if (argument == "--threads") {
            config.threads = std::stoi(value());
        } else if (argument == "--vectors") {
            config.vectors = std::stoull(value());
        } else if (argument == "--vector-offset") {
            config.vector_offset = std::stoull(value());
        } else if (argument == "--context-seed") {
            config.context_seed_hex = value();
        } else if (argument == "--context-key-epoch") {
            config.context_key_epoch = std::stoull(value());
        } else if (argument == "--context-expiry") {
            config.context_expiry = std::stoull(value());
        } else if (argument == "--context-pair-id") {
            config.context_pair_id = std::stoull(value());
        } else if (argument == "--context-execution-id") {
            config.context_execution_id = std::stoull(value());
        } else if (argument == "--context-arc-index") {
            config.context_arc_index = static_cast<std::uint32_t>(
                std::stoul(value()));
        } else if (argument == "--n-values") {
            config.n_values.clear();
            for (const auto& part : split(value(), ',')) {
                config.n_values.push_back(
                    static_cast<std::uint32_t>(std::stoul(part)));
            }
        } else if (argument == "--variants") {
            config.variants.clear();
            for (const auto& part : split(value(), ',')) {
                config.variants.push_back(parse_objective_variant(part));
            }
        } else if (argument == "--help") {
            config.command = "help";
        } else {
            throw std::runtime_error("unknown argument: " + argument);
        }
    }
    require(config.port > 0 && config.port <= 65535,
            "port out of range");
    require(config.trials > 0 && config.warmup >= 0 &&
                config.pairs > 0 && config.threads > 0 &&
                config.inject_bad_partials >= 0 &&
                config.inject_bad_client_partials >= 0 &&
                config.inject_bad_openings >= 0 &&
                config.io_timeout_seconds > 0 &&
                config.io_timeout_seconds <= 3600 &&
                config.listen_backlog > 0 &&
                config.listen_backlog <= 65535 &&
                config.pair_thread_stack_kb >= 64 &&
                config.pair_thread_stack_kb <= 8192 &&
                config.session_cache_capacity > 0 &&
                config.session_cache_capacity <= 1000000 &&
                config.replay_retention_capacity > 0 &&
                config.replay_retention_capacity <= 1000000,
            "invalid positive integer option");
    require(!config.n_values.empty() && !config.variants.empty(),
            "n-values and variants must not be empty");
    require(!config.mutual_tls || config.tls,
            "mutual TLS requires TLS");
    require(config.loss_pct >= 0.0 && config.loss_pct <= 100.0,
            "loss percentage out of range");
    require(!config.campaign_id.empty() &&
                config.campaign_id.size() <= 128 &&
                !config.route.empty() && config.route.size() <= 128,
            "campaign-id and route must contain 1-128 bytes");
    require(!config.fault_profile.empty() &&
                config.fault_profile.size() <= 128 &&
                !config.fault_scope.empty() &&
                config.fault_scope.size() <= 128,
            "fault-profile and fault-scope must contain 1-128 bytes");
    for (std::uint32_t n : config.n_values) {
        require(n >= 1 && n <= 1024, "n must be in [1,1024]");
    }
    if (!config.context_seed_hex.empty()) {
        require(config.context_seed_hex.size() == 64,
                "context seed must contain 64 hexadecimal characters");
        require(config.n_values.size() == 1 && config.pairs == 1,
                "an explicit arc context requires one n value and one pair");
        require(config.context_key_epoch > 0 && config.context_expiry > 0,
                "context key epoch and expiry must be positive");
        require(config.context_arc_index >= 1 &&
                    config.context_arc_index <= config.n_values.front(),
                "context arc index must be in [1,n]");
    }
    return config;
}

void print_help() {
    std::cout
        << "OASIS/ParaSwap native benchmark\n\n"
        << "Commands:\n"
        << "  test    Conformance and differential tests\n"
        << "  local   Native local configuration benchmark\n"
        << "  fallback  Selective-retry fallback benchmark\n"
        << "  server  TCP benchmark server\n"
        << "  client  Cross-region TCP configuration benchmark\n\n"
        << "Common options:\n"
        << "  --n-values 3,5,8,16    ParaSwap address counts "
           "(k=2n-1)\n"
        << "  --variants NAME,...  Descriptive configuration names\n"
        << "  --trials N --warmup N --out PATH\n"
        << "Server/client options:\n"
        << "  --host IP --bind IP --port N --pairs N --threads N\n"
        << "  --io-timeout-seconds N --listen-backlog N\n"
        << "  --pair-thread-stack-kb N\n"
        << "  --session-cache-capacity N\n"
        << "  --replay-retention-capacity N\n"
        << "  --server-metrics PATH\n"
        << "  --inject-bad-partials N  Batch-verification fault injection\n"
        << "  --inject-bad-client-partials N  Initiator fault injection\n"
        << "  --inject-bad-openings N  Responder-opening fault injection\n"
        << "  --tls --cert PATH --key PATH --ca PATH "
           "--server-name NAME\n"
        << "  --mutual-tls  Require certificates from both peers\n"
        << "  --campaign-id ID --route LABEL --loss-pct PCT\n"
        << "  --fault-profile LABEL --fault-scope LABEL\n"
        << "  --allow-failures  Record failed load attempts without "
           "a nonzero exit\n"
        << "  --replay-probe  Retransmit persistent-session payloads\n"
        << "  --reconnect-probe  Verify replay after a lost DONE receipt\n"
        << "  --eviction-replay-probe  Verify replay after hot-cache eviction\n"
        << "Test option:\n"
        << "  --vectors N --vector-offset N\n";
}

Digest parse_digest_hex(const std::string& encoded) {
    Digest digest{};
    for (std::size_t i = 0; i < digest.size(); ++i) {
        const std::string octet = encoded.substr(i * 2, 2);
        std::size_t consumed = 0;
        const unsigned long value = std::stoul(octet, &consumed, 16);
        require(consumed == 2 && value <= 0xff,
                "context seed is not hexadecimal");
        digest[i] = static_cast<std::uint8_t>(value);
    }
    require(oasis::hex(digest) == encoded,
            "context seed must use lowercase hexadecimal");
    return digest;
}

double process_cpu_ms() {
    timespec value{};
    require(clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &value) == 0,
            "clock_gettime failed");
    return value.tv_sec * 1000.0 + value.tv_nsec / 1e6;
}

std::uint64_t soft_nofile_limit() {
    rlimit limit{};
    if (::getrlimit(RLIMIT_NOFILE, &limit) != 0) {
        return 0;
    }
    return limit.rlim_cur == RLIM_INFINITY
        ? std::numeric_limits<std::uint64_t>::max()
        : static_cast<std::uint64_t>(limit.rlim_cur);
}

double thread_cpu_ms() {
    timespec value{};
    require(clock_gettime(CLOCK_THREAD_CPUTIME_ID, &value) == 0,
            "thread clock_gettime failed");
    return value.tv_sec * 1000.0 + value.tv_nsec / 1e6;
}

std::uint64_t current_rss_kb() {
    std::ifstream input("/proc/self/statm");
    std::uint64_t pages = 0;
    std::uint64_t resident = 0;
    input >> pages >> resident;
    return resident *
           static_cast<std::uint64_t>(::sysconf(_SC_PAGESIZE)) / 1024;
}

std::uint64_t peak_rss_kb() {
    rusage usage{};
    require(::getrusage(RUSAGE_SELF, &usage) == 0,
            "getrusage failed");
    return static_cast<std::uint64_t>(usage.ru_maxrss);
}

void ensure_parent(const std::string& path) {
    if (path.empty()) {
        return;
    }
    const auto parent = std::filesystem::path(path).parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent);
    }
}

std::string json_escape(const std::string& value) {
    std::ostringstream out;
    for (char character : value) {
        switch (character) {
            case '"':
                out << "\\\"";
                break;
            case '\\':
                out << "\\\\";
                break;
            case '\n':
                out << "\\n";
                break;
            default:
                out << character;
        }
    }
    return out.str();
}

struct VerifierAuditRecord {
    std::string purpose;
    Digest salt{};
    Digest transcript_digest{};
};

double sample_percentile(std::vector<double> values, double probability) {
    if (values.empty()) {
        return 0.0;
    }
    std::sort(values.begin(), values.end());
    const double position =
        (values.size() - 1) * probability;
    const auto lower = static_cast<std::size_t>(std::floor(position));
    const auto upper = static_cast<std::size_t>(std::ceil(position));
    const double weight = position - lower;
    return values[lower] * (1.0 - weight) + values[upper] * weight;
}

double jain_fairness_from_completion_ms(
    const std::vector<double>& completion_ms) {
    if (completion_ms.empty()) {
        return 0.0;
    }
    double sum = 0.0;
    double square_sum = 0.0;
    for (double duration : completion_ms) {
        require(duration > 0.0, "non-positive pair completion time");
        const double throughput = 1000.0 / duration;
        sum += throughput;
        square_sum += throughput * throughput;
    }
    return square_sum == 0.0
               ? 0.0
               : (sum * sum) /
                     (completion_ms.size() * square_sum);
}

struct Sample {
    std::string environment;
    std::string campaign_id;
    std::string route;
    std::string fault_profile = "none";
    std::string fault_scope = "none";
    double loss_pct = 0;
    bool tls = false;
    Variant variant{};
    std::uint32_t n = 0;
    std::uint32_t k = 0;
    int trial = 0;
    int pairs = 1;
    std::uint32_t fault_count = 0;
    double wall_ms = 0;
    double cpu_ms = 0;
    double verifier_ms = 0;
    std::uint64_t app_messages = 0;
    std::uint64_t logical_sessions = 0;
    std::uint64_t bytes_sent = 0;
    std::uint64_t bytes_received = 0;
    double tcp_rtt_ms = 0;
    double tcp_rttvar_ms = 0;
    double snd_cwnd_segments = 0;
    std::uint32_t retransmissions = 0;
    std::uint32_t failures = 0;
    std::uint64_t frames_sent = 0;
    std::uint64_t frames_received = 0;
    std::uint64_t application_write_calls = 0;
    std::uint64_t application_read_calls = 0;
    std::uint64_t transport_write_ops = 0;
    std::uint64_t transport_read_ops = 0;
    double pair_wall_p50_ms = 0;
    double pair_wall_p95_ms = 0;
    double pair_wall_p99_ms = 0;
    double pair_jain_fairness = 0;
    std::string tls_cipher = "plaintext";
    std::vector<VerifierAuditRecord> verifier_audit;
};

void write_samples(const Config& config,
                   const std::vector<Sample>& samples) {
    require(!config.out.empty(), "--out is required");
    ensure_parent(config.out);
    std::ofstream output(config.out);
    require(output.good(), "cannot open output: " + config.out);
    output << "{\n"
           << "  \"schema\": \"oasis-conformance-transport-v1\",\n"
           << "  \"accounting_revision\": \"logical-frames-done-inclusive-v1\",\n"
           << "  \"workload\": \"ParaSwap n withdraw plus n-1 relock, per-address keys\",\n"
           << "  \"runtime\": {\"io_timeout_seconds\":"
           << config.io_timeout_seconds
           << ",\"listen_backlog\":" << config.listen_backlog
           << ",\"pair_thread_stack_kb\":"
           << config.pair_thread_stack_kb
           << ",\"soft_nofile\":" << soft_nofile_limit()
           << "},\n"
           << "  \"measurement_notes\": {"
              "\"application_messages\":\"logical protocol frames excluding common HELLO/HELLO_ACK and including DONE\","
              "\"application_write_calls\":\"calls to framed/coalesced write_all\","
              "\"transport_ops\":\"SSL_write/SSL_read or send/recv calls\","
              "\"tcp_segments\":\"derive from packet capture\","
              "\"tls_records\":\"not inferred; derive from packet capture\","
              "\"allocations\":\"not collected by the native benchmark\"},\n"
           << "  \"samples\": [\n";
    for (std::size_t i = 0; i < samples.size(); ++i) {
        const auto& sample = samples[i];
        output << "    {\"environment\":\""
               << json_escape(sample.environment)
               << "\",\"campaign_id\":\""
               << json_escape(sample.campaign_id)
               << "\",\"route\":\""
               << json_escape(sample.route)
               << "\",\"fault_profile\":\""
               << json_escape(sample.fault_profile)
               << "\",\"fault_scope\":\""
               << json_escape(sample.fault_scope)
               << "\",\"loss_pct\":" << sample.loss_pct
               << ",\"tls\":"
               << (sample.tls ? "true" : "false")
               << ",\"variant\":\""
               << objective_variant_name(sample.variant)
               << "\",\"n\":" << sample.n
               << ",\"k\":" << sample.k
               << ",\"trial\":" << sample.trial
               << ",\"pairs\":" << sample.pairs
               << ",\"fault_count\":" << sample.fault_count
               << ",\"wall_ms\":" << std::setprecision(10)
               << sample.wall_ms
               << ",\"cpu_ms\":" << sample.cpu_ms
               << ",\"verifier_ms\":" << sample.verifier_ms
               << ",\"application_messages\":"
               << sample.app_messages
               << ",\"logical_sessions\":"
               << sample.logical_sessions
               << ",\"bytes_sent\":" << sample.bytes_sent
               << ",\"bytes_received\":" << sample.bytes_received
               << ",\"tcp_rtt_ms\":" << sample.tcp_rtt_ms
               << ",\"tcp_rttvar_ms\":" << sample.tcp_rttvar_ms
               << ",\"snd_cwnd_segments\":"
               << sample.snd_cwnd_segments
               << ",\"retransmissions\":"
               << sample.retransmissions
               << ",\"failures\":" << sample.failures
               << ",\"frames_sent\":" << sample.frames_sent
               << ",\"frames_received\":"
               << sample.frames_received
               << ",\"application_write_calls\":"
               << sample.application_write_calls
               << ",\"application_read_calls\":"
               << sample.application_read_calls
               << ",\"transport_write_ops\":"
               << sample.transport_write_ops
               << ",\"transport_read_ops\":"
               << sample.transport_read_ops
               << ",\"pair_wall_p50_ms\":"
               << sample.pair_wall_p50_ms
               << ",\"pair_wall_p95_ms\":"
               << sample.pair_wall_p95_ms
               << ",\"pair_wall_p99_ms\":"
               << sample.pair_wall_p99_ms
               << ",\"pair_jain_fairness\":"
               << sample.pair_jain_fairness
               << ",\"tls_cipher\":\""
               << json_escape(sample.tls_cipher) << "\""
               << ",\"verifier_audit\":[";
        for (std::size_t audit_index = 0;
             audit_index < sample.verifier_audit.size();
             ++audit_index) {
            const auto& record = sample.verifier_audit[audit_index];
            output << "{\"purpose\":\""
                   << json_escape(record.purpose)
                   << "\",\"salt\":\"" << oasis::hex(record.salt)
                   << "\",\"transcript_digest\":\""
                   << oasis::hex(record.transcript_digest) << "\"}"
                   << (audit_index + 1 ==
                               sample.verifier_audit.size()
                           ? ""
                           : ",");
        }
        output << "]}";
        output << (i + 1 == samples.size() ? "\n" : ",\n");
    }
    output << "  ]\n}\n";
}

void run_tests(const Config& config, const Crypto& crypto) {
    const auto start = std::chrono::steady_clock::now();
    const auto report =
        oasis::run_conformance_tests(
            crypto, config.vectors, config.vector_offset);
    const double elapsed =
        std::chrono::duration<double>(
            std::chrono::steady_clock::now() - start)
            .count();
    std::ostringstream json;
    json << "{\n"
         << "  \"status\": \"pass\",\n"
         << "  \"vector_offset\": " << config.vector_offset << ",\n"
         << "  \"differential_vectors\": "
         << report.differential_vectors << ",\n"
         << "  \"differential_schedule\": "
            "\"fixture=n_values[vector%4], valid=(vector%2==0), "
            "fault=(vector*0x9e3779b97f4a7c15)%k\",\n"
         << "  \"mutation_checks\": " << report.mutation_checks
         << ",\n"
         << "  \"replay_checks\": " << report.replay_checks
         << ",\n"
         << "  \"retry_checks\": " << report.retry_checks << ",\n"
         << "  \"adaptation_checks\": "
         << report.adaptation_checks << ",\n"
         << "  \"key_separation_checks\": "
         << report.key_separation_checks << ",\n"
         << "  \"independent_batch_checks\": "
         << report.independent_batch_checks << ",\n"
         << "  \"verifier_salt_checks\": "
         << report.verifier_salt_checks << ",\n"
         << "  \"ablation_variant_checks\": "
         << report.ablation_variant_checks << ",\n"
         << "  \"canonical_encoding_checks\": "
         << report.canonical_encoding_checks << ",\n"
         << "  \"cryptographic_kat_checks\": "
         << report.cryptographic_kat_checks << ",\n"
         << "  \"message_accounting_checks\": "
         << report.message_accounting_checks << ",\n"
         << "  \"elapsed_seconds\": " << elapsed << "\n"
         << "}\n";
    std::cout << json.str();
    if (!config.out.empty()) {
        ensure_parent(config.out);
        std::ofstream output(config.out);
        require(output.good(), "cannot write test report");
        output << json.str();
    }
}

void run_local(const Config& config, const Crypto& crypto) {
    std::vector<Sample> samples;
    std::mt19937 order_generator(0x4f415349U);
    for (std::uint32_t n : config.n_values) {
        for (int trial = -config.warmup;
             trial < config.trials; ++trial) {
            auto order = config.variants;
            std::shuffle(order.begin(), order.end(), order_generator);
            const Digest seed = oasis::digest_from_u64(
                crypto, (static_cast<std::uint64_t>(n) << 32) ^
                            static_cast<std::uint64_t>(trial + 100000));
            const Workload workload =
                oasis::make_paraswap_workload(crypto, n, seed);
            for (Variant variant : order) {
                Workload execution_workload = workload;
                execution_workload.execution_id =
                    (static_cast<std::uint64_t>(
                         static_cast<std::uint32_t>(
                             trial + 100000))
                     << 8) |
                    static_cast<std::uint8_t>(variant);
                oasis::finalize_workload(
                    crypto, execution_workload);
                const double cpu_start = process_cpu_ms();
                const auto wall_start =
                    std::chrono::steady_clock::now();
                const auto result =
                    oasis::execute(
                        crypto, execution_workload, variant);
                const double wall_ms =
                    std::chrono::duration<double, std::milli>(
                        std::chrono::steady_clock::now() - wall_start)
                        .count();
                const double cpu_ms = process_cpu_ms() - cpu_start;
                require(result.accepted,
                        "local protocol execution rejected");
                if (trial >= 0) {
                    Sample sample;
                    sample.environment = "local-native";
                    sample.campaign_id = config.campaign_id;
                    sample.route = "local";
                    sample.fault_profile = config.fault_profile;
                    sample.fault_scope = config.fault_scope;
                    sample.variant = variant;
                    sample.n = n;
                    sample.k = static_cast<std::uint32_t>(
                        workload.items.size());
                    sample.trial = trial;
                    sample.wall_ms = wall_ms;
                    sample.cpu_ms = cpu_ms;
                    sample.app_messages = result.application_messages;
                    sample.logical_sessions = result.logical_sessions;
                    samples.push_back(std::move(sample));
                }
            }
        }
        std::cout << "local n=" << n << " k=" << (2 * n - 1)
                  << " complete\n";
    }
    write_samples(config, samples);
    std::cout << "wrote=" << config.out << "\n";
}

void run_fallback(const Config& config, const Crypto& crypto) {
    std::vector<Sample> samples;
    for (std::uint32_t n : config.n_values) {
        const std::uint32_t k = 2 * n - 1;
        std::vector<std::uint32_t> fault_counts{
            1, std::max(1U, k / 4), k};
        std::sort(fault_counts.begin(), fault_counts.end());
        fault_counts.erase(
            std::unique(fault_counts.begin(), fault_counts.end()),
            fault_counts.end());
        for (std::uint32_t fault_count : fault_counts) {
            for (int trial = -config.warmup;
                 trial < config.trials; ++trial) {
                const Digest seed = oasis::digest_from_u64(
                    crypto,
                    (static_cast<std::uint64_t>(n) << 48) ^
                        (static_cast<std::uint64_t>(fault_count) << 32) ^
                        static_cast<std::uint32_t>(trial + 100000));
                const Workload workload =
                    oasis::make_paraswap_workload(
                        crypto, n, seed, 1, 3600, fault_count);
                oasis::FaultPlan faults;
                for (std::uint32_t i = 0; i < fault_count; ++i) {
                    faults.bad_partial_indices.push_back(i);
                }
                const double cpu_start = process_cpu_ms();
                const auto wall_start =
                    std::chrono::steady_clock::now();
                const auto result = oasis::execute(
                    crypto, workload,
                    Variant::B4BatchedVerification, faults);
                const double wall_ms =
                    std::chrono::duration<double, std::milli>(
                        std::chrono::steady_clock::now() - wall_start)
                        .count();
                const double cpu_ms = process_cpu_ms() - cpu_start;
                require(result.accepted &&
                            result.retried_indices.size() ==
                                fault_count,
                        "fallback did not retry every faulty item");
                if (trial >= 0) {
                    Sample sample;
                    sample.environment = "local-fallback";
                    sample.campaign_id = config.campaign_id;
                    sample.route = "local";
                    sample.fault_profile = config.fault_profile;
                    sample.fault_scope = config.fault_scope;
                    sample.variant = Variant::B4BatchedVerification;
                    sample.n = n;
                    sample.k = k;
                    sample.trial = trial;
                    sample.fault_count = fault_count;
                    sample.wall_ms = wall_ms;
                    sample.cpu_ms = cpu_ms;
                    sample.app_messages = result.application_messages;
                    sample.logical_sessions = result.logical_sessions;
                    samples.push_back(std::move(sample));
                }
            }
        }
    }
    write_samples(config, samples);
    std::cout << "wrote=" << config.out << "\n";
}

void append_u32(Bytes& output, std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>(value >> 24));
    output.push_back(static_cast<std::uint8_t>(value >> 16));
    output.push_back(static_cast<std::uint8_t>(value >> 8));
    output.push_back(static_cast<std::uint8_t>(value));
}

void append_u64(Bytes& output, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(
            static_cast<std::uint8_t>(value >> shift));
    }
}

template <std::size_t N>
void append_array(Bytes& output,
                  const std::array<std::uint8_t, N>& value) {
    output.insert(output.end(), value.begin(), value.end());
}

void append_string(Bytes& output, const std::string& value) {
    require(value.size() <= 128, "protocol string exceeds 128 bytes");
    append_u32(output, static_cast<std::uint32_t>(value.size()));
    output.insert(output.end(), value.begin(), value.end());
}

class Reader {
public:
    explicit Reader(const Bytes& input) : input_(input) {}

    std::uint8_t u8() {
        require(offset_ < input_.size(), "short u8");
        return input_[offset_++];
    }

    std::uint32_t u32() {
        require(offset_ + 4 <= input_.size(), "short u32");
        std::uint32_t value = 0;
        for (int i = 0; i < 4; ++i) {
            value = (value << 8) | input_[offset_++];
        }
        return value;
    }

    std::uint64_t u64() {
        require(offset_ + 8 <= input_.size(), "short u64");
        std::uint64_t value = 0;
        for (int i = 0; i < 8; ++i) {
            value = (value << 8) | input_[offset_++];
        }
        return value;
    }

    std::string string(std::size_t maximum_size = 128) {
        const std::uint32_t size = u32();
        require(size > 0 && size <= maximum_size,
                "invalid protocol string length");
        require(offset_ + size <= input_.size(), "short string");
        const auto begin = input_.begin() +
            static_cast<std::ptrdiff_t>(offset_);
        std::string value(begin, begin + size);
        offset_ += size;
        return value;
    }

    template <std::size_t N>
    std::array<std::uint8_t, N> array() {
        require(offset_ + N <= input_.size(), "short array");
        std::array<std::uint8_t, N> value{};
        std::copy_n(input_.begin() +
                        static_cast<std::ptrdiff_t>(offset_),
                    N, value.begin());
        offset_ += N;
        return value;
    }

    void finish() const {
        require(offset_ == input_.size(),
                "trailing bytes in protocol frame");
    }

private:
    const Bytes& input_;
    std::size_t offset_ = 0;
};

class TlsContext {
public:
    TlsContext(const Config& config, bool server) {
        if (!config.tls) {
            return;
        }
        OPENSSL_init_ssl(0, nullptr);
        context_.reset(SSL_CTX_new(
            server ? TLS_server_method() : TLS_client_method()));
        require(context_ != nullptr, "SSL_CTX_new failed");
        require(SSL_CTX_set_min_proto_version(
                    context_.get(), TLS1_3_VERSION) == 1,
                "cannot require TLS 1.3");
        if (server) {
            require(!config.tls_cert.empty() &&
                        !config.tls_key.empty(),
                    "TLS server requires --cert and --key");
            require(SSL_CTX_use_certificate_chain_file(
                        context_.get(),
                        config.tls_cert.c_str()) == 1,
                    "cannot load TLS certificate");
            require(SSL_CTX_use_PrivateKey_file(
                        context_.get(), config.tls_key.c_str(),
                        SSL_FILETYPE_PEM) == 1 &&
                        SSL_CTX_check_private_key(
                            context_.get()) == 1,
                    "cannot load TLS private key");
            if (config.mutual_tls) {
                require(!config.tls_ca.empty(),
                        "mutual TLS server requires --ca");
                require(SSL_CTX_load_verify_locations(
                            context_.get(), config.tls_ca.c_str(),
                            nullptr) == 1,
                        "cannot load mutual TLS CA");
                SSL_CTX_set_verify(
                    context_.get(),
                    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                    nullptr);
            }
        } else {
            require(!config.tls_ca.empty(),
                    "TLS client requires --ca");
            require(SSL_CTX_load_verify_locations(
                        context_.get(), config.tls_ca.c_str(),
                        nullptr) == 1,
                    "cannot load TLS CA");
            SSL_CTX_set_verify(
                context_.get(), SSL_VERIFY_PEER, nullptr);
            if (config.mutual_tls) {
                require(!config.tls_cert.empty() &&
                            !config.tls_key.empty(),
                        "mutual TLS client requires --cert and --key");
                require(SSL_CTX_use_certificate_chain_file(
                            context_.get(),
                            config.tls_cert.c_str()) == 1,
                        "cannot load mutual TLS client certificate");
                require(SSL_CTX_use_PrivateKey_file(
                            context_.get(), config.tls_key.c_str(),
                            SSL_FILETYPE_PEM) == 1 &&
                            SSL_CTX_check_private_key(
                                context_.get()) == 1,
                        "cannot load mutual TLS client private key");
            }
        }
    }

    SSL_CTX* get() const { return context_.get(); }

private:
    struct Deleter {
        void operator()(SSL_CTX* value) const {
            SSL_CTX_free(value);
        }
    };
    std::unique_ptr<SSL_CTX, Deleter> context_;
};

std::string socket_error_message(const std::string& operation,
                                 int error_number = errno) {
    return operation + ": " + std::strerror(error_number) +
        " (errno=" + std::to_string(error_number) + ")";
}

std::string ssl_error_message(const std::string& operation,
                              SSL* ssl, int result) {
    const int ssl_error = SSL_get_error(ssl, result);
    const int error_number = errno;
    std::ostringstream message;
    message << operation << ": SSL_get_error=" << ssl_error;
    if (error_number != 0) {
        message << ", " << std::strerror(error_number)
                << " (errno=" << error_number << ")";
    }
    bool first = true;
    for (unsigned long code = ERR_get_error(); code != 0;
         code = ERR_get_error()) {
        char buffer[256]{};
        ERR_error_string_n(code, buffer, sizeof(buffer));
        message << (first ? ", OpenSSL=" : " | ") << buffer;
        first = false;
    }
    return message.str();
}

void configure_socket(int fd, int timeout_seconds) {
    int enabled = 1;
    require(::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled,
                         sizeof(enabled)) == 0,
            socket_error_message("TCP_NODELAY failed"));
    timeval timeout{timeout_seconds, 0};
    require(::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                         sizeof(timeout)) == 0,
            socket_error_message("SO_RCVTIMEO failed"));
    require(::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                         sizeof(timeout)) == 0,
            socket_error_message("SO_SNDTIMEO failed"));
}

class Channel {
public:
    Channel(int fd, SSL_CTX* tls_context, bool server,
            const std::string& peer_name = "")
        : fd_(fd) {
        try {
            if (tls_context == nullptr) {
                return;
            }
            ssl_ = SSL_new(tls_context);
            require(ssl_ != nullptr &&
                        SSL_set_fd(ssl_, fd_) == 1,
                    "SSL channel initialization failed");
            if (!server) {
                require(!peer_name.empty(),
                        "TLS client peer name is empty");
                X509_VERIFY_PARAM* parameters =
                    SSL_get0_param(ssl_);
                in_addr address{};
                if (::inet_pton(
                        AF_INET, peer_name.c_str(), &address) == 1) {
                    require(X509_VERIFY_PARAM_set1_ip_asc(
                                parameters,
                                peer_name.c_str()) == 1,
                            "cannot set TLS peer IP");
                } else {
                    require(SSL_set1_host(
                                ssl_, peer_name.c_str()) == 1,
                            "cannot set TLS peer name");
                }
            }
            errno = 0;
            const int result =
                server ? SSL_accept(ssl_) : SSL_connect(ssl_);
            if (result != 1) {
                throw std::runtime_error(ssl_error_message(
                    server ? "TLS 1.3 server handshake failed"
                           : "TLS 1.3 client handshake failed",
                    ssl_, result));
            }
            if (!server) {
                require(SSL_get_verify_result(ssl_) == X509_V_OK,
                        "TLS certificate verification failed");
            }
        } catch (...) {
            if (ssl_ != nullptr) {
                SSL_free(ssl_);
                ssl_ = nullptr;
            }
            if (fd_ >= 0) {
                ::close(fd_);
                fd_ = -1;
            }
            throw;
        }
    }

    ~Channel() {
        if (ssl_ != nullptr) {
            SSL_shutdown(ssl_);
            SSL_free(ssl_);
        }
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    Channel(const Channel&) = delete;
    Channel& operator=(const Channel&) = delete;

    int fd() const { return fd_; }
    std::uint64_t transport_write_ops() const {
        return transport_write_ops_;
    }
    std::uint64_t transport_read_ops() const {
        return transport_read_ops_;
    }
    std::string tls_cipher() const {
        return ssl_ == nullptr ? "plaintext"
                               : std::string(SSL_get_cipher_name(ssl_));
    }

    bool write_all(const std::uint8_t* data, std::size_t size) {
        std::size_t sent = 0;
        while (sent < size) {
            errno = 0;
            ++transport_write_ops_;
            const int count =
                ssl_ != nullptr
                    ? SSL_write(
                          ssl_, data + sent,
                          static_cast<int>(std::min<std::size_t>(
                              size - sent, INT_MAX)))
                    : static_cast<int>(::send(
                          fd_, data + sent, size - sent,
                          MSG_NOSIGNAL));
            if (count <= 0) {
                if (ssl_ != nullptr) {
                    throw std::runtime_error(ssl_error_message(
                        "TLS write failed", ssl_, count));
                }
                throw std::runtime_error(
                    count == 0
                        ? "TCP write failed: peer closed connection"
                        : socket_error_message("TCP write failed"));
            }
            sent += static_cast<std::size_t>(count);
        }
        return true;
    }

    bool read_all(std::uint8_t* data, std::size_t size) {
        std::size_t received = 0;
        while (received < size) {
            errno = 0;
            ++transport_read_ops_;
            const int count =
                ssl_ != nullptr
                    ? SSL_read(
                          ssl_, data + received,
                          static_cast<int>(std::min<std::size_t>(
                              size - received, INT_MAX)))
                    : static_cast<int>(::recv(
                          fd_, data + received, size - received, 0));
            if (count <= 0) {
                if (ssl_ != nullptr) {
                    throw std::runtime_error(ssl_error_message(
                        "TLS read failed", ssl_, count));
                }
                throw std::runtime_error(
                    count == 0
                        ? "TCP read failed: peer closed connection"
                        : socket_error_message("TCP read failed"));
            }
            received += static_cast<std::size_t>(count);
        }
        return true;
    }

private:
    int fd_ = -1;
    SSL* ssl_ = nullptr;
    std::uint64_t transport_write_ops_ = 0;
    std::uint64_t transport_read_ops_ = 0;
};

struct IoCounters {
    std::uint64_t sent = 0;
    std::uint64_t received = 0;
    std::uint64_t sent_frames = 0;
    std::uint64_t received_frames = 0;
    std::uint64_t application_write_calls = 0;
    std::uint64_t application_read_calls = 0;
    std::uint64_t transport_write_ops = 0;
    std::uint64_t transport_read_ops = 0;
};

bool send_frame(Channel& channel, const Bytes& payload,
                IoCounters& counters) {
    require(payload.size() <= 16 * 1024 * 1024,
            "frame exceeds 16 MiB");
    Bytes header;
    append_u32(header,
               static_cast<std::uint32_t>(payload.size()));
    const bool ok =
        channel.write_all(header.data(), header.size()) &&
        (payload.empty() ||
         channel.write_all(payload.data(), payload.size()));
    if (ok) {
        counters.sent += header.size() + payload.size();
        ++counters.sent_frames;
        counters.application_write_calls += payload.empty() ? 1 : 2;
    }
    return ok;
}

bool receive_frame(Channel& channel, Bytes& payload,
                   IoCounters& counters) {
    std::array<std::uint8_t, 4> header{};
    if (!channel.read_all(header.data(), header.size())) {
        return false;
    }
    const std::uint32_t size =
        (static_cast<std::uint32_t>(header[0]) << 24) |
        (static_cast<std::uint32_t>(header[1]) << 16) |
        (static_cast<std::uint32_t>(header[2]) << 8) |
        static_cast<std::uint32_t>(header[3]);
    require(size <= 16 * 1024 * 1024, "oversized frame");
    payload.assign(size, 0);
    if (size > 0 &&
        !channel.read_all(payload.data(), payload.size())) {
        return false;
    }
    counters.received += header.size() + payload.size();
    ++counters.received_frames;
    counters.application_read_calls += payload.empty() ? 1 : 2;
    return true;
}

bool send_frames_coalesced(Channel& channel,
                           const std::vector<Bytes>& payloads,
                           IoCounters& counters) {
    Bytes body;
    std::size_t body_size = 0;
    for (const auto& payload : payloads) {
        require(payload.size() <= 16 * 1024 * 1024,
                "frame exceeds 16 MiB");
        body_size += 4 + payload.size();
    }
    require(body_size <= 64 * 1024 * 1024,
            "coalesced phase exceeds 64 MiB");
    body.reserve(body_size);
    for (const auto& payload : payloads) {
        append_u32(body, static_cast<std::uint32_t>(payload.size()));
        body.insert(body.end(), payload.begin(), payload.end());
    }
    Bytes wire;
    wire.reserve(4 + body.size());
    append_u32(wire, static_cast<std::uint32_t>(body.size()));
    wire.insert(wire.end(), body.begin(), body.end());
    if (!wire.empty() && !channel.write_all(wire.data(), wire.size())) {
        return false;
    }
    counters.sent += wire.size();
    counters.sent_frames += payloads.size();
    if (!wire.empty()) {
        ++counters.application_write_calls;
    }
    return true;
}

bool receive_frames_coalesced(Channel& channel, std::size_t expected_count,
                              std::vector<Bytes>& payloads,
                              IoCounters& counters) {
    std::array<std::uint8_t, 4> outer{};
    if (!channel.read_all(outer.data(), outer.size())) {
        return false;
    }
    const std::uint32_t body_size =
        (static_cast<std::uint32_t>(outer[0]) << 24) |
        (static_cast<std::uint32_t>(outer[1]) << 16) |
        (static_cast<std::uint32_t>(outer[2]) << 8) |
        static_cast<std::uint32_t>(outer[3]);
    require(body_size <= 64 * 1024 * 1024,
            "oversized coalesced phase");
    Bytes body(body_size);
    if (body_size > 0 &&
        !channel.read_all(body.data(), body.size())) {
        return false;
    }

    payloads.clear();
    payloads.reserve(expected_count);
    std::size_t offset = 0;
    while (offset < body.size()) {
        require(body.size() - offset >= 4,
                "truncated coalesced frame header");
        const std::uint32_t size =
            (static_cast<std::uint32_t>(body[offset]) << 24) |
            (static_cast<std::uint32_t>(body[offset + 1]) << 16) |
            (static_cast<std::uint32_t>(body[offset + 2]) << 8) |
            static_cast<std::uint32_t>(body[offset + 3]);
        offset += 4;
        require(size <= 16 * 1024 * 1024 &&
                    size <= body.size() - offset,
                "invalid coalesced frame length");
        payloads.emplace_back(body.begin() + offset,
                              body.begin() + offset + size);
        offset += size;
    }
    require(payloads.size() == expected_count,
            "coalesced phase frame count mismatch");
    counters.received += outer.size() + body.size();
    counters.received_frames += payloads.size();
    counters.application_read_calls += body.empty() ? 1 : 2;
    return true;
}

struct TcpInfo {
    double rtt_ms = 0;
    double rttvar_ms = 0;
    double cwnd = 0;
    std::uint32_t retrans = 0;
};

TcpInfo tcp_info_for(int fd) {
    tcp_info info{};
    socklen_t length = sizeof(info);
    require(::getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info,
                         &length) == 0,
            "TCP_INFO failed");
    return {info.tcpi_rtt / 1000.0,
            info.tcpi_rttvar / 1000.0,
            static_cast<double>(info.tcpi_snd_cwnd),
            info.tcpi_total_retrans};
}

int connect_to(const std::string& host, int port,
               int timeout_seconds) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    require(fd >= 0, socket_error_message("socket failed"));
    try {
        configure_socket(fd, timeout_seconds);
    } catch (...) {
        ::close(fd);
        throw;
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port =
        htons(static_cast<std::uint16_t>(port));
    if (::inet_pton(AF_INET, host.c_str(), &address.sin_addr) != 1) {
        ::close(fd);
        throw std::runtime_error("invalid IPv4 address: " + host);
    }
    if (::connect(fd, reinterpret_cast<sockaddr*>(&address),
                  sizeof(address)) != 0) {
        const int error_number = errno;
        ::close(fd);
        throw std::runtime_error(socket_error_message(
            "connect failed: " + host, error_number));
    }
    return fd;
}

enum class MessageType : std::uint8_t {
    Hello = 0,
    Init = 1,
    Commit = 2,
    ClientNonce = 3,
    ServerOpen = 4,
    ClientFinal = 5,
    Done = 6,
    HelloAck = 7,
    RetryPlan = 8,
    FinalStatus = 9,
    Error = 255,
};

Bytes encode_hello(Variant variant, const Workload& workload,
                   std::uint32_t expected_sessions,
                   const Config& config) {
    Bytes output{static_cast<std::uint8_t>(MessageType::Hello),
                 static_cast<std::uint8_t>(variant)};
    append_u32(output, workload.n);
    append_u64(output, workload.key_epoch);
    append_u64(output, workload.expiry);
    append_u64(output, workload.pair_id);
    append_u64(output, workload.execution_id);
    append_u32(output, workload.arc_index);
    append_array(output, workload.seed);
    append_u32(output, expected_sessions);
    append_string(output, config.campaign_id);
    append_string(output, config.route);
    append_string(output, config.fault_profile);
    append_string(output, config.fault_scope);
    append_u32(
        output,
        static_cast<std::uint32_t>(
            std::llround(config.loss_pct * 1000.0)));
    append_u32(output,
               static_cast<std::uint32_t>(workload.items.size()));
    for (const auto& item : workload.items) {
        output.push_back(static_cast<std::uint8_t>(item.type));
        append_u32(output, item.ordinal);
        append_u32(output, item.address_index);
        append_u64(output, item.timeout);
        append_array(output, item.message);
        append_array(output, item.statement);
        append_array(output, item.client_public);
    }
    return output;
}

struct Hello {
    Variant variant{};
    std::uint32_t expected_sessions = 0;
    std::string campaign_id;
    std::string route;
    std::string fault_profile;
    std::string fault_scope;
    double loss_pct = 0;
    Workload workload;
};

Hello decode_hello(const Bytes& payload, const Crypto& crypto) {
    Reader reader(payload);
    require(reader.u8() ==
                static_cast<std::uint8_t>(MessageType::Hello),
            "expected HELLO");
    Hello hello;
    const std::uint8_t variant = reader.u8();
    require(variant <=
                static_cast<std::uint8_t>(
                    Variant::B6PhaseCoalescedItemwise),
            "HELLO has invalid variant");
    hello.variant = static_cast<Variant>(variant);
    const std::uint32_t n = reader.u32();
    const std::uint64_t key_epoch = reader.u64();
    const std::uint64_t expiry = reader.u64();
    const std::uint64_t pair_id = reader.u64();
    const std::uint64_t execution_id = reader.u64();
    const std::uint32_t arc_index = reader.u32();
    const Digest seed = reader.array<32>();
    hello.expected_sessions = reader.u32();
    hello.campaign_id = reader.string();
    hello.route = reader.string();
    hello.fault_profile = reader.string();
    hello.fault_scope = reader.string();
    require(!hello.fault_profile.empty() &&
                hello.fault_profile.size() <= 128 &&
                !hello.fault_scope.empty() &&
                hello.fault_scope.size() <= 128,
            "HELLO fault metadata out of range");
    const std::uint32_t loss_milli_pct = reader.u32();
    require(loss_milli_pct <= 100000,
            "HELLO loss percentage out of range");
    hello.loss_pct = loss_milli_pct / 1000.0;
    hello.workload = oasis::make_paraswap_public_workload(
        crypto, n, seed, key_epoch, expiry, pair_id,
        execution_id, arc_index);
    const std::uint32_t item_count = reader.u32();
    require(item_count == hello.workload.items.size(),
            "HELLO workload cardinality mismatch");
    for (std::uint32_t i = 0; i < item_count; ++i) {
        auto& expected = hello.workload.items[i];
        const auto type = static_cast<oasis::ItemType>(reader.u8());
        const std::uint32_t ordinal = reader.u32();
        const std::uint32_t address_index = reader.u32();
        const std::uint64_t timeout = reader.u64();
        const Digest message = reader.array<32>();
        const Point statement = reader.array<33>();
        const Point client_public = reader.array<33>();
        require(type == expected.type &&
                    ordinal == expected.ordinal &&
                    address_index == expected.address_index &&
                    timeout == expected.timeout &&
                    message == expected.message &&
                    statement == expected.statement,
                "HELLO item does not match ParaSwap workload");
        (void)crypto.point_mul(
            client_public,
            crypto.derive_scalar("OASIS-POINT-VALIDATION-v1", {}));
        expected.client_public = client_public;
    }
    reader.finish();
    const std::uint32_t k =
        static_cast<std::uint32_t>(hello.workload.items.size());
    require(hello.expected_sessions > 0 &&
                hello.expected_sessions <= k,
            "HELLO session count out of range");
    const bool batched =
        hello.variant == Variant::B3BatchedItemwise ||
        hello.variant == Variant::B4BatchedVerification;
    require(!batched || hello.expected_sessions == 1,
            "batched HELLO must contain one logical session");
    return hello;
}

Bytes encode_hello_ack(const Workload& workload) {
    Bytes output{
        static_cast<std::uint8_t>(MessageType::HelloAck)};
    append_u32(output, workload.n);
    for (std::uint32_t address = 1; address <= workload.n; ++address) {
        const auto found = std::find_if(
            workload.items.begin(), workload.items.end(),
            [address](const oasis::Item& item) {
                return item.address_index == address;
            });
        require(found != workload.items.end(),
                "server public key missing");
        append_array(output, found->server_public);
    }
    append_array(output, workload.context_digest);
    append_array(output, workload.batch_digest);
    return output;
}

void decode_hello_ack(const Bytes& payload, Workload& workload,
                      const Crypto& crypto) {
    Reader reader(payload);
    require(reader.u8() ==
                static_cast<std::uint8_t>(MessageType::HelloAck),
            "expected HELLO_ACK");
    require(reader.u32() == workload.n,
            "HELLO_ACK n mismatch");
    std::vector<Point> server_publics(workload.n);
    for (auto& public_key : server_publics) {
        public_key = reader.array<33>();
    }
    const Digest expected_context = reader.array<32>();
    const Digest expected_batch = reader.array<32>();
    reader.finish();
    oasis::attach_server_public_keys(
        crypto, workload, server_publics);
    oasis::finalize_workload(crypto, workload);
    require(workload.context_digest == expected_context &&
                workload.batch_digest == expected_batch,
            "HELLO_ACK transcript digest mismatch");
}

struct SessionHeader {
    MessageType type{};
    std::uint32_t logical_id = 0;
    Digest sid{};
    std::vector<std::uint32_t> indices;
};

void append_session_header(Bytes& output, MessageType type,
                           std::uint32_t logical_id,
                           const Digest& sid,
                           const std::vector<std::uint32_t>& indices) {
    output.push_back(static_cast<std::uint8_t>(type));
    append_u32(output, logical_id);
    append_array(output, sid);
    append_u32(output,
               static_cast<std::uint32_t>(indices.size()));
    for (std::uint32_t index : indices) {
        append_u32(output, index);
    }
}

SessionHeader read_session_header(Reader& reader) {
    SessionHeader header;
    header.type = static_cast<MessageType>(reader.u8());
    header.logical_id = reader.u32();
    header.sid = reader.array<32>();
    const std::uint32_t count = reader.u32();
    require(count > 0 && count <= 2047,
            "invalid record count");
    for (std::uint32_t i = 0; i < count; ++i) {
        header.indices.push_back(reader.u32());
    }
    return header;
}

struct ClientSession {
    std::uint32_t logical_id = 0;
    Digest sid{};
    std::vector<std::uint32_t> indices;
    std::vector<NoncePair> nonces;
    std::vector<ItemTranscript> transcripts;
};

struct ServerSession {
    std::uint32_t logical_id = 0;
    Digest sid{};
    std::vector<std::uint32_t> indices;
    std::vector<Scalar> server_nonces;
    std::vector<ItemTranscript> transcripts;
    Bytes init_payload;
    Bytes commit_response;
    Bytes nonce_payload;
    Bytes open_response;
    Bytes final_payload;
    Bytes retry_plan_payload;
    Bytes final_status_response;
    std::set<std::uint32_t> skipped_indices;
};

VerifierAuditRecord make_verifier_audit_record(
    const Crypto& crypto, std::string purpose, const Digest& salt,
    const Workload& workload,
    const std::vector<ItemTranscript>& transcripts) {
    std::vector<Bytes> fields;
    fields.reserve(2 + transcripts.size() * 10);
    fields.push_back(oasis::bytes(workload.context_digest));
    fields.push_back(oasis::bytes(workload.batch_digest));
    for (std::size_t i = 0; i < transcripts.size(); ++i) {
        const auto& transcript = transcripts[i];
        fields.push_back(oasis::bytes(transcript.sid));
        fields.push_back(oasis::bytes(workload.items.at(i).digest));
        fields.push_back(oasis::bytes(transcript.commitment));
        fields.push_back(oasis::bytes(transcript.server_nonce_point));
        fields.push_back(oasis::bytes(transcript.client_nonce_point));
        fields.push_back(oasis::bytes(transcript.server_partial));
        fields.push_back(oasis::bytes(transcript.client_partial));
        fields.push_back(oasis::bytes(transcript.challenge));
        fields.push_back(
            oasis::bytes(transcript.presignature.adaptor_nonce));
        fields.push_back(oasis::bytes(transcript.presignature.scalar));
    }
    return {std::move(purpose), salt,
            crypto.hash("OASIS-VERIFIER-AUDIT-TRANSCRIPT-v1", fields)};
}

using SessionKey = std::pair<Digest, std::uint32_t>;

struct StoredServerSession {
    explicit StoredServerSession(ServerSession value)
        : session(std::move(value)) {}

    std::mutex mutex;
    ServerSession session;
};

class ServerSessionStore {
public:
    ServerSessionStore(std::size_t capacity,
                       std::size_t replay_retention_capacity)
        : capacity_(capacity),
          replay_retention_capacity_(replay_retention_capacity) {
        require(capacity_ > 0, "session cache capacity must be positive");
        require(replay_retention_capacity_ > 0,
                "replay retention capacity must be positive");
    }

    template <typename Factory>
    std::shared_ptr<StoredServerSession> get_or_create(
        const SessionKey& key, const Bytes& init_payload,
        Factory factory) {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto found = sessions_.find(key);
        if (found != sessions_.end()) {
            require(found->second->session.init_payload ==
                        init_payload,
                    "conflicting INIT replay");
            return found->second;
        }
        const auto retained = replay_retention_.find(key);
        if (retained != replay_retention_.end()) {
            require(retained->second->session.init_payload ==
                        init_payload,
                    "conflicting INIT replay");
            return retained->second;
        }
        evict_if_needed();
        auto stored = std::make_shared<StoredServerSession>(
            factory());
        sessions_.emplace(key, stored);
        insertion_order_.push_back(key);
        return stored;
    }

private:
    void evict_if_needed() {
        std::size_t candidates = insertion_order_.size();
        while (sessions_.size() >= capacity_ && candidates-- > 0) {
            const SessionKey key = insertion_order_.front();
            insertion_order_.pop_front();
            const auto found = sessions_.find(key);
            if (found == sessions_.end()) {
                continue;
            }
            if (found->second.use_count() == 1) {
                require(replay_retention_.size() <
                            replay_retention_capacity_,
                        "replay retention capacity exhausted");
                const auto inserted = replay_retention_.emplace(
                    key, found->second);
                require(inserted.second,
                        "duplicate replay-retention session");
                sessions_.erase(found);
            } else {
                insertion_order_.push_back(key);
            }
        }
        require(sessions_.size() < capacity_,
                "server replay cache has no evictable session");
    }

    const std::size_t capacity_;
    const std::size_t replay_retention_capacity_;
    std::mutex mutex_;
    std::map<SessionKey,
             std::shared_ptr<StoredServerSession>> sessions_;
    std::map<SessionKey,
             std::shared_ptr<StoredServerSession>> replay_retention_;
    std::deque<SessionKey> insertion_order_;
};

Bytes encode_init(const ClientSession& session) {
    Bytes output;
    append_session_header(output, MessageType::Init,
                          session.logical_id, session.sid,
                          session.indices);
    return output;
}

Bytes encode_commit(const ServerSession& session) {
    Bytes output;
    append_session_header(output, MessageType::Commit,
                          session.logical_id, session.sid,
                          session.indices);
    for (const auto& transcript : session.transcripts) {
        append_array(output, transcript.commitment);
    }
    return output;
}

void decode_commit(const Bytes& payload, ClientSession& session) {
    Reader reader(payload);
    const auto header = read_session_header(reader);
    require(header.type == MessageType::Commit &&
                header.logical_id == session.logical_id &&
                header.sid == session.sid &&
                header.indices == session.indices,
            "COMMIT header mismatch");
    session.transcripts.resize(session.indices.size());
    for (std::size_t i = 0; i < session.indices.size(); ++i) {
        session.transcripts[i].sid = session.sid;
        session.transcripts[i].commitment = reader.array<33>();
    }
    reader.finish();
}

Bytes encode_client_nonces(ClientSession& session,
                           const Crypto& crypto) {
    session.nonces =
        oasis::make_nonce_plan(crypto, session.indices.size());
    Bytes output;
    append_session_header(output, MessageType::ClientNonce,
                          session.logical_id, session.sid,
                          session.indices);
    for (std::size_t i = 0; i < session.indices.size(); ++i) {
        session.transcripts[i].client_nonce_point =
            crypto.base_mul(session.nonces[i].client_nonce);
        append_array(
            output,
            session.transcripts[i].client_nonce_point);
    }
    return output;
}

void decode_client_nonces(const Bytes& payload,
                          ServerSession& session) {
    Reader reader(payload);
    const auto header = read_session_header(reader);
    require(header.type == MessageType::ClientNonce &&
                header.logical_id == session.logical_id &&
                header.sid == session.sid &&
                header.indices == session.indices,
            "CLIENT_NONCE header mismatch");
    for (auto& transcript : session.transcripts) {
        transcript.client_nonce_point = reader.array<33>();
    }
    reader.finish();
}

Bytes encode_server_open(ServerSession& session,
                         const Crypto& crypto,
                         const Workload& workload,
                         std::uint32_t bad_partial_count = 0,
                         std::uint32_t bad_opening_count = 0) {
    Bytes output;
    append_session_header(output, MessageType::ServerOpen,
                          session.logical_id, session.sid,
                          session.indices);
    for (std::size_t i = 0; i < session.indices.size(); ++i) {
        auto& transcript = session.transcripts[i];
        const auto& item =
            workload.items.at(session.indices[i]);
        transcript.presignature.adaptor_nonce =
            crypto.point_add(
                crypto.point_add(
                    transcript.client_nonce_point,
                    transcript.server_nonce_point),
                item.statement);
        transcript.challenge = oasis::derive_challenge(
            crypto, session.sid, item,
            transcript.presignature.adaptor_nonce);
        transcript.server_partial = crypto.scalar_add(
            session.server_nonces[i],
            crypto.scalar_mul(transcript.challenge,
                              item.server_secret));
        if (i < bad_partial_count) {
            transcript.server_partial = crypto.scalar_add(
                transcript.server_partial,
                crypto.derive_scalar(
                    "OASIS-NETWORK-FAULT-INJECTION-v1",
                    {oasis::bytes(session.sid),
                     oasis::bytes(item.digest)}));
        }
        if (i < bad_opening_count) {
            transcript.commitment_blind = crypto.scalar_add(
                transcript.commitment_blind,
                crypto.derive_scalar(
                    "OASIS-NETWORK-OPENING-FAULT-v1",
                    {oasis::bytes(session.sid),
                     oasis::bytes(item.digest)}));
        }
        append_array(output, transcript.server_nonce_point);
        append_array(output, transcript.commitment_blind);
        append_array(output, transcript.server_partial);
    }
    return output;
}

std::vector<std::uint32_t> decode_server_open(
    const Bytes& payload, ClientSession& session,
    const Crypto& crypto, const Workload& workload) {
    Reader reader(payload);
    const auto header = read_session_header(reader);
    require(header.type == MessageType::ServerOpen &&
                header.logical_id == session.logical_id &&
                header.sid == session.sid &&
                header.indices == session.indices,
            "SERVER_OPEN header mismatch");
    std::vector<std::uint32_t> opening_failures;
    for (std::size_t i = 0; i < session.indices.size(); ++i) {
        auto& transcript = session.transcripts[i];
        const auto& item =
            workload.items.at(session.indices[i]);
        transcript.server_nonce_point = reader.array<33>();
        transcript.commitment_blind = reader.array<32>();
        transcript.server_partial = reader.array<32>();
        require(crypto.scalar_is_canonical(
                    transcript.commitment_blind) &&
                    crypto.scalar_is_canonical(
                        transcript.server_partial),
                "SERVER_OPEN contains non-canonical scalar");
        const Scalar message =
            oasis::derive_commitment_message(
                crypto, session.sid, item,
                transcript.server_nonce_point);
        if (!crypto.pedersen_verify(
                transcript.commitment, message,
                transcript.commitment_blind)) {
            opening_failures.push_back(session.indices[i]);
        }
        transcript.presignature.adaptor_nonce =
            crypto.point_add(
                crypto.point_add(
                    transcript.client_nonce_point,
                    transcript.server_nonce_point),
                item.statement);
        transcript.challenge = oasis::derive_challenge(
            crypto, session.sid, item,
            transcript.presignature.adaptor_nonce);
    }
    reader.finish();
    return opening_failures;
}

bool verify_server_partial_item(const Crypto& crypto,
                                const oasis::Item& item,
                                const ItemTranscript& transcript) {
    return crypto.base_mul(transcript.server_partial) ==
           crypto.point_add(
               transcript.server_nonce_point,
               crypto.point_mul(item.server_public,
                                transcript.challenge));
}

Bytes encode_client_final(ClientSession& session,
                          const Crypto& crypto,
                          const Workload& workload,
                          const std::set<std::uint32_t>&
                              skipped_indices = {},
                          bool batch_verification = false,
                          double* verifier_ms = nullptr,
                          bool defer_verification = false,
                          std::uint32_t bad_client_partial_count = 0,
                          std::vector<VerifierAuditRecord>* audit = nullptr) {
    std::uint32_t injected = 0;
    for (std::size_t i = 0; i < session.indices.size(); ++i) {
        auto& transcript = session.transcripts[i];
        const auto& item =
            workload.items.at(session.indices[i]);
        if (skipped_indices.count(session.indices[i]) != 0) {
            continue;
        }
        transcript.client_partial = crypto.scalar_add(
            session.nonces[i].client_nonce,
            crypto.scalar_mul(transcript.challenge,
                              item.client_secret));
        transcript.presignature.scalar = crypto.scalar_add(
            transcript.client_partial,
            transcript.server_partial);
    }

    const auto verify_start = std::chrono::steady_clock::now();
    if (defer_verification) {
        // A caller that owns several independent sessions verifies their
        // transcripts together after all client partials are populated.
    } else if (batch_verification) {
        require(skipped_indices.empty() &&
                    session.indices.size() == workload.items.size(),
                "batch final verification requires the complete vector");
        for (std::size_t i = 0; i < session.indices.size(); ++i) {
            require(session.indices[i] == i,
                    "batch final verification order mismatch");
        }
        const Digest salt = verifier_salt(
            crypto, session.sid, workload.batch_digest, "full");
        if (audit != nullptr) {
            audit->push_back(make_verifier_audit_record(
                crypto, "client/final-presignatures/shared", salt,
                workload, session.transcripts));
        }
        require(oasis::verify_presignatures_batch(
                    crypto, workload, session.sid,
                    session.transcripts, salt),
                "client batch pre-signature verification failed");
    } else {
        for (std::size_t i = 0; i < session.indices.size(); ++i) {
            if (skipped_indices.count(session.indices[i]) != 0) {
                continue;
            }
            require(oasis::verify_presignature(
                        crypto,
                        workload.items.at(session.indices[i]),
                        session.sid, session.transcripts[i]),
                    "client constructed invalid pre-signature");
        }
    }
    if (verifier_ms != nullptr) {
        *verifier_ms +=
            std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - verify_start)
                .count();
    }

    Bytes output;
    append_session_header(output, MessageType::ClientFinal,
                          session.logical_id, session.sid,
                          session.indices);
    for (std::size_t i = 0; i < session.indices.size(); ++i) {
        if (skipped_indices.count(session.indices[i]) != 0) {
            append_array(output, Scalar{});
            append_array(output, Point{});
            append_array(output, Scalar{});
            continue;
        }
        Scalar client_partial = session.transcripts[i].client_partial;
        Scalar final_scalar =
            session.transcripts[i].presignature.scalar;
        if (injected < bad_client_partial_count) {
            const Scalar delta = crypto.derive_scalar(
                "OASIS-NETWORK-CLIENT-FAULT-v1",
                {oasis::bytes(session.sid),
                 oasis::bytes(workload.items.at(
                                  session.indices[i]).digest)});
            client_partial = crypto.scalar_add(client_partial, delta);
            final_scalar = crypto.scalar_add(final_scalar, delta);
            ++injected;
        }
        append_array(output, client_partial);
        append_array(output,
                     session.transcripts[i].presignature.adaptor_nonce);
        append_array(output, final_scalar);
    }
    return output;
}

void decode_and_verify_client_final(
    const Bytes& payload, ServerSession& session,
    const Crypto& crypto, const Workload& workload,
    bool batch_verification = false,
    bool defer_verification = false) {
    Reader reader(payload);
    const auto header = read_session_header(reader);
    require(header.type == MessageType::ClientFinal &&
                header.logical_id == session.logical_id &&
                header.sid == session.sid &&
                header.indices == session.indices,
            "CLIENT_FINAL header mismatch");
    bool has_skipped = false;
    for (std::size_t i = 0; i < session.indices.size(); ++i) {
        auto& transcript = session.transcripts[i];
        transcript.client_partial = reader.array<32>();
        transcript.presignature.adaptor_nonce =
            reader.array<33>();
        transcript.presignature.scalar = reader.array<32>();
        if (session.skipped_indices.count(
                session.indices[i]) != 0) {
            has_skipped = true;
            require(transcript.client_partial == Scalar{} &&
                        transcript.presignature.adaptor_nonce ==
                            Point{} &&
                        transcript.presignature.scalar ==
                            Scalar{},
                    "skipped item has nonzero final payload");
            continue;
        }
        require(crypto.scalar_is_canonical(
                    transcript.client_partial) &&
                    crypto.scalar_is_canonical(
                        transcript.presignature.scalar),
                "CLIENT_FINAL contains non-canonical scalar");
        require(transcript.presignature.scalar ==
                    crypto.scalar_add(
                        transcript.client_partial,
                        transcript.server_partial),
                "final scalar does not equal partial sum");
    }
    reader.finish();

    if (defer_verification) {
        return;
    }

    if (batch_verification && !has_skipped) {
        require(session.indices.size() == workload.items.size(),
                "server batch verification requires the complete vector");
        for (std::size_t i = 0; i < session.indices.size(); ++i) {
            require(session.indices[i] == i,
                    "server batch verification order mismatch");
        }
        const Digest partial_salt = verifier_salt(
            crypto, session.sid, workload.batch_digest, "client");
        require(oasis::verify_client_partials_batch(
                    crypto, workload, session.sid,
                    session.transcripts, partial_salt),
                "server batch client-partial verification failed");
        const Digest final_salt = verifier_salt(
            crypto, session.sid, workload.batch_digest, "full");
        require(oasis::verify_presignatures_batch(
                    crypto, workload, session.sid,
                    session.transcripts, final_salt),
                "server batch pre-signature verification failed");
    } else {
        for (std::size_t i = 0; i < session.indices.size(); ++i) {
            if (session.skipped_indices.count(
                    session.indices[i]) != 0) {
                continue;
            }
            const auto& transcript = session.transcripts[i];
            const auto& item =
                workload.items.at(session.indices[i]);
            const Point expected_client = crypto.point_add(
                transcript.client_nonce_point,
                crypto.point_mul(item.client_public,
                                 transcript.challenge));
            require(crypto.base_mul(transcript.client_partial) ==
                        expected_client,
                    "client partial signature invalid");
            require(oasis::verify_presignature(
                        crypto, item, session.sid, transcript),
                    "server rejected final pre-signature");
        }
    }
}

bool verify_client_partial_item(
    const Crypto& crypto, const oasis::Item& item,
    const ItemTranscript& transcript) {
    return crypto.base_mul(transcript.client_partial) ==
           crypto.point_add(
               transcript.client_nonce_point,
               crypto.point_mul(item.client_public,
                                transcript.challenge));
}

std::vector<std::uint32_t> localize_invalid_client_final(
    ServerSession& session, const Crypto& crypto,
    const Workload& workload, bool use_batch_verification) {
    bool aggregate_valid = false;
    if (use_batch_verification && session.skipped_indices.empty()) {
        const Digest partial_salt = verifier_salt(
            crypto, session.sid, workload.batch_digest, "client");
        const Digest final_salt = verifier_salt(
            crypto, session.sid, workload.batch_digest, "full");
        aggregate_valid = oasis::verify_client_partials_batch(
                              crypto, workload, session.sid,
                              session.transcripts, partial_salt) &&
                          oasis::verify_presignatures_batch(
                              crypto, workload, session.sid,
                              session.transcripts, final_salt);
    }
    if (aggregate_valid) {
        return {};
    }

    std::vector<std::uint32_t> bad_indices;
    for (std::size_t i = 0; i < session.indices.size(); ++i) {
        const std::uint32_t index = session.indices[i];
        if (session.skipped_indices.count(index) != 0) {
            continue;
        }
        const auto& transcript = session.transcripts[i];
        const auto& item = workload.items.at(index);
        if (!verify_client_partial_item(crypto, item, transcript) ||
            !oasis::verify_presignature(
                crypto, item, session.sid, transcript)) {
            bad_indices.push_back(index);
        }
    }
    return bad_indices;
}

Bytes encode_final_status(const ServerSession& session,
                          const std::vector<std::uint32_t>& bad_indices) {
    Bytes output;
    append_session_header(output, MessageType::FinalStatus,
                          session.logical_id, session.sid,
                          bad_indices);
    return output;
}

std::vector<std::uint32_t> decode_final_status(
    const Bytes& payload, const ClientSession& parent,
    std::size_t item_count) {
    Reader reader(payload);
    require(static_cast<MessageType>(reader.u8()) ==
                    MessageType::FinalStatus &&
                reader.u32() == parent.logical_id &&
                reader.array<32>() == parent.sid,
            "FINAL_STATUS parent mismatch");
    const std::uint32_t count = reader.u32();
    require(count <= item_count, "FINAL_STATUS count is too large");
    std::vector<std::uint32_t> indices;
    indices.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        indices.push_back(reader.u32());
    }
    reader.finish();
    std::uint32_t previous = 0;
    bool first = true;
    for (std::uint32_t index : indices) {
        require(index < item_count && (first || index > previous),
                "FINAL_STATUS indices must be canonical");
        first = false;
        previous = index;
    }
    return indices;
}

Bytes encode_done() {
    return Bytes{
        static_cast<std::uint8_t>(MessageType::Done)};
}

void require_done(const Bytes& payload) {
    require(payload == encode_done(),
            "expected DONE response");
}

ClientSession make_client_session(
    const Crypto& crypto, const Workload& workload,
    Variant variant, std::uint32_t logical_id,
    const std::vector<std::uint32_t>& indices) {
    ClientSession session;
    session.logical_id = logical_id;
    session.indices = indices;
    if (variant == Variant::B3BatchedItemwise ||
        variant == Variant::B4BatchedVerification) {
        session.sid =
            oasis::make_session_id(crypto, workload, 0);
    } else {
        require(indices.size() == 1,
                "independent session must contain one item");
        session.sid = oasis::make_item_session_id(
            crypto, workload, indices.front());
    }
    return session;
}

ClientSession make_retry_client_session(
    const Crypto& crypto, const Workload& workload,
    std::uint32_t item_index, const Digest& parent_sid) {
    require(item_index < workload.items.size(),
            "retry item index out of range");
    ClientSession session;
    session.logical_id = item_index + 1;
    session.indices = {item_index};
    session.sid = oasis::make_retry_session_id(
        crypto, workload, item_index, 1, parent_sid);
    return session;
}

ServerSession make_server_session(
    const Bytes& init_payload, const Crypto& crypto,
    const Workload& workload, Variant variant) {
    Reader reader(init_payload);
    const auto header = read_session_header(reader);
    reader.finish();
    require(header.type == MessageType::Init,
            "expected INIT");
    for (std::uint32_t index : header.indices) {
        require(index < workload.items.size(),
                "INIT item index out of range");
    }
    const bool b3 =
        variant == Variant::B3BatchedItemwise;
    const bool b4 =
        variant == Variant::B4BatchedVerification;
    const bool initial_batch =
        (b3 || b4) &&
        header.indices.size() == workload.items.size();
    const bool retry = b4 && header.indices.size() == 1 &&
                       header.logical_id > 0;
    Digest expected_sid{};
    if (initial_batch) {
        require(header.logical_id == 0,
                "initial batch logical ID must be zero");
        expected_sid =
            oasis::make_session_id(crypto, workload, 0);
    } else if (retry) {
        const std::uint32_t index = header.indices.front();
        require(header.logical_id == index + 1,
                "retry logical ID must equal item index plus one");
        expected_sid = oasis::make_retry_session_id(
            crypto, workload, index, 1,
            oasis::make_session_id(crypto, workload, 0));
    } else {
        expected_sid = oasis::make_item_session_id(
            crypto, workload, header.indices.at(0));
    }
    require(header.sid == expected_sid,
            "INIT session identifier mismatch");
    require(initial_batch || retry ||
                (!(b3 || b4) &&
                 header.indices.size() == 1),
            "INIT grouping does not match variant");
    if (initial_batch) {
        for (std::size_t i = 0; i < header.indices.size(); ++i) {
            require(header.indices[i] == i,
                    "batched INIT indices are not canonical");
        }
    }

    ServerSession session;
    session.logical_id = header.logical_id;
    session.sid = header.sid;
    session.indices = header.indices;
    session.init_payload = init_payload;
    session.server_nonces.resize(header.indices.size());
    session.transcripts.resize(header.indices.size());
    for (std::size_t i = 0; i < header.indices.size(); ++i) {
        auto& transcript = session.transcripts[i];
        const auto& item =
            workload.items.at(header.indices[i]);
        transcript.sid = session.sid;
        session.server_nonces[i] = crypto.random_scalar();
        transcript.server_nonce_point =
            crypto.base_mul(session.server_nonces[i]);
        transcript.commitment_blind = crypto.random_scalar();
        const Scalar message =
            oasis::derive_commitment_message(
                crypto, session.sid, item,
                transcript.server_nonce_point);
        transcript.commitment = crypto.pedersen_commit(
            message, transcript.commitment_blind);
    }
    return session;
}

struct ConnectionResult {
    IoCounters io;
    TcpInfo tcp;
    std::uint64_t messages = 0;
    std::uint64_t logical_sessions = 0;
    double verifier_ms = 0;
    std::uint32_t fallback_count = 0;
    std::string tls_cipher;
    std::vector<VerifierAuditRecord> verifier_audit;
};

ConnectionResult run_protocol_connection(
    const Config& config, const Crypto& crypto,
    const Workload& client_workload, Variant variant,
    const std::vector<std::uint32_t>& selected_indices,
    SSL_CTX* tls_context) {
    const std::string peer_name =
        config.server_name.empty() ? config.host
                                   : config.server_name;
    Channel channel(connect_to(config.host, config.port,
                               config.io_timeout_seconds), tls_context,
                    false, peer_name);
    IoCounters io;
    Workload workload = client_workload;
    double verifier_ms = 0;
    std::vector<VerifierAuditRecord> verifier_audit;

    const std::uint32_t expected_sessions =
        (variant == Variant::B3BatchedItemwise ||
         variant == Variant::B4BatchedVerification)
            ? 1
            : static_cast<std::uint32_t>(
                  selected_indices.size());
    require(send_frame(
                channel,
                encode_hello(variant, workload,
                             expected_sessions, config),
                io),
            "HELLO send failed");
    Bytes hello_ack;
    require(receive_frame(channel, hello_ack, io),
            "HELLO_ACK receive failed");
    decode_hello_ack(hello_ack, workload, crypto);

    std::vector<ClientSession> sessions;
    const bool batched =
        variant == Variant::B3BatchedItemwise ||
        variant == Variant::B4BatchedVerification;
    if (batched) {
        sessions.push_back(make_client_session(
            crypto, workload, variant, 0, selected_indices));
    } else {
        for (std::uint32_t index : selected_indices) {
            sessions.push_back(make_client_session(
                crypto, workload, variant, index, {index}));
        }
    }

    auto init_one = [&](ClientSession& session) {
        const Bytes request = encode_init(session);
        require(send_frame(channel, request, io),
                "INIT send failed");
        Bytes commit;
        require(receive_frame(channel, commit, io),
                "COMMIT receive failed");
        decode_commit(commit, session);
        if (config.replay_probe) {
            require(send_frame(channel, request, io),
                    "duplicate INIT send failed");
            Bytes duplicate;
            require(receive_frame(channel, duplicate, io) &&
                        duplicate == commit,
                    "duplicate INIT did not return cached COMMIT");
        }
    };
    auto nonce_one = [&](ClientSession& session) {
        const Bytes request =
            encode_client_nonces(session, crypto);
        require(send_frame(
                    channel, request, io),
                "CLIENT_NONCE send failed");
        Bytes open;
        require(receive_frame(channel, open, io),
                "SERVER_OPEN receive failed");
        const auto opening_failures =
            decode_server_open(open, session, crypto, workload);
        if (config.replay_probe) {
            require(send_frame(channel, request, io),
                    "duplicate CLIENT_NONCE send failed");
            Bytes duplicate;
            require(receive_frame(channel, duplicate, io) &&
                        duplicate == open,
                    "duplicate CLIENT_NONCE did not return cached opening");
        }
        return opening_failures;
    };
    auto verify_itemwise_and_finish = [&](ClientSession& session) {
        const auto verify_start =
            std::chrono::steady_clock::now();
        for (std::size_t i = 0;
             i < session.indices.size(); ++i) {
            require(verify_server_partial_item(
                        crypto,
                        workload.items.at(session.indices[i]),
                        session.transcripts[i]),
                "network itemwise verification failed");
        }
        verifier_ms +=
            std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - verify_start)
                .count();
        const Bytes final_payload =
            encode_client_final(
                session, crypto, workload, {}, false,
                &verifier_ms);
        require(send_frame(channel, final_payload, io),
                "CLIENT_FINAL send failed");
        if (config.replay_probe &&
            session.logical_id + 1 < sessions.size()) {
            require(send_frame(channel, final_payload, io),
                    "duplicate CLIENT_FINAL send failed");
        }
    };

    if (variant == Variant::B2PersistentPipelined ||
        variant == Variant::B5IndependentBatchVerification ||
        variant == Variant::B6PhaseCoalescedItemwise) {
        require(!config.replay_probe,
                "replay probe requires persistent sequential sessions");
        std::vector<Bytes> init_payloads;
        init_payloads.reserve(sessions.size());
        for (const auto& session : sessions) {
            init_payloads.push_back(encode_init(session));
        }
        if (variant == Variant::B6PhaseCoalescedItemwise) {
            require(send_frames_coalesced(channel, init_payloads, io),
                    "coalesced INIT send failed");
        } else {
            for (const auto& payload : init_payloads) {
                require(send_frame(channel, payload, io),
                        "pipelined INIT send failed");
            }
        }
        std::vector<Bytes> commit_payloads(sessions.size());
        if (variant == Variant::B6PhaseCoalescedItemwise) {
            require(receive_frames_coalesced(
                        channel, sessions.size(), commit_payloads, io),
                    "coalesced COMMIT receive failed");
        } else {
            for (auto& commit : commit_payloads) {
                require(receive_frame(channel, commit, io),
                        "pipelined COMMIT receive failed");
            }
        }
        for (std::size_t i = 0; i < sessions.size(); ++i) {
            decode_commit(commit_payloads[i], sessions[i]);
        }
        std::vector<Bytes> nonce_payloads(sessions.size());
        for (std::size_t i = 0; i < sessions.size(); ++i) {
            nonce_payloads[i] =
                encode_client_nonces(sessions[i], crypto);
        }
        if (variant == Variant::B6PhaseCoalescedItemwise) {
            require(send_frames_coalesced(channel, nonce_payloads, io),
                    "coalesced CLIENT_NONCE send failed");
        } else {
            for (const auto& payload : nonce_payloads) {
                require(send_frame(
                            channel, payload, io),
                        "pipelined CLIENT_NONCE send failed");
            }
        }
        std::vector<Bytes> open_payloads(sessions.size());
        if (variant == Variant::B6PhaseCoalescedItemwise) {
            require(receive_frames_coalesced(
                        channel, sessions.size(), open_payloads, io),
                    "coalesced SERVER_OPEN receive failed");
        } else {
            for (auto& payload : open_payloads) {
                require(receive_frame(channel, payload, io),
                        "pipelined SERVER_OPEN receive failed");
            }
        }
        std::vector<Bytes> final_payloads(sessions.size());
        std::vector<ItemTranscript> independent_transcripts;
        independent_transcripts.reserve(sessions.size());
        for (std::size_t i = 0; i < sessions.size(); ++i) {
            require(decode_server_open(
                        open_payloads[i], sessions[i], crypto,
                        workload).empty(),
                    "pipelined commitment opening failed");
            independent_transcripts.push_back(
                sessions[i].transcripts.front());
        }
        const bool independent_batch =
            variant == Variant::B5IndependentBatchVerification &&
            sessions.size() >= oasis::kBatchVerificationMinItems;
        if (independent_batch) {
            const auto verify_start =
                std::chrono::steady_clock::now();
            const Digest salt = crypto.hash(
                "OASIS-NETWORK-INDEPENDENT-SERVER-SALT-v1",
                {oasis::bytes(workload.batch_digest),
                 oasis::bytes(crypto.random_scalar())});
            verifier_audit.push_back(make_verifier_audit_record(
                crypto, "client/server-partials/independent", salt,
                workload, independent_transcripts));
            require(oasis::verify_server_partials_batch_independent(
                        crypto, workload, independent_transcripts, salt),
                    "independent server-partial batch verification failed");
            verifier_ms +=
                std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - verify_start)
                    .count();
        } else {
            const auto verify_start =
                std::chrono::steady_clock::now();
            for (std::size_t i = 0; i < sessions.size(); ++i) {
                require(verify_server_partial_item(
                            crypto, workload.items.at(
                                        sessions[i].indices.front()),
                            sessions[i].transcripts.front()),
                        "pipelined itemwise verification failed");
            }
            verifier_ms +=
                std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - verify_start)
                    .count();
        }
        for (std::size_t i = 0; i < sessions.size(); ++i) {
            final_payloads[i] = encode_client_final(
                sessions[i], crypto, workload, {}, false,
                &verifier_ms, independent_batch);
            independent_transcripts[i] =
                sessions[i].transcripts.front();
        }
        if (independent_batch) {
            const auto verify_start =
                std::chrono::steady_clock::now();
            const Digest salt = crypto.hash(
                "OASIS-NETWORK-INDEPENDENT-FINAL-SALT-v1",
                {oasis::bytes(workload.batch_digest),
                 oasis::bytes(crypto.random_scalar())});
            verifier_audit.push_back(make_verifier_audit_record(
                crypto, "client/final-presignatures/independent", salt,
                workload, independent_transcripts));
            require(oasis::verify_presignatures_batch_independent(
                        crypto, workload, independent_transcripts, salt),
                    "independent final batch verification failed");
            verifier_ms +=
                std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - verify_start)
                    .count();
        }
        if (variant == Variant::B6PhaseCoalescedItemwise) {
            require(send_frames_coalesced(channel, final_payloads, io),
                    "coalesced CLIENT_FINAL send failed");
        } else {
            for (const auto& payload : final_payloads) {
                require(send_frame(channel, payload, io),
                        "pipelined CLIENT_FINAL send failed");
            }
        }
    } else if (variant == Variant::B4BatchedVerification) {
        auto& initial = sessions.front();
        init_one(initial);
        std::vector<std::uint32_t> bad_indices =
            nonce_one(initial);
        const bool use_batch_verification =
            initial.indices.size() >=
            oasis::kBatchVerificationMinItems;
        const auto verify_start =
            std::chrono::steady_clock::now();
        if (use_batch_verification && bad_indices.empty()) {
            const Digest salt = verifier_salt(
                crypto, initial.sid, workload.batch_digest, "server");
            verifier_audit.push_back(make_verifier_audit_record(
                crypto, "client/server-partials/shared", salt,
                workload, initial.transcripts));
            if (!oasis::verify_server_partials_batch(
                    crypto, workload, initial.sid,
                    initial.transcripts, salt)) {
                for (std::size_t i = 0;
                     i < initial.indices.size(); ++i) {
                    if (!verify_server_partial_item(
                            crypto,
                            workload.items.at(initial.indices[i]),
                            initial.transcripts[i])) {
                        bad_indices.push_back(initial.indices[i]);
                    }
                }
                require(!bad_indices.empty(),
                        "batch verification failed without a localizable item");
            }
        } else {
            for (std::size_t i = 0;
                 i < initial.indices.size(); ++i) {
                if (std::find(bad_indices.begin(), bad_indices.end(),
                              initial.indices[i]) != bad_indices.end()) {
                    continue;
                }
                if (!verify_server_partial_item(
                        crypto,
                        workload.items.at(initial.indices[i]),
                        initial.transcripts[i])) {
                    bad_indices.push_back(initial.indices[i]);
                }
            }
        }
        verifier_ms +=
            std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - verify_start)
                .count();

        std::set<std::uint32_t> skipped(
            bad_indices.begin(), bad_indices.end());
        if (!bad_indices.empty()) {
            Bytes retry_plan;
            append_session_header(
                retry_plan, MessageType::RetryPlan,
                initial.logical_id, initial.sid, bad_indices);
            require(send_frame(channel, retry_plan, io),
                    "RETRY_PLAN send failed");
        }
        require(send_frame(
                    channel,
                    encode_client_final(
                        initial, crypto, workload, skipped,
                        bad_indices.empty() &&
                            use_batch_verification,
                        &verifier_ms, false,
                        static_cast<std::uint32_t>(
                            config.inject_bad_client_partials),
                        &verifier_audit),
                    io),
                "initial CLIENT_FINAL send failed");

        Bytes final_status;
        require(receive_frame(channel, final_status, io),
                "FINAL_STATUS receive failed");
        const auto client_bad_indices = decode_final_status(
            final_status, initial, workload.items.size());
        bad_indices.insert(bad_indices.end(),
                           client_bad_indices.begin(),
                           client_bad_indices.end());
        std::sort(bad_indices.begin(), bad_indices.end());
        bad_indices.erase(
            std::unique(bad_indices.begin(), bad_indices.end()),
            bad_indices.end());

        const Digest parent_sid = initial.sid;
        for (std::uint32_t index : bad_indices) {
            ClientSession retry = make_retry_client_session(
                crypto, workload, index, parent_sid);
            init_one(retry);
            require(nonce_one(retry).empty(),
                    "retry commitment opening failed");
            verify_itemwise_and_finish(retry);
            sessions.push_back(std::move(retry));
        }
    } else {
        for (auto& session : sessions) {
            init_one(session);
            require(nonce_one(session).empty(),
                    "commitment opening failed");
            verify_itemwise_and_finish(session);
        }
    }

    Bytes done;
    require(receive_frame(channel, done, io),
            "DONE receive failed");
    require_done(done);
    const std::uint32_t fallback_count =
        variant == Variant::B4BatchedVerification
            ? static_cast<std::uint32_t>(sessions.size() - 1)
            : 0;
    io.transport_write_ops = channel.transport_write_ops();
    io.transport_read_ops = channel.transport_read_ops();
    return {io, tcp_info_for(channel.fd()),
            5 * sessions.size() +
                (variant == Variant::B4BatchedVerification ? 1 : 0) +
                (fallback_count > 0 ? 1 : 0) + 1,
            sessions.size(), verifier_ms, fallback_count,
            channel.tls_cipher(),
            std::move(verifier_audit)};
}

void run_reconnect_probe(const Config& config,
                         const Crypto& crypto,
                         const Workload& client_workload,
                         SSL_CTX* tls_context,
                         const Scalar& client_master_secret,
                         bool force_hot_cache_eviction) {
    Bytes expected_init;
    Bytes expected_commit;
    Bytes expected_nonce;
    Bytes expected_open;
    Bytes expected_final;
    std::unique_ptr<ClientSession> session;
    for (int connection = 0; connection < 2; ++connection) {
        if (connection == 1 && force_hot_cache_eviction) {
            Workload pressure = oasis::make_paraswap_public_workload(
                crypto, client_workload.n,
                oasis::digest_from_u64(
                    crypto, 0x4556494354494f4eULL),
                client_workload.key_epoch,
                client_workload.expiry,
                client_workload.pair_id + 1,
                client_workload.execution_id + 1,
                client_workload.arc_index);
            oasis::attach_client_key_shares(
                crypto, pressure, client_master_secret);
            (void)run_protocol_connection(
                config, crypto, pressure,
                Variant::B1PersistentSequential, {0}, tls_context);
        }
        const std::string peer_name =
            config.server_name.empty() ? config.host
                                       : config.server_name;
        Channel channel(
            connect_to(config.host, config.port,
                       config.io_timeout_seconds),
            tls_context, false, peer_name);
        IoCounters io;
        Workload workload = client_workload;
        require(send_frame(
                    channel,
                    encode_hello(
                        Variant::B1PersistentSequential,
                        workload,
                        1,
                        config),
                    io),
                "reconnect probe HELLO send failed");
        Bytes hello_ack;
        require(receive_frame(channel, hello_ack, io),
                "reconnect probe HELLO_ACK receive failed");
        decode_hello_ack(hello_ack, workload, crypto);
        if (session == nullptr) {
            session = std::make_unique<ClientSession>(
                make_client_session(
                    crypto, workload,
                    Variant::B1PersistentSequential, 0, {0}));
        }
        const Bytes init = encode_init(*session);
        require(send_frame(channel, init, io),
                "reconnect probe INIT send failed");
        Bytes commit;
        require(receive_frame(channel, commit, io),
                "reconnect probe COMMIT receive failed");
        if (connection == 0) {
            expected_init = init;
            expected_commit = commit;
            decode_commit(commit, *session);
            expected_nonce =
                encode_client_nonces(*session, crypto);
            require(send_frame(channel, expected_nonce, io),
                    "reconnect probe CLIENT_NONCE send failed");
            require(receive_frame(channel, expected_open, io),
                    "reconnect probe SERVER_OPEN receive failed");
            require(decode_server_open(
                        expected_open, *session, crypto,
                        workload).empty(),
                    "reconnect probe opening verification failed");
            expected_final = encode_client_final(
                *session, crypto, workload);
            require(send_frame(channel, expected_final, io),
                    "reconnect probe CLIENT_FINAL send failed");
            // Close without reading DONE. The second connection must replay
            // the exact transcript and receive the cached completion result.
        } else {
            require(init == expected_init,
                    "reconnect changed deterministic INIT");
            require(commit == expected_commit,
                    "reconnect did not return cached COMMIT");
            require(send_frame(channel, expected_nonce, io),
                    "reconnect probe replay CLIENT_NONCE send failed");
            Bytes open;
            require(receive_frame(channel, open, io) &&
                        open == expected_open,
                    "reconnect did not return cached SERVER_OPEN");
            require(send_frame(channel, expected_final, io),
                    "reconnect probe replay CLIENT_FINAL send failed");
            Bytes done;
            require(receive_frame(channel, done, io),
                    "reconnect probe DONE receive failed");
            require_done(done);
        }
    }
    if (force_hot_cache_eviction) {
        const std::string peer_name =
            config.server_name.empty() ? config.host
                                       : config.server_name;
        Channel channel(
            connect_to(config.host, config.port,
                       config.io_timeout_seconds),
            tls_context, false, peer_name);
        IoCounters io;
        Workload workload = client_workload;
        require(send_frame(
                    channel,
                    encode_hello(
                        Variant::B1PersistentSequential,
                        workload, 1, config),
                    io),
                "conflicting replay probe HELLO send failed");
        Bytes hello_ack;
        require(receive_frame(channel, hello_ack, io),
                "conflicting replay probe HELLO_ACK receive failed");
        decode_hello_ack(hello_ack, workload, crypto);
        Bytes conflicting_init = expected_init;
        require(!conflicting_init.empty(),
                "conflicting replay probe has no INIT payload");
        conflicting_init.back() ^= 1;
        require(send_frame(channel, conflicting_init, io),
                "conflicting replay probe INIT send failed");
        Bytes response;
        bool rejected = false;
        try {
            rejected = !receive_frame(channel, response, io);
        } catch (const std::exception&) {
            rejected = true;
        }
        require(rejected,
                "conflicting replay after eviction was accepted");
    }
}

struct NetworkAggregate {
    std::uint64_t sent = 0;
    std::uint64_t received = 0;
    std::uint64_t messages = 0;
    std::uint64_t sessions = 0;
    double rtt = 0;
    double rttvar = 0;
    double cwnd = 0;
    double verifier_ms = 0;
    std::uint32_t retrans = 0;
    std::uint32_t failures = 0;
    std::uint32_t fallback_count = 0;
    std::uint32_t connections = 0;
    std::uint64_t frames_sent = 0;
    std::uint64_t frames_received = 0;
    std::uint64_t application_write_calls = 0;
    std::uint64_t application_read_calls = 0;
    std::uint64_t transport_write_ops = 0;
    std::uint64_t transport_read_ops = 0;
    std::vector<VerifierAuditRecord> verifier_audit;
    std::string tls_cipher;
    std::vector<double> pair_completion_ms;
};

class PairThreadExecutor {
public:
    PairThreadExecutor(std::size_t count, std::size_t stack_size)
        : workers_(count), arguments_(count) {
        pthread_attr_t attributes{};
        int result = ::pthread_attr_init(&attributes);
        require(result == 0,
                "pthread_attr_init failed: " +
                    std::string(std::strerror(result)));
        const std::size_t effective_stack =
            std::max<std::size_t>(stack_size, PTHREAD_STACK_MIN);
        result = ::pthread_attr_setstacksize(
            &attributes, effective_stack);
        if (result != 0) {
            ::pthread_attr_destroy(&attributes);
            throw std::runtime_error(
                "pthread_attr_setstacksize failed: " +
                std::string(std::strerror(result)));
        }
        for (std::size_t index = 0; index < count; ++index) {
            arguments_[index] = {this, index};
            result = ::pthread_create(
                &workers_[index], &attributes, worker_entry,
                &arguments_[index]);
            if (result != 0) {
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    stopping_ = true;
                }
                start_.notify_all();
                for (std::size_t joined = 0; joined < index; ++joined) {
                    ::pthread_join(workers_[joined], nullptr);
                }
                ::pthread_attr_destroy(&attributes);
                throw std::runtime_error(
                    "pthread_create failed after " +
                    std::to_string(index) + " threads: " +
                    std::strerror(result));
            }
        }
        ::pthread_attr_destroy(&attributes);
    }

    ~PairThreadExecutor() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopping_ = true;
        }
        start_.notify_all();
        for (pthread_t worker : workers_) {
            ::pthread_join(worker, nullptr);
        }
    }

    PairThreadExecutor(const PairThreadExecutor&) = delete;
    PairThreadExecutor& operator=(const PairThreadExecutor&) = delete;

    void execute(std::function<void(std::size_t)> function) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            function_ = std::move(function);
            error_ = nullptr;
            remaining_ = workers_.size();
            ++generation_;
        }
        start_.notify_all();
        std::unique_lock<std::mutex> lock(mutex_);
        done_.wait(lock, [&] { return remaining_ == 0; });
        function_ = {};
        if (error_ != nullptr) {
            std::rethrow_exception(error_);
        }
    }

private:
    struct WorkerArgument {
        PairThreadExecutor* executor = nullptr;
        std::size_t index = 0;
    };

    static void* worker_entry(void* raw_argument) noexcept {
        auto* argument = static_cast<WorkerArgument*>(raw_argument);
        argument->executor->worker_loop(argument->index);
        return nullptr;
    }

    void worker_loop(std::size_t index) noexcept {
        std::uint64_t observed_generation = 0;
        for (;;) {
            std::function<void(std::size_t)> function;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                start_.wait(lock, [&] {
                    return stopping_ ||
                        generation_ != observed_generation;
                });
                if (stopping_) {
                    OPENSSL_thread_stop();
                    return;
                }
                observed_generation = generation_;
                function = function_;
            }
            try {
                function(index);
            } catch (...) {
                std::lock_guard<std::mutex> lock(mutex_);
                if (error_ == nullptr) {
                    error_ = std::current_exception();
                }
            }
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (--remaining_ == 0) {
                    done_.notify_one();
                }
            }
        }
    }

    std::vector<pthread_t> workers_;
    std::vector<WorkerArgument> arguments_;
    std::mutex mutex_;
    std::condition_variable start_;
    std::condition_variable done_;
    std::function<void(std::size_t)> function_;
    std::exception_ptr error_;
    std::size_t remaining_ = 0;
    std::uint64_t generation_ = 0;
    bool stopping_ = false;
};

NetworkAggregate run_network_variant(
    const Config& config, const Crypto& crypto,
    const std::vector<Workload>& workloads, Variant variant,
    SSL_CTX* tls_context, PairThreadExecutor& executor) {
    require(workloads.size() ==
                static_cast<std::size_t>(config.pairs),
            "pair workload count mismatch");
    NetworkAggregate total;
    std::mutex mutex;
    executor.execute([&](std::size_t pair) {
            try {
                const auto pair_start =
                    std::chrono::steady_clock::now();
                const Workload& workload =
                    workloads.at(pair);
                NetworkAggregate local;
                std::vector<std::uint32_t> all_indices(
                    workload.items.size());
                std::iota(all_indices.begin(), all_indices.end(), 0);
                if (variant == Variant::B0FreshSequential) {
                    for (std::uint32_t index : all_indices) {
                        const auto result =
                            run_protocol_connection(
                                config, crypto, workload, variant,
                                {index}, tls_context);
                        local.sent += result.io.sent;
                        local.received += result.io.received;
                        local.messages += result.messages;
                        local.sessions += result.logical_sessions;
                        local.rtt += result.tcp.rtt_ms;
                        local.rttvar += result.tcp.rttvar_ms;
                        local.cwnd += result.tcp.cwnd;
                        local.retrans += result.tcp.retrans;
                        local.verifier_ms += result.verifier_ms;
                        local.fallback_count +=
                            result.fallback_count;
                        local.frames_sent += result.io.sent_frames;
                        local.frames_received +=
                            result.io.received_frames;
                        local.application_write_calls +=
                            result.io.application_write_calls;
                        local.application_read_calls +=
                            result.io.application_read_calls;
                        local.transport_write_ops +=
                            result.io.transport_write_ops;
                        local.transport_read_ops +=
                            result.io.transport_read_ops;
                        local.verifier_audit.insert(
                            local.verifier_audit.end(),
                            result.verifier_audit.begin(),
                            result.verifier_audit.end());
                        if (local.tls_cipher.empty()) {
                            local.tls_cipher = result.tls_cipher;
                        }
                        ++local.connections;
                    }
                } else {
                    const auto result =
                        run_protocol_connection(
                            config, crypto, workload, variant,
                            all_indices, tls_context);
                    local.sent = result.io.sent;
                    local.received = result.io.received;
                    local.messages = result.messages;
                    local.sessions = result.logical_sessions;
                    local.rtt = result.tcp.rtt_ms;
                    local.rttvar = result.tcp.rttvar_ms;
                    local.cwnd = result.tcp.cwnd;
                    local.retrans = result.tcp.retrans;
                    local.verifier_ms = result.verifier_ms;
                    local.fallback_count =
                        result.fallback_count;
                    local.frames_sent = result.io.sent_frames;
                    local.frames_received =
                        result.io.received_frames;
                    local.application_write_calls =
                        result.io.application_write_calls;
                    local.application_read_calls =
                        result.io.application_read_calls;
                    local.transport_write_ops =
                        result.io.transport_write_ops;
                    local.transport_read_ops =
                        result.io.transport_read_ops;
                    local.verifier_audit = result.verifier_audit;
                    local.tls_cipher = result.tls_cipher;
                    local.connections = 1;
                }
                local.pair_completion_ms.push_back(
                    std::chrono::duration<double, std::milli>(
                        std::chrono::steady_clock::now() - pair_start)
                        .count());
                std::lock_guard<std::mutex> lock(mutex);
                total.sent += local.sent;
                total.received += local.received;
                total.messages += local.messages;
                total.sessions += local.sessions;
                total.rtt += local.rtt;
                total.rttvar += local.rttvar;
                total.cwnd += local.cwnd;
                total.retrans += local.retrans;
                total.verifier_ms += local.verifier_ms;
                total.fallback_count += local.fallback_count;
                total.frames_sent += local.frames_sent;
                total.frames_received += local.frames_received;
                total.application_write_calls +=
                    local.application_write_calls;
                total.application_read_calls +=
                    local.application_read_calls;
                total.transport_write_ops += local.transport_write_ops;
                total.transport_read_ops += local.transport_read_ops;
                total.verifier_audit.insert(
                    total.verifier_audit.end(),
                    local.verifier_audit.begin(),
                    local.verifier_audit.end());
                if (total.tls_cipher.empty()) {
                    total.tls_cipher = local.tls_cipher;
                } else {
                    require(total.tls_cipher == local.tls_cipher,
                            "connections negotiated different TLS ciphers");
                }
                total.pair_completion_ms.insert(
                    total.pair_completion_ms.end(),
                    local.pair_completion_ms.begin(),
                    local.pair_completion_ms.end());
                total.connections += local.connections;
            } catch (const std::exception& error) {
                std::lock_guard<std::mutex> lock(mutex);
                ++total.failures;
                std::cerr << "pair failed: " << error.what() << "\n";
            }
    });
    return total;
}

void run_client(const Config& config, const Crypto& crypto) {
    if (config.replay_probe || config.reconnect_probe ||
        config.eviction_replay_probe) {
        require(config.variants.size() == 1 &&
                    config.variants.front() ==
                        Variant::B1PersistentSequential,
                "replay/reconnect probes require persistent-sequential");
    }
    TlsContext tls_context(config, false);
    std::vector<Sample> samples;
    std::uint64_t total_failures = 0;
    std::mt19937 order_generator(0x434c4f55U);
    const Scalar client_master_secret = crypto.random_scalar();
    if (config.reconnect_probe || config.eviction_replay_probe) {
        const std::uint32_t n = config.n_values.front();
        Workload probe = oasis::make_paraswap_public_workload(
            crypto, n,
            oasis::digest_from_u64(
                crypto, 0x5245434f4e4e4543ULL),
            1, 3600, 0x50524f4245ULL);
        oasis::attach_client_key_shares(
            crypto, probe, client_master_secret);
        run_reconnect_probe(
            config, crypto, probe, tls_context.get(),
            client_master_secret, config.eviction_replay_probe);
        std::cout << (config.eviction_replay_probe
                          ? "eviction_replay_probe=pass\n"
                          : "reconnect_probe=pass\n");
        if (config.eviction_replay_probe) {
            return;
        }
    }
    PairThreadExecutor executor(
        static_cast<std::size_t>(config.pairs),
        static_cast<std::size_t>(config.pair_thread_stack_kb) * 1024);
    for (std::uint32_t n : config.n_values) {
        for (int trial = -config.warmup;
             trial < config.trials; ++trial) {
            auto order = config.variants;
            std::shuffle(order.begin(), order.end(), order_generator);
            for (Variant variant : order) {
                std::vector<Workload> workloads;
                workloads.reserve(
                    static_cast<std::size_t>(config.pairs));
                for (int pair = 0; pair < config.pairs; ++pair) {
                    const bool explicit_context =
                        !config.context_seed_hex.empty();
                    const std::uint64_t pair_id = explicit_context
                        ? config.context_pair_id
                        : (static_cast<std::uint64_t>(
                               static_cast<std::uint32_t>(
                                   trial + 200000))
                           << 32) |
                              static_cast<std::uint32_t>(pair);
                    const std::uint64_t execution_id = explicit_context
                        ? config.context_execution_id
                        : (static_cast<std::uint64_t>(
                               static_cast<std::uint32_t>(
                                   trial + 200000))
                           << 8) |
                              static_cast<std::uint8_t>(variant);
                    const Digest seed = explicit_context
                        ? parse_digest_hex(config.context_seed_hex)
                        : oasis::digest_from_u64(
                              crypto,
                              (static_cast<std::uint64_t>(n) << 48) ^
                                  pair_id);
                    Workload workload =
                        oasis::make_paraswap_public_workload(
                            crypto, n, seed,
                            explicit_context
                                ? config.context_key_epoch : 1,
                            explicit_context
                                ? config.context_expiry : 3600,
                            pair_id,
                            execution_id,
                            explicit_context
                                ? config.context_arc_index
                                : static_cast<std::uint32_t>(
                                      pair % static_cast<int>(n)) + 1);
                    oasis::attach_client_key_shares(
                        crypto, workload,
                        client_master_secret);
                    workloads.push_back(
                        std::move(workload));
                }
                const double cpu_start = process_cpu_ms();
                const auto wall_start =
                    std::chrono::steady_clock::now();
                const NetworkAggregate network =
                    run_network_variant(
                        config, crypto, workloads, variant,
                        tls_context.get(), executor);
                total_failures += network.failures;
                const double wall_ms =
                    std::chrono::duration<double, std::milli>(
                        std::chrono::steady_clock::now() - wall_start)
                        .count();
                const double cpu_ms =
                    process_cpu_ms() - cpu_start;
                if (trial >= 0) {
                    const double connections =
                        std::max<std::uint32_t>(
                            1, network.connections);
                    Sample sample;
                    sample.environment = "cloud-tcp";
                    sample.campaign_id = config.campaign_id;
                    sample.route = config.route;
                    sample.fault_profile = config.fault_profile;
                    sample.fault_scope = config.fault_scope;
                    sample.loss_pct = config.loss_pct;
                    sample.tls = config.tls;
                    sample.variant = variant;
                    sample.n = n;
                    sample.k = static_cast<std::uint32_t>(
                        workloads.front().items.size());
                    sample.trial = trial;
                    sample.pairs = config.pairs;
                    sample.fault_count = network.fallback_count;
                    sample.wall_ms = wall_ms;
                    sample.cpu_ms = cpu_ms;
                    sample.verifier_ms = network.verifier_ms;
                    sample.app_messages = network.messages;
                    sample.logical_sessions = network.sessions;
                    sample.bytes_sent = network.sent;
                    sample.bytes_received = network.received;
                    sample.tcp_rtt_ms = network.rtt / connections;
                    sample.tcp_rttvar_ms = network.rttvar / connections;
                    sample.snd_cwnd_segments = network.cwnd / connections;
                    sample.retransmissions = network.retrans;
                    sample.failures = network.failures;
                    sample.frames_sent = network.frames_sent;
                    sample.frames_received = network.frames_received;
                    sample.application_write_calls =
                        network.application_write_calls;
                    sample.application_read_calls =
                        network.application_read_calls;
                    sample.transport_write_ops =
                        network.transport_write_ops;
                    sample.transport_read_ops =
                        network.transport_read_ops;
                    sample.pair_wall_p50_ms = sample_percentile(
                        network.pair_completion_ms, 0.50);
                    sample.pair_wall_p95_ms = sample_percentile(
                        network.pair_completion_ms, 0.95);
                    sample.pair_wall_p99_ms = sample_percentile(
                        network.pair_completion_ms, 0.99);
                    sample.pair_jain_fairness =
                        jain_fairness_from_completion_ms(
                            network.pair_completion_ms);
                    sample.tls_cipher = network.tls_cipher;
                    sample.verifier_audit = network.verifier_audit;
                    samples.push_back(std::move(sample));
                }
            }
        }
        std::cout << "client n=" << n << " k=" << (2 * n - 1)
                  << " complete\n";
    }
    write_samples(config, samples);
    std::cout << "wrote=" << config.out << "\n";
    require(config.allow_failures || total_failures == 0,
            "cloud campaign recorded " +
                std::to_string(total_failures) +
                " failed pair execution(s)");
}

template <typename Function>
class ThreadPool {
public:
    ThreadPool(std::size_t count, Function function)
        : function_(std::move(function)) {
        for (std::size_t i = 0; i < count; ++i) {
            workers_.emplace_back([this] {
                for (;;) {
                    int value = -1;
                    {
                        std::unique_lock<std::mutex> lock(mutex_);
                        condition_.wait(lock, [&] {
                            return stopping_ || !queue_.empty();
                        });
                        if (stopping_ && queue_.empty()) {
                            return;
                        }
                        value = queue_.front();
                        queue_.pop();
                    }
                    function_(value);
                }
            });
        }
    }

    ~ThreadPool() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopping_ = true;
        }
        condition_.notify_all();
        for (auto& worker : workers_) {
            worker.join();
        }
    }

    void submit(int value) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.push(value);
        }
        condition_.notify_one();
    }

private:
    Function function_;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::queue<int> queue_;
    bool stopping_ = false;
    std::vector<std::thread> workers_;
};

struct ServerMetric {
    std::int64_t timestamp_ms = 0;
    std::string campaign_id;
    std::string route;
    std::string fault_profile;
    std::string fault_scope;
    double loss_pct = 0;
    bool tls = false;
    std::string variant;
    std::uint32_t n = 0;
    std::uint32_t k = 0;
    std::uint64_t pair_id = 0;
    std::uint32_t sessions = 0;
    std::uint32_t active_at_start = 0;
    std::uint32_t max_active_seen = 0;
    double wall_ms = 0;
    double cpu_ms = 0;
    std::uint64_t rss_kb = 0;
    std::uint64_t peak_kb = 0;
    TcpInfo tcp;
};

class MetricsWriter {
public:
    explicit MetricsWriter(const std::string& path) {
        if (!path.empty()) {
            ensure_parent(path);
            output_.open(path, std::ios::app);
            require(output_.good(),
                    "cannot open server metrics file");
        }
    }

    void write(const ServerMetric& metric) {
        if (!output_.is_open()) {
            return;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        output_
            << "{\"timestamp_ms\":" << metric.timestamp_ms
            << ",\"campaign_id\":\""
            << json_escape(metric.campaign_id)
            << "\",\"route\":\"" << json_escape(metric.route)
            << "\",\"fault_profile\":\""
            << json_escape(metric.fault_profile)
            << "\",\"fault_scope\":\""
            << json_escape(metric.fault_scope)
            << "\",\"loss_pct\":" << metric.loss_pct
            << ",\"tls\":" << (metric.tls ? "true" : "false")
            << ",\"variant\":\"" << metric.variant
            << "\",\"n\":" << metric.n
            << ",\"k\":" << metric.k
            << ",\"pair_id\":" << metric.pair_id
            << ",\"logical_sessions\":" << metric.sessions
            << ",\"active_at_start\":"
            << metric.active_at_start
            << ",\"max_active_seen\":"
            << metric.max_active_seen
            << ",\"server_wall_ms\":" << metric.wall_ms
            << ",\"server_thread_cpu_ms\":" << metric.cpu_ms
            << ",\"current_rss_kb\":" << metric.rss_kb
            << ",\"peak_rss_kb\":" << metric.peak_kb
            << ",\"tcp_rtt_ms\":" << metric.tcp.rtt_ms
            << ",\"tcp_rttvar_ms\":"
            << metric.tcp.rttvar_ms
            << ",\"snd_cwnd_segments\":" << metric.tcp.cwnd
            << ",\"total_retrans\":"
            << metric.tcp.retrans << "}\n";
        output_.flush();
    }

private:
    std::mutex mutex_;
    std::ofstream output_;
};

std::atomic<int> server_socket{-1};

void stop_server(int) {
    const int fd = server_socket.exchange(-1);
    if (fd >= 0) {
        ::close(fd);
    }
}

void handle_connection(int fd, SSL_CTX* tls_context,
                       const Crypto& crypto,
                       const Scalar& server_master_secret,
                       std::uint32_t inject_bad_partials,
                       std::uint32_t inject_bad_openings,
                       ServerSessionStore& session_store,
                       MetricsWriter& metrics,
                       std::atomic<std::uint32_t>& active,
                       std::atomic<std::uint32_t>& max_active) {
    const std::uint32_t active_now = active.fetch_add(1) + 1;
    std::uint32_t observed = max_active.load();
    while (observed < active_now &&
           !max_active.compare_exchange_weak(observed, active_now)) {
    }
    try {
        Channel channel(fd, tls_context, true);
        IoCounters io;
        const auto wall_start = std::chrono::steady_clock::now();
        const double cpu_start = thread_cpu_ms();
        Bytes hello_payload;
        require(receive_frame(channel, hello_payload, io),
                "server HELLO receive failed");
        const Hello hello = decode_hello(hello_payload, crypto);
        Workload workload = hello.workload;
        oasis::attach_server_key_shares(
            crypto, workload, server_master_secret);
        oasis::finalize_workload(crypto, workload);
        require(send_frame(
                    channel, encode_hello_ack(workload), io),
                "server HELLO_ACK send failed");
        std::map<std::uint32_t,
                 std::shared_ptr<StoredServerSession>> sessions;
        std::set<std::uint32_t> finished_ids;
        std::uint32_t finished = 0;
        std::uint32_t expected_sessions =
            hello.expected_sessions;
        if (hello.variant == Variant::B2PersistentPipelined ||
            hello.variant == Variant::B5IndependentBatchVerification ||
            hello.variant == Variant::B6PhaseCoalescedItemwise) {
            std::vector<Bytes> init_payloads(
                hello.expected_sessions);
            if (hello.variant == Variant::B6PhaseCoalescedItemwise) {
                require(receive_frames_coalesced(
                            channel, hello.expected_sessions,
                            init_payloads, io),
                        "server coalesced INIT receive failed");
            } else {
                for (auto& payload : init_payloads) {
                    require(receive_frame(channel, payload, io),
                            "server pipelined INIT receive failed");
                }
            }
            std::vector<ServerSession> ordered_sessions(
                hello.expected_sessions);
            std::vector<Bytes> commit_payloads(
                hello.expected_sessions);
            for (std::size_t i = 0;
                 i < hello.expected_sessions; ++i) {
                ordered_sessions[i] = make_server_session(
                    init_payloads[i], crypto, workload,
                    hello.variant);
                commit_payloads[i] =
                    encode_commit(ordered_sessions[i]);
            }
            if (hello.variant == Variant::B6PhaseCoalescedItemwise) {
                require(send_frames_coalesced(
                            channel, commit_payloads, io),
                        "server coalesced COMMIT send failed");
            } else {
                for (const auto& payload : commit_payloads) {
                    require(send_frame(channel, payload, io),
                            "server pipelined COMMIT send failed");
                }
            }

            std::vector<Bytes> nonce_payloads(
                hello.expected_sessions);
            if (hello.variant == Variant::B6PhaseCoalescedItemwise) {
                require(receive_frames_coalesced(
                            channel, hello.expected_sessions,
                            nonce_payloads, io),
                        "server coalesced CLIENT_NONCE receive failed");
            } else {
                for (auto& payload : nonce_payloads) {
                    require(receive_frame(channel, payload, io),
                            "server pipelined CLIENT_NONCE receive failed");
                }
            }
            std::vector<Bytes> open_payloads(
                hello.expected_sessions);
            for (std::size_t i = 0;
                 i < hello.expected_sessions; ++i) {
                decode_client_nonces(
                    nonce_payloads[i], ordered_sessions[i]);
                open_payloads[i] = encode_server_open(
                    ordered_sessions[i], crypto, workload);
            }
            if (hello.variant == Variant::B6PhaseCoalescedItemwise) {
                require(send_frames_coalesced(
                            channel, open_payloads, io),
                        "server coalesced SERVER_OPEN send failed");
            } else {
                for (const auto& payload : open_payloads) {
                    require(send_frame(channel, payload, io),
                            "server pipelined SERVER_OPEN send failed");
                }
            }

            std::vector<Bytes> final_payloads(
                hello.expected_sessions);
            if (hello.variant == Variant::B6PhaseCoalescedItemwise) {
                require(receive_frames_coalesced(
                            channel, hello.expected_sessions,
                            final_payloads, io),
                        "server coalesced CLIENT_FINAL receive failed");
            } else {
                for (auto& payload : final_payloads) {
                    require(receive_frame(channel, payload, io),
                            "server pipelined CLIENT_FINAL receive failed");
                }
            }
            const bool independent_batch =
                hello.variant ==
                    Variant::B5IndependentBatchVerification &&
                hello.expected_sessions >=
                    oasis::kBatchVerificationMinItems;
            for (std::size_t i = 0;
                 i < hello.expected_sessions; ++i) {
                decode_and_verify_client_final(
                    final_payloads[i], ordered_sessions[i],
                    crypto, workload, false, independent_batch);
            }
            if (independent_batch) {
                std::vector<ItemTranscript> transcripts;
                transcripts.reserve(ordered_sessions.size());
                for (const auto& session : ordered_sessions) {
                    transcripts.push_back(session.transcripts.front());
                }
                const Digest partial_salt = crypto.hash(
                    "OASIS-SERVER-INDEPENDENT-CLIENT-SALT-v1",
                    {oasis::bytes(workload.batch_digest),
                     oasis::bytes(crypto.random_scalar())});
                require(oasis::verify_client_partials_batch_independent(
                            crypto, workload, transcripts, partial_salt),
                        "server independent client-partial batch failed");
                const Digest final_salt = crypto.hash(
                    "OASIS-SERVER-INDEPENDENT-FINAL-SALT-v1",
                    {oasis::bytes(workload.batch_digest),
                     oasis::bytes(crypto.random_scalar())});
                require(oasis::verify_presignatures_batch_independent(
                            crypto, workload, transcripts, final_salt),
                        "server independent final batch failed");
            }
            finished = hello.expected_sessions;
        }
        while (finished < expected_sessions) {
            Bytes payload;
            require(receive_frame(channel, payload, io),
                    "server protocol receive failed");
            require(!payload.empty(), "empty protocol frame");
            const MessageType type =
                static_cast<MessageType>(payload.front());
            if (type == MessageType::Init) {
                Reader header_reader(payload);
                const auto header =
                    read_session_header(header_reader);
                header_reader.finish();
                const SessionKey key{
                    header.sid, header.logical_id};
                if (hello.variant ==
                        Variant::B4BatchedVerification &&
                    header.logical_id > 0) {
                    const auto parent = sessions.find(0);
                    require(parent != sessions.end(),
                            "retry INIT before initial batch");
                    std::lock_guard<std::mutex> parent_lock(
                        parent->second->mutex);
                    require(
                        header.indices.size() == 1 &&
                            parent->second->session
                                    .skipped_indices.count(
                                        header.indices.front()) != 0,
                        "retry INIT was not authorized");
                }
                const auto stored = session_store.get_or_create(
                    key, payload, [&] {
                        ServerSession created =
                            make_server_session(
                                payload, crypto, workload,
                                hello.variant);
                        created.commit_response =
                            encode_commit(created);
                        return created;
                    });
                const auto local = sessions.find(header.logical_id);
                require(local == sessions.end() ||
                            local->second == stored,
                        "logical session ID reused with another SID");
                sessions[header.logical_id] = stored;
                Bytes response;
                {
                    std::lock_guard<std::mutex> lock(
                        stored->mutex);
                    response = stored->session.commit_response;
                }
                require(send_frame(channel, response, io),
                        "server COMMIT send failed");
            } else if (type == MessageType::ClientNonce) {
                Reader header_reader(payload);
                const auto header =
                    read_session_header(header_reader);
                auto found = sessions.find(header.logical_id);
                require(found != sessions.end(),
                        "CLIENT_NONCE for unknown session");
                auto& stored = *found->second;
                std::lock_guard<std::mutex> lock(stored.mutex);
                auto& session = stored.session;
                if (!session.nonce_payload.empty()) {
                    require(session.nonce_payload == payload,
                            "conflicting CLIENT_NONCE replay");
                    require(send_frame(
                                channel,
                                session.open_response, io),
                            "server replayed SERVER_OPEN send failed");
                    continue;
                }
                require(session.final_payload.empty(),
                        "CLIENT_NONCE after CLIENT_FINAL");
                decode_client_nonces(payload, session);
                session.nonce_payload = payload;
                const std::uint32_t fault_count =
                    hello.variant ==
                                Variant::B4BatchedVerification &&
                            session.logical_id == 0
                        ? std::min<std::uint32_t>(
                              inject_bad_partials,
                              static_cast<std::uint32_t>(
                                  session.indices.size()))
                        : 0;
                const std::uint32_t opening_fault_count =
                    hello.variant == Variant::B4BatchedVerification &&
                            session.logical_id == 0
                        ? std::min<std::uint32_t>(
                              inject_bad_openings,
                              static_cast<std::uint32_t>(
                                  session.indices.size()))
                        : 0;
                session.open_response = encode_server_open(
                    session, crypto, workload, fault_count,
                    opening_fault_count);
                const Bytes response = session.open_response;
                require(send_frame(channel, response, io),
                        "server SERVER_OPEN send failed");
            } else if (type == MessageType::RetryPlan) {
                require(hello.variant ==
                            Variant::B4BatchedVerification,
                        "RETRY_PLAN requires batched verification");
                Reader header_reader(payload);
                const auto header =
                    read_session_header(header_reader);
                header_reader.finish();
                require(header.logical_id == 0 &&
                            header.sid ==
                                oasis::make_session_id(
                                    crypto, workload, 0),
                        "RETRY_PLAN parent mismatch");
                auto found = sessions.find(0);
                require(found != sessions.end(),
                        "RETRY_PLAN before initial INIT");
                auto& stored = *found->second;
                std::lock_guard<std::mutex> lock(stored.mutex);
                auto& session = stored.session;
                require(!session.nonce_payload.empty() &&
                            session.final_payload.empty(),
                        "RETRY_PLAN in invalid phase");
                if (!session.retry_plan_payload.empty()) {
                    require(session.retry_plan_payload == payload,
                            "conflicting RETRY_PLAN replay");
                    continue;
                }
                std::uint32_t previous = 0;
                bool first = true;
                for (std::uint32_t index : header.indices) {
                    require(index < workload.items.size() &&
                                (first || index > previous),
                            "RETRY_PLAN indices must be canonical");
                    first = false;
                    previous = index;
                    session.skipped_indices.insert(index);
                }
                session.retry_plan_payload = payload;
                expected_sessions +=
                    static_cast<std::uint32_t>(
                        header.indices.size());
                require(expected_sessions <=
                            workload.items.size() + 1,
                        "too many retry sessions");
            } else if (type == MessageType::ClientFinal) {
                Reader header_reader(payload);
                const auto header =
                    read_session_header(header_reader);
                auto found = sessions.find(header.logical_id);
                require(found != sessions.end(),
                        "CLIENT_FINAL for unknown session");
                auto& stored = *found->second;
                std::lock_guard<std::mutex> lock(stored.mutex);
                auto& session = stored.session;
                require(!session.nonce_payload.empty(),
                        "CLIENT_FINAL before CLIENT_NONCE");
                if (!session.final_payload.empty()) {
                    require(session.final_payload == payload,
                            "conflicting CLIENT_FINAL replay");
                    if (!session.final_status_response.empty()) {
                        require(send_frame(
                                    channel,
                                    session.final_status_response, io),
                                "server replayed FINAL_STATUS send failed");
                    }
                    if (finished_ids.insert(
                            header.logical_id).second) {
                        ++finished;
                    }
                    continue;
                }
                const bool b4_parent =
                    hello.variant == Variant::B4BatchedVerification &&
                    session.logical_id == 0;
                const bool use_batch_verification =
                    b4_parent &&
                    session.indices.size() >=
                        oasis::kBatchVerificationMinItems;
                decode_and_verify_client_final(
                    payload, session, crypto, workload, false,
                    b4_parent);
                if (b4_parent) {
                    const auto bad_indices =
                        localize_invalid_client_final(
                            session, crypto, workload,
                            use_batch_verification);
                    std::uint32_t newly_skipped = 0;
                    for (std::uint32_t index : bad_indices) {
                        if (session.skipped_indices.insert(index).second) {
                            ++newly_skipped;
                        }
                    }
                    expected_sessions += newly_skipped;
                    require(expected_sessions <=
                                workload.items.size() + 1,
                            "too many initiator retry sessions");
                    session.final_status_response =
                        encode_final_status(session, bad_indices);
                    require(send_frame(
                                channel,
                                session.final_status_response, io),
                            "server FINAL_STATUS send failed");
                }
                session.final_payload = payload;
                if (finished_ids.insert(header.logical_id).second) {
                    ++finished;
                }
            } else {
                throw std::runtime_error(
                    "unexpected server message type");
            }
        }
        require(send_frame(channel, encode_done(), io),
                "server DONE send failed");
        const TcpInfo tcp = tcp_info_for(channel.fd());
        const auto timestamp =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now()
                    .time_since_epoch())
                .count();
        metrics.write(
            {timestamp, hello.campaign_id, hello.route,
             hello.fault_profile, hello.fault_scope,
             hello.loss_pct, tls_context != nullptr,
             objective_variant_name(hello.variant),
             workload.n,
             static_cast<std::uint32_t>(
                 workload.items.size()),
             workload.pair_id, expected_sessions, active_now,
             max_active.load(),
             std::chrono::duration<double, std::milli>(
                 std::chrono::steady_clock::now() - wall_start).count(),
             thread_cpu_ms() - cpu_start, current_rss_kb(),
             peak_rss_kb(), tcp});
    } catch (const std::exception& error) {
        std::cerr << "server connection failed: "
                  << error.what() << "\n";
    }
    active.fetch_sub(1);
}

void run_server(const Config& config, const Crypto& crypto) {
    TlsContext tls_context(config, true);
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    require(fd >= 0, "server socket failed");
    int enabled = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled,
                 sizeof(enabled));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port =
        htons(static_cast<std::uint16_t>(config.port));
    require(::inet_pton(AF_INET, config.bind.c_str(),
                        &address.sin_addr) == 1,
            "invalid bind address");
    require(::bind(fd, reinterpret_cast<sockaddr*>(&address),
                   sizeof(address)) == 0,
            "bind failed");
    require(::listen(fd, config.listen_backlog) == 0,
            socket_error_message("listen failed"));
    server_socket = fd;
    std::signal(SIGINT, stop_server);
    std::signal(SIGTERM, stop_server);

    MetricsWriter metrics(config.server_metrics);
    ServerSessionStore session_store(
        static_cast<std::size_t>(config.session_cache_capacity),
        static_cast<std::size_t>(config.replay_retention_capacity));
    std::atomic<std::uint32_t> active{0};
    std::atomic<std::uint32_t> max_active{0};
    const Scalar server_master_secret = crypto.random_scalar();
    auto worker = [&](int client_fd) {
        handle_connection(client_fd, tls_context.get(), crypto,
                          server_master_secret,
                          static_cast<std::uint32_t>(
                              config.inject_bad_partials),
                          static_cast<std::uint32_t>(
                              config.inject_bad_openings),
                          session_store,
                          metrics, active,
                          max_active);
    };
    ThreadPool<decltype(worker)> pool(
        static_cast<std::size_t>(config.threads), worker);
    std::cout << "server_ready bind=" << config.bind
              << " port=" << config.port
              << " threads=" << config.threads
              << " io_timeout_seconds="
              << config.io_timeout_seconds
              << " listen_backlog=" << config.listen_backlog
              << " session_cache_capacity="
              << config.session_cache_capacity
              << " replay_retention_capacity="
              << config.replay_retention_capacity
              << " soft_nofile=" << soft_nofile_limit() << "\n";
    while (server_socket.load() >= 0) {
        sockaddr_in peer{};
        socklen_t peer_size = sizeof(peer);
        const int client =
            ::accept(fd, reinterpret_cast<sockaddr*>(&peer),
                     &peer_size);
        if (client < 0) {
            if (server_socket.load() < 0) {
                break;
            }
            continue;
        }
        try {
            configure_socket(client, config.io_timeout_seconds);
        } catch (const std::exception& error) {
            std::cerr << "accepted socket setup failed: "
                      << error.what() << "\n";
            ::close(client);
            continue;
        }
        pool.submit(client);
    }
}

}  // namespace

int main(int argc, char** argv) {
    try {
        std::signal(SIGPIPE, SIG_IGN);
        const Config config = parse_args(argc, argv);
        if (config.command == "help" ||
            config.command == "--help") {
            print_help();
            return 0;
        }
        Crypto crypto;
        if (config.command == "test") {
            run_tests(config, crypto);
        } else if (config.command == "local") {
            run_local(config, crypto);
        } else if (config.command == "fallback") {
            run_fallback(config, crypto);
        } else if (config.command == "server") {
            run_server(config, crypto);
        } else if (config.command == "client") {
            run_client(config, crypto);
        } else {
            throw std::runtime_error(
                "unknown command: " + config.command);
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << "\n";
        return 1;
    }
}
