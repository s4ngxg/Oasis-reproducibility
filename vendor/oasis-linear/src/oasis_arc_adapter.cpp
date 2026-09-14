#include "oasis/core.hpp"

#include <time.h>

#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

struct Config {
    std::uint32_t n = 5;
    std::uint32_t arc_id = 0;
    std::uint64_t execution_id = 1;
    std::uint64_t key_epoch = 1;
    std::uint64_t expiry = 3600;
    std::string preparation_digest;
    std::string variant =
        "batch-joint-presigning-batch-verification";
    int bad_opening = -1;
    int bad_partial = -1;
};

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

Config parse_args(int argc, char** argv) {
    Config config;
    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        auto value = [&]() {
            require(i + 1 < argc, "missing value for " + argument);
            return std::string(argv[++i]);
        };
        if (argument == "--n") {
            config.n = static_cast<std::uint32_t>(std::stoul(value()));
        } else if (argument == "--arc-id") {
            config.arc_id =
                static_cast<std::uint32_t>(std::stoul(value()));
        } else if (argument == "--execution-id") {
            config.execution_id = std::stoull(value());
        } else if (argument == "--key-epoch") {
            config.key_epoch = std::stoull(value());
        } else if (argument == "--expiry") {
            config.expiry = std::stoull(value());
        } else if (argument == "--preparation-digest") {
            config.preparation_digest = value();
        } else if (argument == "--variant") {
            config.variant = value();
        } else if (argument == "--bad-opening") {
            config.bad_opening = std::stoi(value());
        } else if (argument == "--bad-partial") {
            config.bad_partial = std::stoi(value());
        } else if (argument == "--help") {
            std::cout
                << "Usage: oasis_arc_adapter --n N --arc-id N "
                   "--execution-id N --variant NAME\n"
                << "Configurations: persistent-pipelined-itemwise, "
                   "phase-coalesced-itemwise, "
                   "batch-joint-presigning-itemwise, "
                   "phase-coalesced-batch-verification, "
                   "batch-joint-presigning-batch-verification\n";
            std::exit(0);
        } else {
            throw std::runtime_error("unknown argument: " + argument);
        }
    }
    require(config.n >= 1 && config.n <= 1024, "n must be in [1,1024]");
    require(config.key_epoch > 0, "key epoch must be positive");
    require(config.expiry > 0, "expiry must be positive");
    require(config.preparation_digest.size() == 64,
            "preparation digest must contain 64 hexadecimal characters");
    require(config.variant == "persistent-pipelined-itemwise" ||
                config.variant == "batch-joint-presigning-itemwise" ||
                config.variant == "phase-coalesced-batch-verification" ||
                config.variant ==
                    "batch-joint-presigning-batch-verification" ||
                config.variant == "phase-coalesced-itemwise",
            "unsupported configuration");
    return config;
}

oasis::Digest parse_digest(const std::string& encoded) {
    oasis::Digest digest{};
    for (std::size_t i = 0; i < digest.size(); ++i) {
        const std::string octet = encoded.substr(i * 2, 2);
        std::size_t consumed = 0;
        const unsigned long value = std::stoul(octet, &consumed, 16);
        require(consumed == 2 && value <= 0xff,
                "preparation digest is not canonical hexadecimal");
        digest[i] = static_cast<std::uint8_t>(value);
    }
    std::ostringstream canonical;
    canonical << std::hex << std::setfill('0');
    for (std::uint8_t value : digest) {
        canonical << std::setw(2) << static_cast<unsigned>(value);
    }
    require(canonical.str() == encoded,
            "preparation digest must use lowercase hexadecimal");
    return digest;
}

void attach_paraswap_statement_witnesses(
    const oasis::Crypto& crypto, oasis::Workload& workload) {
    std::vector<oasis::Scalar> participant_y(workload.n);
    std::vector<oasis::Scalar> participant_k(workload.n);
    oasis::Scalar global_y{};
    for (std::uint32_t participant = 1;
         participant <= workload.n; ++participant) {
        participant_y[participant - 1] = crypto.derive_scalar(
            "PARASWAP-OASIS-PARTICIPANT-Y-WITNESS-v1",
            {oasis::bytes(workload.seed),
             oasis::bytes(oasis::digest_from_u64(crypto, workload.pair_id)),
             oasis::bytes(oasis::digest_from_u64(crypto, participant))});
        participant_k[participant - 1] = crypto.derive_scalar(
            "PARASWAP-OASIS-PARTICIPANT-K-WITNESS-v1",
            {oasis::bytes(workload.seed),
             oasis::bytes(oasis::digest_from_u64(crypto, workload.pair_id)),
             oasis::bytes(oasis::digest_from_u64(crypto, participant))});
        global_y = crypto.scalar_add(
            global_y, participant_y[participant - 1]);
    }

    oasis::Scalar cumulative = global_y;
    for (std::uint32_t j = 1; j <= workload.n; ++j) {
        const std::uint32_t participant =
            ((workload.arc_index + j - 1) % workload.n) + 1;
        cumulative = crypto.scalar_add(
            cumulative, participant_k[participant - 1]);
        auto& item = workload.items.at(j - 1);
        require(item.type == oasis::ItemType::Withdraw &&
                    item.address_index == j,
                "unexpected ParaSwap Withdraw ordering");
        item.statement_witness = cumulative;
        item.has_statement_witness = true;
        item.statement = crypto.base_mul(cumulative);
    }

    for (std::uint32_t x = 1; x < workload.n; ++x) {
        auto& item = workload.items.at(workload.n + x - 1);
        require(item.type == oasis::ItemType::Relock &&
                    item.address_index == x,
                "unexpected ParaSwap Re-lock ordering");
        const std::uint32_t receiver =
            (workload.arc_index % workload.n) + 1;
        item.statement_witness = crypto.derive_scalar(
            "PARASWAP-OASIS-VTD-U-WITNESS-v1",
            {oasis::bytes(workload.seed),
             oasis::bytes(oasis::digest_from_u64(crypto, workload.pair_id)),
             oasis::bytes(oasis::digest_from_u64(crypto, receiver)),
             oasis::bytes(oasis::digest_from_u64(crypto, x)),
             oasis::bytes(oasis::digest_from_u64(crypto, item.timeout))});
        item.has_statement_witness = true;
        item.statement = crypto.base_mul(item.statement_witness);
    }
}

oasis::Variant native_variant(const std::string& value) {
    if (value == "persistent-pipelined-itemwise") {
        return oasis::Variant::B2PersistentPipelined;
    }
    if (value == "batch-joint-presigning-itemwise") {
        return oasis::Variant::B3BatchedItemwise;
    }
    if (value == "phase-coalesced-batch-verification") {
        return oasis::Variant::B5IndependentBatchVerification;
    }
    if (value == "phase-coalesced-itemwise") {
        return oasis::Variant::B6PhaseCoalescedItemwise;
    }
    return oasis::Variant::B4BatchedVerification;
}

double process_cpu_ms() {
    timespec value{};
    require(clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &value) == 0,
            "process CPU clock failed");
    return static_cast<double>(value.tv_sec) * 1000.0 +
           static_cast<double>(value.tv_nsec) / 1e6;
}

oasis::Digest verifier_salt(const oasis::Crypto& crypto,
                            const oasis::Digest& sid,
                            const oasis::Digest& batch,
                            const std::string& direction) {
    return crypto.hash(
        "OASIS-VERIFIER-SALT-v1",
        {oasis::Bytes(direction.begin(), direction.end()),
         oasis::bytes(sid), oasis::bytes(batch),
         oasis::bytes(crypto.random_scalar())});
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const Config config = parse_args(argc, argv);
        oasis::Crypto crypto;
        const oasis::Digest preparation_digest =
            parse_digest(config.preparation_digest);
        const auto seed = crypto.hash(
            "PARASWAP-OASIS-PREPARATION-CONTEXT-v1",
            {oasis::bytes(preparation_digest),
             oasis::bytes(oasis::digest_from_u64(crypto, config.execution_id)),
             oasis::bytes(oasis::digest_from_u64(crypto, config.arc_id))});
        oasis::Workload workload = oasis::make_paraswap_workload(
            crypto, config.n, seed, config.key_epoch, config.expiry,
            config.arc_id,
            config.execution_id, config.arc_id + 1);
        attach_paraswap_statement_witnesses(crypto, workload);
        oasis::finalize_workload(crypto, workload);
        require(workload.items.size() == 2ULL * config.n - 1,
                "incorrect ParaSwap item count");

        oasis::FaultPlan faults;
        if (config.bad_opening >= 0) {
            require(static_cast<std::size_t>(config.bad_opening) <
                        workload.items.size(),
                    "bad-opening index out of range");
            faults.bad_opening_indices.push_back(
                static_cast<std::size_t>(config.bad_opening));
        }
        if (config.bad_partial >= 0) {
            require(static_cast<std::size_t>(config.bad_partial) <
                        workload.items.size(),
                    "bad-partial index out of range");
            faults.bad_partial_indices.push_back(
                static_cast<std::size_t>(config.bad_partial));
        }

        const double cpu_started = process_cpu_ms();
        const auto wall_started = std::chrono::steady_clock::now();
        const oasis::SessionResult result = oasis::execute(
            crypto, workload, native_variant(config.variant), faults);
        const auto wall_stopped = std::chrono::steady_clock::now();
        const double cpu_ms = process_cpu_ms() - cpu_started;
        const double wall_ms = std::chrono::duration<double, std::milli>(
                                   wall_stopped - wall_started)
                                   .count();

        require(result.accepted, "OASIS session was not accepted");
        require(result.client_outputs == result.server_outputs,
                "client/server outputs differ");

        std::size_t itemwise_checks = 0;
        std::size_t adaptation_checks = 0;
        for (std::size_t i = 0; i < workload.items.size(); ++i) {
            const auto& item = workload.items[i];
            const auto& transcript = result.transcripts[i];
            require(oasis::verify_presignature(
                        crypto, item, transcript.sid, transcript),
                    "item-wise pre-signature audit failed");
            ++itemwise_checks;
            require(item.has_statement_witness,
                    "workload omitted adaptor witness");
            const oasis::Scalar signature = oasis::adapt(
                crypto, result.client_outputs[i], item.statement_witness);
            const auto extracted = oasis::extract(
                crypto, item, transcript.sid, transcript, signature);
            require(extracted.has_value() &&
                        *extracted == item.statement_witness,
                    "adapt/extract compatibility failed");
            ++adaptation_checks;
        }

        const bool wants_msm =
            config.variant ==
                "batch-joint-presigning-batch-verification" ||
            config.variant == "phase-coalesced-batch-verification";
        const bool msm_active =
            wants_msm && workload.items.size() >=
                             oasis::kBatchVerificationMinItems;
        bool aggregate_audit_performed = false;
        bool aggregate_audit_valid = false;
        double aggregate_reverification_ms = 0.0;
        std::size_t aggregate_reverification_checks = 0;
        std::size_t audit_pippenger_calls = 0;
        std::size_t audit_pippenger_terms = 0;
        if (msm_active && result.retried_indices.empty()) {
            aggregate_audit_performed = true;
            const auto audit_started = std::chrono::steady_clock::now();
            const auto& sid = result.transcripts.front().sid;
            if (config.variant ==
                "batch-joint-presigning-batch-verification") {
                aggregate_audit_valid =
                    oasis::verify_server_partials_batch(
                        crypto, workload, sid, result.transcripts,
                        verifier_salt(crypto, sid, workload.batch_digest,
                                      "server")) &&
                    oasis::verify_client_partials_batch(
                        crypto, workload, sid, result.transcripts,
                        verifier_salt(crypto, sid, workload.batch_digest,
                                      "client")) &&
                    oasis::verify_presignatures_batch(
                        crypto, workload, sid, result.transcripts,
                        verifier_salt(crypto, sid, workload.batch_digest,
                                      "full"));
            } else {
                aggregate_audit_valid =
                    oasis::verify_server_partials_batch_independent(
                        crypto, workload, result.transcripts,
                        verifier_salt(crypto, sid, workload.batch_digest,
                                      "server")) &&
                    oasis::verify_client_partials_batch_independent(
                        crypto, workload, result.transcripts,
                        verifier_salt(crypto, sid, workload.batch_digest,
                                      "client")) &&
                    oasis::verify_presignatures_batch_independent(
                        crypto, workload, result.transcripts,
                        verifier_salt(crypto, sid, workload.batch_digest,
                                      "full"));
            }
            aggregate_reverification_ms =
                std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - audit_started)
                    .count();
            aggregate_reverification_checks = 3;
            audit_pippenger_calls = 3;
            audit_pippenger_terms = 6 * workload.items.size();
            require(aggregate_audit_valid, "aggregate MSM audit failed");
        }

        const std::size_t withdraw_items = config.n;
        const std::size_t relock_items = config.n - 1;
        std::cout
            << "{\"schema\":\"oasis-preswap-arc-v1\""
            << ",\"scheme\":\"linear-schnorr-adaptor\""
            << ",\"configuration\":\"" << config.variant << "\""
            << ",\"n\":" << config.n
            << ",\"k\":" << workload.items.size()
            << ",\"arc_id\":" << config.arc_id
            << ",\"execution_id\":" << config.execution_id
            << ",\"preparation_digest\":\""
            << config.preparation_digest << "\""
            << ",\"paraswap_statement_mapping_valid\":true"
            << ",\"withdraw_items\":" << withdraw_items
            << ",\"relock_items\":" << relock_items
            << ",\"accepted\":true"
            << ",\"wall_ms\":" << wall_ms
            << ",\"cpu_ms\":" << cpu_ms
            << ",\"logical_messages\":" << result.application_messages
            << ",\"logical_sessions\":" << result.logical_sessions
            << ",\"itemwise_audit_checks\":" << itemwise_checks
            << ",\"adapt_extract_checks\":" << adaptation_checks
            << ",\"aggregate_verification_requested\":"
            << (wants_msm ? "true" : "false")
            << ",\"aggregate_verification_active\":"
            << (msm_active ? "true" : "false")
            << ",\"aggregate_reverification_performed\":"
            << (aggregate_audit_performed ? "true" : "false")
            << ",\"aggregate_audit_valid\":"
            << (aggregate_audit_valid ? "true" : "false")
            << ",\"aggregate_reverification_ms\":"
            << aggregate_reverification_ms
            << ",\"aggregate_reverification_checks\":"
            << aggregate_reverification_checks
            << ",\"audit_pippenger_calls\":" << audit_pippenger_calls
            << ",\"audit_pippenger_terms\":" << audit_pippenger_terms
            << ",\"aggregate_soundness_bound\":\""
            << (msm_active ? "min(1,Q*2^-254)" : "not-applicable")
            << "\""
            << ",\"retries\":" << result.retried_indices.size()
            << ",\"opening_failures\":" << result.opening_failures.size()
            << ",\"partial_failures\":" << result.schnorr_failures.size()
            << "}\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "oasis_arc_adapter: " << error.what() << '\n';
        return 1;
    }
}
