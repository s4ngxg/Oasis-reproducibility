#include "oasis/core.hpp"

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>

int main(int argc, char** argv) {
    try {
        std::uint64_t vectors = 32;
        if (argc == 3 && std::string(argv[1]) == "--vectors") {
            vectors = std::stoull(argv[2]);
        } else if (argc != 1) {
            throw std::runtime_error(
                "usage: oasis_core_conformance [--vectors N]");
        }
        oasis::Crypto crypto;
        const oasis::TestReport report =
            oasis::run_conformance_tests(crypto, vectors);
        std::cout
            << "{\"status\":\"pass\""
            << ",\"differential_vectors\":" << report.differential_vectors
            << ",\"mutation_checks\":" << report.mutation_checks
            << ",\"replay_checks\":" << report.replay_checks
            << ",\"retry_checks\":" << report.retry_checks
            << ",\"adaptation_checks\":" << report.adaptation_checks
            << ",\"key_separation_checks\":"
            << report.key_separation_checks
            << ",\"independent_batch_checks\":"
            << report.independent_batch_checks
            << ",\"verifier_salt_checks\":"
            << report.verifier_salt_checks
            << ",\"ablation_variant_checks\":"
            << report.ablation_variant_checks
            << ",\"canonical_encoding_checks\":"
            << report.canonical_encoding_checks
            << ",\"cryptographic_kat_checks\":"
            << report.cryptographic_kat_checks
            << ",\"message_accounting_checks\":"
            << report.message_accounting_checks
            << "}\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "oasis_core_conformance: " << error.what() << '\n';
        return 1;
    }
}
