#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace oasis {

inline constexpr std::size_t kBatchVerificationMinItems = 8;

using Bytes = std::vector<std::uint8_t>;
using Digest = std::array<std::uint8_t, 32>;
using Scalar = std::array<std::uint8_t, 32>;
using Point = std::array<std::uint8_t, 33>;

enum class ItemType : std::uint8_t {
    Withdraw = 1,
    Relock = 2,
};

enum class Variant : std::uint8_t {
    B0FreshSequential = 0,
    B1PersistentSequential = 1,
    B2PersistentPipelined = 2,
    B3BatchedItemwise = 3,
    B4BatchedVerification = 4,
    B5IndependentBatchVerification = 5,
    B6PhaseCoalescedItemwise = 6,
};

struct Item {
    ItemType type{};
    std::uint32_t ordinal = 0;
    std::uint32_t address_index = 0;
    std::uint64_t timeout = 0;
    Digest message{};
    Point statement{};
    Scalar statement_witness{};
    bool has_statement_witness = false;
    Scalar client_secret{};
    bool has_client_secret = false;
    Scalar server_secret{};
    bool has_server_secret = false;
    Point client_public{};
    Point server_public{};
    Point joint_public{};
    Digest digest{};
};

struct Workload {
    std::uint32_t n = 0;
    std::uint64_t key_epoch = 0;
    std::uint64_t expiry = 0;
    std::uint64_t pair_id = 0;
    std::uint64_t execution_id = 0;
    std::uint32_t arc_index = 1;
    Digest seed{};
    Digest context_digest{};
    Digest batch_digest{};
    std::vector<Item> items;
};

struct NoncePair {
    Scalar client_nonce{};
    Scalar server_nonce{};
};

struct PreSignature {
    Point adaptor_nonce{};
    Scalar scalar{};

    bool operator==(const PreSignature& other) const {
        return adaptor_nonce == other.adaptor_nonce && scalar == other.scalar;
    }
};

struct ItemTranscript {
    Digest sid{};
    Point commitment{};
    Point server_nonce_point{};
    Scalar commitment_blind{};
    Point client_nonce_point{};
    Scalar server_partial{};
    Scalar client_partial{};
    Scalar challenge{};
    PreSignature presignature{};
};

struct FaultPlan {
    std::vector<std::size_t> bad_opening_indices;
    std::vector<std::size_t> bad_partial_indices;
};

struct SessionResult {
    bool accepted = false;
    std::vector<PreSignature> client_outputs;
    std::vector<PreSignature> server_outputs;
    std::vector<ItemTranscript> transcripts;
    std::vector<std::size_t> retried_indices;
    std::vector<std::size_t> opening_failures;
    std::vector<std::size_t> schnorr_failures;
    std::uint64_t application_messages = 0;
    std::uint64_t logical_sessions = 0;
};

struct TestReport {
    std::uint64_t differential_vectors = 0;
    std::uint64_t mutation_checks = 0;
    std::uint64_t replay_checks = 0;
    std::uint64_t retry_checks = 0;
    std::uint64_t adaptation_checks = 0;
    std::uint64_t key_separation_checks = 0;
    std::uint64_t independent_batch_checks = 0;
    std::uint64_t verifier_salt_checks = 0;
    std::uint64_t ablation_variant_checks = 0;
    std::uint64_t canonical_encoding_checks = 0;
    std::uint64_t cryptographic_kat_checks = 0;
    std::uint64_t message_accounting_checks = 0;
};

class Crypto {
public:
    struct Impl;

    Crypto();
    ~Crypto();
    Crypto(const Crypto&) = delete;
    Crypto& operator=(const Crypto&) = delete;

    Scalar random_scalar() const;
    Scalar derive_scalar(const std::string& domain,
                         const std::vector<Bytes>& parts) const;
    Digest hash(const std::string& domain,
                const std::vector<Bytes>& parts) const;

    Point base_mul(const Scalar& scalar) const;
    Point point_mul(const Point& point, const Scalar& scalar) const;
    Point multi_scalar_mul(const std::vector<Point>& points,
                           const std::vector<Scalar>& scalars) const;
    Point point_add(const Point& left, const Point& right) const;
    Point point_sub(const Point& left, const Point& right) const;
    Point hash_to_point(const std::string& domain,
                        const std::vector<Bytes>& parts) const;
    Scalar scalar_add(const Scalar& left, const Scalar& right) const;
    Scalar scalar_sub(const Scalar& left, const Scalar& right) const;
    Scalar scalar_mul(const Scalar& left, const Scalar& right) const;
    bool scalar_is_zero(const Scalar& scalar) const;
    bool scalar_is_canonical(const Scalar& scalar) const;

    Point pedersen_commit(const Scalar& message,
                          const Scalar& blind) const;
    bool pedersen_verify(const Point& commitment,
                         const Scalar& message,
                         const Scalar& blind) const;

private:
    std::unique_ptr<Impl> impl_;
};

Workload make_paraswap_workload(const Crypto& crypto, std::uint32_t n,
                                const Digest& seed, std::uint64_t key_epoch = 1,
                                std::uint64_t expiry = 3600,
                                std::uint64_t pair_id = 0,
                                std::uint64_t execution_id = 0,
                                std::uint32_t arc_index = 1);
Workload make_paraswap_public_workload(const Crypto& crypto, std::uint32_t n,
                                       const Digest& seed,
                                       std::uint64_t key_epoch = 1,
                                       std::uint64_t expiry = 3600,
                                       std::uint64_t pair_id = 0,
                                       std::uint64_t execution_id = 0,
                                       std::uint32_t arc_index = 1);
void attach_client_key_shares(const Crypto& crypto, Workload& workload,
                              const Scalar& master_secret);
void attach_server_key_shares(const Crypto& crypto, Workload& workload,
                              const Scalar& master_secret);
void attach_server_public_keys(const Crypto& crypto, Workload& workload,
                               const std::vector<Point>& public_keys);
void finalize_workload(const Crypto& crypto, Workload& workload);
void validate_workload(const Crypto& crypto, const Workload& workload);

Digest make_session_id(const Crypto& crypto, const Workload& workload,
                       std::uint32_t retry_counter,
                       const std::optional<Digest>& parent_sid = std::nullopt,
                       const std::optional<std::uint32_t>& failed_ordinal =
                           std::nullopt);
Digest make_item_session_id(const Crypto& crypto, const Workload& workload,
                            std::uint32_t item_index,
                            std::uint32_t retry_counter = 0,
                            const std::optional<Digest>& parent_sid =
                                std::nullopt);
Digest make_retry_session_id(const Crypto& crypto,
                             const Workload& workload,
                             std::uint32_t item_index,
                             std::uint32_t retry_counter,
                             const Digest& parent_sid);
Scalar derive_commitment_message(const Crypto& crypto, const Digest& sid,
                                 const Item& item,
                                 const Point& server_nonce);
Scalar derive_challenge(const Crypto& crypto, const Digest& sid,
                        const Item& item, const Point& adaptor_nonce);

std::vector<NoncePair> make_nonce_plan(const Crypto& crypto,
                                      std::size_t item_count);

SessionResult execute(const Crypto& crypto, const Workload& workload,
                      Variant variant, const FaultPlan& faults = {},
                      const std::optional<std::vector<NoncePair>>& nonces =
                          std::nullopt);

bool verify_presignature(const Crypto& crypto, const Item& item,
                         const Digest& sid,
                         const ItemTranscript& transcript);
bool verify_presignatures_batch(const Crypto& crypto,
                                const Workload& workload,
                                const Digest& sid,
                                const std::vector<ItemTranscript>& transcripts,
                                const Digest& verifier_salt);
bool verify_server_partials_batch(
    const Crypto& crypto, const Workload& workload, const Digest& sid,
    const std::vector<ItemTranscript>& transcripts,
    const Digest& verifier_salt);
bool verify_client_partials_batch(
    const Crypto& crypto, const Workload& workload, const Digest& sid,
    const std::vector<ItemTranscript>& transcripts,
    const Digest& verifier_salt);
bool verify_presignatures_batch_independent(
    const Crypto& crypto, const Workload& workload,
    const std::vector<ItemTranscript>& transcripts,
    const Digest& verifier_salt);
bool verify_server_partials_batch_independent(
    const Crypto& crypto, const Workload& workload,
    const std::vector<ItemTranscript>& transcripts,
    const Digest& verifier_salt);
bool verify_client_partials_batch_independent(
    const Crypto& crypto, const Workload& workload,
    const std::vector<ItemTranscript>& transcripts,
    const Digest& verifier_salt);

Scalar adapt(const Crypto& crypto, const PreSignature& presignature,
             const Scalar& witness);
std::optional<Scalar> extract(const Crypto& crypto, const Item& item,
                              const Digest& sid,
                              const ItemTranscript& transcript,
                              const Scalar& signature);

class ReplayCache {
public:
    Bytes process(const Digest& sid, std::uint8_t phase, const Bytes& payload,
                  const Bytes& response);

private:
    struct Entry {
        Digest payload_digest{};
        Bytes response;
    };
    std::map<std::pair<Digest, std::uint8_t>, Entry> entries_;
    std::map<Digest, std::uint8_t> highest_phase_;
};

TestReport run_conformance_tests(const Crypto& crypto,
                                 std::uint64_t differential_vectors,
                                 std::uint64_t vector_offset = 0);

std::string variant_name(Variant variant);
Variant parse_variant(const std::string& name);

Bytes bytes(const Digest& value);
Bytes bytes(const Scalar& value);
Bytes bytes(const Point& value);
std::string hex(const Digest& value);
std::string hex(const Scalar& value);
std::string hex(const Point& value);
Digest digest_from_u64(const Crypto& crypto, std::uint64_t value);

}  // namespace oasis
