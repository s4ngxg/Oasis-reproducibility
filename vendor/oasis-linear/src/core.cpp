#include "oasis/core.hpp"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <functional>
#include <iomanip>
#include <limits>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <thread>

namespace oasis {
namespace {

using BNPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using PointPtr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
using CtxPtr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void append_u32(Bytes& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>(value >> 24));
    out.push_back(static_cast<std::uint8_t>(value >> 16));
    out.push_back(static_cast<std::uint8_t>(value >> 8));
    out.push_back(static_cast<std::uint8_t>(value));
}

void append_u64(Bytes& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

Bytes u32_bytes(std::uint32_t value) {
    Bytes out;
    append_u32(out, value);
    return out;
}

Bytes u64_bytes(std::uint64_t value) {
    Bytes out;
    append_u64(out, value);
    return out;
}

Digest sha256_framed(const std::string& domain,
                     const std::vector<Bytes>& parts) {
    using MdPtr =
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    MdPtr context(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    require(context != nullptr &&
                EVP_DigestInit_ex(
                    context.get(), EVP_sha256(), nullptr) == 1,
            "SHA-256 initialization failed");
    const Bytes tag(domain.begin(), domain.end());
    auto update = [&](const Bytes& part) {
        Bytes length;
        append_u64(length, part.size());
        require(EVP_DigestUpdate(
                    context.get(), length.data(), length.size()) == 1,
                "SHA-256 length update failed");
        if (!part.empty()) {
            require(EVP_DigestUpdate(
                        context.get(), part.data(), part.size()) == 1,
                    "SHA-256 data update failed");
        }
    };
    update(tag);
    for (const auto& part : parts) {
        update(part);
    }
    Digest result{};
    unsigned int size = 0;
    require(EVP_DigestFinal_ex(
                context.get(), result.data(), &size) == 1 &&
                size == result.size(),
            "SHA-256 finalization failed");
    return result;
}

template <std::size_t N>
Bytes array_bytes(const std::array<std::uint8_t, N>& value) {
    return Bytes(value.begin(), value.end());
}

template <std::size_t N>
std::string array_hex(const std::array<std::uint8_t, N>& value) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::uint8_t byte : value) {
        out << std::setw(2) << static_cast<unsigned>(byte);
    }
    return out.str();
}

bool contains(const std::vector<std::size_t>& values, std::size_t needle) {
    return std::find(values.begin(), values.end(), needle) != values.end();
}

Digest item_digest(const Crypto& crypto, const Digest& context_digest,
                   const Item& item) {
    return crypto.hash(
        "OASIS-ITEM-v1",
        {bytes(context_digest), Bytes{static_cast<std::uint8_t>(item.type)},
         u32_bytes(item.ordinal),
         u32_bytes(item.address_index), u64_bytes(item.timeout),
         bytes(item.message), bytes(item.statement), bytes(item.client_public),
         bytes(item.server_public), bytes(item.joint_public)});
}

Digest context_digest(const Crypto& crypto, const Workload& workload) {
    return crypto.hash(
        "OASIS-CONTEXT-v1",
        {Bytes{'P', 'a', 'r', 'a', 'S', 'w', 'a', 'p'},
         u32_bytes(workload.n), u64_bytes(workload.key_epoch),
         u64_bytes(workload.expiry), u64_bytes(workload.pair_id),
         u64_bytes(workload.execution_id),
         u32_bytes(workload.arc_index),
         bytes(workload.seed)});
}

Digest batch_digest(const Crypto& crypto, const Workload& workload) {
    std::vector<Bytes> parts{
        bytes(workload.context_digest),
        u32_bytes(static_cast<std::uint32_t>(workload.items.size()))};
    for (const auto& item : workload.items) {
        parts.push_back(bytes(item.digest));
    }
    return crypto.hash("OASIS-ORDERED-BATCH-v1", parts);
}

void validate_workload_impl(const Crypto& crypto,
                            const Workload& workload) {
    require(workload.n > 0, "n must be positive");
    require(workload.arc_index >= 1 &&
                workload.arc_index <= workload.n,
            "arc index must be in [1,n]");
    require(workload.items.size() == 2 * workload.n - 1,
            "ParaSwap workload must contain exactly 2n-1 items");
    require(context_digest(crypto, workload) == workload.context_digest,
            "context digest mismatch");
    std::vector<std::optional<Point>> client_keys(workload.n);
    std::vector<std::optional<Point>> server_keys(workload.n);
    for (std::size_t i = 0; i < workload.items.size(); ++i) {
        const auto& item = workload.items[i];
        require(item.ordinal == i, "item order mismatch");
        require(item.address_index >= 1 &&
                    item.address_index <= workload.n,
                "invalid joint-address index");
        if (i < workload.n) {
            require(item.type == ItemType::Withdraw &&
                        item.address_index == i + 1,
                    "invalid ParaSwap withdraw mapping");
        } else {
            const std::size_t relock = i - workload.n + 1;
            require(item.type == ItemType::Relock &&
                        item.address_index == relock,
                    "invalid ParaSwap re-lock mapping");
        }
        require(item.joint_public ==
                    crypto.point_add(item.client_public, item.server_public),
                "joint public key does not match its shares");
        const std::size_t key_index = item.address_index - 1;
        if (client_keys[key_index]) {
            require(*client_keys[key_index] == item.client_public &&
                        *server_keys[key_index] == item.server_public,
                    "items for one address use inconsistent keys");
        } else {
            client_keys[key_index] = item.client_public;
            server_keys[key_index] = item.server_public;
        }
        if (item.has_statement_witness) {
            require(item.statement ==
                        crypto.base_mul(item.statement_witness),
                    "statement does not match benchmark witness");
        }
        if (item.has_client_secret) {
            require(item.client_public ==
                        crypto.base_mul(item.client_secret),
                    "client key share does not match public key");
        }
        if (item.has_server_secret) {
            require(item.server_public ==
                        crypto.base_mul(item.server_secret),
                    "server key share does not match public key");
        }
        require(item_digest(crypto, workload.context_digest, item) == item.digest,
                "item digest mismatch");
    }
    require(batch_digest(crypto, workload) == workload.batch_digest,
            "ordered batch digest mismatch");
}

Scalar address_share(const Crypto& crypto, const Workload& workload,
                     const Scalar& master_secret,
                     std::uint32_t address,
                     const std::string& role) {
    Scalar share = crypto.scalar_add(
        master_secret,
        crypto.derive_scalar(
            "OASIS-" + role + "-ADDRESS-TWEAK-v2",
            {bytes(workload.seed), u64_bytes(workload.pair_id),
             u32_bytes(workload.arc_index), u32_bytes(address),
             u64_bytes(workload.key_epoch)}));
    if (crypto.scalar_is_zero(share)) {
        share = crypto.derive_scalar(
            "OASIS-" + role + "-ADDRESS-NONZERO-v2",
            {bytes(workload.seed), u64_bytes(workload.pair_id),
             u32_bytes(workload.arc_index), u32_bytes(address),
             u64_bytes(workload.key_epoch)});
    }
    return share;
}

Scalar commitment_message(const Crypto& crypto, const Digest& sid,
                          const Item& item, const Point& server_nonce) {
    return crypto.derive_scalar(
        "OASIS-NONCE-COMMIT-MESSAGE-v1",
        {bytes(sid), bytes(item.digest), bytes(server_nonce)});
}

Scalar challenge(const Crypto& crypto, const Digest& sid, const Item& item,
                 const Point& adaptor_nonce) {
    return crypto.derive_scalar(
        "OASIS-ADAPTOR-CHALLENGE-v1",
        {bytes(sid), bytes(item.digest), bytes(item.message),
         bytes(item.statement), bytes(item.joint_public),
             bytes(adaptor_nonce)});
}

Digest verifier_salt(const Crypto& crypto, const Digest& sid,
                     const Digest& batch, const std::string& purpose) {
    return crypto.hash(
        "OASIS-VERIFIER-SALT-v1",
        {Bytes(purpose.begin(), purpose.end()), bytes(sid), bytes(batch),
         bytes(crypto.random_scalar())});
}

Scalar coefficient(const Crypto& crypto, const Digest& verifier_salt,
                   const Digest& sid, const Digest& batch,
                   const Item& item, const ItemTranscript& transcript,
                   std::uint32_t index, const std::string& purpose) {
    return crypto.derive_scalar(
        "OASIS-BATCH-COEFFICIENT-" + purpose + "-v1",
        {bytes(verifier_salt), bytes(sid), bytes(batch), u32_bytes(index),
         bytes(item.digest), bytes(transcript.client_nonce_point),
         bytes(transcript.server_nonce_point),
         bytes(item.statement), bytes(item.client_public),
         bytes(item.server_public), bytes(item.joint_public),
         bytes(transcript.challenge),
         bytes(transcript.server_partial),
         bytes(transcript.client_partial),
         bytes(transcript.presignature.scalar)});
}

bool verify_server_partial(const Crypto& crypto, const Item& item,
                           const ItemTranscript& transcript) {
    const Point left = crypto.base_mul(transcript.server_partial);
    const Point right = crypto.point_add(
        transcript.server_nonce_point,
        crypto.point_mul(item.server_public, transcript.challenge));
    return left == right;
}

bool verify_client_partial(const Crypto& crypto, const Item& item,
                           const ItemTranscript& transcript) {
    const Point left = crypto.base_mul(transcript.client_partial);
    const Point right = crypto.point_add(
        transcript.client_nonce_point,
        crypto.point_mul(item.client_public, transcript.challenge));
    return left == right;
}

Workload single_item_workload(const Crypto& crypto, const Workload& parent,
                              std::size_t index) {
    Workload one = parent;
    one.n = 1;
    one.items = {parent.items.at(index)};
    one.context_digest = crypto.hash(
        "OASIS-SINGLE-ITEM-CONTEXT-v1",
        {bytes(parent.context_digest), u32_bytes(static_cast<std::uint32_t>(index))});
    one.batch_digest = batch_digest(crypto, one);
    return one;
}

struct BatchAttempt {
    std::vector<ItemTranscript> transcripts;
    std::vector<std::size_t> failed;
    std::vector<std::size_t> opening_failures;
    std::vector<std::size_t> schnorr_failures;
};

BatchAttempt execute_attempt(
    const Crypto& crypto, const Workload& workload, const Digest& sid,
    bool use_batch_verification, const FaultPlan& faults,
    const std::vector<NoncePair>& nonce_plan,
    bool defer_verification = false) {
    require(nonce_plan.size() == workload.items.size(),
            "nonce plan size mismatch");
    BatchAttempt result;
    result.transcripts.resize(workload.items.size());

    // Phase 2: the server fixes all nonces with Pedersen commitments.
    for (std::size_t i = 0; i < workload.items.size(); ++i) {
        auto& transcript = result.transcripts[i];
        const auto& item = workload.items[i];
        transcript.sid = sid;
        transcript.server_nonce_point =
            crypto.base_mul(nonce_plan[i].server_nonce);
        transcript.commitment_blind = crypto.random_scalar();
        const Scalar message = commitment_message(
            crypto, sid, item, transcript.server_nonce_point);
        transcript.commitment =
            crypto.pedersen_commit(message, transcript.commitment_blind);
    }

    // Phase 3: the client reveals its nonce only after receiving commitments.
    for (std::size_t i = 0; i < workload.items.size(); ++i) {
        result.transcripts[i].client_nonce_point =
            crypto.base_mul(nonce_plan[i].client_nonce);
    }

    // Phase 4: server opens commitments and returns its partial signatures.
    for (std::size_t i = 0; i < workload.items.size(); ++i) {
        auto& transcript = result.transcripts[i];
        const auto& item = workload.items[i];
        transcript.presignature.adaptor_nonce = crypto.point_add(
            crypto.point_add(transcript.client_nonce_point,
                             transcript.server_nonce_point),
            item.statement);
        transcript.challenge =
            challenge(crypto, sid, item,
                      transcript.presignature.adaptor_nonce);
        transcript.server_partial = crypto.scalar_add(
            nonce_plan[i].server_nonce,
            crypto.scalar_mul(transcript.challenge, item.server_secret));

        if (contains(faults.bad_opening_indices, i)) {
            transcript.commitment_blind[31] ^= 1;
        }
        if (contains(faults.bad_partial_indices, i)) {
            transcript.server_partial =
                crypto.scalar_add(transcript.server_partial,
                                  crypto.derive_scalar(
                                      "OASIS-FAULT-v1",
                                      {bytes(sid), u32_bytes(i)}));
        }
    }

    // The client checks every opening before accepting any partial signature.
    std::vector<std::size_t> opening_failures;
    for (std::size_t i = 0; i < workload.items.size(); ++i) {
        const auto& item = workload.items[i];
        const auto& transcript = result.transcripts[i];
        const Scalar message = commitment_message(
            crypto, sid, item, transcript.server_nonce_point);
        if (!crypto.pedersen_verify(
                transcript.commitment, message,
                transcript.commitment_blind)) {
            opening_failures.push_back(i);
        }
    }
    result.opening_failures = opening_failures;

    std::set<std::size_t> failures(opening_failures.begin(),
                                   opening_failures.end());
    if (defer_verification) {
        // The caller verifies transcripts from independent sessions in one
        // aggregate equation after all sessions reach the same phase.
    } else if (use_batch_verification && opening_failures.empty()) {
        const Digest salt = verifier_salt(
            crypto, sid, workload.batch_digest, "server");
        if (!verify_server_partials_batch(
                crypto, workload, sid, result.transcripts, salt)) {
            for (std::size_t i = 0; i < workload.items.size(); ++i) {
                if (!verify_server_partial(
                        crypto, workload.items[i], result.transcripts[i])) {
                    failures.insert(i);
                    result.schnorr_failures.push_back(i);
                }
            }
        }
    } else {
        for (std::size_t i = 0; i < workload.items.size(); ++i) {
            if (failures.count(i) == 0 &&
                !verify_server_partial(
                    crypto, workload.items[i], result.transcripts[i])) {
                failures.insert(i);
                result.schnorr_failures.push_back(i);
            }
        }
    }

    // Phase 5: client returns its partials; both parties derive and verify
    // exactly the same ordered pre-signature vector.
    for (std::size_t i = 0; i < workload.items.size(); ++i) {
        if (failures.count(i) != 0) {
            continue;
        }
        auto& transcript = result.transcripts[i];
        const auto& item = workload.items[i];
        transcript.client_partial = crypto.scalar_add(
            nonce_plan[i].client_nonce,
            crypto.scalar_mul(transcript.challenge, item.client_secret));
        transcript.presignature.scalar = crypto.scalar_add(
            transcript.client_partial, transcript.server_partial);
    }

    if (defer_verification) {
        // Verification is deliberately deferred to the cross-session MSM.
    } else if (use_batch_verification && failures.empty()) {
        const Digest client_salt = verifier_salt(
            crypto, sid, workload.batch_digest, "client");
        if (!verify_client_partials_batch(
                crypto, workload, sid, result.transcripts,
                client_salt)) {
            for (std::size_t i = 0; i < workload.items.size(); ++i) {
                if (!verify_client_partial(
                        crypto, workload.items[i],
                        result.transcripts[i])) {
                    failures.insert(i);
                }
            }
        }
        const Digest final_salt = verifier_salt(
            crypto, sid, workload.batch_digest, "full");
        if (failures.empty() && !verify_presignatures_batch(
                crypto, workload, sid, result.transcripts,
                final_salt)) {
            for (std::size_t i = 0; i < workload.items.size(); ++i) {
                if (!verify_presignature(
                        crypto, workload.items[i], sid,
                        result.transcripts[i])) {
                    failures.insert(i);
                }
            }
        }
    } else {
        for (std::size_t i = 0; i < workload.items.size(); ++i) {
            if (failures.count(i) != 0) {
                continue;
            }
            if (!verify_client_partial(
                    crypto, workload.items[i], result.transcripts[i]) ||
                !verify_presignature(
                    crypto, workload.items[i], sid,
                    result.transcripts[i])) {
                failures.insert(i);
            }
        }
    }
    result.failed.assign(failures.begin(), failures.end());
    return result;
}

void require_throws(const std::function<void()>& operation,
                    const std::string& message) {
    bool threw = false;
    try {
        operation();
    } catch (const std::exception&) {
        threw = true;
    }
    require(threw, message);
}

}  // namespace

struct Crypto::Impl {
    std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)> group{
        EC_GROUP_new_by_curve_name(NID_secp256k1), &EC_GROUP_free};
    BNPtr order{BN_new(), &BN_free};
    Point pedersen_h{};

    Impl() {
        require(group != nullptr && order != nullptr,
                "failed to allocate secp256k1 context");
        CtxPtr context(BN_CTX_new(), &BN_CTX_free);
        require(context != nullptr &&
                    EC_GROUP_get_order(group.get(), order.get(),
                                       context.get()) == 1,
                "failed to read secp256k1 order");

        // Try-and-increment maps a domain-separated digest to a curve point.
        // No discrete logarithm relative to G is constructed or retained.
        for (std::uint32_t counter = 0;; ++counter) {
            const Digest x = sha256_framed(
                "OASIS-PEDERSEN-H-v1", {u32_bytes(counter)});
            Point encoded{};
            encoded[0] = static_cast<std::uint8_t>(2 + (x[31] & 1));
            std::copy(x.begin(), x.end(), encoded.begin() + 1);
            PointPtr point(EC_POINT_new(group.get()), &EC_POINT_free);
            require(point != nullptr, "failed to allocate Pedersen point");
            if (EC_POINT_oct2point(group.get(), point.get(), encoded.data(),
                                   encoded.size(), context.get()) == 1 &&
                EC_POINT_is_at_infinity(group.get(), point.get()) == 0) {
                pedersen_h = encoded;
                break;
            }
            require(counter != std::numeric_limits<std::uint32_t>::max(),
                    "hash-to-curve exhausted");
        }
    }
};

Crypto::Crypto() : impl_(std::make_unique<Impl>()) {}
Crypto::~Crypto() = default;

Digest Crypto::hash(const std::string& domain,
                    const std::vector<Bytes>& parts) const {
    return sha256_framed(domain, parts);
}

Scalar Crypto::derive_scalar(const std::string& domain,
                             const std::vector<Bytes>& parts) const {
    const Digest digest = hash(domain, parts);
    BNPtr candidate(BN_bin2bn(digest.data(), digest.size(), nullptr), &BN_free);
    BNPtr reduced(BN_new(), &BN_free);
    CtxPtr context(BN_CTX_new(), &BN_CTX_free);
    require(candidate != nullptr && reduced != nullptr && context != nullptr,
            "scalar derivation allocation failed");
    require(BN_mod(reduced.get(), candidate.get(), impl_->order.get(),
                   context.get()) == 1,
            "scalar reduction failed");
    if (BN_is_zero(reduced.get())) {
        BN_one(reduced.get());
    }
    Scalar result{};
    require(BN_bn2binpad(reduced.get(), result.data(), result.size()) ==
                static_cast<int>(result.size()),
            "scalar serialization failed");
    return result;
}

Scalar Crypto::random_scalar() const {
    BNPtr value(BN_new(), &BN_free);
    require(value != nullptr, "random scalar allocation failed");
    do {
        require(BN_priv_rand_range(value.get(), impl_->order.get()) == 1,
                "secure random scalar generation failed");
    } while (BN_is_zero(value.get()));
    Scalar result{};
    require(BN_bn2binpad(value.get(), result.data(), result.size()) ==
                static_cast<int>(result.size()),
            "random scalar serialization failed");
    return result;
}

namespace {

BNPtr to_bn(const Scalar& scalar) {
    return BNPtr(BN_bin2bn(scalar.data(), scalar.size(), nullptr), &BN_free);
}

PointPtr to_point(const Crypto::Impl& impl, const Point& encoded,
                  BN_CTX* context) {
    PointPtr point(EC_POINT_new(impl.group.get()), &EC_POINT_free);
    require(point != nullptr &&
                EC_POINT_oct2point(impl.group.get(), point.get(),
                                   encoded.data(), encoded.size(),
                                   context) == 1 &&
                EC_POINT_is_on_curve(impl.group.get(), point.get(),
                                     context) == 1,
            "invalid secp256k1 point");
    return point;
}

Point from_point(const Crypto::Impl& impl, const EC_POINT* point,
                 BN_CTX* context) {
    require(EC_POINT_is_at_infinity(impl.group.get(), point) == 0,
            "point at infinity cannot be serialized");
    Point encoded{};
    require(EC_POINT_point2oct(
                impl.group.get(), point, POINT_CONVERSION_COMPRESSED,
                encoded.data(), encoded.size(), context) == encoded.size(),
            "point serialization failed");
    return encoded;
}

Scalar scalar_binary(const Crypto::Impl& impl, const Scalar& left,
                     const Scalar& right,
                     int (*operation)(BIGNUM*, const BIGNUM*, const BIGNUM*,
                                      const BIGNUM*, BN_CTX*)) {
    BNPtr a = to_bn(left);
    BNPtr b = to_bn(right);
    BNPtr out(BN_new(), &BN_free);
    CtxPtr context(BN_CTX_new(), &BN_CTX_free);
    require(a != nullptr && b != nullptr && out != nullptr &&
                context != nullptr &&
                operation(out.get(), a.get(), b.get(), impl.order.get(),
                          context.get()) == 1,
            "scalar operation failed");
    Scalar result{};
    require(BN_bn2binpad(out.get(), result.data(), result.size()) ==
                static_cast<int>(result.size()),
            "scalar operation serialization failed");
    return result;
}

int modular_add(BIGNUM* out, const BIGNUM* left, const BIGNUM* right,
                const BIGNUM* modulus, BN_CTX* context) {
    return BN_mod_add(out, left, right, modulus, context);
}

int modular_sub(BIGNUM* out, const BIGNUM* left, const BIGNUM* right,
                const BIGNUM* modulus, BN_CTX* context) {
    return BN_mod_sub(out, left, right, modulus, context);
}

int modular_mul(BIGNUM* out, const BIGNUM* left, const BIGNUM* right,
                const BIGNUM* modulus, BN_CTX* context) {
    return BN_mod_mul(out, left, right, modulus, context);
}

}  // namespace

Point Crypto::base_mul(const Scalar& scalar) const {
    BNPtr value = to_bn(scalar);
    PointPtr out(EC_POINT_new(impl_->group.get()), &EC_POINT_free);
    CtxPtr context(BN_CTX_new(), &BN_CTX_free);
    require(value != nullptr && out != nullptr && context != nullptr &&
                EC_POINT_mul(impl_->group.get(), out.get(), value.get(),
                             nullptr, nullptr, context.get()) == 1,
            "base-point multiplication failed");
    return from_point(*impl_, out.get(), context.get());
}

Point Crypto::point_mul(const Point& point, const Scalar& scalar) const {
    CtxPtr context(BN_CTX_new(), &BN_CTX_free);
    BNPtr value = to_bn(scalar);
    PointPtr input = to_point(*impl_, point, context.get());
    PointPtr out(EC_POINT_new(impl_->group.get()), &EC_POINT_free);
    require(context != nullptr && value != nullptr && out != nullptr &&
                EC_POINT_mul(impl_->group.get(), out.get(), nullptr,
                             input.get(), value.get(), context.get()) == 1,
            "point multiplication failed");
    return from_point(*impl_, out.get(), context.get());
}

Point Crypto::multi_scalar_mul(
    const std::vector<Point>& points,
    const std::vector<Scalar>& scalars) const {
    require(!points.empty() && points.size() == scalars.size(),
            "MSM input size mismatch");
    CtxPtr context(BN_CTX_new(), &BN_CTX_free);
    require(context != nullptr, "MSM context allocation failed");

    std::vector<BNPtr> native_scalars;
    std::vector<PointPtr> native_points;
    native_scalars.reserve(scalars.size());
    native_points.reserve(points.size());
    int maximum_bits = 0;
    for (std::size_t i = 0; i < points.size(); ++i) {
        BNPtr scalar = to_bn(scalars[i]);
        require(scalar != nullptr &&
                    !BN_is_negative(scalar.get()) &&
                    BN_cmp(scalar.get(), impl_->order.get()) < 0,
                "MSM scalar is not canonical");
        maximum_bits = std::max(
            maximum_bits, BN_num_bits(scalar.get()));
        native_scalars.push_back(std::move(scalar));
        native_points.push_back(
            to_point(*impl_, points[i], context.get()));
    }
    require(maximum_bits > 0, "MSM has only zero scalars");

    // Variable-time Pippenger is safe here because every verifier scalar and
    // point is public transcript data. One shared doubling schedule replaces
    // an independent EC_POINT_mul call for every term.
    const int window_bits = points.size() <= 8
                                ? 3
                                : (points.size() <= 32 ? 4 : 5);
    const int bucket_count = 1 << window_bits;
    const int window_count =
        (maximum_bits + window_bits - 1) / window_bits;
    PointPtr result(EC_POINT_new(impl_->group.get()), &EC_POINT_free);
    PointPtr running(EC_POINT_new(impl_->group.get()), &EC_POINT_free);
    require(result != nullptr && running != nullptr &&
                EC_POINT_set_to_infinity(
                    impl_->group.get(), result.get()) == 1,
            "MSM accumulator allocation failed");

    std::vector<PointPtr> buckets;
    buckets.reserve(static_cast<std::size_t>(bucket_count));
    for (int bucket = 0; bucket < bucket_count; ++bucket) {
        buckets.emplace_back(
            EC_POINT_new(impl_->group.get()), &EC_POINT_free);
        require(buckets.back() != nullptr,
                "MSM bucket allocation failed");
    }

    for (int window = window_count - 1; window >= 0; --window) {
        if (window != window_count - 1) {
            for (int bit = 0; bit < window_bits; ++bit) {
                require(EC_POINT_dbl(
                            impl_->group.get(), result.get(),
                            result.get(), context.get()) == 1,
                        "MSM accumulator doubling failed");
            }
        }
        for (auto& bucket : buckets) {
            require(EC_POINT_set_to_infinity(
                        impl_->group.get(), bucket.get()) == 1,
                    "MSM bucket reset failed");
        }
        const int offset = window * window_bits;
        for (std::size_t i = 0; i < native_scalars.size(); ++i) {
            int digit = 0;
            for (int bit = 0; bit < window_bits; ++bit) {
                if (BN_is_bit_set(
                        native_scalars[i].get(), offset + bit)) {
                    digit |= 1 << bit;
                }
            }
            if (digit != 0) {
                require(EC_POINT_add(
                            impl_->group.get(), buckets[digit].get(),
                            buckets[digit].get(), native_points[i].get(),
                            context.get()) == 1,
                        "MSM bucket accumulation failed");
            }
        }
        require(EC_POINT_set_to_infinity(
                    impl_->group.get(), running.get()) == 1,
                "MSM running sum reset failed");
        for (int bucket = bucket_count - 1; bucket > 0; --bucket) {
            require(EC_POINT_add(
                        impl_->group.get(), running.get(), running.get(),
                        buckets[bucket].get(), context.get()) == 1 &&
                        EC_POINT_add(
                            impl_->group.get(), result.get(), result.get(),
                            running.get(), context.get()) == 1,
                    "MSM bucket reduction failed");
        }
    }
    require(EC_POINT_is_at_infinity(
                impl_->group.get(), result.get()) == 0,
            "MSM result is the point at infinity");
    return from_point(*impl_, result.get(), context.get());
}

Point Crypto::point_add(const Point& left, const Point& right) const {
    CtxPtr context(BN_CTX_new(), &BN_CTX_free);
    PointPtr a = to_point(*impl_, left, context.get());
    PointPtr b = to_point(*impl_, right, context.get());
    PointPtr out(EC_POINT_new(impl_->group.get()), &EC_POINT_free);
    require(context != nullptr && out != nullptr &&
                EC_POINT_add(impl_->group.get(), out.get(), a.get(), b.get(),
                             context.get()) == 1,
            "point addition failed");
    return from_point(*impl_, out.get(), context.get());
}

Point Crypto::point_sub(const Point& left, const Point& right) const {
    CtxPtr context(BN_CTX_new(), &BN_CTX_free);
    PointPtr a = to_point(*impl_, left, context.get());
    PointPtr b = to_point(*impl_, right, context.get());
    PointPtr out(EC_POINT_new(impl_->group.get()), &EC_POINT_free);
    require(context != nullptr && out != nullptr &&
                EC_POINT_invert(impl_->group.get(), b.get(), context.get()) ==
                    1 &&
                EC_POINT_add(impl_->group.get(), out.get(), a.get(), b.get(),
                             context.get()) == 1,
            "point subtraction failed");
    return from_point(*impl_, out.get(), context.get());
}

Point Crypto::hash_to_point(const std::string& domain,
                            const std::vector<Bytes>& parts) const {
    for (std::uint32_t counter = 0;; ++counter) {
        std::vector<Bytes> framed = parts;
        framed.push_back(u32_bytes(counter));
        const Digest x = hash(domain, framed);
        Point encoded{};
        encoded[0] = static_cast<std::uint8_t>(2 + (x[31] & 1));
        std::copy(x.begin(), x.end(), encoded.begin() + 1);
        CtxPtr context(BN_CTX_new(), &BN_CTX_free);
        PointPtr point(EC_POINT_new(impl_->group.get()), &EC_POINT_free);
        require(context != nullptr && point != nullptr,
                "hash-to-point allocation failed");
        if (EC_POINT_oct2point(impl_->group.get(), point.get(),
                               encoded.data(), encoded.size(),
                               context.get()) == 1 &&
            EC_POINT_is_at_infinity(impl_->group.get(), point.get()) == 0) {
            return encoded;
        }
        require(counter != std::numeric_limits<std::uint32_t>::max(),
                "hash-to-point exhausted");
    }
}

Scalar Crypto::scalar_add(const Scalar& left, const Scalar& right) const {
    return scalar_binary(*impl_, left, right, modular_add);
}

Scalar Crypto::scalar_sub(const Scalar& left, const Scalar& right) const {
    return scalar_binary(*impl_, left, right, modular_sub);
}

Scalar Crypto::scalar_mul(const Scalar& left, const Scalar& right) const {
    return scalar_binary(*impl_, left, right, modular_mul);
}

bool Crypto::scalar_is_zero(const Scalar& scalar) const {
    return std::all_of(scalar.begin(), scalar.end(),
                       [](std::uint8_t value) { return value == 0; });
}

bool Crypto::scalar_is_canonical(const Scalar& scalar) const {
    BNPtr value = to_bn(scalar);
    return value != nullptr &&
           BN_cmp(value.get(), impl_->order.get()) < 0;
}

Point Crypto::pedersen_commit(const Scalar& message,
                              const Scalar& blind) const {
    return point_add(base_mul(message), point_mul(impl_->pedersen_h, blind));
}

bool Crypto::pedersen_verify(const Point& commitment,
                             const Scalar& message,
                             const Scalar& blind) const {
    try {
        return commitment == pedersen_commit(message, blind);
    } catch (const std::exception&) {
        return false;
    }
}

Workload make_paraswap_public_workload(
    const Crypto& crypto, std::uint32_t n, const Digest& seed,
    std::uint64_t key_epoch, std::uint64_t expiry,
    std::uint64_t pair_id, std::uint64_t execution_id,
    std::uint32_t arc_index) {
    require(n > 0 && n <= 1024, "n must be in [1, 1024]");
    require(arc_index >= 1 && arc_index <= n,
            "arc index must be in [1,n]");
    Workload workload;
    workload.n = n;
    workload.key_epoch = key_epoch;
    workload.expiry = expiry;
    workload.pair_id = pair_id;
    workload.execution_id = execution_id;
    workload.arc_index = arc_index;
    workload.seed = seed;

    auto add_item = [&](ItemType type, std::uint32_t address,
                        std::uint64_t timeout,
                        const Point& statement) {
        Item item;
        item.type = type;
        item.ordinal =
            static_cast<std::uint32_t>(workload.items.size());
        item.address_index = address;
        item.timeout = timeout;
        const std::string type_name =
            type == ItemType::Withdraw ? "withdraw" : "relock";
        item.message = crypto.hash(
            "OASIS-PARASWAP-TRANSACTION-DIGEST-v2",
            {bytes(seed), Bytes(type_name.begin(), type_name.end()),
             u64_bytes(pair_id), u32_bytes(arc_index),
             u32_bytes(address), u64_bytes(timeout)});
        item.statement = statement;
        workload.items.push_back(item);
    };

    Point cumulative_statement = crypto.hash_to_point(
        "OASIS-PARASWAP-PARTICIPANT-Y-v3",
        {bytes(seed), u64_bytes(pair_id), u32_bytes(1)});
    for (std::uint32_t participant = 2;
         participant <= n; ++participant) {
        cumulative_statement = crypto.point_add(
            cumulative_statement,
            crypto.hash_to_point(
                "OASIS-PARASWAP-PARTICIPANT-Y-v3",
                {bytes(seed), u64_bytes(pair_id),
                 u32_bytes(participant)}));
    }
    for (std::uint32_t j = 1; j <= n; ++j) {
        const std::uint32_t participant =
            ((arc_index + j - 1) % n) + 1;
        const Point participant_statement = crypto.hash_to_point(
            "OASIS-PARASWAP-PARTICIPANT-K-v3",
            {bytes(seed), u64_bytes(pair_id),
             u32_bytes(participant)});
        cumulative_statement = crypto.point_add(
            cumulative_statement, participant_statement);
        add_item(ItemType::Withdraw, j, expiry + j * 10,
                 cumulative_statement);
    }
    for (std::uint32_t x = 1; x < n; ++x) {
        const Point vtd_statement = crypto.hash_to_point(
            "OASIS-PARASWAP-VTD-U-v3",
            {bytes(seed), u64_bytes(pair_id),
             u32_bytes((arc_index % n) + 1), u32_bytes(x),
             u64_bytes(expiry + x * 10 + 5)});
        add_item(ItemType::Relock, x, expiry + x * 10 + 5,
                 vtd_statement);
    }

    workload.context_digest = context_digest(crypto, workload);
    return workload;
}

void attach_client_key_shares(const Crypto& crypto, Workload& workload,
                              const Scalar& master_secret) {
    std::vector<Scalar> secrets(workload.n);
    std::vector<Point> publics(workload.n);
    for (std::uint32_t address = 1; address <= workload.n; ++address) {
        secrets[address - 1] = address_share(
            crypto, workload, master_secret, address, "CLIENT");
        publics[address - 1] =
            crypto.base_mul(secrets[address - 1]);
    }
    for (auto& item : workload.items) {
        item.client_secret = secrets.at(item.address_index - 1);
        item.has_client_secret = true;
        item.client_public = publics.at(item.address_index - 1);
    }
}

void attach_server_key_shares(const Crypto& crypto, Workload& workload,
                              const Scalar& master_secret) {
    std::vector<Scalar> secrets(workload.n);
    std::vector<Point> publics(workload.n);
    for (std::uint32_t address = 1; address <= workload.n; ++address) {
        secrets[address - 1] = address_share(
            crypto, workload, master_secret, address, "SERVER");
        publics[address - 1] =
            crypto.base_mul(secrets[address - 1]);
    }
    for (auto& item : workload.items) {
        item.server_secret = secrets.at(item.address_index - 1);
        item.has_server_secret = true;
        item.server_public = publics.at(item.address_index - 1);
    }
}

void attach_server_public_keys(const Crypto& crypto, Workload& workload,
                               const std::vector<Point>& public_keys) {
    require(public_keys.size() == workload.n,
            "server public-key vector size mismatch");
    for (auto& item : workload.items) {
        item.server_public = public_keys.at(item.address_index - 1);
        (void)crypto.point_mul(
            item.server_public,
            crypto.derive_scalar("OASIS-POINT-VALIDATION-v1", {}));
    }
}

void finalize_workload(const Crypto& crypto, Workload& workload) {
    workload.context_digest = context_digest(crypto, workload);
    for (auto& item : workload.items) {
        item.joint_public =
            crypto.point_add(item.client_public, item.server_public);
        item.digest = item_digest(crypto, workload.context_digest, item);
    }
    workload.batch_digest = batch_digest(crypto, workload);
    validate_workload_impl(crypto, workload);
}

void validate_workload(const Crypto& crypto,
                       const Workload& workload) {
    validate_workload_impl(crypto, workload);
}

Workload make_paraswap_workload(const Crypto& crypto, std::uint32_t n,
                                const Digest& seed, std::uint64_t key_epoch,
                                std::uint64_t expiry,
                                std::uint64_t pair_id,
                                std::uint64_t execution_id,
                                std::uint32_t arc_index) {
    Workload workload = make_paraswap_public_workload(
        crypto, n, seed, key_epoch, expiry, pair_id,
        execution_id, arc_index);
    const Scalar client_master = crypto.derive_scalar(
        "OASIS-LOCAL-CLIENT-MASTER-v2",
        {bytes(seed), u64_bytes(pair_id), u64_bytes(key_epoch)});
    const Scalar server_master = crypto.derive_scalar(
        "OASIS-LOCAL-SERVER-MASTER-v2",
        {bytes(seed), u64_bytes(pair_id), u64_bytes(key_epoch)});
    attach_client_key_shares(crypto, workload, client_master);
    attach_server_key_shares(crypto, workload, server_master);
    finalize_workload(crypto, workload);
    return workload;
}

Digest make_session_id(const Crypto& crypto, const Workload& workload,
                       std::uint32_t retry_counter,
                       const std::optional<Digest>& parent_sid,
                       const std::optional<std::uint32_t>& failed_ordinal) {
    std::vector<Bytes> parts{
        bytes(workload.context_digest), bytes(workload.batch_digest),
        u32_bytes(retry_counter)};
    parts.push_back(parent_sid ? bytes(*parent_sid) : Bytes{});
    parts.push_back(failed_ordinal ? u32_bytes(*failed_ordinal) : Bytes{});
    return crypto.hash("OASIS-SESSION-ID-v1", parts);
}

Digest make_item_session_id(const Crypto& crypto, const Workload& workload,
                            std::uint32_t item_index,
                            std::uint32_t retry_counter,
                            const std::optional<Digest>& parent_sid) {
    require(item_index < workload.items.size(),
            "item session index out of range");
    return crypto.hash(
        "OASIS-ITEM-SESSION-ID-v1",
        {bytes(workload.context_digest), bytes(workload.batch_digest),
         u32_bytes(item_index), bytes(workload.items[item_index].digest),
         u32_bytes(retry_counter),
         parent_sid ? bytes(*parent_sid) : Bytes{}});
}

Digest make_retry_session_id(const Crypto& crypto,
                             const Workload& workload,
                             std::uint32_t item_index,
                             std::uint32_t retry_counter,
                             const Digest& parent_sid) {
    require(item_index < workload.items.size(),
            "retry item index out of range");
    require(retry_counter > 0,
            "retry counter must be positive");
    return crypto.hash(
        "OASIS-RETRY-ITEM-SESSION-ID-v1",
        {bytes(workload.context_digest),
         bytes(workload.batch_digest), u32_bytes(item_index),
         bytes(workload.items[item_index].digest),
         u32_bytes(retry_counter), bytes(parent_sid)});
}

Scalar derive_commitment_message(const Crypto& crypto, const Digest& sid,
                                 const Item& item,
                                 const Point& server_nonce) {
    return commitment_message(crypto, sid, item, server_nonce);
}

Scalar derive_challenge(const Crypto& crypto, const Digest& sid,
                        const Item& item, const Point& adaptor_nonce) {
    return challenge(crypto, sid, item, adaptor_nonce);
}

std::vector<NoncePair> make_nonce_plan(const Crypto& crypto,
                                      std::size_t item_count) {
    std::vector<NoncePair> plan(item_count);
    for (auto& pair : plan) {
        pair.client_nonce = crypto.random_scalar();
        pair.server_nonce = crypto.random_scalar();
    }
    return plan;
}

SessionResult execute(const Crypto& crypto, const Workload& workload,
                      Variant variant, const FaultPlan& faults,
                      const std::optional<std::vector<NoncePair>>& nonces) {
    validate_workload(crypto, workload);
    SessionResult result;

    const bool shared_batch =
        variant == Variant::B3BatchedItemwise ||
        variant == Variant::B4BatchedVerification;
    const bool batch_verification =
        variant == Variant::B4BatchedVerification &&
        workload.items.size() >= kBatchVerificationMinItems;
    const bool independent_batch_verification =
        variant == Variant::B5IndependentBatchVerification &&
        workload.items.size() >= kBatchVerificationMinItems;
    const auto nonce_plan =
        nonces.value_or(make_nonce_plan(crypto, workload.items.size()));
    require(nonce_plan.size() == workload.items.size(),
            "nonce plan size mismatch");

    if (shared_batch) {
        const Digest sid = make_session_id(crypto, workload, 0);
        BatchAttempt attempt = execute_attempt(
            crypto, workload, sid, batch_verification, faults, nonce_plan);
        result.opening_failures = attempt.opening_failures;
        result.schnorr_failures = attempt.schnorr_failures;
        result.transcripts = attempt.transcripts;
        result.logical_sessions = 1;
        result.application_messages = 5;

        std::set<std::size_t> failed(attempt.failed.begin(),
                                    attempt.failed.end());
        for (std::size_t i = 0; i < workload.items.size(); ++i) {
            if (failed.count(i) == 0) {
                result.client_outputs.push_back(
                    attempt.transcripts[i].presignature);
                result.server_outputs.push_back(
                    attempt.transcripts[i].presignature);
                continue;
            }

            Workload retry_workload =
                single_item_workload(crypto, workload, i);
            const Digest retry_sid = make_retry_session_id(
                crypto, workload,
                static_cast<std::uint32_t>(i), 1, sid);
            const auto retry_nonces = make_nonce_plan(crypto, 1);
            BatchAttempt retry = execute_attempt(
                crypto, retry_workload, retry_sid, false, {},
                retry_nonces);
            require(retry.failed.empty(), "selective retry failed");
            result.retried_indices.push_back(i);
            result.transcripts[i] = retry.transcripts.front();
            result.client_outputs.push_back(
                retry.transcripts.front().presignature);
            result.server_outputs.push_back(
                retry.transcripts.front().presignature);
            result.logical_sessions += 1;
            result.application_messages += 5;
        }
    } else if (independent_batch_verification) {
        result.logical_sessions = workload.items.size();
        result.application_messages = 5 * workload.items.size();
        result.transcripts.reserve(workload.items.size());
        std::set<std::size_t> failed;

        for (std::size_t i = 0; i < workload.items.size(); ++i) {
            Workload one = single_item_workload(crypto, workload, i);
            const Digest sid = make_item_session_id(
                crypto, workload, static_cast<std::uint32_t>(i));
            FaultPlan one_fault;
            if (contains(faults.bad_opening_indices, i)) {
                one_fault.bad_opening_indices = {0};
            }
            if (contains(faults.bad_partial_indices, i)) {
                one_fault.bad_partial_indices = {0};
            }
            BatchAttempt attempt = execute_attempt(
                crypto, one, sid, false, one_fault, {nonce_plan[i]}, true);
            if (!attempt.opening_failures.empty()) {
                failed.insert(i);
                result.opening_failures.push_back(i);
            }
            result.transcripts.push_back(attempt.transcripts.front());
        }

        if (failed.empty()) {
            const Digest server_salt = crypto.hash(
                "OASIS-INDEPENDENT-SERVER-SALT-v1",
                {bytes(workload.batch_digest),
                 bytes(crypto.random_scalar())});
            if (!verify_server_partials_batch_independent(
                    crypto, workload, result.transcripts, server_salt)) {
                for (std::size_t i = 0; i < workload.items.size(); ++i) {
                    if (!verify_server_partial(
                            crypto, workload.items[i],
                            result.transcripts[i])) {
                        failed.insert(i);
                        result.schnorr_failures.push_back(i);
                    }
                }
            }
        }

        if (failed.empty()) {
            const Digest client_salt = crypto.hash(
                "OASIS-INDEPENDENT-CLIENT-SALT-v1",
                {bytes(workload.batch_digest),
                 bytes(crypto.random_scalar())});
            if (!verify_client_partials_batch_independent(
                    crypto, workload, result.transcripts, client_salt)) {
                for (std::size_t i = 0; i < workload.items.size(); ++i) {
                    if (!verify_client_partial(
                            crypto, workload.items[i],
                            result.transcripts[i])) {
                        failed.insert(i);
                    }
                }
            }
            const Digest final_salt = crypto.hash(
                "OASIS-INDEPENDENT-FINAL-SALT-v1",
                {bytes(workload.batch_digest),
                 bytes(crypto.random_scalar())});
            if (failed.empty() &&
                !verify_presignatures_batch_independent(
                    crypto, workload, result.transcripts, final_salt)) {
                for (std::size_t i = 0; i < workload.items.size(); ++i) {
                    if (!verify_presignature(
                            crypto, workload.items[i],
                            result.transcripts[i].sid,
                            result.transcripts[i])) {
                        failed.insert(i);
                    }
                }
            }
        }

        for (std::size_t i = 0; i < workload.items.size(); ++i) {
            if (failed.count(i) != 0) {
                Workload retry_workload =
                    single_item_workload(crypto, workload, i);
                const Digest retry_sid = make_retry_session_id(
                    crypto, workload, static_cast<std::uint32_t>(i), 1,
                    result.transcripts[i].sid);
                BatchAttempt retry = execute_attempt(
                    crypto, retry_workload, retry_sid, false, {},
                    make_nonce_plan(crypto, 1));
                require(retry.failed.empty(),
                        "independent batch retry failed");
                result.transcripts[i] = retry.transcripts.front();
                result.retried_indices.push_back(i);
                result.logical_sessions += 1;
                result.application_messages += 5;
            }
            result.client_outputs.push_back(
                result.transcripts[i].presignature);
            result.server_outputs.push_back(
                result.transcripts[i].presignature);
        }
    } else {
        // These variants preserve one logical Pi_JPSig session per item.
        // B2/B6 change transport scheduling only.
        result.logical_sessions = workload.items.size();
        result.application_messages = 5 * workload.items.size();
        result.transcripts.reserve(workload.items.size());
        for (std::size_t i = 0; i < workload.items.size(); ++i) {
            Workload one = single_item_workload(crypto, workload, i);
            const Digest sid =
                (variant == Variant::B2PersistentPipelined ||
                 variant == Variant::B5IndependentBatchVerification ||
                 variant == Variant::B6PhaseCoalescedItemwise)
                    ? make_item_session_id(
                          crypto, workload,
                          static_cast<std::uint32_t>(i))
                    : make_session_id(crypto, one, 0);
            FaultPlan one_fault;
            if (contains(faults.bad_opening_indices, i)) {
                one_fault.bad_opening_indices = {0};
            }
            if (contains(faults.bad_partial_indices, i)) {
                one_fault.bad_partial_indices = {0};
            }
            BatchAttempt attempt = execute_attempt(
                crypto, one, sid, false, one_fault, {nonce_plan[i]});
            if (!attempt.opening_failures.empty()) {
                result.opening_failures.push_back(i);
            }
            if (!attempt.schnorr_failures.empty()) {
                result.schnorr_failures.push_back(i);
            }
            if (!attempt.failed.empty()) {
                const Digest retry_sid =
                    (variant == Variant::B2PersistentPipelined ||
                     variant == Variant::B5IndependentBatchVerification ||
                     variant == Variant::B6PhaseCoalescedItemwise)
                        ? make_item_session_id(
                              crypto, workload,
                              static_cast<std::uint32_t>(i), 1, sid)
                        : make_session_id(
                              crypto, one, 1, sid,
                              static_cast<std::uint32_t>(i));
                BatchAttempt retry = execute_attempt(
                    crypto, one, retry_sid, false, {},
                    make_nonce_plan(crypto, 1));
                require(retry.failed.empty(), "independent retry failed");
                attempt = std::move(retry);
                result.retried_indices.push_back(i);
                result.logical_sessions += 1;
                result.application_messages += 5;
            }
            result.transcripts.push_back(attempt.transcripts.front());
            result.client_outputs.push_back(
                attempt.transcripts.front().presignature);
            result.server_outputs.push_back(
                attempt.transcripts.front().presignature);
        }
    }

    result.accepted =
        result.client_outputs.size() == workload.items.size() &&
        result.client_outputs == result.server_outputs;
    if (result.accepted) {
        // The schema counts logical protocol frames, including the final
        // connection-scoped completion receipt.
        ++result.application_messages;  // DONE
        if (variant == Variant::B4BatchedVerification) {
            ++result.application_messages;  // FINAL_STATUS
        }
        if (shared_batch && !result.retried_indices.empty()) {
            ++result.application_messages;  // RETRY_PLAN
        }
    }
    return result;
}

bool verify_presignature(const Crypto& crypto, const Item& item,
                         const Digest& sid,
                         const ItemTranscript& transcript) {
    try {
        const Scalar expected_challenge = challenge(
            crypto, sid, item,
            transcript.presignature.adaptor_nonce);
        if (expected_challenge != transcript.challenge) {
            return false;
        }
        const Point left =
            crypto.base_mul(transcript.presignature.scalar);
        const Point nonce_without_statement = crypto.point_sub(
            transcript.presignature.adaptor_nonce, item.statement);
        const Point right = crypto.point_add(
            nonce_without_statement,
            crypto.point_mul(item.joint_public, transcript.challenge));
        return left == right;
    } catch (const std::exception&) {
        return false;
    }
}

namespace {

enum class BatchEquation {
    ServerPartial,
    ClientPartial,
    PreSignature,
};

bool verify_batch_equation(
    const Crypto& crypto, const Workload& workload,
    const std::vector<ItemTranscript>& transcripts,
    const Digest& verifier_salt, BatchEquation equation,
    const std::optional<Digest>& shared_sid) {
    if (transcripts.size() != workload.items.size() ||
        transcripts.empty()) {
        return false;
    }
    try {
        Scalar scalar_sum{};
        std::vector<Point> points;
        std::vector<Scalar> scalars;
        points.reserve(transcripts.size() * 2);
        scalars.reserve(transcripts.size() * 2);
        for (std::size_t i = 0; i < transcripts.size(); ++i) {
            const auto& item = workload.items[i];
            const auto& transcript = transcripts[i];
            if ((shared_sid.has_value() &&
                 transcript.sid != *shared_sid) ||
                transcript.challenge != challenge(
                    crypto, transcript.sid, item,
                    transcript.presignature.adaptor_nonce)) {
                return false;
            }
            const char* purpose = equation == BatchEquation::ServerPartial
                                      ? "SERVER-PARTIAL"
                                  : equation == BatchEquation::ClientPartial
                                      ? "CLIENT-PARTIAL"
                                      : "FULL";
            const Scalar alpha = coefficient(
                crypto, verifier_salt, transcript.sid,
                workload.batch_digest, item,
                transcript, static_cast<std::uint32_t>(i),
                purpose);
            if (equation == BatchEquation::ServerPartial) {
                scalar_sum = crypto.scalar_add(
                    scalar_sum,
                    crypto.scalar_mul(alpha,
                                      transcript.server_partial));
                points.push_back(transcript.server_nonce_point);
                points.push_back(item.server_public);
            } else if (equation == BatchEquation::ClientPartial) {
                scalar_sum = crypto.scalar_add(
                    scalar_sum,
                    crypto.scalar_mul(alpha,
                                      transcript.client_partial));
                points.push_back(transcript.client_nonce_point);
                points.push_back(item.client_public);
            } else {
                scalar_sum = crypto.scalar_add(
                    scalar_sum,
                    crypto.scalar_mul(
                        alpha, transcript.presignature.scalar));
                points.push_back(crypto.point_sub(
                    transcript.presignature.adaptor_nonce,
                    item.statement));
                points.push_back(item.joint_public);
            }
            scalars.push_back(alpha);
            scalars.push_back(
                crypto.scalar_mul(alpha, transcript.challenge));
        }
        return crypto.base_mul(scalar_sum) ==
               crypto.multi_scalar_mul(points, scalars);
    } catch (const std::exception&) {
        return false;
    }
}

}  // namespace

bool verify_server_partials_batch(
    const Crypto& crypto, const Workload& workload, const Digest& sid,
    const std::vector<ItemTranscript>& transcripts,
    const Digest& verifier_salt) {
    return verify_batch_equation(
        crypto, workload, transcripts, verifier_salt,
        BatchEquation::ServerPartial, sid);
}

bool verify_client_partials_batch(
    const Crypto& crypto, const Workload& workload, const Digest& sid,
    const std::vector<ItemTranscript>& transcripts,
    const Digest& verifier_salt) {
    return verify_batch_equation(
        crypto, workload, transcripts, verifier_salt,
        BatchEquation::ClientPartial, sid);
}

bool verify_presignatures_batch(
    const Crypto& crypto, const Workload& workload, const Digest& sid,
    const std::vector<ItemTranscript>& transcripts,
    const Digest& verifier_salt) {
    return verify_batch_equation(
        crypto, workload, transcripts, verifier_salt,
        BatchEquation::PreSignature, sid);
}

bool verify_server_partials_batch_independent(
    const Crypto& crypto, const Workload& workload,
    const std::vector<ItemTranscript>& transcripts,
    const Digest& verifier_salt) {
    return verify_batch_equation(
        crypto, workload, transcripts, verifier_salt,
        BatchEquation::ServerPartial, std::nullopt);
}

bool verify_client_partials_batch_independent(
    const Crypto& crypto, const Workload& workload,
    const std::vector<ItemTranscript>& transcripts,
    const Digest& verifier_salt) {
    return verify_batch_equation(
        crypto, workload, transcripts, verifier_salt,
        BatchEquation::ClientPartial, std::nullopt);
}

bool verify_presignatures_batch_independent(
    const Crypto& crypto, const Workload& workload,
    const std::vector<ItemTranscript>& transcripts,
    const Digest& verifier_salt) {
    return verify_batch_equation(
        crypto, workload, transcripts, verifier_salt,
        BatchEquation::PreSignature, std::nullopt);
}

Scalar adapt(const Crypto& crypto, const PreSignature& presignature,
             const Scalar& witness) {
    return crypto.scalar_add(presignature.scalar, witness);
}

std::optional<Scalar> extract(const Crypto& crypto, const Item& item,
                              const Digest& sid,
                              const ItemTranscript& transcript,
                              const Scalar& signature) {
    if (!crypto.scalar_is_canonical(signature) ||
        !verify_presignature(crypto, item, sid, transcript)) {
        return std::nullopt;
    }
    const Scalar witness = crypto.scalar_sub(
        signature, transcript.presignature.scalar);
    try {
        if (crypto.base_mul(witness) != item.statement) {
            return std::nullopt;
        }
        const Point expected = crypto.point_add(
            transcript.presignature.adaptor_nonce,
            crypto.point_mul(item.joint_public,
                             transcript.challenge));
        if (crypto.base_mul(signature) != expected) {
            return std::nullopt;
        }
        return witness;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

Bytes ReplayCache::process(const Digest& sid, std::uint8_t phase,
                           const Bytes& payload, const Bytes& response) {
    require(phase >= 1 && phase <= 5, "invalid protocol phase");
    const Digest payload_digest =
        sha256_framed("OASIS-REPLAY-PAYLOAD-v1", {payload});
    const auto key = std::make_pair(sid, phase);
    const auto found = entries_.find(key);
    if (found != entries_.end()) {
        require(found->second.payload_digest == payload_digest,
                "conflicting replay for session phase");
        return found->second.response;
    }
    const std::uint8_t highest =
        highest_phase_.count(sid) ? highest_phase_.at(sid) : 0;
    require(phase == highest + 1, "out-of-order protocol phase");
    entries_[key] = {payload_digest, response};
    highest_phase_[sid] = phase;
    return response;
}

TestReport run_conformance_tests(const Crypto& crypto,
                                 std::uint64_t differential_vectors,
                                 std::uint64_t vector_offset) {
    TestReport report;

    // Golden values were generated independently from the normative
    // I2OSP64-length-prefixed SHA-256 grammar documented by the artifact.
    auto byte_range = [](std::uint8_t first, std::size_t count) {
        Bytes output;
        output.reserve(count);
        for (std::size_t i = 0; i < count; ++i) {
            output.push_back(static_cast<std::uint8_t>(first + i));
        }
        return output;
    };
    const Bytes kat_seed = byte_range(0, 32);
    require(array_hex(crypto.hash(
                "OASIS-CONTEXT-v1",
                {Bytes{'P', 'a', 'r', 'a', 'S', 'w', 'a', 'p'},
                 u32_bytes(8), u64_bytes(7), u64_bytes(3600),
                 u64_bytes(17), u64_bytes(23), u32_bytes(2), kat_seed})) ==
                "effffa23bc53c1298f92a84708c3a34f6ea91f68e35b817585a18c00aaf1d929",
            "canonical context encoding KAT failed");
    ++report.canonical_encoding_checks;

    Bytes statement{2};
    Bytes client_public{3};
    Bytes server_public{2};
    Bytes joint_public{3};
    const Bytes statement_tail = byte_range(1, 32);
    const Bytes client_tail = byte_range(33, 32);
    const Bytes server_tail = byte_range(65, 32);
    const Bytes joint_tail = byte_range(97, 32);
    statement.insert(statement.end(), statement_tail.begin(),
                     statement_tail.end());
    client_public.insert(client_public.end(), client_tail.begin(),
                         client_tail.end());
    server_public.insert(server_public.end(), server_tail.begin(),
                         server_tail.end());
    joint_public.insert(joint_public.end(), joint_tail.begin(),
                        joint_tail.end());
    require(array_hex(crypto.hash(
                "OASIS-ITEM-v1",
                {byte_range(0, 32), Bytes{1}, u32_bytes(0), u32_bytes(1),
                 u64_bytes(3600),
                 byte_range(32, 32), statement, client_public,
                 server_public, joint_public})) ==
                "a7c148d436449ec3eee8451b4901eb73352f5ccc75ec598bed6d214f57e2d7af",
            "canonical item encoding KAT failed");
    ++report.canonical_encoding_checks;

    require(array_hex(crypto.hash(
                "OASIS-KAT-v1", {Bytes{}, Bytes{'a', 'b', 'c'},
                                  Bytes{0, 255}})) ==
                "d2695ce08a585d414937b77c9e515833fbd84db970e6301ddef9a52257f88d01",
            "framed hash KAT failed");
    require(crypto.hash("OASIS-FRAMING-SEPARATION-v1",
                        {Bytes{'a'}, Bytes{'b', 'c'}}) !=
                crypto.hash("OASIS-FRAMING-SEPARATION-v1",
                            {Bytes{'a', 'b'}, Bytes{'c'}}),
            "length framing failed to separate ambiguous concatenations");
    report.canonical_encoding_checks += 2;

    Scalar scalar_one{};
    Scalar scalar_two{};
    scalar_one.back() = 1;
    scalar_two.back() = 2;
    const Point generator = crypto.base_mul(scalar_one);
    const Point twice_generator = crypto.base_mul(scalar_two);
    require(array_hex(generator) ==
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "secp256k1 generator KAT failed");
    require(array_hex(twice_generator) ==
                "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            "secp256k1 double-generator KAT failed");
    require(crypto.point_add(generator, generator) == twice_generator,
            "secp256k1 point-addition KAT failed");
    report.cryptographic_kat_checks += 3;

    const Digest seed = digest_from_u64(crypto, 0x4f41534953ULL);
    const Workload workload =
        make_paraswap_workload(crypto, 3, seed, 7, 7200);
    require(workload.items.size() == 5,
            "n=3 must create exactly five items");
    require(std::count_if(
                workload.items.begin(), workload.items.end(),
                [](const Item& item) {
                    return item.type == ItemType::Withdraw;
                }) == 3,
            "workload must contain n withdraw items");
    require(std::count_if(
                workload.items.begin(), workload.items.end(),
                [](const Item& item) {
                    return item.type == ItemType::Relock;
                }) == 2,
            "workload must contain n-1 re-lock items");
    for (std::size_t i = 1; i < 3; ++i) {
        require(workload.items[i - 1].joint_public !=
                    workload.items[i].joint_public,
                "joint addresses must use distinct keys");
    }
    const Workload next_arc = make_paraswap_workload(
        crypto, 3, seed, 7, 7200, 0, 0, 2);
    require(
        next_arc.items[0].statement !=
                workload.items[0].statement &&
            next_arc.items[1].statement !=
                workload.items[1].statement &&
            next_arc.items[2].statement ==
                workload.items[2].statement &&
            next_arc.items[3].statement !=
                workload.items[3].statement,
        "arc-aware cyclic withdraw/re-lock statements are incorrect");
    ++report.key_separation_checks;

    Workload client_view = make_paraswap_public_workload(
        crypto, 3, digest_from_u64(crypto, 0x434c49454e54ULL),
        9, 8000, 17);
    attach_client_key_shares(
        crypto, client_view,
        crypto.derive_scalar("OASIS-TEST-CLIENT-MASTER-v1", {}));
    require(std::all_of(
                client_view.items.begin(), client_view.items.end(),
                [](const Item& item) {
                    return item.has_client_secret &&
                           !item.has_server_secret;
                }),
            "client view contains a server private share");
    ++report.key_separation_checks;
    Workload server_view = client_view;
    for (auto& item : server_view.items) {
        item.client_secret = {};
        item.has_client_secret = false;
    }
    attach_server_key_shares(
        crypto, server_view,
        crypto.derive_scalar("OASIS-TEST-SERVER-MASTER-v1", {}));
    finalize_workload(crypto, server_view);
    require(std::all_of(
                server_view.items.begin(), server_view.items.end(),
                [](const Item& item) {
                    return !item.has_client_secret &&
                           item.has_server_secret;
                }),
            "server view contains a client private share");
    ++report.key_separation_checks;
    std::vector<Point> server_publics(server_view.n);
    for (std::uint32_t address = 1;
         address <= server_view.n; ++address) {
        server_publics[address - 1] =
            server_view.items[address - 1].server_public;
    }
    attach_server_public_keys(crypto, client_view, server_publics);
    finalize_workload(crypto, client_view);
    require(client_view.context_digest ==
                server_view.context_digest &&
                client_view.batch_digest ==
                    server_view.batch_digest,
            "client/server public transcript views disagree");
    ++report.key_separation_checks;

    const auto nonce_plan =
        make_nonce_plan(crypto, workload.items.size());
    const SessionResult itemwise = execute(
        crypto, workload, Variant::B2PersistentPipelined, {}, nonce_plan);
    const SessionResult batched = execute(
        crypto, workload, Variant::B4BatchedVerification, {}, nonce_plan);
    require(itemwise.accepted && batched.accepted,
            "valid execution rejected");
    require(itemwise.client_outputs.size() ==
                batched.client_outputs.size(),
            "independent and batched outputs differ in length");
    for (std::size_t i = 0; i < workload.items.size(); ++i) {
        require(verify_presignature(
                    crypto, workload.items[i],
                    itemwise.transcripts[i].sid,
                    itemwise.transcripts[i]),
                "independent pre-signature invalid");
        require(verify_presignature(
                    crypto, workload.items[i],
                    batched.transcripts[i].sid,
                    batched.transcripts[i]),
                "batched pre-signature invalid");
    }

    const Workload ablation_workload = make_paraswap_workload(
        crypto, 8, digest_from_u64(crypto, 0x3241424c4154494fULL),
        7, 7200, 41);
    const auto ablation_nonces =
        make_nonce_plan(crypto, ablation_workload.items.size());
    const SessionResult ablation_itemwise = execute(
        crypto, ablation_workload, Variant::B2PersistentPipelined, {},
        ablation_nonces);
    const SessionResult ablation_shared_itemwise = execute(
        crypto, ablation_workload, Variant::B3BatchedItemwise, {},
        ablation_nonces);
    const SessionResult ablation_shared_batch = execute(
        crypto, ablation_workload, Variant::B4BatchedVerification, {},
        ablation_nonces);
    const SessionResult ablation_independent_batch = execute(
        crypto, ablation_workload,
        Variant::B5IndependentBatchVerification, {}, ablation_nonces);
    const SessionResult ablation_coalesced = execute(
        crypto, ablation_workload,
        Variant::B6PhaseCoalescedItemwise, {}, ablation_nonces);
    require(ablation_itemwise.accepted &&
                ablation_shared_itemwise.accepted &&
                ablation_shared_batch.accepted &&
                ablation_independent_batch.accepted &&
                ablation_coalesced.accepted &&
                ablation_itemwise.client_outputs ==
                    ablation_independent_batch.client_outputs &&
                ablation_itemwise.client_outputs ==
                    ablation_coalesced.client_outputs,
            "ablation variants changed independent-session outputs");
    report.ablation_variant_checks += 5;

    const std::uint64_t item_count = ablation_workload.items.size();
    require(ablation_itemwise.application_messages == 5 * item_count + 1,
            "persistent-pipelined message accounting excludes DONE");
    require(ablation_shared_itemwise.application_messages == 6,
            "shared item-wise message accounting must be six frames");
    require(ablation_shared_batch.application_messages == 7,
            "shared aggregate message accounting must be seven frames");
    require(ablation_independent_batch.application_messages ==
                5 * item_count + 1,
            "independent aggregate message accounting excludes DONE");
    require(ablation_coalesced.application_messages == 5 * item_count + 1,
            "phase-coalesced message accounting excludes DONE");
    report.message_accounting_checks += 5;

    const Digest independent_salt = crypto.hash(
        "OASIS-INDEPENDENT-CONFORMANCE-SALT-v1",
        {bytes(ablation_workload.batch_digest), bytes(seed)});
    require(verify_server_partials_batch_independent(
                crypto, ablation_workload,
                ablation_independent_batch.transcripts,
                independent_salt) &&
                verify_client_partials_batch_independent(
                    crypto, ablation_workload,
                    ablation_independent_batch.transcripts,
                    independent_salt) &&
                verify_presignatures_batch_independent(
                    crypto, ablation_workload,
                    ablation_independent_batch.transcripts,
                    independent_salt),
            "valid independent-session aggregate rejected");
    report.independent_batch_checks += 3;
    require(verify_presignatures_batch_independent(
                crypto, ablation_workload,
                ablation_independent_batch.transcripts,
                independent_salt),
            "replayed verifier salt changed a deterministic decision");
    ++report.verifier_salt_checks;
    auto salt_mutation = ablation_independent_batch.transcripts;
    salt_mutation[3].client_partial = crypto.scalar_add(
        salt_mutation[3].client_partial,
        crypto.derive_scalar("OASIS-INDEPENDENT-MUTATION-v1", {}));
    salt_mutation[3].presignature.scalar = crypto.scalar_add(
        salt_mutation[3].presignature.scalar,
        crypto.derive_scalar("OASIS-INDEPENDENT-MUTATION-v1", {}));
    require(!verify_client_partials_batch_independent(
                crypto, ablation_workload, salt_mutation,
                independent_salt) &&
                !verify_presignatures_batch_independent(
                    crypto, ablation_workload, salt_mutation,
                    independent_salt),
            "mutated independent transcript passed aggregate replay");
    report.independent_batch_checks += 2;
    ++report.verifier_salt_checks;

    Workload adaptation_workload = workload;
    for (std::size_t i = 0;
         i < adaptation_workload.items.size(); ++i) {
        auto& item = adaptation_workload.items[i];
        item.statement_witness = crypto.derive_scalar(
            "OASIS-ADAPTATION-TEST-WITNESS-v2",
            {bytes(seed), u32_bytes(static_cast<std::uint32_t>(i))});
        item.has_statement_witness = true;
        item.statement = crypto.base_mul(item.statement_witness);
    }
    finalize_workload(crypto, adaptation_workload);
    const SessionResult adaptation = execute(
        crypto, adaptation_workload,
        Variant::B4BatchedVerification);
    require(adaptation.accepted,
            "adaptation test execution rejected");
    for (std::size_t i = 0;
         i < adaptation_workload.items.size(); ++i) {
        const auto& item = adaptation_workload.items[i];
        const auto& transcript = adaptation.transcripts[i];
        const Scalar signature = adapt(
            crypto, adaptation.client_outputs[i],
            item.statement_witness);
        const auto extracted = extract(
            crypto, item, transcript.sid, transcript, signature);
        require(extracted.has_value() &&
                    *extracted == item.statement_witness,
                "adaptor witness extraction failed");
        const Point signature_left = crypto.base_mul(signature);
        const Point signature_right = crypto.point_add(
            adaptation.client_outputs[i].adaptor_nonce,
            crypto.point_mul(
                item.joint_public, transcript.challenge));
        require(signature_left == signature_right,
                "adapted Schnorr signature invalid");
        ++report.adaptation_checks;
    }

    // Every security-relevant field is validated against its canonical digest.
    auto mutation_must_fail = [&](const std::function<void(Workload&)>& mutate) {
        Workload changed = workload;
        mutate(changed);
        require_throws(
            [&] {
                (void)execute(crypto, changed,
                              Variant::B4BatchedVerification);
            },
            "transcript mutation was accepted");
        ++report.mutation_checks;
    };
    mutation_must_fail([](Workload& value) {
        value.items[0].message[0] ^= 1;
    });
    mutation_must_fail([](Workload& value) {
        value.items[0].type = ItemType::Relock;
    });
    mutation_must_fail([](Workload& value) {
        value.items[0].ordinal += 1;
    });
    mutation_must_fail([](Workload& value) {
        value.items[0].timeout += 1;
    });
    mutation_must_fail([](Workload& value) {
        value.items[0].address_index += 1;
    });
    mutation_must_fail([](Workload& value) {
        value.items[0].statement[5] ^= 1;
    });
    mutation_must_fail([](Workload& value) {
        value.items[0].server_public[7] ^= 1;
    });
    mutation_must_fail([](Workload& value) {
        value.items[0].client_public[8] ^= 1;
    });
    mutation_must_fail([](Workload& value) {
        value.items[0].joint_public[9] ^= 1;
    });
    mutation_must_fail([](Workload& value) {
        value.batch_digest[0] ^= 1;
    });
    mutation_must_fail([](Workload& value) {
        std::swap(value.items[0], value.items[1]);
    });
    mutation_must_fail([](Workload& value) {
        value.key_epoch += 1;
    });
    mutation_must_fail([](Workload& value) {
        value.expiry += 1;
    });
    mutation_must_fail([](Workload& value) {
        value.pair_id += 1;
    });
    mutation_must_fail([](Workload& value) {
        value.execution_id += 1;
    });
    mutation_must_fail([](Workload& value) {
        value.arc_index =
            value.arc_index == value.n ? 1 : value.arc_index + 1;
    });
    mutation_must_fail([](Workload& value) {
        value.seed[0] ^= 1;
    });

    const auto& reference_item = workload.items.front();
    const auto& reference = batched.transcripts.front();
    const Scalar opening_message = commitment_message(
        crypto, reference.sid, reference_item,
        reference.server_nonce_point);
    require(crypto.pedersen_verify(
                reference.commitment, opening_message,
                reference.commitment_blind),
            "valid commitment opening rejected");
    ItemTranscript changed = reference;
    changed.commitment = workload.items[1].joint_public;
    require(!crypto.pedersen_verify(
                changed.commitment, opening_message,
                changed.commitment_blind),
            "mutated commitment accepted");
    ++report.mutation_checks;
    changed = reference;
    changed.commitment_blind = crypto.scalar_add(
        changed.commitment_blind,
        crypto.derive_scalar("OASIS-OPENING-MUTATION-v1", {}));
    require(!crypto.pedersen_verify(
                changed.commitment, opening_message,
                changed.commitment_blind),
            "mutated commitment opening accepted");
    ++report.mutation_checks;
    changed = reference;
    changed.sid[0] ^= 1;
    require(!verify_presignature(
                crypto, reference_item, changed.sid, changed),
            "mutated session ID accepted");
    ++report.mutation_checks;
    changed = reference;
    changed.challenge = crypto.scalar_add(
        changed.challenge,
        crypto.derive_scalar("OASIS-CHALLENGE-MUTATION-v1", {}));
    require(!verify_presignature(
                crypto, reference_item, reference.sid, changed),
            "mutated challenge accepted");
    ++report.mutation_checks;
    changed = reference;
    changed.presignature.adaptor_nonce =
        workload.items[1].statement;
    require(!verify_presignature(
                crypto, reference_item, reference.sid, changed),
            "mutated adaptor nonce accepted");
    ++report.mutation_checks;
    changed = reference;
    changed.presignature.scalar = crypto.scalar_add(
        changed.presignature.scalar,
        crypto.derive_scalar("OASIS-SCALAR-MUTATION-v1", {}));
    require(!verify_presignature(
                crypto, reference_item, reference.sid, changed),
            "mutated pre-signature scalar accepted");
    ++report.mutation_checks;
    changed = reference;
    changed.server_nonce_point =
        workload.items[1].statement;
    require(!verify_server_partial(
                crypto, reference_item, changed),
            "mutated server nonce accepted");
    ++report.mutation_checks;
    changed = reference;
    changed.client_nonce_point =
        workload.items[1].statement;
    require(!verify_client_partial(
                crypto, reference_item, changed),
            "mutated client nonce accepted");
    ++report.mutation_checks;
    changed = reference;
    changed.server_partial = crypto.scalar_add(
        changed.server_partial,
        crypto.derive_scalar("OASIS-PARTIAL-MUTATION-v1", {}));
    require(!verify_server_partial(
                crypto, reference_item, changed),
            "mutated server partial accepted");
    ++report.mutation_checks;
    auto reordered_transcripts = batched.transcripts;
    std::swap(reordered_transcripts[0], reordered_transcripts[1]);
    const Digest reorder_salt = crypto.hash(
        "OASIS-REORDER-SALT-v1", {bytes(reference.sid)});
    require(!verify_server_partials_batch(
                crypto, workload, reference.sid,
                reordered_transcripts, reorder_salt),
            "reordered transcript vector accepted");
    ++report.mutation_checks;

    const SessionResult retried = execute(
        crypto, workload, Variant::B4BatchedVerification,
        FaultPlan{{1}, {3}}, nonce_plan);
    require(retried.accepted &&
                retried.retried_indices == std::vector<std::size_t>({1, 3}),
            "selective retry did not isolate both faults");
    require(retried.opening_failures ==
                    std::vector<std::size_t>({1}) &&
                retried.schnorr_failures ==
                    std::vector<std::size_t>({3}),
            "opening and Schnorr failures were not attributed separately");
    require(retried.transcripts[1].sid != batched.transcripts[1].sid &&
                retried.transcripts[1].client_nonce_point !=
                    batched.transcripts[1].client_nonce_point &&
                retried.transcripts[1].server_nonce_point !=
                    batched.transcripts[1].server_nonce_point,
            "retry reused a session identifier or nonce");
    report.retry_checks += 3;

    ReplayCache replay;
    const Digest replay_sid = batched.transcripts.front().sid;
    const Bytes first_response{9, 8, 7};
    require(replay.process(replay_sid, 1, Bytes{1}, first_response) ==
                first_response,
            "first replay-cache response mismatch");
    require(replay.process(replay_sid, 1, Bytes{1}, Bytes{0}) ==
                first_response,
            "exact duplicate did not return cached response");
    report.replay_checks += 2;
    require_throws(
        [&] {
            replay.process(replay_sid, 1, Bytes{2}, Bytes{0});
        },
        "conflicting duplicate was accepted");
    ++report.replay_checks;
    require_throws(
        [&] {
            replay.process(replay_sid, 3, Bytes{3}, Bytes{0});
        },
        "out-of-order phase was accepted");
    ++report.replay_checks;
    replay.process(replay_sid, 2, Bytes{2}, Bytes{6});
    ++report.replay_checks;

    // Differential oracle over every paper-relevant multi-key size.
    struct DifferentialFixture {
        Workload workload;
        SessionResult execution;
    };
    std::vector<DifferentialFixture> fixtures;
    for (std::uint32_t n : {3U, 5U, 8U, 16U}) {
        Workload candidate = make_paraswap_workload(
            crypto, n, digest_from_u64(crypto, 991 + n),
            11, 9000, n);
        SessionResult execution = execute(
            crypto, candidate, Variant::B4BatchedVerification);
        require(execution.accepted,
                "differential fixture execution rejected");
        fixtures.push_back(
            {std::move(candidate), std::move(execution)});
    }
    const std::uint64_t vector_end =
        vector_offset + differential_vectors;
    require(vector_end >= vector_offset,
            "differential vector range overflow");
    for (std::uint64_t vector = vector_offset;
         vector < vector_end; ++vector) {
        const auto& fixture =
            fixtures.at(vector % fixtures.size());
        const auto& differential_workload = fixture.workload;
        const Digest sid = fixture.execution.transcripts.front().sid;
        auto transcripts = fixture.execution.transcripts;
        const bool should_be_valid = (vector & 1U) == 0;
        const std::size_t fault_index =
            static_cast<std::size_t>(
                (vector * 0x9e3779b97f4a7c15ULL) %
                transcripts.size());
        if (!should_be_valid) {
            transcripts[fault_index].server_partial = crypto.scalar_add(
                transcripts[fault_index].server_partial,
                crypto.derive_scalar(
                    "OASIS-DIFFERENTIAL-FAULT-v1",
                    {u64_bytes(vector),
                     u32_bytes(static_cast<std::uint32_t>(
                         fault_index))}));
        }
        const Digest salt = crypto.hash(
            "OASIS-DIFFERENTIAL-SALT-v1",
            {bytes(sid), u64_bytes(vector)});
        bool individual = true;
        for (std::size_t i = 0; i < transcripts.size(); ++i) {
            individual =
                individual &&
                verify_server_partial(
                    crypto, differential_workload.items[i],
                    transcripts[i]);
        }
        const bool batch = verify_server_partials_batch(
            crypto, differential_workload, sid, transcripts, salt);
        if (individual != batch ||
            individual != should_be_valid) {
            throw std::runtime_error(
                "batch verifier mismatch at vector=" +
                std::to_string(vector) + " n=" +
                std::to_string(differential_workload.n) +
                " fault_index=" +
                std::to_string(fault_index));
        }

        auto client_transcripts = fixture.execution.transcripts;
        if (!should_be_valid) {
            client_transcripts[fault_index].client_partial =
                crypto.scalar_add(
                    client_transcripts[fault_index].client_partial,
                    crypto.derive_scalar(
                        "OASIS-DIFFERENTIAL-CLIENT-FAULT-v1",
                        {u64_bytes(vector),
                         u32_bytes(static_cast<std::uint32_t>(
                             fault_index))}));
        }
        bool individual_client = true;
        for (std::size_t i = 0;
             i < client_transcripts.size(); ++i) {
            individual_client =
                individual_client &&
                verify_client_partial(
                    crypto, differential_workload.items[i],
                    client_transcripts[i]);
        }
        const Digest client_salt = crypto.hash(
            "OASIS-DIFFERENTIAL-CLIENT-SALT-v1",
            {bytes(sid), u64_bytes(vector)});
        const bool batch_client = verify_client_partials_batch(
            crypto, differential_workload, sid,
            client_transcripts, client_salt);
        if (individual_client != batch_client ||
            individual_client != should_be_valid) {
            throw std::runtime_error(
                "client batch verifier mismatch at vector=" +
                std::to_string(vector) + " n=" +
                std::to_string(differential_workload.n) +
                " fault_index=" + std::to_string(fault_index));
        }

        auto final_transcripts = fixture.execution.transcripts;
        if (!should_be_valid) {
            final_transcripts[fault_index].presignature.scalar =
                crypto.scalar_add(
                    final_transcripts[fault_index]
                        .presignature.scalar,
                    crypto.derive_scalar(
                        "OASIS-DIFFERENTIAL-FINAL-FAULT-v1",
                        {u64_bytes(vector),
                         u32_bytes(static_cast<std::uint32_t>(
                             fault_index))}));
        }
        bool individual_final = true;
        for (std::size_t i = 0;
             i < final_transcripts.size(); ++i) {
            individual_final =
                individual_final &&
                verify_presignature(
                    crypto, differential_workload.items[i], sid,
                    final_transcripts[i]);
        }
        const Digest final_salt = crypto.hash(
            "OASIS-DIFFERENTIAL-FINAL-SALT-v1",
            {bytes(sid), u64_bytes(vector)});
        const bool batch_final = verify_presignatures_batch(
            crypto, differential_workload, sid,
            final_transcripts, final_salt);
        if (individual_final != batch_final ||
            individual_final != should_be_valid) {
            throw std::runtime_error(
                "final batch verifier mismatch at vector=" +
                std::to_string(vector) + " n=" +
                std::to_string(differential_workload.n) +
                " fault_index=" + std::to_string(fault_index));
        }
        ++report.differential_vectors;
    }
    return report;
}

std::string variant_name(Variant variant) {
    switch (variant) {
        case Variant::B0FreshSequential:
            return "B0_fresh_sequential";
        case Variant::B1PersistentSequential:
            return "B1_persistent_sequential";
        case Variant::B2PersistentPipelined:
            return "B2_persistent_pipelined";
        case Variant::B3BatchedItemwise:
            return "B3_batched_itemwise";
        case Variant::B4BatchedVerification:
            return "B4_batched_verification";
        case Variant::B5IndependentBatchVerification:
            return "B5_independent_batch_verification";
        case Variant::B6PhaseCoalescedItemwise:
            return "B6_phase_coalesced_itemwise";
    }
    throw std::runtime_error("unknown variant");
}

Variant parse_variant(const std::string& name) {
    if (name == "B0" || name == "B0_fresh_sequential") {
        return Variant::B0FreshSequential;
    }
    if (name == "B1" || name == "B1_persistent_sequential") {
        return Variant::B1PersistentSequential;
    }
    if (name == "B2" || name == "B2_persistent_pipelined") {
        return Variant::B2PersistentPipelined;
    }
    if (name == "B3" || name == "B3_batched_itemwise") {
        return Variant::B3BatchedItemwise;
    }
    if (name == "B4" || name == "B4_batched_verification") {
        return Variant::B4BatchedVerification;
    }
    if (name == "B5" ||
        name == "B5_independent_batch_verification") {
        return Variant::B5IndependentBatchVerification;
    }
    if (name == "B6" || name == "B6_phase_coalesced_itemwise") {
        return Variant::B6PhaseCoalescedItemwise;
    }
    throw std::runtime_error("unknown variant: " + name);
}

Bytes bytes(const Digest& value) {
    return array_bytes(value);
}

Bytes bytes(const Point& value) {
    return array_bytes(value);
}

std::string hex(const Digest& value) {
    return array_hex(value);
}

std::string hex(const Point& value) {
    return array_hex(value);
}

Digest digest_from_u64(const Crypto& crypto, std::uint64_t value) {
    return crypto.hash("OASIS-SEED-v1", {u64_bytes(value)});
}

}  // namespace oasis
