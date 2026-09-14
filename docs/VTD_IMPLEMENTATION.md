# Native VTD implementation boundary

The ParaSwap reference [43] is *Verifiable Timed Signatures Made Practical*.
Its Appendix E, Figure 16 specifies commitments to discrete logarithms;
Section 4.5, Figure 5 specifies the accompanying puzzle range proof.
Source: https://verifiable-timed-signatures.github.io/web/assets/paper.pdf

## Implemented foundation

The underlying LHTLP specification is Section 4.1 of
https://eprint.iacr.org/2019/635.pdf. Its setup samples distinct safe primes,
sets g=-a^2 mod N for a unit a, and h=g^(2^T) mod N. Puzzle exponents are
uniform in [1,N^2]; commitment sampling and opening/prover checks use that
exact interval. Range-mask exponents and summed responses are different
objects and need not use the original puzzle interval. The low-level puzzle
algebra intentionally supports exponent zero for homomorphic operations,
but zero is not accepted for an opened original puzzle. The reference C
setup's inverse-square operation is not the specified negative-square
operation; it must not be copied as if those operations were interchangeable.

`vtd_sharing.c` implements field-polynomial sharing, Lagrange coefficients at
zero, and scalar reconstruction using the native curve order. Shares have
distinct nonzero indices. A degree threshold-minus-one polynomial implements
the interpolation relation in Appendix E without the PDF's ambiguous sum
index. Zero-valued shares are valid field elements and are not rejected.

The local `vtd_sharing_test` checks an independent polynomial known answer,
all 56 threshold-five subsets of eight shares over 16 random polynomials,
the corresponding public-point interpolation, altered-share detection against
the original public point, duplicate/zero/out-of-range indices, noncanonical
scalars, and invalid thresholds. Reconstruction alone cannot detect a bad
share: the resulting point must be compared with the expected public key.

These are primitive correctness tests, not full VTD soundness evidence. The
test's eight shares and threshold five are small test parameters, not the
statistical security parameters of a deployment.

`vtd_puzzle.c` supplies explicit-exponent generation and sequential-squaring
recovery over GMP. It accepts centered plaintexts, preserves exponent addition,
validates unit elements, and rejects nonintegral plaintext decoding. Outputs
are committed only on success; callers must check the return code. Setup is
still a trusted input and callers must bound untrusted iteration counts.
The native puzzle test passed 61 centered-message cases, homomorphic
combinations and malformed inputs. Its tiny public modulus is only an algebra
fixture, not a secure time-delay setup or performance measurement.

`vtd_random_below` samples integers with Linux `getrandom` and rejection
sampling, not C `rand()` or biased modular reduction. It handles interrupted
and short reads, limits allocation/attempts, clears its byte buffer and leaves
the output unchanged on failure. Tests exercise positive bounds through 16384
bits, bound one, and invalid bounds. These tests check functional boundaries,
not the operating system entropy source's security. GMP allocations are not
claimed to provide secure erasure or locked memory.

## Required next integration

`vtd_proof_encode/decode` provide a bounded public-proof wire format. The
header is ASCII `OASISV01`, uint32 BE share count and uint32 BE row count.
Each share contains its fixed 33-byte point encoding and unsigned puzzle u,v.
Each range row contains unsigned commitment u,v, a signed plaintext response
and an unsigned exponent response. Finally come the opened scalar/exponent
pairs in recomputed subset order. Integers use uint32 BE minimal byte lengths;
signed values add a preceding 0/1 sign byte. Leading-zero magnitudes and
negative zero are rejected. No additional bytes may follow the proof.

The decoder checks caller-selected dimensions and clears initialized output
arrays on malformed input; maximum encoded size is 8 MiB, each integer at
most 4096 bytes. Parsing does not authenticate setup, context or sender and
does not verify proof equations: the receiver must invoke the verifier with
its expected context/key/setup before using it. Round-trip byte equality,
verification and ForceOp after decoding passed, and truncated/extended proofs,
invalid point prefixes and modified counts were rejected. No proof was saved
to disk; tests use memory buffers.

The fresh-setup `vtd_integration_test` passed with a 2048-bit modulus,
256 shares, 128 range rows and 32 squarings: commit, independent verification,
and ForceOp recovered the original scalar; wrong-context verification failed.
Core dumps are disabled. Run `make native-vtd-integration-test` to repeat it.
This uses a single process for the correctness test, not an isolated trusted
setup ceremony. The short delay is not a timed-privacy experiment and a
2048-bit modulus is not a 128-bit-security claim. Host integration and cloud
measurements are still pending.

`vtd_setup_generate` creates distinct safe-prime factors with OS-random
candidates and GMP probable-prime tests (64 repetitions), then samples the
specified negative square and excludes small-order bases using the factors.
It computes h using the known group order during setup. Only (N,g,h) are
returned; no factors are exported. Even modulus sizes from 2048 to 4096 bits
are accepted, with a caller-bounded candidate budget and positive squaring
count. Failed generation leaves output unchanged. This is a single-party
trusted setup, not a distributed ceremony or proof of correct erasure.
Use a dedicated short-lived process with core dumps disabled in integration.
No claim of production-secure secret memory follows from GMP cleanup.

`make native-vtd-setup-test` runs fresh 2048-bit generation, independently
checks the delay relation by squaring, and performs puzzle generation/solve.
It is kept outside the short smoke suite because safe-prime generation time
varies. The test's delay is only 16 squarings and is never a usable security
deadline. A 2048-bit modulus is not a claim of 128-bit factoring security.

`vtd_commit` packages in-memory generation: it validates the secret/key
relation, samples field shares and OS-random puzzle exponents, constructs the
range proof, derives the opening subset, and verifies the finished proof
before success. Only opened shares are returned; temporary unopened values
and exponents are released, not serialized or logged. The caller allocates
initialized arrays via `vtd_proof_output`; `vtd_commit_view` exposes a read-only
view to verification/recovery. Tests pass for the complete in-memory
commit/verify/ForceOp round trip and reject secret/key mismatch with cleared
outputs. GMP secure erasure is not guaranteed. Trusted setup, safe deployment
parameters, serialization and host integration are still outstanding.

`vtd_force_open` now revalidates the proof, recomputes the opened subset and
solves unopened puzzles sequentially until a valid additional share permits
reconstruction. The caller supplies a total squaring budget. Every recovered
plaintext is centered modulo N, checked against L, then reduced modulo the
curve order and checked against its public share point. The reconstructed
secret must match the expected key before output. Failed calls leave output
unchanged. The native integration test recovers its original scalar with 12
sequential squarings, rejects an insufficient budget with zero work, and
rejects an altered proof before any puzzle work. These tiny-delay known-factor
tests do not establish timed privacy. Recovery is currently serial across
attempts, not a parallel solver benchmark or a calibrated wall-clock timeout.

`vtd_verify_relations` composes the checks using an in-memory proof view:
it encodes validated points itself, verifies the range proof, recomputes its
challenge and the opening subset, then verifies the openings and all unopened
point interpolations. No prover-supplied subset or point encoding is trusted.
The caller's expected share count must match the proof. Identity shares use
33 zero bytes; finite points use the pinned RELIC compressed secp256k1 encoding.
The key itself
must not be the identity. Integrated tests pass with an eight-share proof and
reject altered openings, altered range responses and a share-count policy
mismatch. Trusted setup, complete commitment generation/recovery, serialization
and host lifecycle integration remain required. This gate is not full VTD.

### Opening-subset derivation

`vtd_opening_challenge` binds the expected public key and ordered public-share
encodings (33 bytes each), all recomputed range-challenge bits, and every
range response. Its tag is `OASIS-VTD-OPENING-v1`, followed by uint32 BE share
and row counts, point encodings, row-major bits as bytes 0/1, and responses.
Each plaintext response has a sign byte (0 nonnegative, 1 negative) then an
unsigned length-prefixed magnitude; exponent responses use unsigned encoding.
SHA-256 hashes that string. Draw blocks hash `OASIS-VTD-OPENING-DRAW-v1`, the
digest and a uint32 BE counter. Tags omit NUL. Consecutive uint16 BE draws feed
a partial Fisher-Yates shuffle with rejection above the largest multiple of
the remaining count below or equal to 65536. Output is the sorted half-size
subset of 1-based indices. Counts must be even and at most 256.

This is an internal helper: the VTD verifier must validate the points and
recompute range bits itself, not accept these bindings from the prover. Zero
point bytes in the encoding KAT are not valid production public keys. An
independent Python KAT gives digest
`f968640d35b3b2490bdc0742afdd43caeae68ea95daf82a382cafecb01a8133e`
and subset [1,2,6,7] for the test's eight-share zero encoding. Tests pass for
that KAT and changes to points, range bits and signed/unsigned responses.
These checks still need composition into the complete VTD verifier before
the resulting commitment can authorize host lifecycle actions.

`vtd_verify_openings` verifies that each opened canonical scalar generates its
public share point and regenerates exactly its puzzle with the supplied
exponent in [1,N^2]. It checks every unopened point by interpolating it with
the opened half-subset back to the expected public key. Indices must be the
recomputed sorted challenge subset, not prover-selected input. Zero shares
remain valid; the expected public key cannot be the identity. Tests pass for
honest shares and reject changed opened values, altered opened puzzles,
altered unopened points and duplicate indices. The known-factor modulus and
eight-share fixture provide correctness evidence only, not VTD security.

### Range transcript encoding

`vtd_range_challenge` derives challenge bits from SHA-256 using RELIC. The
hashed byte string is the ASCII tag `OASIS-VTD-RANGE-v1` (without NUL), the
32-byte host context, squaring count as uint64 big-endian, puzzle count and
proof-row count as uint32 big-endian, then N, g, h, L, ordered puzzle (u,v)
pairs, and ordered row-commitment (u,v) pairs. Each integer is unsigned minimal
big-endian with a uint32 byte-length prefix; zero has length zero. Negative or
over-4096-byte integers are rejected. Counts are bounded to 1..256.

Challenge expansion hashes `OASIS-VTD-RANGE-BITS-v1` (without NUL), the
32-byte transcript digest, and a uint32 big-endian block counter starting at
zero. Bits are consumed most-significant-bit first, in row-major order.
No proof response is part of this pre-response challenge transcript.
The host context must bind the expected VTD statement and session; callers
must not accept an arbitrary context supplied only by the prover.

The native test passes a 256-bit independent Python hashlib known answer and
mutations of context, squaring count, parameters, puzzle ordering and both
ends of the commitment vector. Encoding success does not validate setup or
proof semantics. VTD cut-and-choose integration remains outstanding.

`vtd_range_verify` recomputes the challenge internally and checks every row.
It requires 128..256 rows, bounds response sizes, and has no external challenge
argument. The expected setup/context/range policy is still the caller's
responsibility. A deterministic tiny-modulus algebra fixture passes; modifying
each of its 128 response rows separately, changing context/commitments, or
requesting fewer than 128 rows is rejected. This is not a secure prover fixture
and does not demonstrate zero knowledge or VTD public-key linkage.

`vtd_range_prove` now checks every witness/puzzle pair before generating the
commitments, derives the challenge, forms all responses and invokes the
verifier before success. It accepts original puzzle exponents in [1,N^2],
requires L >= count*B*2^144 and 2L<N, and samples message masks uniformly from
[-floor(L/4),floor(L/4)]. Exponent masks are sampled from
[0,count*N^2*2^144); responses are integer sums, never reduced modulo N.
This explicit wide-integer sampling implements bounded shift hiding rather
than assuming that the publicly known N is the unknown group order. Its
composition/privacy argument must be audited with the complete VTD setup.
For <=256 rows the elementary interval-shift bounds have ample slack below
2^-128; this observation is not a proof of the complete construction.
The output arrays are cleared on failure after pointer/count validation.
Caller-owned initialized arrays must not alias inputs or each other.

The prover/verifier test uses a known-factor 234-bit public composite with
real OS randomness to exercise these paths, rejects a mismatched witness,
checks cleared failed outputs, and rejects insufficient mask width. It is
still an insecure algebra fixture, NOT a timed-privacy or cloud benchmark.

The Figure-5 row equation is implemented by `vtd_range_check_row`. It checks
`2L < N`, response magnitude at most `L/2`, bit challenges, unit elements
(including unselected puzzles), and equality with the explicitly generated
response puzzle. Its challenge is an internal caller input, NOT a proof field
that an adversary may choose. This helper alone is not a NIZK verifier.
Tests cover all four challenges for two puzzles, modified responses, both
range boundaries beyond the allowed interval, an invalid unselected puzzle,
a non-bit challenge and invalid modulus/range separation.

1. Integrate puzzle functions with validated trusted setup, secure exponent
   sampling and canonical parameter serialization.
2. Implement the Figure 5 range proof with canonical Fiat-Shamir inputs and
   justified bounds B, L and the statistical challenge size.
3. Bind the cut-and-choose challenge to the public key, share points, puzzles,
   proof, and setup parameters. Verify opened shares and interpolate each
   unopened point against the public key, as specified in Figure 16.
4. Verify recovered secrets against their public keys before permitting any
   Re-lock or Refund state transition. Never report a simulated timer as
   cryptographic ForceOp work.

The official puzzle source was inspected at commit
`ee6c893bc932012bdaa80f199c99722ce7a0399c` of
https://github.com/verifiable-timed-signatures/liblhtlp (GPL-3.0).
It is research reference material in `.deps`, not a linked dependency or a
newly vendored release component. Its seeded PGen API expands a seed through
a PRNG: adding those seeds does not implement addition of puzzle exponents.
Figure 5's response uses addition of the actual random exponents. Its default
PGen also seeds from C `rand()`, so it must not be silently promoted to a secure
deployment RNG. The original upstream files remain unchanged.

No claim of complete VTD, distributed witness delivery, or complete lifecycle
is established by this module. No secret is written to a test report.
