#!/usr/bin/env python3
"""Cross-check native transcript and adaptor output without project helpers."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


FIELD_PRIME = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
GROUP_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GENERATOR = (
    55066263022277343669578718895168534326250603453777594175500187360389116729240,
    32670510020758816978083085130507043184471273380659243275938904335757337482424,
)
MONTGOMERY_FACTOR = pow(2, 256, FIELD_PRIME)


@dataclass(frozen=True)
class Point:
    x: int
    y: int


def inverse(value: int) -> int:
    return pow(value, FIELD_PRIME - 2, FIELD_PRIME)


def add(left: Point | None, right: Point | None) -> Point | None:
    if left is None:
        return right
    if right is None:
        return left
    if left.x == right.x and (left.y + right.y) % FIELD_PRIME == 0:
        return None
    if left == right:
        slope = (3 * left.x * left.x * inverse(2 * left.y)) % FIELD_PRIME
    else:
        slope = ((right.y - left.y) * inverse((right.x - left.x) % FIELD_PRIME)) % FIELD_PRIME
    x = (slope * slope - left.x - right.x) % FIELD_PRIME
    return Point(x, (slope * (left.x - x) - left.y) % FIELD_PRIME)


def multiply(point: Point | None, scalar: int) -> Point | None:
    result = None
    current = point
    while scalar:
        if scalar & 1:
            result = add(result, current)
        current = add(current, current)
        scalar >>= 1
    return result


def decode_compressed(value: str | bytes) -> Point:
    encoded = bytes.fromhex(value) if isinstance(value, str) else value
    if len(encoded) != 33 or encoded[0] not in (2, 3):
        raise ValueError("invalid compressed point")
    x = int.from_bytes(encoded[1:], "big")
    if x >= FIELD_PRIME:
        raise ValueError("point x is out of range")
    y = pow((x * x * x + 7) % FIELD_PRIME, (FIELD_PRIME + 1) // 4, FIELD_PRIME)
    if (y * y - (x * x * x + 7)) % FIELD_PRIME:
        raise ValueError("point is not on secp256k1")
    # RELIC's ep_write_bin emits the low bit of the Montgomery field
    # representation (y * R mod p), rather than the parity of the ordinary
    # integer representative used by SEC1 decoders.
    if (((y * MONTGOMERY_FACTOR) % FIELD_PRIME) & 1) != (encoded[0] & 1):
        y = FIELD_PRIME - y
    point = Point(x, y)
    if multiply(point, GROUP_ORDER) is not None:
        raise ValueError("point is not in the prime-order subgroup")
    return point


def encode_compressed(point: Point) -> bytes:
    """Encode the pinned RELIC compressed-point convention independently."""
    if point is None or point.y * point.y % FIELD_PRIME != (
        point.x * point.x * point.x + 7
    ) % FIELD_PRIME:
        raise ValueError("invalid point")
    prefix = 2 | (((point.y * MONTGOMERY_FACTOR) % FIELD_PRIME) & 1)
    return bytes((prefix,)) + point.x.to_bytes(32, "big")


def field(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def canonical(domain: bytes, *values: bytes) -> bytes:
    return hashlib.sha256(field(domain) + b"".join(field(value) for value in values)).digest()


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def parse_rows(output: str, prefix: str) -> list[dict[str, str]]:
    rows = []
    for line in output.splitlines():
        if not line.startswith(prefix + "\t"):
            continue
        rows.append(dict(field.split("=", 1) for field in line.split("\t")[1:]))
    return rows


def verify_signature_row(row: dict[str, str], ordinal: int) -> None:
    message = bytes.fromhex(row["message"])
    statement = decode_compressed(row["statement"])
    joint_key = decode_compressed(row["joint_key"])
    challenge = int.from_bytes(bytes.fromhex(row["e"]), "big")
    scalar = int.from_bytes(bytes.fromhex(row["s"]), "big")
    for point in (statement, joint_key):
        if decode_compressed(encode_compressed(point)) != point:
            raise AssertionError(f"point encoding round trip failed at ordinal {ordinal}")
    reconstructed = add(
        add(multiply(Point(*GENERATOR), scalar), multiply(joint_key, challenge)),
        statement,
    )
    if reconstructed is None:
        raise AssertionError("reconstructed adaptor nonce is infinity")
    expected = int.from_bytes(
        hashlib.sha256(
            message + (reconstructed.x % GROUP_ORDER).to_bytes(32, "big")
        ).digest(),
        "big",
    ) % GROUP_ORDER
    if challenge != expected:
        raise AssertionError(f"independent adaptor verification failed at ordinal {ordinal}")


def verify(output: str) -> None:
    kat = parse_rows(output, "JOINT_TRANSCRIPT_KAT")
    items = parse_rows(output, "JOINT_TRANSCRIPT_ITEM")
    signatures = parse_rows(output, "JOINT_SIGNATURE")
    if len(kat) != 1 or len(items) != 7 or len(signatures) != 7:
        raise AssertionError("native KAT diagnostics are incomplete")

    seed = bytes(range(1, 33))
    context = canonical(
        b"OASIS-CONTEXT-v1", b"ParaSwap", u32(4), u64(9), u64(7200),
        u64(3), u64(19), u64(4), seed,
    )
    item_digests = []
    for ordinal, row in enumerate(items):
        message = canonical(
            b"OASIS-BENCH-MESSAGE-v2", seed, u64(3), u32(ordinal),
            bytes((1 if ordinal < 4 else 2,)),
        )
        expected_item = canonical(
            b"OASIS-ITEM-v1", context,
            b"Withdraw" if ordinal < 4 else b"Re-lock", u32(ordinal),
            u32(ordinal if ordinal < 4 else ordinal - 4), u64(7200), message,
            bytes.fromhex(row["statement"]), bytes.fromhex(row["client_key"]),
            bytes.fromhex(row["server_key"]), bytes.fromhex(row["joint_key"]),
        )
        if bytes.fromhex(row["message"]) != message:
            raise AssertionError(f"message digest mismatch at ordinal {ordinal}")
        if bytes.fromhex(row["item"]) != expected_item:
            raise AssertionError(f"item digest mismatch at ordinal {ordinal}")
        item_digests.append(expected_item)

    batch = canonical(b"OASIS-ORDERED-BATCH-v1", context, u32(7), *item_digests)
    parent = canonical(b"OASIS-SESSION-ID-v1", context, batch, u32(0), b"", b"")
    if bytes.fromhex(kat[0]["context"]) != context:
        raise AssertionError("context digest mismatch")
    if bytes.fromhex(kat[0]["batch"]) != batch:
        raise AssertionError("ordered batch digest mismatch")
    if bytes.fromhex(kat[0]["parent_sid"]) != parent:
        raise AssertionError("parent SID mismatch")

    for ordinal, row in enumerate(signatures):
        if int(row["ordinal"]) != ordinal:
            raise AssertionError("non-canonical signature ordinal")
        verify_signature_row(row, ordinal)

    mutated = dict(signatures[0])
    scalar = bytearray.fromhex(mutated["s"])
    scalar[-1] ^= 1
    mutated["s"] = bytes(scalar).hex()
    try:
        verify_signature_row(mutated, 0)
    except AssertionError:
        return
    raise AssertionError("independent oracle accepted a mutated pre-signature")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    binary = root / "vendor/paraswap/two-party computation/bin/joint_presign_test"
    if not binary.is_file():
        raise SystemExit(f"missing native test binary: {binary}")
    environment = dict(os.environ)
    environment["OASIS_KAT_DIAGNOSTIC"] = "1"
    result = subprocess.run([str(binary)], cwd=root, env=environment,
                            check=True, capture_output=True, text=True)
    verify(result.stdout)
    print("INDEPENDENT_ORACLE\ttranscript=pass\tadaptor=pass\tmutation=reject")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, ValueError) as error:
        print(f"independent oracle failed: {error}", file=sys.stderr)
        raise SystemExit(1)
