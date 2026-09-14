#!/usr/bin/env python3
"""Validate the secondary C++/OpenSSL conformance-transport results.

The primary native C11/RELIC cloud schema is validated by
``analyze_cloud_results.py``; it performs native MSM at every measured batch size.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path


REQUIRED_VARIANTS = {
    "persistent-pipelined-itemwise",
    "batch-joint-presigning-itemwise",
    "batch-joint-presigning-batch-verification",
    "phase-coalesced-batch-verification",
    "phase-coalesced-itemwise",
}


def fail(path: Path, message: str) -> None:
    raise SystemExit(f"error: {path}: {message}")


def validate(
    path: Path,
    allow_failures: bool,
    required_variants: set[str],
) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") != "oasis-conformance-transport-v1":
        fail(path, "expected oasis-conformance-transport-v1")
    samples = payload.get("samples")
    if not isinstance(samples, list) or not samples:
        fail(path, "missing samples")

    grouped: dict[tuple[object, ...], dict[str, dict]] = defaultdict(dict)
    failures = 0
    for sample in samples:
        variant = sample.get("variant")
        if variant not in required_variants:
            fail(path, f"unexpected variant {variant!r}")
        if sample.get("tls") is not True:
            fail(path, "non-TLS sample")
        if not str(sample.get("tls_cipher", "")).startswith("TLS_"):
            fail(path, "missing negotiated TLS cipher")
        n = int(sample["n"])
        k = int(sample["k"])
        if k != 2 * n - 1:
            fail(path, f"invalid workload n={n}, k={k}")
        failures += int(sample.get("failures", 0))
        if k >= 8 and variant in {
            "batch-joint-presigning-batch-verification",
            "phase-coalesced-batch-verification",
        }:
            audits = sample.get("verifier_audit", [])
            opening_rejected_before_verification = (
                int(sample.get("fault_count", 0)) > 0
                and sample.get("fault_scope") == "responder-opening"
            )
            if not audits and not opening_rejected_before_verification:
                fail(path, f"{variant} has no verifier audit at k={k}")
            for audit in audits:
                if len(str(audit.get("salt", ""))) != 64:
                    fail(path, "non-canonical verifier salt")
                if len(str(audit.get("transcript_digest", ""))) != 64:
                    fail(path, "non-canonical verifier transcript digest")

        key = (
            sample["campaign_id"], sample["route"],
            sample["loss_pct"], n, k, int(sample["pairs"]),
            int(sample["fault_count"]), sample["trial"],
        )
        if variant in grouped[key]:
            fail(path, f"duplicate sample for {key} and {variant}")
        grouped[key][variant] = sample

    if failures and not allow_failures:
        fail(path, f"recorded {failures} failed pair executions")

    complete_groups = 0
    for key, variants in grouped.items():
        if set(variants) != required_variants:
            missing = required_variants - set(variants)
            fail(path, f"incomplete paired trial {key}; missing={sorted(missing)}")
        if required_variants != REQUIRED_VARIANTS:
            complete_groups += 1
            continue
        persistent_itemwise = variants["persistent-pipelined-itemwise"]
        batch_joint_itemwise = variants[
            "batch-joint-presigning-itemwise"
        ]
        batch_joint_verification = variants[
            "batch-joint-presigning-batch-verification"
        ]
        coalesced_batch = variants["phase-coalesced-batch-verification"]
        coalesced_itemwise = variants["phase-coalesced-itemwise"]
        k = int(persistent_itemwise["k"])
        pairs = int(persistent_itemwise["pairs"])
        expected_independent_sessions = pairs * k
        for variant_name, sample in {
            "persistent-pipelined-itemwise": persistent_itemwise,
            "phase-coalesced-batch-verification": coalesced_batch,
            "phase-coalesced-itemwise": coalesced_itemwise,
        }.items():
            if int(sample["logical_sessions"]) != expected_independent_sessions:
                fail(path, f"{variant_name} session count mismatch")
        if (
            int(batch_joint_itemwise["logical_sessions"]) != pairs
            or int(batch_joint_verification["logical_sessions"]) != pairs
        ):
            fail(
                path,
                "Batch Joint Pre-signing must use one parent session per pair",
            )
        if (
            int(batch_joint_itemwise["application_messages"])
            >= int(persistent_itemwise["application_messages"])
        ):
            fail(path, "Batch Joint Pre-signing did not reduce logical messages")
        if int(coalesced_itemwise["application_messages"]) != int(persistent_itemwise["application_messages"]):
            fail(path, "phase coalescing changed logical-message accounting")
        if int(coalesced_itemwise["application_write_calls"]) >= int(persistent_itemwise["application_write_calls"]):
            fail(path, "phase coalescing did not reduce application writes")
        complete_groups += 1

    return {
        "file": str(path),
        "samples": len(samples),
        "paired_trials": complete_groups,
        "failures": failures,
        "campaigns": sorted({sample["campaign_id"] for sample in samples}),
        "routes": sorted({sample["route"] for sample in samples}),
        "n_values": sorted({int(sample["n"]) for sample in samples}),
        "pair_values": sorted({int(sample["pairs"]) for sample in samples}),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--allow-failures", action="store_true")
    parser.add_argument(
        "--variants",
        default=",".join(sorted(REQUIRED_VARIANTS)),
        help="comma-separated expected objective variant names",
    )
    args = parser.parse_args()
    required_variants = set(args.variants.split(","))
    unknown = required_variants - REQUIRED_VARIANTS
    if not required_variants or unknown:
        raise SystemExit(f"error: invalid expected variants: {sorted(unknown)}")
    reports = [
        validate(path, args.allow_failures, required_variants)
        for path in args.inputs
    ]
    print(json.dumps({"status": "pass", "results": reports}, indent=2))


if __name__ == "__main__":
    main()
