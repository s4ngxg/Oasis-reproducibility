#!/usr/bin/env python3
"""Run paired retained-cycle diagnostic timings for baseline and OASIS modes.

Every baseline/OASIS pair is cloned from one immutable Preparation fixture.
The report records the public fixture identifier plus source/binary/result
hashes so evidence cannot silently be reused after implementation changes.
These timings are local correctness-harness diagnostics, not transaction/WAN
latency evidence.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import resource
import statistics
import subprocess
import sys
import time

from run_native_handoff import MODES, TPC, memory_file
from run_retained_arc_coordinator import coordinate

BASELINE = "reference-itemwise"
OASIS = "batch-joint-presigning-batch-verification"
ROOT = TPC.parents[2]


def _median_metric(runs, path):
    values = []
    for run in runs:
        value = run
        for key in path:
            value = value[key]
        if value is not None:
            values.append(float(value))
    return None if not values else statistics.median(values)


def _ratio(numerator, denominator):
    if numerator is None or denominator is None or denominator == 0:
        return None
    return numerator / denominator


def _sha256_bytes(payload):
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _fresh_fixture(n):
    """Generate one Preparation fixture and return byte-identical clone inputs."""
    k = 2*n-1
    started = time.monotonic_ns()
    with memory_file("paired-preparation-private") as private, \
         memory_file("paired-preparation-public") as public, \
         memory_file("paired-participant-secrets") as participants:
        result = subprocess.run(
            [str(TPC/"bin/host_cycle_tool"), "prepare-participants", str(n),
             str(private), str(public), str(participants)],
            pass_fds=(private, public, participants), capture_output=True, timeout=60,
        )
        finished = time.monotonic_ns()
        if result.returncode:
            raise RuntimeError("native Preparation failed for paired fixture")
        public_bytes = os.pread(public, 8+n*k*33, 0)
        private_bytes = os.pread(private, 8+n*k*32, 0)
        participant_bytes = os.pread(participants, 12+64*n, 0)
    if (len(public_bytes) != 8+n*k*33 or len(private_bytes) != 8+n*k*32 or
            len(participant_bytes) != 12+64*n):
        raise AssertionError("Preparation emitted an incomplete paired fixture")
    return {
        "public": public_bytes,
        "private": private_bytes,
        "participants": participant_bytes,
        "public_fixture_sha256": _sha256_bytes(public_bytes),
        "preparation_fixture_ms": (finished-started)/1e6,
    }


def _run_fixture(n, mode, fixture, *, recover_cycle, all_honest, progress, refund_cycle=False):
    """Run one mode on a fresh writable clone of the same immutable fixture."""
    started = time.monotonic_ns()
    with memory_file("paired-public", fixture["public"]) as public, \
         memory_file("paired-private", fixture["private"]) as private, \
         memory_file("paired-participants", fixture["participants"]) as participants:
        checked = coordinate(
            n, mode, public, private, participants, progress,
            recover_cycle=recover_cycle, all_honest=all_honest,
            refund_cycle=refund_cycle,
        )
    finished = time.monotonic_ns()
    checked["paired_fixture"] = {
        "public_fixture_sha256": fixture["public_fixture_sha256"],
        "byte_identical_clone": True,
        "preparation_generated_once_per_pair": True,
    }
    checked["coordinator_timing"]["paired_clone_runner_ms"] = (finished-started)/1e6
    checked["coordinator_timing"]["shared_preparation_fixture_ms"] = fixture["preparation_fixture_ms"]
    return checked


def _provenance():
    source_paths = [
        "scripts/compare_full_cycle_modes.py",
        "scripts/run_retained_arc_coordinator.py",
        "scripts/lifecycle_preswap.py",
        "scripts/run_native_handoff.py",
        "vendor/paraswap/two-party computation/src/host_cycle_tool.c",
        "vendor/paraswap/two-party computation/src/host_ledger.c",
        "vendor/paraswap/two-party computation/src/host_recovery.c",
        "vendor/paraswap/two-party computation/src/host_refund.c",
        "vendor/paraswap/two-party computation/src/host_schedule.c",
        "vendor/paraswap/two-party computation/src/host_handoff.c",
        "vendor/paraswap/two-party computation/include/host_recovery.h",
        "vendor/paraswap/two-party computation/include/host_ledger.h",
        "vendor/paraswap/two-party computation/include/host_schedule.h",
        "vendor/paraswap/two-party computation/src/vtd_integration_test.c",
        "vendor/paraswap/two-party computation/src/vtd_public_solver.c",
    ]
    binaries = [
        TPC/"bin/host_cycle_tool", TPC/"bin/preswap_client", TPC/"bin/preswap_server",
        TPC/"bin/curve_keygen", TPC/"bin/vtd_integration_test", TPC/"bin/vtd_public_solver",
    ]
    # Capture cryptographic implementation changes, not just coordinator code.
    for directory in (TPC / "src", TPC / "include"):
        for path in directory.rglob("*"):
            if path.is_file() and (path.suffix in (".c", ".h", ".cpp", ".hpp")
                                   or path.name == "CMakeLists.txt"):
                source_paths.append(str(path.relative_to(ROOT)))
    source_paths.extend([
        "Makefile", "vendor/paraswap-artifact.lock.json",
        "vendor/paraswap/two-party computation/CMakeLists.txt",
        "scripts/test_retained_full_cycle.py",
    ])
    source_hashes = {}
    for relative in sorted(set(source_paths)):
        path = ROOT/relative
        if not path.is_file():
            raise RuntimeError(f"missing provenance source: {relative}")
        source_hashes[relative] = _sha256_file(path)
    binary_hashes = {}
    for path in binaries:
        if not path.is_file():
            raise RuntimeError(f"missing provenance binary: {path}")
        binary_hashes[str(path.relative_to(ROOT))] = _sha256_file(path)
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, timeout=10,
    )
    if commit.returncode or len(commit.stdout.strip()) != 40:
        raise RuntimeError("cannot resolve tested git commit")
    return {
        "git_commit": commit.stdout.strip(),
        "source_sha256": source_hashes,
        "binary_sha256": binary_hashes,
        "evidence_valid_only_for_exact_hash_set": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--participants", type=int, default=3, choices=range(3, 129))
    parser.add_argument("--repetitions", type=int, default=1)
    outcome = parser.add_mutually_exclusive_group(required=True)
    outcome.add_argument("--all-honest", action="store_true")
    outcome.add_argument("--recover-cycle", action="store_true")
    outcome.add_argument("--refund-cycle", action="store_true")
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error("--repetitions must be >= 1")
    if BASELINE not in MODES or OASIS not in MODES:
        raise RuntimeError("required comparison modes are not available")

    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    runs = {BASELINE: [], OASIS: []}
    pair_ids = []

    def progress(mode, repetition):
        def emit(stage, arc):
            print(
                f"mode={mode} repetition={repetition} stage={stage} arc={arc}",
                file=sys.stderr, flush=True,
            )
        return emit

    # Generate exactly one Preparation fixture per repetition, then clone those
    # bytes for both modes. Alternate order only to reduce systematic warmup bias.
    for repetition in range(args.repetitions):
        fixture = _fresh_fixture(args.participants)
        pair_ids.append(fixture["public_fixture_sha256"])
        order = (BASELINE, OASIS) if repetition % 2 == 0 else (OASIS, BASELINE)
        for mode in order:
            run = _run_fixture(
                args.participants, mode, fixture,
                recover_cycle=args.recover_cycle,
                all_honest=args.all_honest,
                refund_cycle=args.refund_cycle,
                progress=progress(mode, repetition),
            )
            if run["paired_fixture"]["public_fixture_sha256"] != fixture["public_fixture_sha256"]:
                raise AssertionError("comparison mode escaped its paired fixture")
            runs[mode].append(run)

    metrics = {
        "preswap_all_arcs_wall_ms": ("coordinator_timing", "phases_ms", "preswap_all_arcs_wall_ms"),
        "retained_cycle_to_terminal_ms": ("coordinator_timing", "phases_ms", "retained_cycle_to_terminal_ms"),
        "paired_clone_runner_ms": ("coordinator_timing", "paired_clone_runner_ms"),
    }
    summary = {}
    for name, path in metrics.items():
        baseline = _median_metric(runs[BASELINE], path)
        oasis = _median_metric(runs[OASIS], path)
        summary[name] = {
            "baseline_median_ms": baseline,
            "oasis_median_ms": oasis,
            "baseline_over_oasis_speedup": _ratio(baseline, oasis),
            "oasis_reduction_fraction": (
                None if baseline in (None, 0) or oasis is None else (baseline-oasis)/baseline
            ),
        }

    report = {
        "schema": "oasis-retained-cycle-diagnostic-comparison-v3",
        "participants": args.participants,
        "repetitions": args.repetitions,
        "outcome": ("all-honest" if args.all_honest else
                    "refund-cycle" if args.refund_cycle else "recover-cycle"),
        "baseline_mode": BASELINE,
        "oasis_mode": OASIS,
        "comparative_scope": (
            "local retained lifecycle correctness harness; one identical Preparation "
            "fixture per mode pair; diagnostic timing only"
        ),
        "transaction_latency_claim": False,
        "wan_latency_claim": False,
        "publication_performance_evidence": False,
        "paired_fixture_public_sha256": pair_ids,
        "same_fixture_within_each_pair": True,
        "distributed_participant_custody": False,
        "timed_privacy": False,
        "full_lifecycle": False,
        "provenance": _provenance(),
        "runs": runs,
        "summary": summary,
    }
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
    report["report_payload_sha256"] = _sha256_bytes(canonical)
    print(json.dumps(report))


if __name__ == "__main__":
    main()
