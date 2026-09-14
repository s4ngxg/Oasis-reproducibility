#!/usr/bin/env python3
"""Smoke-check retained n=3 cycles for baseline and OASIS modes.

This test intentionally exercises three terminal branches through the same
coordinator. It is a local correctness/integration gate, not a performance,
WAN, distributed-custody, or timed-privacy benchmark.
"""
import argparse
import json
import resource
import subprocess
import sys
from pathlib import Path
from compare_full_cycle_modes import _provenance

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run_retained_arc_coordinator.py"
MODES = (
    "reference-itemwise",
    "batch-joint-presigning-batch-verification",
)
OUTCOMES = ("--all-honest", "--recover-cycle", "--refund-cycle")


def _run(mode, outcome, participants):
    process = subprocess.run(
        [sys.executable, str(RUNNER), "--participants", str(participants),
         "--mode", mode, outcome],
        cwd=ROOT, stdout=subprocess.PIPE, text=True, timeout=3600,
    )
    if process.returncode:
        raise RuntimeError(
            f"retained cycle failed: mode={mode} outcome={outcome} "
            f"exit={process.returncode}; diagnostics were emitted to stderr"
        )
    try:
        report = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"invalid retained-cycle JSON: mode={mode} outcome={outcome}"
        ) from exc
    return report


def _assert_report(report, mode, outcome, participants):
    assert report["mode"] == mode
    assert report["participants"] == participants
    assert report["vtd_count"] == participants * participants
    assert report["all_proofs_before_locks"] is True
    assert report["vtd_expected_context_and_keys_checked_before_locks"] is True
    assert report["all_locks_before_preswap"] is True
    assert report["all_arcs_preswap_concurrent"] is True
    assert report["retained_funded_ledgers"] is True
    assert report["local_retained_cycle_exercised"] is True
    assert report["local_retained_full_cycle"] is False
    assert report["full_lifecycle"] is False
    assert report["distributed_participant_custody"] is False
    assert report["timed_privacy"] is False
    assert len(report["arcs"]) == participants
    assert all(arc["preswap"].get("preswap_wall_ns", 0) > 0 for arc in report["arcs"])
    assert all(arc["preswap"].get("transport") == "tcp" for arc in report["arcs"])
    assert all(arc["preswap"].get("transport_authenticated") is True for arc in report["arcs"])
    assert all(arc["preswap"].get("transport_scope") == "loopback-correctness"
               for arc in report["arcs"])
    assert len({arc["preswap"]["host_export_deadline_ns"] for arc in report["arcs"]}) == 1
    assert all(len(arc["vtd_checks"]) == participants for arc in report["arcs"])

    timing = report["coordinator_timing"]
    phases = timing["phases_ms"]
    assert timing["all_arcs_preswap_concurrent"] is True
    assert timing["preswap_transport"] == "curve-tcp"
    assert timing["preswap_transport_scope"] == "authenticated TCP loopback correctness"
    assert timing["host_deadline_bound_to_preswap"] is True
    assert timing["ledger_monotonic_deadline_bound"] is False
    assert timing["network_authentication_negative_checks_included"] is False
    assert timing["transaction_latency_claim"] is False
    assert timing["end_to_end_runner_is_transaction_latency"] is False
    assert timing["end_to_end_runner_ms"] > 0
    assert timing["preparation_fixture_ms"] >= 0
    assert phases["preswap_all_arcs_wall_ms"] > 0
    assert phases["funding_and_lock_admission_ms"] >= 0
    assert phases["witness_sharing_ms"] >= 0

    if outcome == "--all-honest":
        assert report["cycle_withdrawal"] is not None
        assert report["cycle_recovery"] is None
        assert report["withdrawal_precedes_solver_join"] is True
    elif outcome == "--recover-cycle":
        assert report["cycle_recovery"] is not None
        assert report["cycle_withdrawal"] is None
        assert report["withdrawal_precedes_solver_join"] is False
    else:
        assert outcome == "--refund-cycle"
        assert report["cycle_recovery"] is None
        assert report["cycle_withdrawal"] is None
        assert report["cycle_refund"]["retained_cycle_refund"] is True
        assert report["cycle_refund"]["refunded_arcs"] == participants
        assert report["cycle_refund"]["withdrawn_arcs"] == 0
        assert report["withdrawal_precedes_solver_join"] is False
        assert timing["preswap_to_withdrawal_receipt_ms"] is None
        assert phases["retained_cycle_to_terminal_ms"] > 0
        assert all(arc["witness_sharing"].get("withheld_in_fixture") is True
                   for arc in report["arcs"])


def main():
    if not __debug__:
        raise RuntimeError("smoke evidence validation requires Python assertions; do not use -O")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--participants", type=int, default=3, choices=range(3, 129))
    parser.add_argument("--results-dir", type=Path,
                        help="new directory for per-run checked reports and provenance")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument(
        "--quick", action="store_true",
        help="run only all-honest cycles; default also exercises recovery and refund",
    )
    selection.add_argument("--outcome", choices=[value[2:] for value in OUTCOMES],
                           help="exercise one branch for both modes; default runs all branches")
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if args.results_dir is not None:
        args.results_dir.mkdir(parents=True, exist_ok=False)

    outcomes = (("--" + args.outcome,) if args.outcome else
                ("--all-honest",) if args.quick else OUTCOMES)
    completed = []
    for outcome in outcomes:
        for mode in MODES:
            print(f"retained cycle smoke: {mode} {outcome}", file=sys.stderr, flush=True)
            provenance = _provenance() if args.results_dir is not None else None
            report = _run(mode, outcome, args.participants)
            _assert_report(report, mode, outcome, args.participants)
            if args.results_dir is not None:
                if _provenance() != provenance:
                    raise RuntimeError("source or binary changed during smoke run")
                destination = args.results_dir / f"{outcome[2:]}-{mode}.json"
                with destination.open("x", encoding="utf-8") as output:
                    json.dump({"provenance": provenance, "report": report}, output, indent=2)
                    output.write("\n")
            completed.append({
                "mode": mode,
                "outcome": outcome[2:],
                "end_to_end_runner_ms": report["coordinator_timing"]["end_to_end_runner_ms"],
            })

    print(json.dumps({
        "retained_cycle_correctness_smoke": True,
        "full_lifecycle": False,
        "all_terminal_branches_exercised": outcomes == OUTCOMES,
        "participants": args.participants,
        "runs": completed,
    }))


if __name__ == "__main__":
    main()
