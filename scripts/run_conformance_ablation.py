#!/usr/bin/env python3
"""Run the secondary conformance-path ablation."""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from paraswap_lifecycle import (  # noqa: E402
    Config,
    Lifecycle,
    OasisLinearBackend,
)


CONFIGURATIONS = (
    "persistent-pipelined-itemwise",
    "phase-coalesced-itemwise",
    "batch-joint-presigning-itemwise",
    "phase-coalesced-batch-verification",
    "batch-joint-presigning-batch-verification",
)

LABELS = {
    "persistent-pipelined-itemwise": (
        "persistent pipelined sessions + item-wise verification"
    ),
    "phase-coalesced-itemwise": (
        "phase-coalesced independent sessions + item-wise verification"
    ),
    "batch-joint-presigning-itemwise": (
        "Batch Joint Pre-signing + item-wise verification"
    ),
    "phase-coalesced-batch-verification": (
        "phase-coalesced sessions + randomized batch verification"
    ),
    "batch-joint-presigning-batch-verification": (
        "Batch Joint Pre-signing + randomized batch verification"
    ),
}

COMPARISONS = (
    (
        "batch-joint-presigning-itemwise",
        "persistent-pipelined-itemwise",
        "coordination_effect",
    ),
    (
        "phase-coalesced-batch-verification",
        "persistent-pipelined-itemwise",
        "verification_effect_with_phase_coalescing",
    ),
    (
        "batch-joint-presigning-batch-verification",
        "batch-joint-presigning-itemwise",
        "verification_effect_with_batch_joint_presigning",
    ),
    (
        "batch-joint-presigning-batch-verification",
        "persistent-pipelined-itemwise",
        "combined_effect",
    ),
)


def percent_reduction(candidate: float, baseline: float) -> float:
    return 100.0 * (baseline - candidate) / baseline


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the conformance-path coordination/verification ablation"
    )
    parser.add_argument("--participants", default="5,8,16")
    parser.add_argument("--trials", type=int, default=10)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "results" / "conformance-ablation.json",
    )
    args = parser.parse_args()
    if args.trials < 1:
        parser.error("--trials must be positive")
    n_values = [int(value) for value in args.participants.split(",")]
    if any(value < 3 for value in n_values):
        parser.error("all participant counts must be at least three")

    backend = OasisLinearBackend()
    samples: list[dict[str, object]] = []
    for n in n_values:
        for trial in range(args.trials):
            offset = trial % len(CONFIGURATIONS)
            execution_order = CONFIGURATIONS[offset:] + CONFIGURATIONS[:offset]
            for configuration in execution_order:
                report = Lifecycle(
                    Config(
                        participants=n,
                        mode="batch",
                        backend="oasis",
                        configuration=configuration,
                        seed=f"oasis-ablation-{n}-{trial}",
                    ),
                    backend,
                ).run()
                if not report["outputs_exported"]:
                    raise RuntimeError(
                        f"failed n={n} trial={trial} configuration={configuration}"
                    )
                arcs = report["pre_swap"]
                samples.append(
                    {
                        "participants": n,
                        "items_per_arc": 2 * n - 1,
                        "arcs": n,
                        "trial": trial,
                        "configuration": configuration,
                        "configuration_label": LABELS[configuration],
                        "lifecycle_wall_ms": report["lifecycle_wall_ns"] / 1e6,
                        "critical_arc_transport_wall_ms": max(
                            float(row["wall_ns"]) for row in arcs
                        ) / 1e6,
                        "aggregate_client_process_cpu_ms": sum(
                            float(row["crypto_ns"]) for row in arcs
                        ) / 1e6,
                        "transport_bytes": sum(
                            int(row["sent_bytes"]) + int(row["received_bytes"])
                            for row in arcs
                        ),
                        "transport_frames": sum(
                            int(row["sent_frames"]) + int(row["received_frames"])
                            for row in arcs
                        ),
                        "authenticated_transport_arcs": sum(
                            bool(row["transport_authenticated"]) for row in arcs
                        ),
                        "verifier_ms": sum(
                            int(row["verifier_ns"]) for row in arcs
                        ) / 1e6,
                        "application_write_calls": sum(
                            int(row["application_write_calls"]) for row in arcs
                        ),
                        "application_read_calls": sum(
                            int(row["application_read_calls"]) for row in arcs
                        ),
                        "transport_write_ops": sum(
                            int(row["transport_write_ops"]) for row in arcs
                        ),
                        "transport_read_ops": sum(
                            int(row["transport_read_ops"]) for row in arcs
                        ),
                        "retransmissions": sum(
                            int(row["retransmissions"]) for row in arcs
                        ),
                        "logical_messages": sum(
                            int(row["logical_messages"]) for row in arcs
                        ),
                        "logical_sessions": sum(
                            int(row["logical_sessions"]) for row in arcs
                        ),
                        "audit_pippenger_calls": sum(
                            int(row["audit_pippenger_calls"]) for row in arcs
                        ),
                        "audit_pippenger_terms": sum(
                            int(row["audit_pippenger_terms"]) for row in arcs
                        ),
                        "adapt_extract_checks": sum(
                            int(row["adaptation_checks"]) for row in arcs
                        ),
                        "itemwise_audit_checks": sum(
                            int(row["itemwise_audit_checks"]) for row in arcs
                        ),
                        "failures": sum(not bool(row["accepted"]) for row in arcs),
                    }
                )

    summary: list[dict[str, object]] = []
    comparisons: list[dict[str, object]] = []
    for n in n_values:
        by_configuration: dict[str, list[dict[str, object]]] = {}
        for configuration in CONFIGURATIONS:
            group = [
                row for row in samples
                if row["participants"] == n
                and row["configuration"] == configuration
            ]
            by_configuration[configuration] = group
            summary.append(
                {
                    "participants": n,
                    "items_per_arc": 2 * n - 1,
                    "configuration": configuration,
                    "configuration_label": LABELS[configuration],
                    "trials": len(group),
                    "median_lifecycle_wall_ms": statistics.median(
                        float(row["lifecycle_wall_ms"]) for row in group
                    ),
                    "median_critical_arc_transport_wall_ms": statistics.median(
                        float(row["critical_arc_transport_wall_ms"])
                        for row in group
                    ),
                    "median_aggregate_client_process_cpu_ms": statistics.median(
                        float(row["aggregate_client_process_cpu_ms"])
                        for row in group
                    ),
                    "median_transport_bytes": statistics.median(
                        int(row["transport_bytes"]) for row in group
                    ),
                    "median_transport_frames": statistics.median(
                        int(row["transport_frames"]) for row in group
                    ),
                    "median_verifier_ms": statistics.median(
                        float(row["verifier_ms"]) for row in group
                    ),
                    "median_application_write_calls": statistics.median(
                        int(row["application_write_calls"]) for row in group
                    ),
                    "median_application_read_calls": statistics.median(
                        int(row["application_read_calls"]) for row in group
                    ),
                    "median_transport_write_ops": statistics.median(
                        int(row["transport_write_ops"]) for row in group
                    ),
                    "median_transport_read_ops": statistics.median(
                        int(row["transport_read_ops"]) for row in group
                    ),
                    "median_retransmissions": statistics.median(
                        int(row["retransmissions"]) for row in group
                    ),
                    "logical_messages": group[0]["logical_messages"],
                    "logical_sessions": group[0]["logical_sessions"],
                    "audit_pippenger_calls": group[0]["audit_pippenger_calls"],
                    "adapt_extract_checks": group[0]["adapt_extract_checks"],
                    "itemwise_audit_checks": group[0]["itemwise_audit_checks"],
                }
            )

        for candidate, baseline, effect in COMPARISONS:
            candidate_by_trial = {
                int(row["trial"]): (
                    float(row["critical_arc_transport_wall_ms"]),
                    float(row["lifecycle_wall_ms"]),
                )
                for row in by_configuration[candidate]
            }
            baseline_by_trial = {
                int(row["trial"]): (
                    float(row["critical_arc_transport_wall_ms"]),
                    float(row["lifecycle_wall_ms"]),
                )
                for row in by_configuration[baseline]
            }
            protocol_reductions = [
                percent_reduction(candidate_by_trial[trial][0],
                                  baseline_by_trial[trial][0])
                for trial in sorted(candidate_by_trial)
            ]
            lifecycle_reductions = [
                percent_reduction(candidate_by_trial[trial][1],
                                  baseline_by_trial[trial][1])
                for trial in sorted(candidate_by_trial)
            ]
            comparisons.append(
                {
                    "participants": n,
                    "items_per_arc": 2 * n - 1,
                    "effect": effect,
                    "candidate": LABELS[candidate],
                    "baseline": LABELS[baseline],
                    "paired_trials": len(protocol_reductions),
                    "median_transport_critical_arc_reduction_pct": statistics.median(
                        protocol_reductions
                    ),
                    "median_artifact_lifecycle_wall_reduction_pct": statistics.median(
                        lifecycle_reductions
                    ),
                }
            )

    output = {
        "schema": "oasis-preswap-conformance-ablation-v1",
        "scope": (
            "native five-phase artifact lifecycle with 2x2 ablation and "
            "phase-coalesced baseline; deterministic ledger/VTD "
            "adapters; each OASIS arc uses separate native peers over mutual "
            "TLS 1.3 on TCP loopback"
        ),
        "batch_soundness": "at most min(1,Q*2^-254) for Q fresh-salted checks",
        "batch_verification_activation": (
            "multi-scalar multiplication is enabled when k >= 8"
        ),
        "timing_definition": {
            "critical_arc_transport_wall_ms": (
                "slowest arc's end-to-end client measurement, including mutual "
                "TLS setup, protocol frames, verification, retry, and DONE; "
                "excludes the independent Adapt/Extract conformance process"
            ),
            "artifact_lifecycle_wall_ms": (
                "coordinator wall time including server/client process launch, "
                "transport, independent conformance checks, export validation, "
                "and deterministic outer-state transitions"
            ),
            "aggregate_client_process_cpu_ms": (
                "sum of client-process CPU measurements across arcs; server CPU "
                "is not inferred from this field"
            ),
        },
        "samples": samples,
        "summary": summary,
        "paired_effects": comparisons,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(f"wrote={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
