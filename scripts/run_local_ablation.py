#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import statistics
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from paraswap_lifecycle import (  # noqa: E402
    Config,
    Lifecycle,
    NativePreSigningBackend,
    canonical_native_mode,
)


DEFAULT_MODES = (
    "reference-itemwise",
    "phase-coalesced-itemwise",
    "batch-joint-presigning-itemwise",
    "phase-coalesced-batch-verification",
    "batch-joint-presigning-batch-verification",
)
EFFECT_COMPARISONS = {
    "phase_coalescing_vs_reference": (
        "reference-itemwise", "phase-coalesced-itemwise"
    ),
    "batch_joint_presigning_vs_phase_coalesced_itemwise": (
        "phase-coalesced-itemwise", "batch-joint-presigning-itemwise"
    ),
    "batch_joint_presigning_vs_reference": (
        "reference-itemwise", "batch-joint-presigning-itemwise"
    ),
    "batch_verification_with_phase_coalescing": (
        "phase-coalesced-itemwise", "phase-coalesced-batch-verification"
    ),
    "batch_verification_with_batch_joint_presigning": (
        "batch-joint-presigning-itemwise",
        "batch-joint-presigning-batch-verification",
    ),
    "batch_joint_presigning_vs_phase_coalesced_aggregate": (
        "phase-coalesced-batch-verification",
        "batch-joint-presigning-batch-verification",
    ),
}


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(len(ordered) * fraction + 0.999) - 1))
    return ordered[index]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run the five-cell ParaSwap Pre-swap ablation using one native "
            "implementation"
        )
    )
    parser.add_argument("--participants", default="3,5,8")
    parser.add_argument("--trials", type=int, default=10)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument(
        "--modes",
        default=",".join(DEFAULT_MODES),
        help="comma-separated native Pre-swap configurations",
    )
    parser.add_argument("--base-port", type=int, default=20000)
    parser.add_argument("--output", type=Path,
                        default=ROOT / "results" / "preswap-local-ablation.json")
    args = parser.parse_args()
    n_values = [int(value) for value in args.participants.split(",")]
    modes = [canonical_native_mode(value.strip())
             for value in args.modes.split(",") if value.strip()]
    unknown = sorted(set(modes) - set(DEFAULT_MODES))
    if unknown:
        raise ValueError(f"unsupported modes: {', '.join(unknown)}")
    if args.trials <= 0 or args.warmup < 0:
        raise ValueError("trials must be positive and warmup non-negative")
    samples: list[dict[str, object]] = []
    backend = NativePreSigningBackend()

    campaign_index = 0
    for n in n_values:
        for warmup in range(args.warmup):
            for mode in modes:
                config = Config(
                    participants=n,
                    mode=mode,
                    base_port=args.base_port + campaign_index * (n + 1),
                    seed=f"lifecycle-warmup-{n}-{warmup}",
                )
                report = Lifecycle(config, backend).run()
                if not report["outputs_exported"]:
                    raise RuntimeError(
                        f"failed warmup n={n} warmup={warmup} mode={mode}"
                    )
                campaign_index += 1
        for trial in range(args.trials):
            offset = trial % len(modes)
            trial_modes = modes[offset:] + modes[:offset]
            for mode in trial_modes:
                config = Config(
                    participants=n,
                    mode=mode,
                    base_port=args.base_port + campaign_index * (n + 1),
                    seed=f"lifecycle-benchmark-{n}-{trial}",
                )
                report = Lifecycle(config, backend).run()
                if not report["outputs_exported"]:
                    raise RuntimeError(f"failed lifecycle sample n={n} trial={trial} mode={mode}")
                pre_swap = report["pre_swap"]
                samples.append(
                    {
                        "participants": n,
                        "items_per_arc": 2 * n - 1,
                        "arcs": n,
                        "mode": mode,
                        "trial": trial,
                        "lifecycle_wall_ms": report["lifecycle_wall_ns"] / 1e6,
                        "max_arc_wall_ms": max(row["wall_ns"] for row in pre_swap) / 1e6,
                        "client_crypto_ms": sum(row["crypto_ns"] for row in pre_swap) / 1e6,
                        "server_crypto_ms": sum(row["server_crypto_ns"] for row in pre_swap) / 1e6,
                        "client_verifier_challenge_ms": sum(
                            row["verifier_challenge_ns"] for row in pre_swap
                        ) / 1e6,
                        "client_verifier_msm_ms": sum(
                            row["verifier_msm_ns"] for row in pre_swap
                        ) / 1e6,
                        "server_verifier_challenge_ms": sum(
                            row["server_verifier_challenge_ns"] for row in pre_swap
                        ) / 1e6,
                        "server_verifier_msm_ms": sum(
                            row["server_verifier_msm_ns"] for row in pre_swap
                        ) / 1e6,
                        "verifier_equations": sum(
                            row["verifier_equations"] +
                            row["server_verifier_equations"]
                            for row in pre_swap
                        ),
                        "verifier_msm_calls": sum(
                            row["verifier_msm_calls"] +
                            row["server_verifier_msm_calls"]
                            for row in pre_swap
                        ),
                        "verifier_fallbacks": sum(
                            row["verifier_fallbacks"] +
                            row["server_verifier_fallbacks"]
                            for row in pre_swap
                        ),
                        "sent_frames": sum(row["sent_frames"] for row in pre_swap),
                        "received_frames": sum(row["received_frames"] for row in pre_swap),
                        "sent_bytes": sum(row["sent_bytes"] for row in pre_swap),
                        "received_bytes": sum(row["received_bytes"] for row in pre_swap),
                    }
                )
                campaign_index += 1

    summary = []
    for n in n_values:
        for mode in modes:
            group = [row for row in samples
                     if row["participants"] == n and row["mode"] == mode]
            wall = [float(row["lifecycle_wall_ms"]) for row in group]
            critical_arc = [float(row["max_arc_wall_ms"]) for row in group]
            summary.append(
                {
                    "participants": n,
                    "items_per_arc": 2 * n - 1,
                    "mode": mode,
                    "trials": len(group),
                    "median_lifecycle_wall_ms": statistics.median(wall),
                    "p95_lifecycle_wall_ms": percentile(wall, 0.95),
                    "median_preswap_critical_arc_ms": statistics.median(critical_arc),
                    "p95_preswap_critical_arc_ms": percentile(critical_arc, 0.95),
                    "median_sent_frames": statistics.median(
                        int(row["sent_frames"]) for row in group
                    ),
                    "median_received_frames": statistics.median(
                        int(row["received_frames"]) for row in group
                    ),
                    "median_sent_bytes": statistics.median(
                        int(row["sent_bytes"]) for row in group
                    ),
                    "median_received_bytes": statistics.median(
                        int(row["received_bytes"]) for row in group
                    ),
                    "median_verifier_msm_calls": statistics.median(
                        int(row["verifier_msm_calls"]) for row in group
                    ),
                    "total_verifier_fallbacks": sum(
                        int(row["verifier_fallbacks"]) for row in group
                    ),
                }
            )

    paired_effects = []
    for n in n_values:
        for comparison, (baseline, candidate) in EFFECT_COMPARISONS.items():
            if baseline not in modes or candidate not in modes:
                continue
            baseline_by_trial = {
                int(row["trial"]): row
                for row in samples
                if row["participants"] == n and row["mode"] == baseline
            }
            candidate_by_trial = {
                int(row["trial"]): row
                for row in samples
                if row["participants"] == n and row["mode"] == candidate
            }
            paired_trials = sorted(set(baseline_by_trial) & set(candidate_by_trial))
            lifecycle_reductions = [
                100.0 * (
                    float(baseline_by_trial[trial]["lifecycle_wall_ms"])
                    - float(candidate_by_trial[trial]["lifecycle_wall_ms"])
                ) / float(baseline_by_trial[trial]["lifecycle_wall_ms"])
                for trial in paired_trials
            ]
            critical_arc_reductions = [
                100.0 * (
                    float(baseline_by_trial[trial]["max_arc_wall_ms"])
                    - float(candidate_by_trial[trial]["max_arc_wall_ms"])
                ) / float(baseline_by_trial[trial]["max_arc_wall_ms"])
                for trial in paired_trials
            ]
            paired_effects.append(
                {
                    "participants": n,
                    "items_per_arc": 2 * n - 1,
                    "comparison": comparison,
                    "baseline": baseline,
                    "candidate": candidate,
                    "paired_trials": len(lifecycle_reductions),
                    "median_lifecycle_wall_reduction_pct": statistics.median(
                        lifecycle_reductions
                    ),
                    "mean_lifecycle_wall_reduction_pct": statistics.fmean(
                        lifecycle_reductions
                    ),
                    "median_critical_arc_reduction_pct": statistics.median(
                        critical_arc_reductions
                    ),
                    "mean_critical_arc_reduction_pct": statistics.fmean(
                        critical_arc_reductions
                    ),
                    "positive_means_candidate_faster": True,
                }
            )

    output = {
        "schema": "oasis-preswap-local-ablation-v1",
        "measurement_scope": (
            "native full-lifecycle harness; deterministic ledger and VTD "
            "adapters; all five Pre-swap configurations use the same native C/"
            "ZeroMQ processes, fixture keys, curve, and compiler build"
        ),
        "configuration_semantics": {
            "reference-itemwise": "reference per-item sessions and verification",
            "phase-coalesced-itemwise": (
                "independent item sessions coalesced by phase; item-wise verification"
            ),
            "batch-joint-presigning-itemwise": "one parent BJP session; item-wise verification",
            "phase-coalesced-batch-verification": (
                "independent item sessions coalesced by phase; native MSM verification"
            ),
            "batch-joint-presigning-batch-verification": "one parent BJP session; native MSM verification",
        },
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "client_sha256": sha256(ROOT / "vendor" / "paraswap" /
                                      "two-party computation" / "bin" /
                                      "preswap_client"),
            "server_sha256": sha256(ROOT / "vendor" / "paraswap" /
                                      "two-party computation" / "bin" /
                                      "preswap_server"),
            "warmup_per_configuration": args.warmup,
            "mode_order": "cyclic rotation by paired trial",
        },
        "samples": samples,
        "summary": summary,
        "paired_effects": paired_effects,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(f"wrote={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
