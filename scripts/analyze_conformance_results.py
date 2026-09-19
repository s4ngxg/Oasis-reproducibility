#!/usr/bin/env python3
"""Summarize OASIS raw samples and compute paired bootstrap confidence intervals."""

import argparse
import json
import math
import random
import statistics
from collections import defaultdict
from pathlib import Path

from scipy.stats import rankdata, wilcoxon


def percentile(values, probability):
    ordered = sorted(values)
    if not ordered:
        return 0.0
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def bootstrap_ci(
    values,
    statistic=statistics.median,
    iterations=10000,
    seed=0x4F415349,
):
    if not values:
        return [0.0, 0.0]
    generator = random.Random(seed)
    estimates = []
    for _ in range(iterations):
        sample = [generator.choice(values) for _ in values]
        estimates.append(statistic(sample))
    return [percentile(estimates, 0.025), percentile(estimates, 0.975)]


def signed_rank(values):
    nonzero = [float(value) for value in values if value != 0]
    if not nonzero:
        return 1.0, 0.0
    ranks = rankdata([abs(value) for value in nonzero], method="average")
    positive = sum(rank for rank, value in zip(ranks, nonzero) if value > 0)
    negative = sum(rank for rank, value in zip(ranks, nonzero) if value < 0)
    total = positive + negative
    effect = (positive - negative) / total if total else 0.0
    result = wilcoxon(
        values,
        zero_method="wilcox",
        correction=False,
        alternative="two-sided",
        method="auto",
    )
    return float(result.pvalue), effect


def holm_family(row, load_campaigns):
    campaign_key = (
        row["environment"],
        row["campaign_id"],
        row["route"],
    )
    if row["fault_profile"] != "none" or row["fault_scope"] != "none":
        key = (
            "network-fault",
            row["route"],
            row["fault_scope"],
            row["comparison"],
        )
    elif campaign_key in load_campaigns:
        key = (
            "load",
            row["route"],
            row["n"],
            row["comparison"],
        )
    elif row["environment"] == "cloud-tcp" and row["fault_count"] == 0:
        key = ("primary", row["route"], row["comparison"])
    else:
        key = (
            "campaign",
            row["environment"],
            row["campaign_id"],
            row["route"],
            row["comparison"],
        )
    return key, ":".join(str(part) for part in key)


def apply_holm(rows):
    load_campaigns = {
        (row["environment"], row["campaign_id"], row["route"])
        for row in rows
        if row["pairs"] > 1
        and row["fault_profile"] == "none"
        and row["fault_scope"] == "none"
    }
    families = defaultdict(list)
    for row in rows:
        key, label = holm_family(row, load_campaigns)
        row["holm_family"] = label
        families[key].append(row)

    for family_rows in families.values():
        apply_holm_family(family_rows)


def apply_holm_family(rows):
    order = sorted(
        range(len(rows)),
        key=lambda index: rows[index]["wilcoxon_signed_rank_p"],
    )
    running = 0.0
    total = len(order)
    for rank, index in enumerate(order):
        adjusted = min(
            1.0,
            (total - rank) * rows[index]["wilcoxon_signed_rank_p"],
        )
        running = max(running, adjusted)
        rows[index]["holm_adjusted_p"] = running
        rows[index]["holm_family_size"] = total


def summarize(samples):
    groups = defaultdict(list)
    for sample in samples:
        key = (
            sample["environment"],
            sample["campaign_id"],
            sample["route"],
            sample["loss_pct"],
            sample["tls"],
            sample["variant"],
            sample["n"],
            sample["k"],
            sample["pairs"],
            sample["fault_count"],
            sample.get("fault_profile", "none"),
            sample.get("fault_scope", "none"),
        )
        groups[key].append(sample)

    rows = []
    for key, values in sorted(groups.items()):
        walls = [value["wall_ms"] for value in values]
        cpus = [value["cpu_ms"] for value in values]
        sent = [value["bytes_sent"] for value in values]
        received = [value["bytes_received"] for value in values]
        verifier = [value["verifier_ms"] for value in values]
        frames_sent = [value["frames_sent"] for value in values]
        frames_received = [value["frames_received"] for value in values]
        write_calls = [
            value.get("application_write_calls", 0) for value in values
        ]
        read_calls = [
            value.get("application_read_calls", 0) for value in values
        ]
        transport_writes = [
            value.get("transport_write_ops", 0) for value in values
        ]
        transport_reads = [
            value.get("transport_read_ops", 0) for value in values
        ]
        pair_p95 = [value.get("pair_wall_p95_ms", 0) for value in values]
        pair_p99 = [value.get("pair_wall_p99_ms", 0) for value in values]
        fairness = [value.get("pair_jain_fairness", 0) for value in values]
        pairs_per_second = [
            value["pairs"] * 1000.0 / value["wall_ms"]
            for value in values
            if value["wall_ms"] > 0
        ]
        application_goodput = [
            (value["bytes_sent"] + value["bytes_received"])
            * 8.0
            / (value["wall_ms"] * 1000.0)
            for value in values
            if value["wall_ms"] > 0
        ]
        process_cpu_utilization = [
            value["cpu_ms"] * 100.0 / value["wall_ms"]
            for value in values
            if value["wall_ms"] > 0
        ]
        rows.append(
            {
                "environment": key[0],
                "campaign_id": key[1],
                "route": key[2],
                "fault_profile": key[10],
                "fault_scope": key[11],
                "loss_pct": key[3],
                "tls": key[4],
                "variant": key[5],
                "n": key[6],
                "k": key[7],
                "pairs": key[8],
                "fault_count": key[9],
                "trials": len(values),
                "median_wall_ms": statistics.median(walls),
                "median_wall_95_ci_ms": bootstrap_ci(walls),
                "p95_wall_ms": percentile(walls, 0.95),
                "p95_wall_95_ci_ms": bootstrap_ci(
                    walls, lambda sample: percentile(sample, 0.95)
                ),
                "p99_wall_ms": percentile(walls, 0.99),
                "median_cpu_ms": statistics.median(cpus),
                "median_cpu_95_ci_ms": bootstrap_ci(cpus),
                "median_verifier_ms": statistics.median(verifier),
                "median_verifier_95_ci_ms": bootstrap_ci(verifier),
                "median_bytes_sent": statistics.median(sent),
                "median_bytes_received": statistics.median(received),
                "median_frames_sent": statistics.median(frames_sent),
                "median_frames_received": statistics.median(frames_received),
                "median_application_write_calls": statistics.median(
                    write_calls
                ),
                "median_application_read_calls": statistics.median(
                    read_calls
                ),
                "median_transport_write_ops": statistics.median(
                    transport_writes
                ),
                "median_transport_read_ops": statistics.median(
                    transport_reads
                ),
                "median_pair_wall_p95_ms": statistics.median(pair_p95),
                "median_pair_wall_p99_ms": statistics.median(pair_p99),
                "median_pair_jain_fairness": statistics.median(fairness),
                "median_pairs_per_second": statistics.median(
                    pairs_per_second
                ),
                "median_application_goodput_mbps": statistics.median(
                    application_goodput
                ),
                "median_process_cpu_utilization_pct": statistics.median(
                    process_cpu_utilization
                ),
                "total_failures": sum(value["failures"] for value in values),
                "total_retransmissions": sum(
                    value["retransmissions"] for value in values
                ),
            }
        )
    return rows


def paired_effects(samples):
    by_trial = defaultdict(dict)
    for sample in samples:
        key = (
            sample["environment"],
            sample["campaign_id"],
            sample["route"],
            sample["loss_pct"],
            sample["tls"],
            sample["n"],
            sample["k"],
            sample["pairs"],
            sample["fault_count"],
            sample.get("fault_profile", "none"),
            sample.get("fault_scope", "none"),
            sample["trial"],
        )
        by_trial[key][sample["variant"]] = sample

    comparisons = {
        "complete_method_vs_persistent_pipelined": (
            "batch-joint-presigning-batch-verification",
            "persistent-pipelined-itemwise",
        ),
        "batch_verification_with_batch_joint_presigning": (
            "batch-joint-presigning-batch-verification",
            "batch-joint-presigning-itemwise",
        ),
        "batch_joint_presigning_vs_persistent_pipelined": (
            "batch-joint-presigning-itemwise",
            "persistent-pipelined-itemwise",
        ),
        "batch_joint_presigning_vs_phase_coalesced_itemwise": (
            "batch-joint-presigning-itemwise",
            "phase-coalesced-itemwise",
        ),
        "batch_verification_with_phase_coalescing": (
            "phase-coalesced-batch-verification",
            "persistent-pipelined-itemwise",
        ),
        "batch_joint_presigning_vs_phase_coalesced_aggregate": (
            "batch-joint-presigning-batch-verification",
            "phase-coalesced-batch-verification",
        ),
        "phase_coalescing_vs_persistent_pipelined": (
            "phase-coalesced-itemwise",
            "persistent-pipelined-itemwise",
        ),
        "complete_method_vs_phase_coalesced_itemwise": (
            "batch-joint-presigning-batch-verification",
            "phase-coalesced-itemwise",
        ),
    }
    grouped = defaultdict(list)
    for key, variants in by_trial.items():
        for label, (candidate, baseline) in comparisons.items():
            if candidate not in variants or baseline not in variants:
                continue
            candidate_wall = variants[candidate]["wall_ms"]
            baseline_wall = variants[baseline]["wall_ms"]
            if baseline_wall <= 0:
                continue
            reduction = 100.0 * (baseline_wall - candidate_wall) / baseline_wall
            grouped[(
                key[0], key[1], key[2], key[3], key[4],
                key[5], key[6], key[7], key[8], key[9], key[10], label
            )].append(
                {
                    "reduction_pct": reduction,
                    "wall_difference_ms": baseline_wall - candidate_wall,
                }
            )

    rows = []
    for key, paired_values in sorted(grouped.items()):
        reductions = [value["reduction_pct"] for value in paired_values]
        differences = [value["wall_difference_ms"] for value in paired_values]
        p_value, effect = signed_rank(differences)
        rows.append(
            {
                "environment": key[0],
                "campaign_id": key[1],
                "route": key[2],
                "fault_profile": key[9],
                "fault_scope": key[10],
                "loss_pct": key[3],
                "tls": key[4],
                "n": key[5],
                "k": key[6],
                "pairs": key[7],
                "fault_count": key[8],
                "comparison": key[11],
                "paired_trials": len(reductions),
                "mean_wall_reduction_pct": statistics.mean(reductions),
                "median_wall_reduction_pct": statistics.median(reductions),
                "mean_bootstrap_95_ci_pct": bootstrap_ci(
                    reductions, statistics.mean
                ),
                "median_bootstrap_95_ci_pct": bootstrap_ci(reductions),
                "median_wall_difference_ms": statistics.median(differences),
                "wilcoxon_signed_rank_p": p_value,
                "wilcoxon_input": "baseline_wall_ms-candidate_wall_ms",
                "rank_biserial_effect": effect,
            }
        )
    apply_holm(rows)
    return rows


def markdown(summary, effects):
    lines = [
        "# OASIS benchmark summary",
        "",
        "## Distribution statistics",
        "",
        "| Campaign | Route | Profile | Scope | Loss | TLS | Variant | n | k | Pairs | Faults | Trials | Median wall [95% CI] (ms) | P95 [95% CI] (ms) | Median CPU [95% CI] (ms) | Verifier [95% CI] (ms) | Failures | Retrans |",
        "|---|---|---|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in summary:
        lines.append(
            f"| {row['campaign_id']} | {row['route']} | "
            f"{row['fault_profile']} | {row['fault_scope']} | "
            f"{row['loss_pct']:.1f}% | "
            f"{row['tls']} | {row['variant']} | {row['n']} | "
            f"{row['k']} | {row['pairs']} | {row['fault_count']} | {row['trials']} | "
            f"{row['median_wall_ms']:.3f} [{row['median_wall_95_ci_ms'][0]:.3f}, {row['median_wall_95_ci_ms'][1]:.3f}] | "
            f"{row['p95_wall_ms']:.3f} [{row['p95_wall_95_ci_ms'][0]:.3f}, {row['p95_wall_95_ci_ms'][1]:.3f}] | "
            f"{row['median_cpu_ms']:.3f} [{row['median_cpu_95_ci_ms'][0]:.3f}, {row['median_cpu_95_ci_ms'][1]:.3f}] | "
            f"{row['median_verifier_ms']:.3f} [{row['median_verifier_95_ci_ms'][0]:.3f}, {row['median_verifier_95_ci_ms'][1]:.3f}] | "
            f"{row['total_failures']} | {row['total_retransmissions']} |"
        )
    lines.extend(
        [
            "",
            "## Transport instrumentation",
            "",
            "Counts are medians per measured trial. TLS records and TCP segments are derived from packet capture, not inferred here.",
            "",
            "| Campaign | Route | Variant | n | Pairs | Pairs/s | App goodput Mbps | Process CPU % | Bytes sent | Bytes received | Frames sent | App writes | Transport writes | Pair P95 ms | Pair P99 ms | Jain fairness |",
            "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in summary:
        lines.append(
            f"| {row['campaign_id']} | {row['route']} | {row['variant']} | "
            f"{row['n']} | {row['pairs']} | "
            f"{row['median_pairs_per_second']:.3f} | "
            f"{row['median_application_goodput_mbps']:.6f} | "
            f"{row['median_process_cpu_utilization_pct']:.2f} | "
            f"{row['median_bytes_sent']:.0f} | "
            f"{row['median_bytes_received']:.0f} | {row['median_frames_sent']:.0f} | "
            f"{row['median_application_write_calls']:.0f} | "
            f"{row['median_transport_write_ops']:.0f} | "
            f"{row['median_pair_wall_p95_ms']:.3f} | "
            f"{row['median_pair_wall_p99_ms']:.3f} | "
            f"{row['median_pair_jain_fairness']:.4f} |"
        )
    lines.extend(
        [
            "",
            "## Paired wall-time effects",
            "",
            "Positive reduction means the candidate is faster than the baseline.",
            "",
            "Wilcoxon tests and rank-biserial effects use paired wall-time differences; percentage reductions are descriptive effect summaries.",
            "",
            "| Campaign | Route | Profile | Scope | Loss | Comparison | n | k | Pairs | Faults | Paired trials | Mean reduction [95% CI] | Median reduction [95% CI] | Rank-biserial | Holm family | Holm p |",
            "|---|---|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|",
        ]
    )
    for row in effects:
        mean_low, mean_high = row["mean_bootstrap_95_ci_pct"]
        median_low, median_high = row["median_bootstrap_95_ci_pct"]
        lines.append(
            f"| {row['campaign_id']} | {row['route']} | "
            f"{row['fault_profile']} | {row['fault_scope']} | "
            f"{row['loss_pct']:.1f}% | "
            f"{row['comparison']} | {row['n']} | "
            f"{row['k']} | {row['pairs']} | {row['fault_count']} | {row['paired_trials']} | "
            f"{row['mean_wall_reduction_pct']:.2f}% [{mean_low:.2f}%, {mean_high:.2f}%] | "
            f"{row['median_wall_reduction_pct']:.2f}% [{median_low:.2f}%, {median_high:.2f}%] | "
            f" {row['rank_biserial_effect']:.3f} | "
            f"{row['holm_family']} ($m={row['holm_family_size']}$) | "
            f"{row['holm_adjusted_p']:.4g} |"
        )
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--md-out", type=Path, required=True)
    args = parser.parse_args()

    samples = []
    for path in args.inputs:
        payload = json.loads(path.read_text())
        if payload.get("schema") != "oasis-conformance-transport-v1":
            raise SystemExit(f"unsupported schema in {path}")
        samples.extend(payload["samples"])

    summary = summarize(samples)
    effects = paired_effects(samples)
    result = {
        "schema": "oasis-conformance-analysis-v1",
        "statistics": {
            "paired_test": "scipy.stats.wilcoxon",
            "wilcoxon_zero_method": "wilcox",
            "wilcoxon_alternative": "two-sided",
            "wilcoxon_method": "auto",
            "wilcoxon_input": "baseline_wall_ms-candidate_wall_ms",
            "multiple_testing": (
                "Holm step-down within analysis-pipeline-defined scientific "
                "families; these families were not preregistered"
            ),
        },
        "source_files": [str(path) for path in args.inputs],
        "summary": summary,
        "paired_effects": effects,
    }
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.md_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    args.md_out.write_text(markdown(summary, effects))
    print(f"wrote={args.json_out}")
    print(f"wrote={args.md_out}")


if __name__ == "__main__":
    main()
