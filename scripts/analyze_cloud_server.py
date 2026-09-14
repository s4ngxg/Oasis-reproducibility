#!/usr/bin/env python3
"""Summarize per-connection server metrics with bootstrap intervals."""

import argparse
import json
import random
import statistics
from collections import defaultdict
from pathlib import Path


def percentile(values, probability):
    ordered = sorted(values)
    if not ordered:
        return 0.0
    position = (len(ordered) - 1) * probability
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def bootstrap_median_ci(values, iterations=10000, seed=0x53455256):
    if not values:
        return [0.0, 0.0]
    ordered = sorted(values)
    count = len(ordered)
    generator = random.Random(seed)
    estimates = []
    if count % 2:
        median_rank = count // 2 + 1
        for _ in range(iterations):
            quantile = generator.betavariate(
                median_rank, count - median_rank + 1
            )
            index = min(int(quantile * count), count - 1)
            estimates.append(ordered[index])
    else:
        lower_rank = count // 2
        for _ in range(iterations):
            # The two central uniform order statistics have Dirichlet
            # spacings (lower_rank, 1, count-lower_rank). Mapping them onto
            # the empirical CDF produces the exact nonparametric bootstrap
            # median without materializing an O(count) resample.
            lower_mass = generator.gammavariate(lower_rank, 1.0)
            gap_mass = generator.gammavariate(1.0, 1.0)
            upper_mass = generator.gammavariate(
                count - lower_rank, 1.0
            )
            total = lower_mass + gap_mass + upper_mass
            lower_index = min(
                int(count * lower_mass / total), count - 1
            )
            upper_index = min(
                int(count * (lower_mass + gap_mass) / total), count - 1
            )
            estimates.append(
                (ordered[lower_index] + ordered[upper_index]) / 2.0
            )
    return [percentile(estimates, 0.025), percentile(estimates, 0.975)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--campaign-id")
    parser.add_argument("--route")
    parser.add_argument(
        "--include-campaign-prefix", action="append", default=[]
    )
    parser.add_argument(
        "--exclude-campaign-prefix", action="append", default=[]
    )
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    groups = defaultdict(list)
    for path in args.inputs:
        for line_number, line in enumerate(path.read_text().splitlines(), 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as error:
                raise SystemExit(f"{path}:{line_number}: {error}") from error
            campaign_id = row.get("campaign_id", args.campaign_id)
            route = row.get("route", args.route)
            if not campaign_id or not route:
                raise SystemExit(
                    f"{path}:{line_number}: older-format row requires "
                    "--campaign-id and --route"
                )
            if (
                args.include_campaign_prefix
                and not any(
                    campaign_id.startswith(prefix)
                    for prefix in args.include_campaign_prefix
                )
            ):
                continue
            if any(
                campaign_id.startswith(prefix)
                for prefix in args.exclude_campaign_prefix
            ):
                continue
            key = (
                campaign_id,
                route,
                row.get("fault_profile", "none"),
                row.get("fault_scope", "none"),
                row.get("loss_pct", 0),
                row.get("tls", False),
                row["variant"],
                row["n"],
                row["k"],
                row.get("pairs", 1),
            )
            groups[key].append(row)

    results = []
    for key, rows in sorted(groups.items()):
        (
            campaign_id,
            route,
            fault_profile,
            fault_scope,
            loss_pct,
            tls,
            variant,
            n,
            k,
            pairs,
        ) = key
        cpu = [row["server_thread_cpu_ms"] for row in rows]
        rss = [row["current_rss_kb"] for row in rows]
        cpu_utilization = [
            row["server_thread_cpu_ms"] * 100.0 / row["server_wall_ms"]
            for row in rows
            if row.get("server_wall_ms", 0) > 0
        ]
        results.append({
            "campaign_id": campaign_id,
            "route": route,
            "fault_profile": fault_profile,
            "fault_scope": fault_scope,
            "loss_pct": loss_pct,
            "tls": tls,
            "variant": variant,
            "n": n,
            "k": k,
            "pairs": pairs,
            "connections": len(rows),
            "median_server_thread_cpu_ms": statistics.median(cpu),
            "median_server_thread_cpu_95_ci_ms": bootstrap_median_ci(cpu),
            "median_server_thread_cpu_utilization_pct": (
                statistics.median(cpu_utilization)
                if cpu_utilization
                else None
            ),
            "median_current_rss_kb": statistics.median(rss),
            "median_current_rss_95_ci_kb": bootstrap_median_ci(rss),
            "peak_rss_kb": max(row["peak_rss_kb"] for row in rows),
            "max_active_connections": max(
                row["max_active_seen"] for row in rows
            ),
            "total_retransmissions": sum(
                row["total_retrans"] for row in rows
            ),
        })

    payload = {
        "schema": "oasis-server-analysis-v1",
        "source_files": [str(path) for path in args.inputs],
        "include_campaign_prefixes": args.include_campaign_prefix,
        "exclude_campaign_prefixes": args.exclude_campaign_prefix,
        "results": results,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2) + "\n")
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
