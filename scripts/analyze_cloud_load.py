#!/usr/bin/env python3
"""Find sustainable complete-pair load from codefinal raw sample files."""

import argparse
import glob
import json
import statistics
from collections import defaultdict
from pathlib import Path


def percentile(values, fraction):
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("patterns", nargs="+")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    files = []
    for pattern in args.patterns:
        files.extend(Path(path) for path in glob.glob(pattern))
    if not files:
        raise SystemExit("no input files")

    groups = defaultdict(list)
    for path in files:
        payload = json.loads(path.read_text())
        if payload.get("schema") != "oasis-conformance-transport-v1":
            raise SystemExit(f"unsupported schema in {path}")
        for sample in payload["samples"]:
            key = (
                sample["campaign_id"],
                sample["route"],
                sample["loss_pct"],
                sample["tls"],
                sample["variant"],
                sample["n"],
                sample["k"],
                sample["pairs"],
                sample.get("fault_profile", "none"),
                sample.get("fault_scope", "none"),
            )
            groups[key].append(sample)

    rows = []
    for key, samples in sorted(groups.items()):
        wall = [sample["wall_ms"] for sample in samples]
        attempts = len(samples) * key[7]
        failures = sum(sample["failures"] for sample in samples)
        rows.append(
            {
                "campaign_id": key[0],
                "route": key[1],
                "fault_profile": key[8],
                "fault_scope": key[9],
                "loss_pct": key[2],
                "tls": key[3],
                "variant": key[4],
                "n": key[5],
                "k": key[6],
                "pairs": key[7],
                "trials": len(samples),
                "median_wall_ms": statistics.median(wall),
                "p95_wall_ms": percentile(wall, 0.95),
                "p99_wall_ms": percentile(wall, 0.99),
                "median_pair_wall_p95_ms": statistics.median(
                    sample.get("pair_wall_p95_ms", 0) for sample in samples
                ),
                "median_pair_wall_p99_ms": statistics.median(
                    sample.get("pair_wall_p99_ms", 0) for sample in samples
                ),
                "median_pair_jain_fairness": statistics.median(
                    sample.get("pair_jain_fairness", 0)
                    for sample in samples
                ),
                "error_rate_pct": 100.0 * failures / attempts if attempts else 0,
                "median_pairs_per_second": statistics.median(
                    key[7] * 1000.0 / value for value in wall
                ),
                "median_application_goodput_mbps": statistics.median(
                    (
                        sample["bytes_sent"] + sample["bytes_received"]
                    ) * 8.0 / (sample["wall_ms"] * 1000.0)
                    for sample in samples
                    if sample["wall_ms"] > 0
                ),
                "median_process_cpu_utilization_pct": statistics.median(
                    sample["cpu_ms"] * 100.0 / sample["wall_ms"]
                    for sample in samples
                    if sample["wall_ms"] > 0
                ),
            }
        )

    sustainable = []
    configurations = sorted({
        (
            row["campaign_id"], row["route"], row["loss_pct"],
            row["tls"], row["variant"], row["n"], row["k"],
            row["fault_profile"], row["fault_scope"]
        )
        for row in rows
    })
    for configuration in configurations:
        candidates = [
            row for row in rows
            if (
                row["campaign_id"], row["route"], row["loss_pct"],
                row["tls"], row["variant"], row["n"], row["k"],
                row["fault_profile"], row["fault_scope"]
            ) == configuration
        ]
        baseline = next(
            (row for row in candidates if row["pairs"] == 1), None
        )
        if baseline is None:
            raise SystemExit(
                "load analysis requires a p=1 reference for "
                f"campaign={configuration[0]} variant={configuration[4]} "
                f"n={configuration[5]}"
            )
        base = baseline["p95_wall_ms"]
        accepted = [
            row
            for row in candidates
            if row["error_rate_pct"] == 0
            and row["p95_wall_ms"] <= 2 * base
        ]
        sustainable.append({
            "campaign_id": configuration[0],
            "route": configuration[1],
            "loss_pct": configuration[2],
            "tls": configuration[3],
            "variant": configuration[4],
            "n": configuration[5],
            "k": configuration[6],
            "fault_profile": configuration[7],
            "fault_scope": configuration[8],
            "maximum_sustainable_pairs": max(
                (row["pairs"] for row in accepted), default=0
            ),
        })

    result = {
        "saturation_rule": (
            "largest p with 0% errors and P95 <= 2x P95 at p=1"
        ),
        "maximum_sustainable_pairs": sustainable,
        "results": rows,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
