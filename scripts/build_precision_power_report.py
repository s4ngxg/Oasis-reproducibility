#!/usr/bin/env python3
"""Build a transparent precision/MDE report from paired analysis JSON."""

from __future__ import annotations

import argparse
import json
import math
import statistics
from pathlib import Path

from scipy.stats import norm


def normal_quantile(probability: float) -> float:
    if not 0.0 < probability < 1.0:
        raise ValueError("probability must be in (0,1)")
    return float(norm.ppf(probability))


def raw_differences(row: dict) -> list[float]:
    values = row.get("raw_paired_differences_ms", [])
    if isinstance(values, str):
        values = json.loads(values)
    return [float(value) for value in values]


def load_rows(paths: list[Path]) -> list[dict]:
    rows: list[dict] = []
    for path in paths:
        payload = json.loads(path.read_text(encoding="utf-8"))
        rows.extend(payload.get("paired_effects", []))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, nargs="+", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--power", type=float, default=0.80)
    args = parser.parse_args()
    if not 0.5 < args.power < 1.0:
        parser.error("--power must be in (0.5,1)")
    z_alpha = normal_quantile(0.975)
    z_power = normal_quantile(args.power)
    report = []
    for row in load_rows(args.input):
        differences = raw_differences(row)
        if len(differences) < 2:
            continue
        sd = statistics.stdev(differences)
        n = len(differences)
        mde_ms = (z_alpha + z_power) * sd / math.sqrt(n)
        report.append({
            "route": row.get("route"),
            "participants": row.get("participants"),
            "concurrent_pairs": row.get("concurrent_pairs"),
            "comparison": row.get("comparison"),
            "metric": row.get("effect_metric"),
            "paired_trials": n,
            "paired_difference_sd_ms": sd,
            "observed_median_difference_ms": row.get("median_difference_ms"),
            "reported_median_difference_ci95_ms": row.get(
                "median_difference_ci95_ms"
            ),
            "approximate_two_sided_mde_ms": mde_ms,
            "planning_note": (
                "Normal approximation for a paired-mean planning diagnostic; "
                "the paper's primary estimand remains paired median reduction."
            ),
        })
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({
        "schema": "oasis-precision-power-report-v1",
        "alpha": 0.05,
        "target_power": args.power,
        "rows": report,
    }, indent=2) + "\n", encoding="utf-8")
    print(f"wrote={args.output} rows={len(report)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
