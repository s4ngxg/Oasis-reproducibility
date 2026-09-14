#!/usr/bin/env python3
"""Annotate sequential load-sweep server telemetry with its pair count."""

import argparse
import json
from pathlib import Path


def parse_ints(value):
    return [int(item) for item in value.replace(",", " ").split()]


def segment_rows(rows, pair_values, n_count, variant_count, trials, warmup):
    segmented = []
    offset = 0
    runs_per_pair = n_count * variant_count * (trials + warmup)
    expected_total = runs_per_pair * sum(pair_values)
    if len(rows) != expected_total:
        raise ValueError(
            f"expected {expected_total} rows, found {len(rows)}"
        )

    for pairs in pair_values:
        count = runs_per_pair * pairs
        segment = rows[offset:offset + count]
        groups = {}
        for row in segment:
            key = (row["variant"], int(row["n"]))
            groups.setdefault(key, []).append(row)
        if len(groups) != n_count * variant_count:
            raise ValueError(
                f"p={pairs}: expected {n_count * variant_count} "
                f"variant/n groups, found {len(groups)}"
            )
        expected_rows = pairs * (trials + warmup)
        reference_ids = None
        for key, group in groups.items():
            pair_ids = {int(row["pair_id"]) for row in group}
            if len(group) != expected_rows:
                raise ValueError(
                    f"p={pairs} group={key}: expected {expected_rows} rows, "
                    f"found {len(group)}"
                )
            if len(pair_ids) != expected_rows:
                raise ValueError(
                    f"p={pairs} group={key}: expected {expected_rows} "
                    f"unique pair IDs, found {len(pair_ids)}"
                )
            if reference_ids is None:
                reference_ids = pair_ids
            elif pair_ids != reference_ids:
                raise ValueError(
                    f"p={pairs} group={key}: pair IDs do not match "
                    "the other variant/n groups"
                )
        for row in segment:
            if "pairs" in row and int(row["pairs"]) != pairs:
                raise ValueError(f"p={pairs}: conflicting pairs field")
            annotated = dict(row)
            annotated["pairs"] = pairs
            segmented.append(annotated)
        offset += count
    return segmented


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--pair-values", default="1,64,128,1024")
    parser.add_argument("--n-count", type=int, default=2)
    parser.add_argument("--variant-count", type=int, default=5)
    parser.add_argument("--trials", type=int, default=20)
    parser.add_argument("--warmup", type=int, default=5)
    args = parser.parse_args()

    rows = [
        json.loads(line)
        for line in args.input.read_text().splitlines()
        if line.strip()
    ]
    segmented = segment_rows(
        rows,
        parse_ints(args.pair_values),
        args.n_count,
        args.variant_count,
        args.trials,
        args.warmup,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w") as output:
        for row in segmented:
            output.write(json.dumps(row, separators=(",", ":")) + "\n")
    print(f"wrote={args.out} rows={len(segmented)}")


if __name__ == "__main__":
    main()
