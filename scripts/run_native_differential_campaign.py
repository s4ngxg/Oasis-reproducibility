#!/usr/bin/env python3
"""Run deterministic differential checks against the native C/RELIC core."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BINARY = (
    ROOT / "vendor" / "paraswap" / "two-party computation" / "bin"
    / "joint_presign_test"
)
CORE_SOURCE = (
    ROOT / "vendor" / "paraswap" / "two-party computation" / "src"
    / "preswap_joint.c"
)
TEST_SOURCE = (
    ROOT / "vendor" / "paraswap" / "two-party computation" / "src"
    / "joint_presign_test.c"
)
SOURCE_FILES = (
    CORE_SOURCE,
    TEST_SOURCE,
    ROOT / "vendor" / "paraswap" / "two-party computation" / "src"
    / "util.c",
    ROOT / "vendor" / "paraswap" / "two-party computation" / "src"
    / "bob.c",
    ROOT / "vendor" / "paraswap" / "two-party computation" / "src"
    / "tumbler.c",
    ROOT / "vendor" / "paraswap-artifact.lock.json",
)
COUNTERS = (
    "valid_server_partial_checks",
    "valid_client_partial_checks",
    "valid_full_presignature_checks",
    "mutated_server_partial_rejections",
    "mutated_client_partial_rejections",
    "mutated_full_presignature_rejections",
    "subrange_checks",
    "exact_localization_checks",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ranges(total: int, workers: int) -> list[tuple[int, int]]:
    base, extra = divmod(total, workers)
    offset = 0
    chunks = []
    for worker in range(workers):
        count = base + (1 if worker < extra else 0)
        if count:
            chunks.append((offset, count))
            offset += count
    return chunks


def run_chunk(binary: Path, directory: Path,
              chunk: tuple[int, int]) -> dict[str, object]:
    offset, count = chunk
    output = directory / f"chunk-{offset}-{count}.json"
    process = subprocess.run(
        [
            str(binary),
            "--vectors", str(count),
            "--vector-offset", str(offset),
            "--out", str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if process.returncode != 0:
        raise RuntimeError(
            f"native differential chunk offset={offset} count={count} "
            f"failed:\n{process.stdout}\n{process.stderr}"
        )
    report = json.loads(output.read_text(encoding="utf-8"))
    if (
        report.get("schema") != "oasis-native-differential-v1"
        or report.get("status") != "pass"
        or report.get("backend") != "native-c11-relic"
        or report.get("vector_offset") != offset
        or report.get("differential_vectors") != count
    ):
        raise RuntimeError(f"invalid native differential report: {report}")
    for field in COUNTERS:
        if field == "subrange_checks":
            expected = 3 * count
        elif field == "exact_localization_checks":
            expected = 3 * 7 * count
        else:
            expected = count
        if report.get(field) != expected:
            raise RuntimeError(
                f"invalid {field} for chunk {offset}: "
                f"{report.get(field)} != {expected}"
            )
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--vectors", type=int, default=100_000)
    parser.add_argument("--workers", type=int, default=0)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.vectors <= 0:
        parser.error("--vectors must be positive")
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error(f"native test binary does not exist: {binary}")
    workers = args.workers or min(8, os.cpu_count() or 1)
    workers = max(1, min(workers, args.vectors))
    chunks = ranges(args.vectors, workers)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="oasis-native-differential-") as raw:
        directory = Path(raw)
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=workers
        ) as executor:
            reports = list(
                executor.map(
                    lambda chunk: run_chunk(binary, directory, chunk), chunks
                )
            )
    reports.sort(key=lambda row: int(row["vector_offset"]))
    expected_offset = 0
    for report in reports:
        if report["vector_offset"] != expected_offset:
            raise RuntimeError("native differential ranges are not contiguous")
        expected_offset += int(report["differential_vectors"])
    if expected_offset != args.vectors:
        raise RuntimeError("native differential campaign has incomplete coverage")
    result = {
        "schema": "oasis-native-differential-campaign-v1",
        "status": "pass",
        "backend": "native-c11-relic",
        "generator": "splitmix64-domain-separated",
        "differential_vectors": args.vectors,
        "workers": workers,
        "elapsed_seconds": time.monotonic() - started,
        "binary_sha256": sha256(binary),
        "core_source_sha256": sha256(CORE_SOURCE),
        "test_source_sha256": sha256(TEST_SOURCE),
        "source_sha256": {
            str(path.relative_to(ROOT)): sha256(path)
            for path in SOURCE_FILES
        },
        "runner_sha256": sha256(Path(__file__)),
        "ranges": [
            {
                "offset": int(report["vector_offset"]),
                "count": int(report["differential_vectors"]),
            }
            for report in reports
        ],
        "checks": {
            field: sum(int(report[field]) for report in reports)
            for field in COUNTERS
        },
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
