#!/usr/bin/env python3
"""Run disjoint verifier-test ranges in isolated native processes."""

import argparse
import concurrent.futures
import json
import os
import pathlib
import subprocess
import tempfile
import time


def ranges(total: int, workers: int):
    base, extra = divmod(total, workers)
    offset = 0
    for worker in range(workers):
        count = base + (1 if worker < extra else 0)
        if count:
            yield offset, count
            offset += count


def run_chunk(binary: pathlib.Path, directory: pathlib.Path, chunk):
    offset, count = chunk
    output = directory / f"chunk_{offset}_{count}.json"
    command = [
        str(binary),
        "test",
        "--vectors",
        str(count),
        "--vector-offset",
        str(offset),
        "--out",
        str(output),
    ]
    completed = subprocess.run(
        command, check=False, text=True, capture_output=True
    )
    if completed.returncode:
        raise RuntimeError(
            f"chunk offset={offset} count={count} failed:\n"
            f"{completed.stdout}\n{completed.stderr}"
        )
    return json.loads(output.read_text())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--vectors", type=int, default=100_000)
    parser.add_argument("--workers", type=int, default=0)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()

    if args.vectors <= 0:
        parser.error("--vectors must be positive")
    cpu_count = os.cpu_count() or 1
    workers = args.workers or min(8, cpu_count)
    workers = max(1, min(workers, args.vectors))
    chunks = list(ranges(args.vectors, workers))
    started = time.monotonic()

    with tempfile.TemporaryDirectory(prefix="oasis-differential-") as temp:
        directory = pathlib.Path(temp)
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=workers
        ) as executor:
            reports = list(
                executor.map(
                    lambda chunk: run_chunk(
                        args.binary.resolve(), directory, chunk
                    ),
                    chunks,
                )
            )

    reports.sort(key=lambda report: report["vector_offset"])
    expected_offset = 0
    for report in reports:
        if report["status"] != "pass":
            raise RuntimeError("a differential chunk did not pass")
        if report["vector_offset"] != expected_offset:
            raise RuntimeError("differential chunks are not contiguous")
        expected_offset += report["differential_vectors"]
    if expected_offset != args.vectors:
        raise RuntimeError("differential campaign has incomplete coverage")

    output = {
        "status": "pass",
        "differential_vectors": args.vectors,
        "workers": workers,
        "ranges": [
            {
                "offset": report["vector_offset"],
                "count": report["differential_vectors"],
            }
            for report in reports
        ],
        "differential_schedule": reports[0]["differential_schedule"],
        "mutation_checks_per_process": reports[0]["mutation_checks"],
        "replay_checks_per_process": reports[0]["replay_checks"],
        "retry_checks_per_process": reports[0]["retry_checks"],
        "adaptation_checks_per_process": reports[0]["adaptation_checks"],
        "key_separation_checks_per_process": reports[0][
            "key_separation_checks"
        ],
        "elapsed_seconds": time.monotonic() - started,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
