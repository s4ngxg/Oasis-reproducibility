#!/usr/bin/env python3
"""Validate and summarize dedicated allocation or syscall campaigns."""

from __future__ import annotations

import argparse
import json
import statistics
from collections import defaultdict
from pathlib import Path

import analyze_cloud_results as common


ALLOCATION_FIELDS = (
    "malloc_calls", "calloc_calls", "realloc_calls", "free_calls",
    "requested_allocation_bytes",
)
NETWORK_SYSCALLS = {
    "send", "sendto", "sendmsg", "sendmmsg", "recv", "recvfrom",
    "recvmsg", "recvmmsg", "read", "write", "poll", "ppoll",
    "select", "pselect6", "epoll_wait", "epoll_pwait", "epoll_ctl",
}


def syscall_counts(row: dict[str, object]) -> dict[str, int]:
    """Return endpoint syscall counts without inventing per-session attribution."""
    arc_maps = [arc.get("syscall_counts") for arc in row["arcs"]]
    if arc_maps and all(isinstance(counts, dict) for counts in arc_maps):
        sources = arc_maps
    else:
        profile = row.get("process_profile")
        if not isinstance(profile, dict):
            raise ValueError(f"missing process syscall profile for {common.sample_key(row)}")
        gateway = profile.get("gateway")
        worker_pool = profile.get("worker_pool")
        if not isinstance(gateway, dict) or not isinstance(worker_pool, dict):
            raise ValueError(f"missing worker-pool syscall profile for {common.sample_key(row)}")
        workers = worker_pool.get("workers")
        if not isinstance(workers, list):
            raise ValueError(f"missing worker syscall profiles for {common.sample_key(row)}")
        sources = [gateway.get("syscall_counts")] + [
            worker.get("syscall_counts")
            for worker in workers
            if isinstance(worker, dict)
        ]
        if not sources or not all(isinstance(counts, dict) for counts in sources):
            raise ValueError(f"incomplete worker-pool syscall maps for {common.sample_key(row)}")
    combined: dict[str, int] = defaultdict(int)
    for counts in sources:
        for name, count in counts.items():
            combined[str(name)] += int(count)
    return dict(combined)


def runtime_without_output(payload: dict[str, object]) -> dict[str, object]:
    runtime = dict(payload["runtime"])
    runtime.pop("profile_output_dir", None)
    return runtime


def validate_profile_sample(row: dict[str, object], mode: str) -> None:
    if mode == "allocation":
        if any(int(row.get(field, -1)) < 0 for field in ALLOCATION_FIELDS):
            raise ValueError(f"missing allocation telemetry for {common.sample_key(row)}")
        if int(row["malloc_calls"]) + int(row["calloc_calls"]) <= 0:
            raise ValueError(f"empty allocation telemetry for {common.sample_key(row)}")
    elif mode == "syscall":
        if int(row.get("total_syscalls", 0)) <= 0:
            raise ValueError(f"missing syscall telemetry for {common.sample_key(row)}")
        counts = syscall_counts(row)
        if sum(counts.values()) != int(row["total_syscalls"]):
            raise ValueError(f"syscall total mismatch for {common.sample_key(row)}")


def summarize(client: dict[str, object], server: dict[str, object],
              profile_mode: str) -> list[dict[str, object]]:
    server_index = common.indexed_samples(server, "server")
    grouped: dict[tuple[int, int, str], list[tuple[dict, dict]]] = defaultdict(list)
    for client_row in client["samples"]:
        key = common.sample_key(client_row)
        grouped[(key[0], key[1], key[2])].append((client_row, server_index[key]))

    output = []
    for (n, p, configuration), rows in sorted(grouped.items()):
        row = {
            "participants": n,
            "items_per_arc": 2 * n - 1,
            "concurrent_pairs": p,
            "configuration": configuration,
            "trials": len(rows),
        }
        if profile_mode == "allocation":
            for endpoint, index in (("initiator", 0), ("responder", 1)):
                for field in ALLOCATION_FIELDS:
                    row[f"median_{endpoint}_{field}_per_pair"] = statistics.median(
                        int(pair[index][field]) / p for pair in rows
                    )
        else:
            for endpoint, index in (("initiator", 0), ("responder", 1)):
                totals = []
                network = []
                errors = []
                for pair in rows:
                    sample = pair[index]
                    totals.append(int(sample["total_syscalls"]) / p)
                    errors.append(int(sample["total_syscall_errors"]) / p)
                    counts = syscall_counts(sample)
                    network.append(sum(
                        int(count)
                        for name, count in counts.items()
                        if name in NETWORK_SYSCALLS
                    ) / p)
                row[f"median_{endpoint}_syscalls_per_pair"] = statistics.median(totals)
                row[f"median_{endpoint}_network_syscalls_per_pair"] = statistics.median(network)
                row[f"median_{endpoint}_syscall_errors_per_pair"] = statistics.median(errors)
        output.append(row)
    return output


def render(report: dict[str, object]) -> str:
    mode = report["profiling_mode"]
    lines = [
        "# Native systems profile",
        "",
        f"Campaign: `{report['campaign_id']}`. Profile: `{mode}`.",
        "Timing values from this instrumented campaign are not primary latency evidence.",
        "",
    ]
    if mode == "allocation":
        lines.extend([
            "| n | k | p | Configuration | Trials | Initiator alloc calls/pair | Responder alloc calls/pair | Initiator requested bytes/pair | Responder requested bytes/pair |",
            "|---:|---:|---:|---|---:|---:|---:|---:|---:|",
        ])
        for row in report["summary"]:
            initiator_calls = sum(
                row[f"median_initiator_{field}_per_pair"]
                for field in ALLOCATION_FIELDS[:3]
            )
            responder_calls = sum(
                row[f"median_responder_{field}_per_pair"]
                for field in ALLOCATION_FIELDS[:3]
            )
            lines.append(
                f"| {row['participants']} | {row['items_per_arc']} | {row['concurrent_pairs']} | "
                f"{row['configuration']} | {row['trials']} | {initiator_calls:.1f} | "
                f"{responder_calls:.1f} | "
                f"{row['median_initiator_requested_allocation_bytes_per_pair']:.1f} | "
                f"{row['median_responder_requested_allocation_bytes_per_pair']:.1f} |"
            )
    else:
        lines.extend([
            "| n | k | p | Configuration | Trials | Initiator syscalls/pair | Responder syscalls/pair | Initiator network syscalls/pair | Responder network syscalls/pair |",
            "|---:|---:|---:|---|---:|---:|---:|---:|---:|",
        ])
        for row in report["summary"]:
            lines.append(
                f"| {row['participants']} | {row['items_per_arc']} | {row['concurrent_pairs']} | "
                f"{row['configuration']} | {row['trials']} | "
                f"{row['median_initiator_syscalls_per_pair']:.1f} | "
                f"{row['median_responder_syscalls_per_pair']:.1f} | "
                f"{row['median_initiator_network_syscalls_per_pair']:.1f} | "
                f"{row['median_responder_network_syscalls_per_pair']:.1f} |"
            )
    lines.extend([
        "",
        "Both endpoints used ZeroMQ CURVE with responder-key pinning and a ZAP initiator-key allowlist.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("client", type=Path)
    parser.add_argument("server", type=Path)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--md-out", type=Path, required=True)
    args = parser.parse_args()
    client = json.loads(args.client.read_text(encoding="utf-8"))
    server = json.loads(args.server.read_text(encoding="utf-8"))
    profile_mode = client.get("runtime", {}).get("profiling_mode")
    if profile_mode not in {"allocation", "syscall"}:
        raise ValueError("expected an allocation or syscall campaign")
    common.validate_role(client, "client", profile_mode)
    common.validate_role(server, "server", profile_mode)
    for field in (
        "campaign_id", "route", "participants", "concurrent_pair_values",
        "modes", "trials", "warmup", "provenance", "transport_security",
    ):
        if client.get(field) != server.get(field):
            raise ValueError(f"client/server {field} mismatch")
    if runtime_without_output(client) != runtime_without_output(server):
        raise ValueError("client/server runtime mismatch")
    if client["environment"]["protocol_source_sha256"] != server["environment"]["protocol_source_sha256"]:
        raise ValueError("client/server source mismatch")
    client_rows = common.indexed_samples(client, "client")
    server_rows = common.indexed_samples(server, "server")
    if set(client_rows) != set(server_rows):
        raise ValueError("client/server sample sets differ")
    for key in sorted(client_rows):
        common.validate_audit(client_rows[key], server_rows[key])
        validate_profile_sample(client_rows[key], profile_mode)
        validate_profile_sample(server_rows[key], profile_mode)
    report = {
        "schema": "oasis-preswap-system-profile-v1",
        "campaign_id": client["campaign_id"],
        "route": client["route"],
        "profiling_mode": profile_mode,
        "summary": summarize(client, server, profile_mode),
        "matched_samples": len(client_rows),
        "transport_security": client["transport_security"],
    }
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    args.md_out.write_text(render(report), encoding="utf-8")
    print(f"wrote={args.json_out}")
    print(f"wrote={args.md_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
