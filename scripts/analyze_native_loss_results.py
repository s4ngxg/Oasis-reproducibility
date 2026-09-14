#!/usr/bin/env python3
"""Validate and summarize paired native C/RELIC packet-loss campaigns."""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    index = (len(ordered) - 1) * q
    lower = int(index)
    upper = min(lower + 1, len(ordered) - 1)
    weight = index - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def sample_key(row: dict[str, object]) -> tuple[object, ...]:
    return (
        row["participants"], row["items_per_arc"], row["concurrent_pairs"],
        row["mode"], row["trial"], row["paired_trial_id"],
    )


def load_manifest(path: Path) -> tuple[dict[str, object], dict[str, object]]:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("schema") != "oasis-native-loss-evidence-v1":
        raise ValueError(f"invalid loss manifest schema: {path}")
    result_path = path.parent / str(manifest["result_file"])
    evidence_path = path.parent / str(manifest["tc_evidence_file"])
    if sha256(result_path) != manifest["result_sha256"]:
        raise ValueError(f"result checksum mismatch: {result_path}")
    if sha256(evidence_path) != manifest["tc_evidence_sha256"]:
        raise ValueError(f"tc evidence checksum mismatch: {evidence_path}")
    result = json.loads(result_path.read_text(encoding="utf-8"))
    if len(result.get("samples", [])) != manifest["sample_count"]:
        raise ValueError(f"sample count mismatch: {result_path}")
    if any(
        result.get(field) != manifest.get(field)
        for field in ("role", "route", "campaign_id")
    ):
        raise ValueError(f"result identity mismatch: {result_path}")
    if (
        result.get("schema") != manifest.get("result_schema")
        or result.get("environment", {}).get("protocol_source_sha256")
        != manifest.get("protocol_source_sha256")
        or result.get("provenance", {}).get("runner_sha256")
        != manifest.get("campaign_runner_sha256")
    ):
        raise ValueError(f"result provenance mismatch: {result_path}")
    return manifest, result


def validate_endpoint_pair(
    campaign: str,
    client_manifest: dict[str, object],
    client: dict[str, object],
    server_manifest: dict[str, object],
    server: dict[str, object],
) -> tuple[dict[tuple[object, ...], dict[str, object]],
           dict[tuple[object, ...], dict[str, object]]]:
    if (
        client_manifest.get("backend") != "native-c11-relic"
        or server_manifest.get("backend") != "native-c11-relic"
        or client_manifest.get("service_port")
        != server_manifest.get("service_port")
        or client_manifest.get("protocol_source_sha256")
        != server_manifest.get("protocol_source_sha256")
        or client_manifest.get("campaign_runner_sha256")
        != server_manifest.get("campaign_runner_sha256")
        or client_manifest.get("loss_role_runner_sha256")
        != server_manifest.get("loss_role_runner_sha256")
        or client_manifest.get("netem_runner_sha256")
        != server_manifest.get("netem_runner_sha256")
        or client_manifest.get("manifest_writer_sha256")
        != server_manifest.get("manifest_writer_sha256")
    ):
        raise ValueError(f"endpoint provenance mismatch for {campaign}")
    if (
        client.get("schema") != "oasis-preswap-cloud-v8"
        or server.get("schema") != "oasis-preswap-cloud-v8"
        or client.get("authenticated_transport") is not True
        or server.get("authenticated_transport") is not True
    ):
        raise ValueError(f"invalid native result schema for {campaign}")
    if (
        client.get("experiment_identity") != server.get("experiment_identity")
        or client.get("randomization") != server.get("randomization")
    ):
        raise ValueError(f"endpoint identity mismatch for {campaign}")
    client_rows = {sample_key(row): row for row in client["samples"]}
    server_rows = {sample_key(row): row for row in server["samples"]}
    if (
        len(client_rows) != len(client["samples"])
        or len(server_rows) != len(server["samples"])
        or client_rows.keys() != server_rows.keys()
    ):
        raise ValueError(f"endpoint sample mismatch for {campaign}")
    return client_rows, server_rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifests", nargs="+", type=Path)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--md-out", type=Path, required=True)
    args = parser.parse_args()
    groups: dict[tuple[str, str, float], dict[str, tuple[dict, dict]]] = {}
    for path in args.manifests:
        manifest, result = load_manifest(path)
        key = (
            str(manifest["campaign_id"]), str(manifest["route"]),
            float(manifest["loss_pct"]),
        )
        role = str(manifest["role"])
        if role in groups.setdefault(key, {}):
            raise ValueError(f"duplicate {role} manifest for {key}")
        groups[key][role] = (manifest, result)

    summary = []
    for (campaign, route, loss), roles in sorted(
        groups.items(), key=lambda row: (row[0][1], row[0][2])
    ):
        if set(roles) != {"client", "server"}:
            raise ValueError(f"missing endpoint manifest for {campaign}")
        client_manifest, client = roles["client"]
        server_manifest, server = roles["server"]
        client_rows, server_rows = validate_endpoint_pair(
            campaign, client_manifest, client, server_manifest, server
        )
        workloads = sorted({
            (int(row["participants"]), int(row["items_per_arc"]),
             int(row["concurrent_pairs"]), str(row["mode"]))
            for row in client_rows.values()
        })
        for n, k, pairs, mode in workloads:
            rows = [
                row for row in client_rows.values()
                if (row["participants"], row["items_per_arc"],
                    row["concurrent_pairs"], row["mode"])
                == (n, k, pairs, mode)
            ]
            wall = [float(row["critical_arc_wall_ns"]) / 1_000_000 for row in rows]
            summary.append({
                "campaign_id": campaign,
                "route": route,
                "loss_pct": loss,
                "participants": n,
                "items_per_arc": k,
                "concurrent_pairs": pairs,
                "mode": mode,
                "trials": len(rows),
                "median_critical_arc_ms": statistics.median(wall),
                "p95_critical_arc_ms": percentile(wall, 0.95),
                "median_items_per_second": statistics.median(
                    float(row["items_per_second"]) for row in rows
                ),
                "median_application_goodput_mbps": statistics.median(
                    float(row["application_goodput_mbps"]) for row in rows
                ),
                "verifier_fallbacks": sum(
                    int(row["verifier_fallbacks"]) for row in rows
                ),
            })
    output = {
        "schema": "oasis-native-loss-analysis-v1",
        "matched_campaigns": len(groups),
        "summary": summary,
    }
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.md_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# Native packet-loss campaign", "",
        "| Route | Loss | n | k | p | Configuration | Trials | "
        "Median/P95 critical arc (ms) | Items/s | App goodput (Mbps) | Fallbacks |",
        "|---|---:|---:|---:|---:|---|---:|---:|---:|---:|---:|",
    ]
    for row in summary:
        lines.append(
            f"| {row['route']} | {row['loss_pct']:.1f}% | "
            f"{row['participants']} | {row['items_per_arc']} | "
            f"{row['concurrent_pairs']} | {row['mode']} | {row['trials']} | "
            f"{row['median_critical_arc_ms']:.3f}/"
            f"{row['p95_critical_arc_ms']:.3f} | "
            f"{row['median_items_per_second']:.3f} | "
            f"{row['median_application_goodput_mbps']:.6f} | "
            f"{row['verifier_fallbacks']} |"
        )
    args.md_out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote={args.json_out}")
    print(f"wrote={args.md_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
