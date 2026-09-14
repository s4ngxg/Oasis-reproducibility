#!/usr/bin/env python3
"""Generate paper assets and a claim manifest from validated final analyses."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def provenance_path(path: Path) -> str:
    """Keep generated provenance portable when an input is inside the artifact."""
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)
DEFAULT_OUT = ROOT / "results" / "final-paper-assets"
LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
REFERENCE = "reference-itemwise"
COMPLETE = "batch-joint-presigning-batch-verification"
MODES = {
    "reference-itemwise",
    "phase-coalesced-itemwise",
    "batch-joint-presigning-itemwise",
    "phase-coalesced-batch-verification",
    "batch-joint-presigning-batch-verification",
}
FACTORIAL_COMPARISONS = {
    "batch_joint_presigning_vs_phase_coalesced_itemwise",
    "batch_joint_presigning_vs_phase_coalesced_aggregate",
    "batch_verification_with_phase_coalescing",
    "batch_verification_with_batch_joint_presigning",
}
PAIRWISE_COMPARISONS = {
    "complete_method_vs_reference",
    "phase_coalescing_vs_reference",
    "batch_joint_presigning_vs_phase_coalesced_itemwise",
    "batch_joint_presigning_vs_reference",
    "batch_verification_with_batch_joint_presigning",
    "batch_verification_with_phase_coalescing",
    "batch_joint_presigning_vs_phase_coalesced_aggregate",
}
INTERACTION_COMPARISON = "session_verification_interaction"
REQUIRED_COMPARISONS = PAIRWISE_COMPARISONS | {INTERACTION_COMPARISON}
FINAL_ROUTES = {"eu_to_us", "sg_to_us"}
EXPECTED_AWS_REGIONS = {
    "eu_to_us": {"client": "eu-central-1", "server": "us-east-1"},
    "sg_to_us": {"client": "ap-southeast-1", "server": "us-east-1"},
}
PRIMARY_WORKLOADS = {(n, 1) for n in (3, 5, 8, 16)}
LOAD_WORKLOADS = {
    (n, p) for n in (8, 16) for p in (1, 64, 128, 1024)
}


def timing_profile(payload: dict[str, Any]) -> str:
    """Classify one analyzer output by its exact fixed workload matrix."""
    rows = payload.get("summary", [])
    coverage = {
        (int(row["participants"]), int(row["concurrent_pairs"]), str(row["mode"]))
        for row in rows
    }
    primary = {(n, p, mode) for n, p in PRIMARY_WORKLOADS for mode in MODES}
    load = {(n, p, mode) for n, p in LOAD_WORKLOADS for mode in MODES}
    if coverage == primary and len(rows) == len(primary):
        return "primary"
    if coverage == load and len(rows) == len(load):
        return "load"
    return "unknown"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_evidence(values: list[str], kind: str) -> list[dict[str, Any]]:
    expected = {
        "timing": "oasis-preswap-cloud-analysis-v5",
        "system": "oasis-preswap-system-profile-v1",
        "pcap": "oasis-preswap-pcap-profile-v3",
        "cost": "oasis-cloud-cost-report-v1",
    }[kind]
    records = []
    for value in values:
        if "=" not in value:
            raise ValueError(f"{kind} evidence must be LABEL=PATH: {value}")
        label, raw_path = value.split("=", 1)
        if not LABEL_RE.fullmatch(label):
            raise ValueError(f"invalid evidence label: {label}")
        path = Path(raw_path).expanduser().resolve()
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("schema") != expected:
            raise ValueError(
                f"{label}: expected schema {expected}, got {payload.get('schema')}"
            )
        if kind == "timing":
            integrity = payload.get("integrity", {})
            if int(integrity.get("matched_samples", 0)) <= 0:
                raise ValueError(f"{label}: timing analysis has no matched samples")
            if int(integrity.get("verifier_fallbacks", -1)) != 0:
                raise ValueError(f"{label}: verifier fallback is not final evidence")
        records.append({
            "label": label,
            "kind": kind,
            "path": path,
            "sha256": sha256(path),
            "payload": payload,
        })
    return records


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    fields = sorted({key for row in rows for key in row})
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def markdown_table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
    ]
    lines.extend("| " + " | ".join(str(value) for value in row) + " |"
                 for row in rows)
    return "\n".join(lines)


def timing_rows(records: list[dict[str, Any]]) -> tuple[list[dict], list[dict]]:
    summaries: list[dict] = []
    effects: list[dict] = []
    for record in records:
        payload = record["payload"]
        common = {
            "evidence_label": record["label"],
            "campaign_id": payload["campaign_id"],
            "route": payload["route"],
            "campaign_profile": timing_profile(payload),
        }
        summaries.extend({**common, **row} for row in payload["summary"])
        effects.extend({**common, **row} for row in payload["paired_effects"])
    return summaries, effects


def profile_rows(records: list[dict[str, Any]]) -> list[dict]:
    rows = []
    for record in records:
        payload = record["payload"]
        common = {
            "evidence_label": record["label"],
            "campaign_id": payload["campaign_id"],
            "route": payload["route"],
            "profiling_mode": payload["profiling_mode"],
        }
        rows.extend({**common, **row} for row in payload["summary"])
    return rows


def validate_final_environment(label: str, endpoint: str, route: str,
                               environment: dict[str, Any]) -> None:
    imds = environment.get("aws_imds", {})
    if not imds.get("instance_type") or not imds.get("availability_zone"):
        raise ValueError(f"{label}: missing exact {endpoint} AWS metadata")
    if imds.get("burstable_instance") is not False:
        raise ValueError(
            f"{label}: final evidence requires a non-burstable {endpoint}"
        )
    if imds.get("flex_scheduled_instance") is not False or \
            imds.get("fixed_performance_instance") is not True:
        raise ValueError(
            f"{label}: final evidence requires a fixed-performance {endpoint}"
        )
    expected_region = EXPECTED_AWS_REGIONS[route][endpoint]
    placement = environment.get("placement_validation", {})
    if imds.get("region") != expected_region or not isinstance(
        placement, dict
    ) or placement.get("route") != route or placement.get("role") != endpoint or \
            placement.get("expected_region") != expected_region or \
            placement.get("observed_region") != expected_region or \
            placement.get("matched") is not True:
        raise ValueError(
            f"{label}: {endpoint} placement does not match {route}"
        )
    cpu = environment.get("cpu", {})
    memory = environment.get("memory", {})
    required_text = {
        "compiler": environment.get("compiler"),
        "kernel": environment.get("kernel"),
        "zeromq": environment.get("zeromq"),
        "libsodium": environment.get("libsodium"),
        "cpu model": cpu.get("model_name") if isinstance(cpu, dict) else None,
        "CMake build type": environment.get("cmake_build_type"),
        "CMake release flags": environment.get("cmake_release_c_flags"),
        "thread model": environment.get("thread_model"),
    }
    missing = sorted(
        name for name, value in required_text.items()
        if value is None or str(value).strip() in {"", "unknown"}
    )
    if missing:
        raise ValueError(
            f"{label}: incomplete {endpoint} build/environment metadata: {missing}"
        )
    if int(environment.get("cpu_count") or 0) <= 0:
        raise ValueError(f"{label}: missing {endpoint} CPU count")
    if not isinstance(memory, dict) or int(memory.get("mem_total_kb", 0)) <= 0:
        raise ValueError(f"{label}: missing {endpoint} physical-memory metadata")


def validate_final_evidence_matrix(
    timing: list[dict[str, Any]],
    systems: list[dict[str, Any]],
    pcaps: list[dict[str, Any]],
    costs: list[dict[str, Any]],
) -> None:
    """Reject incomplete or provisional evidence presented as camera-ready."""
    timing_routes = {str(record["payload"].get("route")) for record in timing}
    if timing_routes != FINAL_ROUTES:
        raise ValueError(
            f"final timing routes must be {sorted(FINAL_ROUTES)}, "
            f"got {sorted(timing_routes)}"
        )

    for route in sorted(FINAL_ROUTES):
        route_records = [
            record for record in timing
            if record["payload"].get("route") == route
        ]
        profiles = [timing_profile(record["payload"]) for record in route_records]
        if sorted(profiles) != ["load", "primary"]:
            raise ValueError(
                f"{route}: final evidence requires exactly one primary and one "
                f"load analysis; got {profiles}"
            )
        for record, profile in zip(route_records, profiles):
            workloads = PRIMARY_WORKLOADS if profile == "primary" else LOAD_WORKLOADS
            expected_trials = 100 if profile == "primary" else 20
            analysis_plan = record["payload"].get("analysis_plan", {})
            if analysis_plan.get("bootstrap_rounds") != 10_000 or not all(
                analysis_plan.get(field)
                for field in (
                    "bootstrap_seed_domain", "bootstrap_seed_derivation",
                    "bootstrap_interval", "paired_test", "holm_families",
                    "effect_size", "sample_size_policy",
                )
            ):
                raise ValueError(
                    f"{record['label']}: incomplete or non-final analysis plan"
                )
            payload = record["payload"]
            identity = payload.get("experiment_identity", {})
            randomization = payload.get("randomization", {})
            transport = payload.get("transport_security", {})
            if not isinstance(identity, dict) or (
                identity.get("campaign_id") != payload.get("campaign_id")
                or identity.get("route") != route
                or len(str(identity.get("schedule_sha256", ""))) != 64
            ):
                raise ValueError(
                    f"{record['label']}: invalid synchronized experiment identity"
                )
            if not isinstance(randomization, dict) or (
                randomization.get("schedule_sha256")
                != identity.get("schedule_sha256")
                or randomization.get("route_is_campaign_constant") is not True
                or randomization.get("block_factors") != [
                    "campaign_id", "route", "warmup_status", "participants",
                    "items_per_arc", "concurrent_pairs",
                ]
            ):
                raise ValueError(
                    f"{record['label']}: invalid blocked randomization evidence"
                )
            if not isinstance(transport, dict) or transport.get(
                "tls_session_reuse"
            ) != "not-applicable-native-transport-is-not-tls":
                raise ValueError(
                    f"{record['label']}: ambiguous transport reuse state"
                )
            for row in record["payload"].get("summary", []):
                if int(row.get("trials", -1)) != expected_trials:
                    raise ValueError(
                        f"{record['label']}: {profile} cells require exactly "
                        f"{expected_trials} measured trials"
                    )
                for field in (
                    "median_client_host_cpu_steal_pct",
                    "median_server_host_cpu_steal_pct",
                    "total_client_cgroup_throttled_periods",
                    "total_server_cgroup_throttled_periods",
                    "median_server_gateway_peak_queue_depth",
                    "median_server_gateway_peak_queue_utilization_pct",
                    "total_server_gateway_queued_sessions",
                    "total_server_gateway_rejected_sessions",
                    "median_server_gateway_queue_wait_ms_per_queued_session",
                    "max_server_gateway_queue_wait_ms",
                ):
                    if field not in row:
                        raise ValueError(
                            f"{record['label']}: summary missing {field}"
                        )
                    if field.startswith("total_") and "cgroup_throttled" in field:
                        if type(row[field]) is not int or row[field] < 0:
                            raise ValueError(
                                f"{record['label']}: unavailable or invalid throttling evidence: {field}"
                            )
                    value = row[field]
                    if (type(value) not in (int, float) or
                            not math.isfinite(value) or value < 0 or
                            (field.endswith("_pct") and value > 100) or
                            (field.startswith("total_") and type(value) is not int)):
                        raise ValueError(
                            f"{record['label']}: invalid systems evidence: {field}"
                        )
            effect_coverage = {
                (
                    int(row["participants"]), int(row["concurrent_pairs"]),
                    str(row["comparison"]),
                )
                for row in record["payload"].get("paired_effects", [])
            }
            required_record_effects = {
                (n, p, comparison)
                for n, p in workloads
                for comparison in REQUIRED_COMPARISONS
            }
            missing_record_effects = sorted(
                required_record_effects - effect_coverage
            )
            if missing_record_effects:
                raise ValueError(
                    f"{record['label']}: factorial effects are incomplete; "
                    f"first missing cells={missing_record_effects[:5]}"
                )
            for row in record["payload"].get("paired_effects", []):
                if int(row.get("paired_trials", -1)) != expected_trials:
                    raise ValueError(
                        f"{record['label']}: paired effects require exactly "
                        f"{expected_trials} matched trials"
                    )
                trial_ids = row.get("trial_ids", [])
                differences = row.get("raw_paired_differences_ms", [])
                if len(trial_ids) != expected_trials or \
                        len(differences) != expected_trials:
                    raise ValueError(
                        f"{record['label']}: paired effect lacks raw trial evidence"
                    )
                if not all(
                    field in row for field in (
                        "median_difference_ci95_ms",
                        "median_reduction_ci95_pct",
                        "rank_biserial_ci95", "holm_adjusted_p",
                    )
                ):
                    raise ValueError(
                        f"{record['label']}: paired effect lacks uncertainty fields"
                    )
                seeds = row.get("bootstrap_seeds", {})
                if set(seeds) != {
                    "median_reduction", "median_difference", "rank_biserial"
                } or len(set(seeds.values())) != 3:
                    raise ValueError(
                        f"{record['label']}: invalid bootstrap seed evidence"
                    )
        summaries = [
            row for record in route_records
            for row in record["payload"].get("summary", [])
        ]
        effects = [
            row for record in route_records
            for row in record["payload"].get("paired_effects", [])
        ]
        coverage = {
            (
                int(row["participants"]),
                int(row["concurrent_pairs"]),
                str(row["mode"]),
            )
            for row in summaries
        }
        required_primary = {
            (n, p, mode) for n, p in PRIMARY_WORKLOADS for mode in MODES
        }
        required_load = {
            (n, p, mode) for n, p in LOAD_WORKLOADS for mode in MODES
        }
        missing = sorted((required_primary | required_load) - coverage)
        if missing:
            raise ValueError(
                f"{route}: final timing matrix is incomplete; "
                f"first missing cells={missing[:5]}"
            )
        effect_coverage = {
            (
                int(row["participants"]),
                int(row["concurrent_pairs"]),
                str(row["comparison"]),
            )
            for row in effects
        }
        required_effects = {
            (n, p, comparison)
            for n, p, _ in required_primary | required_load
            for comparison in REQUIRED_COMPARISONS
        }
        missing_effects = sorted(required_effects - effect_coverage)
        if missing_effects:
            raise ValueError(
                f"{route}: factorial effects are incomplete; "
                f"first missing cells={missing_effects[:5]}"
            )
        for record in route_records:
            payload = record["payload"]
            for endpoint in ("client_environment", "server_environment"):
                environment = payload.get(endpoint, {})
                validate_final_environment(
                    record["label"], endpoint.removesuffix("_environment"),
                    route,
                    environment if isinstance(environment, dict) else {},
                )

    artifact_fields = (
        "protocol_source_sha256", "client_binary_sha256",
        "server_binary_sha256",
    )
    for field in artifact_fields:
        values = {
            str(record["payload"].get("integrity", {}).get(field, ""))
            for record in timing
        }
        if len(values) != 1 or not next(iter(values), ""):
            raise ValueError(
                f"final timing evidence disagrees on {field}: {sorted(values)}"
            )

    authentication_fields = (
        "initiator_public_key_sha256", "responder_public_key_sha256",
    )
    for route in sorted(FINAL_ROUTES):
        route_records = [
            record for record in timing
            if record["payload"].get("route") == route
        ]
        for field in authentication_fields:
            values = {
                str(record["payload"].get("integrity", {}).get(field, ""))
                for record in route_records
            }
            if len(values) != 1 or not next(iter(values), ""):
                raise ValueError(
                    f"{route}: final timing evidence disagrees on {field}: "
                    f"{sorted(values)}"
                )

    profile_modes = {
        str(record["payload"].get("profiling_mode")) for record in systems
    }
    if not {"allocation", "syscall"}.issubset(profile_modes):
        raise ValueError(
            "final evidence requires separate allocation and syscall profiles"
        )
    for record in systems:
        modes = {
            str(row.get("configuration"))
            for row in record["payload"].get("summary", [])
        }
        if modes != MODES:
            raise ValueError(
                f"{record['label']}: systems profile must cover all five modes"
            )
    pcap_coverage = {
        (str(record["payload"].get("route")),
         str(record["payload"].get("role")))
        for record in pcaps
    }
    required_pcap_coverage = {
        (route, role) for route in FINAL_ROUTES for role in ("client", "server")
    }
    if pcap_coverage != required_pcap_coverage:
        raise ValueError(
            "final evidence requires campaign-scoped packet captures at both "
            "endpoints on both WAN routes"
        )
    for route in FINAL_ROUTES:
        route_captures = [
            record for record in pcaps
            if record["payload"].get("route") == route
        ]
        pcap_campaigns = {
            (
                str(record["payload"].get("campaign_id")),
                int(record["payload"].get("service_port", -1)),
            )
            for record in route_captures
        }
        if len(pcap_campaigns) != 1:
            raise ValueError(
                f"{route}: endpoint captures must bind the same campaign and "
                "service port"
            )
        _, service_port = next(iter(pcap_campaigns))
        if not (1 <= service_port <= 65535):
            raise ValueError("invalid final packet-capture route or service port")
    for record in pcaps:
        metrics = record["payload"].get("metrics", {})
        if int(metrics.get("tcp_connections", 0)) <= 0 or int(
            metrics.get("tcp_segments", 0)
        ) <= 0:
            raise ValueError(f"{record['label']}: empty packet-capture evidence")
        if int(metrics.get("tcp_ack_rtt_sample_count", 0)) <= 0 or any(
            metrics.get(field) is None for field in (
                "tcp_ack_rtt_min_ms", "tcp_ack_rtt_p50_ms",
                "tcp_ack_rtt_p95_ms", "tcp_ack_rtt_p99_ms",
                "tcp_ack_rtt_max_ms",
            )
        ):
            raise ValueError(
                f"{record['label']}: packet capture lacks an RTT distribution"
            )
        if record["payload"].get("tls_session_reuse") != (
            "not-applicable-native-transport-is-not-tls"
        ):
            raise ValueError(
                f"{record['label']}: ambiguous TLS session-reuse metadata"
            )

    if len(costs) != 1:
        raise ValueError("final evidence requires exactly one cloud-cost report")
    cost = costs[0]["payload"]
    timing_campaigns = {
        str(record["payload"].get("campaign_id", "")) for record in timing
    }
    covered_campaigns = set(cost.get("covered_campaign_ids", []))
    if not timing_campaigns.issubset(covered_campaigns):
        raise ValueError(
            "cloud-cost report does not cover every final timing campaign"
        )
    campaign_rows = cost.get("campaigns", [])
    if not isinstance(campaign_rows, list):
        raise ValueError("cloud-cost report campaigns must be a list")
    cost_campaigns = {
        str(row.get("campaign_id", "")): row
        for row in campaign_rows if isinstance(row, dict)
    }
    if set(cost_campaigns) != covered_campaigns:
        raise ValueError(
            "cloud-cost campaign rows do not match covered_campaign_ids"
        )
    timing_by_campaign = {
        str(record["payload"].get("campaign_id", "")): record
        for record in timing
    }
    for campaign_id, record in timing_by_campaign.items():
        route = str(record["payload"].get("route", ""))
        row = cost_campaigns.get(campaign_id)
        if row is None:
            raise ValueError(
                f"cloud-cost report lacks campaign row for {campaign_id}"
            )
        if str(row.get("route", "")) != route:
            raise ValueError(
                f"cloud-cost route mismatch for {campaign_id}"
            )
        profile = timing_profile(record["payload"])
        if profile not in {"primary", "load"}:
            raise ValueError(
                f"cannot derive cost run counts for {campaign_id}"
            )
        expected_measured = sum(
            int(summary_row.get("trials", 0))
            for summary_row in record["payload"].get("summary", [])
        )
        warmups_per_cell = 10 if profile == "primary" else 5
        expected_warmups = len(
            record["payload"].get("summary", [])
        ) * warmups_per_cell
        if int(row.get("measured_runs", -1)) != expected_measured or int(
            row.get("warmup_runs", -1)
        ) != expected_warmups:
            raise ValueError(
                f"cloud-cost campaign {campaign_id} run counts do not match "
                f"timing evidence (expected measured={expected_measured}, "
                f"warm-up={expected_warmups})"
            )
        if int(row.get("failed_runs", -1)) < 0:
            raise ValueError(
                f"cloud-cost campaign {campaign_id} has invalid failed runs"
            )
        if float(row.get("compute_usd", 0)) <= 0 or float(
            row.get("total_usd", 0)
        ) <= 0:
            raise ValueError(
                f"cloud-cost campaign {campaign_id} lacks positive cost"
            )
    pricing_timestamp = str(cost.get("pricing_retrieved_at_utc", ""))
    if not str(cost.get("pricing_source_url", "")).startswith("https://") or \
            not pricing_timestamp.endswith("Z"):
        raise ValueError("cloud-cost report lacks auditable pricing metadata")
    try:
        datetime.fromisoformat(pricing_timestamp[:-1] + "+00:00")
    except ValueError as error:
        raise ValueError(
            "cloud-cost report has invalid pricing retrieval timestamp"
        ) from error
    line_items = cost.get("line_items", [])
    if not isinstance(line_items, list) or not line_items:
        raise ValueError("cloud-cost report has no line items")
    category_subtotals = {
        "compute": 0.0, "storage": 0.0, "data_transfer": 0.0
    }
    for index, line in enumerate(line_items):
        if not isinstance(line, dict):
            raise ValueError(f"cloud-cost line_items[{index}] is not an object")
        category = str(line.get("category", ""))
        campaign_id = str(line.get("campaign_id", ""))
        if category not in category_subtotals or campaign_id not in cost_campaigns:
            raise ValueError(
                f"cloud-cost line_items[{index}] has invalid campaign/category"
            )
        try:
            quantity = float(line["quantity"])
            unit_price = float(line["unit_price_usd"])
            subtotal = float(line["subtotal_usd"])
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(
                f"cloud-cost line_items[{index}] has invalid numeric fields"
            ) from error
        if not all(value >= 0 for value in (quantity, unit_price, subtotal)):
            raise ValueError(
                f"cloud-cost line_items[{index}] has negative values"
            )
        expected_subtotal = quantity * unit_price
        if abs(subtotal - expected_subtotal) > max(
            1e-9, expected_subtotal * 1e-9
        ):
            raise ValueError(
                f"cloud-cost line_items[{index}] subtotal is inconsistent"
            )
        category_subtotals[category] += subtotal
    categories = {
        str(row.get("category")) for row in line_items
        if isinstance(row, dict)
    }
    if categories != {"compute", "storage", "data_transfer"}:
        raise ValueError(
            "cloud-cost report must separate compute, storage, and data transfer"
        )
    for campaign_id, record in timing_by_campaign.items():
        route = str(record["payload"].get("route", ""))
        campaign_lines = [
            line for line in line_items
            if str(line.get("campaign_id", "")) == campaign_id
        ]
        campaign_categories = {
            str(line.get("category", "")) for line in campaign_lines
        }
        if campaign_categories != {"compute", "storage", "data_transfer"}:
            raise ValueError(
                f"cloud-cost campaign {campaign_id} lacks a cost category"
            )
        compute_line_regions = {
            str(line.get("region", "")) for line in campaign_lines
            if line.get("category") == "compute"
            and line.get("unit") == "instance-hour"
            and float(line.get("quantity", 0)) > 0
        }
        expected_regions = set(EXPECTED_AWS_REGIONS[route].values())
        if not expected_regions.issubset(compute_line_regions):
            raise ValueError(
                f"cloud-cost campaign {campaign_id} lacks route instance-hours"
            )
    compute_regions = {
        str(row.get("region")) for row in line_items
        if isinstance(row, dict) and row.get("category") == "compute"
    }
    if not {"us-east-1", "eu-central-1", "ap-southeast-1"}.issubset(
        compute_regions
    ):
        raise ValueError("cloud-cost report lacks instance-hours for every region")
    for region in ("us-east-1", "eu-central-1", "ap-southeast-1"):
        region_hours = sum(
            float(row.get("quantity", 0))
            for row in line_items
            if isinstance(row, dict)
            and row.get("category") == "compute"
            and row.get("region") == region
            and row.get("unit") == "instance-hour"
        )
        if region_hours <= 0:
            raise ValueError(
                f"cloud-cost report lacks positive instance-hours for {region}"
            )
    totals = cost.get("totals", {})
    for field in (
        "compute_usd", "storage_usd", "data_transfer_usd",
        "grand_total_usd", "measured_runs", "warmup_runs", "failed_runs",
    ):
        if field not in totals:
            raise ValueError(f"cloud-cost report lacks totals.{field}")
    if float(totals["compute_usd"]) <= 0 or \
            float(totals["grand_total_usd"]) <= 0:
        raise ValueError("cloud-cost report must contain positive measured cost")
    for category, subtotal in category_subtotals.items():
        field = f"{category}_usd"
        if abs(float(totals[field]) - subtotal) > max(
            1e-9, subtotal * 1e-9
        ):
            raise ValueError(
                f"cloud-cost totals.{field} does not match line items"
            )
    expected_grand_total = sum(category_subtotals.values())
    if abs(float(totals["grand_total_usd"]) - expected_grand_total) > max(
        1e-9, expected_grand_total * 1e-9
    ):
        raise ValueError(
            "cloud-cost totals.grand_total_usd does not match line items"
        )
    if int(totals["measured_runs"]) <= 0 or \
            int(totals["warmup_runs"]) <= 0:
        raise ValueError(
            "cloud-cost report must account for measured and warm-up runs"
        )
    for field in ("measured_runs", "warmup_runs", "failed_runs"):
        campaign_total = sum(
            int(row.get(field, -1)) for row in cost_campaigns.values()
        )
        if int(totals[field]) != campaign_total:
            raise ValueError(
                f"cloud-cost totals.{field} does not match campaign rows"
            )


def configure_matplotlib(out: Path):
    cache = out / ".matplotlib"
    cache.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("MPLCONFIGDIR", str(cache))
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    return plt


def style_axis(axis) -> None:
    axis.spines["top"].set_visible(False)
    axis.spines["right"].set_visible(False)
    axis.grid(axis="y", color="#D9DEE5", linewidth=0.7)
    axis.set_axisbelow(True)


def plot_primary(plt, effects: list[dict], output: Path) -> bool:
    rows = [
        row for row in effects
        if row["comparison"] == "complete_method_vs_reference"
        and int(row["concurrent_pairs"]) == 1
    ]
    if not rows:
        return False
    figure, axis = plt.subplots(figsize=(7.2, 4.1))
    for label in sorted({row["evidence_label"] for row in rows}):
        selected = sorted(
            (row for row in rows if row["evidence_label"] == label),
            key=lambda row: int(row["items_per_arc"]),
        )
        axis.plot(
            [int(row["items_per_arc"]) for row in selected],
            [float(row["median_reduction_pct"]) for row in selected],
            marker="o", linewidth=2, label=label.replace("_", " "),
        )
    axis.axhline(0, color="#666666", linewidth=0.8)
    axis.set_xlabel("Pre-swap items per directed arc (k)")
    axis.set_ylabel("Paired median wall-time reduction (%)")
    axis.set_title("Complete method vs persistent item-wise reference")
    axis.legend(frameon=False)
    style_axis(axis)
    figure.tight_layout()
    figure.savefig(output, dpi=220, bbox_inches="tight")
    plt.close(figure)
    return True


def plot_load(plt, effects: list[dict], output: Path) -> bool:
    rows = [
        row for row in effects
        if row["comparison"] == "complete_method_vs_reference"
        and int(row["concurrent_pairs"]) > 1
    ]
    if not rows:
        return False
    figure, axis = plt.subplots(figsize=(7.4, 4.2))
    keys = sorted({
        (row["evidence_label"], int(row["items_per_arc"])) for row in rows
    })
    for label, item_count in keys:
        selected = sorted(
            (
                row for row in rows
                if row["evidence_label"] == label
                and int(row["items_per_arc"]) == item_count
            ),
            key=lambda row: int(row["concurrent_pairs"]),
        )
        axis.plot(
            [int(row["concurrent_pairs"]) for row in selected],
            [float(row["median_reduction_pct"]) for row in selected],
            marker="o", linewidth=2,
            label=f"{label.replace('_', ' ')}, k={item_count}",
        )
    axis.axhline(0, color="#666666", linewidth=0.8)
    axis.set_xscale("log", base=2)
    axis.set_xlabel("Concurrent participant-pair sessions (p)")
    axis.set_ylabel("Paired median stage-wall reduction (%)")
    axis.set_title("Load scaling of the complete method")
    axis.legend(frameon=False, fontsize=8)
    style_axis(axis)
    figure.tight_layout()
    figure.savefig(output, dpi=220, bbox_inches="tight")
    plt.close(figure)
    return True


def plot_systems(plt, summaries: list[dict], output: Path) -> bool:
    required = {
        "median_client_cpu_pct", "median_server_cpu_pct",
        "median_client_process_peak_rss_sum_kb",
        "median_server_process_peak_rss_sum_kb",
    }
    candidates = [
        row for row in summaries
        if row.get("mode") in {REFERENCE, COMPLETE}
        and required.issubset(row)
    ]
    if not candidates:
        return False
    max_pairs = max(int(row["concurrent_pairs"]) for row in candidates)
    max_items = max(
        int(row["items_per_arc"])
        for row in candidates if int(row["concurrent_pairs"]) == max_pairs
    )
    selected = [
        row for row in candidates
        if int(row["concurrent_pairs"]) == max_pairs
        and int(row["items_per_arc"]) == max_items
    ]
    labels = [
        f"{row['evidence_label']}\n{row['mode']}" for row in selected
    ]
    cpu = [
        float(row["median_client_cpu_pct"])
        + float(row["median_server_cpu_pct"])
        for row in selected
    ]
    rss = [
        (
            float(row["median_client_process_peak_rss_sum_kb"])
            + float(row["median_server_process_peak_rss_sum_kb"])
        ) / 1024
        for row in selected
    ]
    figure, axes = plt.subplots(1, 2, figsize=(10.5, 4.2))
    positions = list(range(len(selected)))
    axes[0].bar(positions, cpu, color="#0072B2")
    axes[1].bar(positions, rss, color="#009E73")
    for axis in axes:
        axis.set_xticks(positions, labels, rotation=20, ha="right", fontsize=7)
        style_axis(axis)
    axes[0].set_ylabel("Combined endpoint process CPU (%)")
    axes[1].set_ylabel("Combined endpoint peak RSS sum (MiB)")
    figure.suptitle(f"Systems profile at k={max_items}, p={max_pairs}")
    figure.tight_layout()
    figure.savefig(output, dpi=220, bbox_inches="tight")
    plt.close(figure)
    return True


def write_report(path: Path, summaries: list[dict], effects: list[dict],
                 profiles: list[dict], evidence: list[dict]) -> None:
    distribution = [
        [
            row["evidence_label"], row["route"], row["participants"],
            row["items_per_arc"], row["concurrent_pairs"], row["mode"],
            row["trials"], f"{float(row['pair_p50_ms']):.3f}",
            f"{float(row['pair_p95_ms']):.3f}",
            f"{float(row['pair_p99_ms']):.3f}",
            f"{float(row['pair_p95_ci95_ms'][0]):.3f}.."
            f"{float(row['pair_p95_ci95_ms'][1]):.3f}",
            f"{float(row['pair_p99_ci95_ms'][0]):.3f}.."
            f"{float(row['pair_p99_ci95_ms'][1]):.3f}",
            f"{float(row['median_completed_pairs_per_second']):.3f}",
            f"{float(row['median_application_goodput_mbps']):.6f}",
            f"{float(row['median_client_cpu_ms_per_completed_pair']):.3f}",
            f"{float(row['median_server_cpu_ms_per_completed_pair']):.3f}",
            f"{float(row['median_total_cpu_ms_per_completed_pair']):.3f}",
        ]
        for row in summaries
    ]
    paired = [
        [
            row["evidence_label"], row["participants"], row["items_per_arc"],
            row["concurrent_pairs"], row["comparison"], row["effect_metric"],
            row["paired_trials"],
            f"{float(row['median_difference_ms']):.3f}",
            f"[{float(row['median_difference_ci95_ms'][0]):.3f}, "
            f"{float(row['median_difference_ci95_ms'][1]):.3f}]",
            f"{float(row['median_reduction_pct']):.2f}%",
            f"[{float(row['median_reduction_ci95_pct'][0]):.2f}, "
            f"{float(row['median_reduction_ci95_pct'][1]):.2f}]",
            f"{float(row['rank_biserial_effect']):.3f}",
            f"[{float(row['rank_biserial_ci95'][0]):.3f}, "
            f"{float(row['rank_biserial_ci95'][1]):.3f}]",
            f"{float(row['wilcoxon_signed_rank_p']):.4g}",
            f"{float(row['holm_adjusted_p']):.4g}",
            row["holm_family"], row["holm_family_size"],
        ]
        for row in effects
    ]
    lines = [
        "# OASIS Pre-swap v4 final evidence",
        "",
        "This report is generated only from analyzer-accepted v4 evidence. "
        "Positive reduction means the candidate is faster than its named baseline.",
        "",
        "## Evidence inputs",
        "",
        markdown_table(
            ["Label", "Kind", "Schema", "SHA-256"],
            [[row["label"], row["kind"], row["payload"]["schema"], row["sha256"]]
             for row in evidence],
        ),
        "",
        "## Timing distributions",
        "",
        markdown_table(
            ["Evidence", "Route", "n", "k", "p", "Configuration", "Trials",
             "P50 ms", "P95 ms", "P99 ms", "P95 CI ms", "P99 CI ms",
             "Pairs/s", "App goodput Mbps", "Client CPU ms/pair",
             "Server CPU ms/pair", "Total CPU ms/pair"],
            distribution,
        ),
        "",
        "## Paired effects",
        "",
        markdown_table(
            ["Evidence", "n", "k", "p", "Comparison", "Metric", "Trials",
             "Median difference ms", "Difference CI ms", "Median reduction",
             "Reduction CI", "Rank-biserial", "Effect CI", "Raw p", "Holm p",
             "Holm family", "Family size"],
            paired,
        ),
    ]
    if profiles:
        lines.extend([
            "", "## Isolated allocation and syscall profiles", "",
            f"See `systems_profiles.csv` for all {len(profiles)} rows. "
            "Timing from these instrumented campaigns is not primary latency evidence.",
        ])
    cost_records = [row for row in evidence if row["kind"] == "cost"]
    if cost_records:
        totals = cost_records[0]["payload"]["totals"]
        lines.extend([
            "", "## Cloud cost accounting", "",
            markdown_table(
                ["Compute USD", "Storage USD", "Transfer USD", "Total USD",
                 "Measured runs", "Warm-ups", "Failed runs"],
                [[
                    f"{float(totals['compute_usd']):.6f}",
                    f"{float(totals['storage_usd']):.6f}",
                    f"{float(totals['data_transfer_usd']):.6f}",
                    f"{float(totals['grand_total_usd']):.6f}",
                    int(totals["measured_runs"]),
                    int(totals["warmup_runs"]),
                    int(totals["failed_runs"]),
                ]],
            ),
        ])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def format_p_value(value: object) -> str:
    number = float(value)
    return "$<10^{-4}$" if 0 < number < 1e-4 else f"{number:.4f}"


def write_latex_tables(path: Path, summaries: list[dict], effects: list[dict],
                       evidence: list[dict]) -> None:
    """Emit paper-ready tables whose cells come only from accepted analyses."""
    routes = {"eu_to_us": "EU--US", "sg_to_us": "Singapore--US"}
    summary_index = {
        (
            row["evidence_label"], int(row["participants"]),
            int(row["concurrent_pairs"]), str(row["mode"]),
        ): row
        for row in summaries
    }
    matched = sum(
        int(record["payload"].get("integrity", {}).get("matched_samples", 0))
        for record in evidence if record["kind"] == "timing"
    )
    lines = [
        "% Generated by scripts/build_final_experiment_report.py.",
        "% Do not edit numeric cells manually.",
        f"\\newcommand{{\\OasisFinalMatchedSamples}}{{{matched:,}}}",
        f"\\newcommand{{\\OasisFinalEvidenceInputs}}{{{len(evidence)}}}",
        "",
    ]

    complete_effects = [
        row for row in effects
        if row["comparison"] == "complete_method_vs_reference"
    ]
    primary = sorted(
        (row for row in complete_effects if row["campaign_profile"] == "primary"),
        key=lambda row: (str(row["route"]), int(row["participants"])),
    )
    if primary:
        lines.extend([
            "\\begin{table*}[t]",
            "\\centering",
            "\\caption{Native primary Pre-swap comparison. Positive paired reduction means the complete shared-envelope aggregate method is faster than the persistent independent item-wise reference. All cells are generated from analyzer-accepted evidence.}",
            "\\label{tab:native-primary-generated}",
            "\\small",
            "\\begin{tabular}{lrrrrrr}",
            "\\toprule",
            "Route & $n$ & $k$ & Reference P50 (ms) & Complete P50 (ms) & Paired reduction [95\\% CI] & Holm $p$ \\\\",
            "\\midrule",
        ])
        for row in primary:
            key = (row["evidence_label"], int(row["participants"]), 1)
            reference = summary_index[(*key, REFERENCE)]
            complete = summary_index[(*key, COMPLETE)]
            low, high = row["median_reduction_ci95_pct"]
            lines.append(
                f"{routes[str(row['route'])]} & {int(row['participants'])} & "
                f"{int(row['items_per_arc'])} & {float(reference['pair_p50_ms']):.3f} & "
                f"{float(complete['pair_p50_ms']):.3f} & "
                f"{float(row['median_reduction_pct']):.2f}\\% "
                f"[{float(low):.2f}, {float(high):.2f}] & "
                f"{format_p_value(row['holm_adjusted_p'])} \\\\"
            )
        lines.extend(["\\bottomrule", "\\end{tabular}", "\\end{table*}", ""])

    load = sorted(
        (row for row in complete_effects if row["campaign_profile"] == "load"),
        key=lambda row: (
            str(row["route"]), int(row["participants"]),
            int(row["concurrent_pairs"]),
        ),
    )
    if load:
        lines.extend([
            "\\begin{table*}[t]",
            "\\centering",
            "\\caption{Native load-scaling comparison. Throughput is completed participant-pair sessions per second for the complete method.}",
            "\\label{tab:native-load-generated}",
            "\\scriptsize",
            "\\begin{tabular}{lrrrrrrr}",
            "\\toprule",
            "Route & $n$ & $k$ & $p$ & Reference stage (ms) & Complete stage (ms) & Paired reduction [95\\% CI] & Complete pairs/s \\\\",
            "\\midrule",
        ])
        for row in load:
            key = (
                row["evidence_label"], int(row["participants"]),
                int(row["concurrent_pairs"]),
            )
            reference = summary_index[(*key, REFERENCE)]
            complete = summary_index[(*key, COMPLETE)]
            low, high = row["median_reduction_ci95_pct"]
            lines.append(
                f"{routes[str(row['route'])]} & {int(row['participants'])} & "
                f"{int(row['items_per_arc'])} & {int(row['concurrent_pairs'])} & "
                f"{float(reference['median_stage_wall_ms']):.3f} & "
                f"{float(complete['median_stage_wall_ms']):.3f} & "
                f"{float(row['median_reduction_pct']):.2f}\\% "
                f"[{float(low):.2f}, {float(high):.2f}] & "
                f"{float(complete['median_completed_pairs_per_second']):.3f} \\\\"
            )
        lines.extend(["\\bottomrule", "\\end{tabular}", "\\end{table*}", ""])

    systems = sorted(
        (
            row for row in summaries
            if row["campaign_profile"] == "load"
            and int(row["concurrent_pairs"]) == 1024
            and row["mode"] in {REFERENCE, COMPLETE}
        ),
        key=lambda row: (
            str(row["route"]), int(row["participants"]), str(row["mode"]),
        ),
    )
    if systems:
        names = {REFERENCE: "Persistent item-wise", COMPLETE: "Complete method"}
        lines.extend([
            "\\begin{table*}[t]",
            "\\centering",
            "\\caption{Systems profile from the uninstrumented timing campaign at $p=1024$. CPU is the sum of initiator and responder process utilization; CPU-ms/pair is the corresponding total process CPU cost; RSS is the sum of endpoint peak resident sets.}",
            "\\label{tab:native-systems-generated}",
            "\\small",
            "\\begin{tabular}{lrrlrrrrr}",
            "\\toprule",
            "Route & $n$ & $k$ & Configuration & CPU (\\%) & CPU-ms/pair & Peak RSS (MiB) & P95 (ms) & P99 (ms) \\\\",
            "\\midrule",
        ])
        for row in systems:
            cpu = float(row["median_client_cpu_pct"]) + float(row["median_server_cpu_pct"])
            rss = (
                float(row["median_client_process_peak_rss_sum_kb"])
                + float(row["median_server_process_peak_rss_sum_kb"])
            ) / 1024.0
            lines.append(
                f"{routes[str(row['route'])]} & {int(row['participants'])} & "
                f"{int(row['items_per_arc'])} & {names[str(row['mode'])]} & "
                f"{cpu:.2f} & {float(row['median_total_cpu_ms_per_completed_pair']):.3f} & "
                f"{rss:.2f} & {float(row['pair_p95_ms']):.3f} & "
                f"{float(row['pair_p99_ms']):.3f} \\\\"
            )
        lines.extend(["\\bottomrule", "\\end{tabular}", "\\end{table*}", ""])

    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--timing", action="append", default=[], metavar="LABEL=PATH",
        help="validated oasis-preswap-cloud-analysis-v5 JSON",
    )
    parser.add_argument(
        "--system", action="append", default=[], metavar="LABEL=PATH",
        help="validated oasis-preswap-system-profile-v1 JSON",
    )
    parser.add_argument(
        "--pcap", action="append", default=[], metavar="LABEL=PATH",
        help="validated oasis-preswap-pcap-profile-v3 JSON",
    )
    parser.add_argument(
        "--cost", action="append", default=[], metavar="LABEL=PATH",
        help="validated oasis-cloud-cost-report-v1 JSON",
    )
    parser.add_argument(
        "--require-final-matrix", action="store_true",
        help="reject incomplete camera-ready route, ablation, profile, or PCAP evidence",
    )
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    if not args.timing:
        parser.error("at least one --timing LABEL=PATH is required")

    timing = parse_evidence(args.timing, "timing")
    systems = parse_evidence(args.system, "system")
    pcaps = parse_evidence(args.pcap, "pcap")
    costs = parse_evidence(args.cost, "cost")
    if args.require_final_matrix:
        validate_final_evidence_matrix(timing, systems, pcaps, costs)
    evidence = timing + systems + pcaps + costs
    labels = [record["label"] for record in evidence]
    if len(labels) != len(set(labels)):
        raise ValueError("evidence labels must be unique")

    out = args.out_dir.resolve()
    figures = out / "figures"
    out.mkdir(parents=True, exist_ok=True)
    figures.mkdir(parents=True, exist_ok=True)
    summaries, effects = timing_rows(timing)
    profiles = profile_rows(systems)
    write_csv(out / "timing_summary.csv", summaries)
    write_csv(out / "paired_effects.csv", effects)
    write_csv(out / "systems_profiles.csv", profiles)

    plt = configure_matplotlib(out)
    generated_figures = []
    for name, builder, rows in (
        ("primary_wall_reduction.png", plot_primary, effects),
        ("load_wall_reduction.png", plot_load, effects),
        ("systems_profile.png", plot_systems, summaries),
    ):
        path = figures / name
        if builder(plt, rows, path):
            generated_figures.append(path)

    report_path = out / "FINAL_EVIDENCE_REPORT.md"
    write_report(report_path, summaries, effects, profiles, evidence)
    latex_path = out / "paper_results.tex"
    write_latex_tables(latex_path, summaries, effects, evidence)
    assets = [
        path for path in (
            out / "timing_summary.csv",
            out / "paired_effects.csv",
            out / "systems_profiles.csv",
            report_path,
            latex_path,
            *generated_figures,
        ) if path.exists()
    ]
    manifest = {
        "schema": "oasis-paper-claim-evidence-v1",
        "evidence": [
            {
                "label": record["label"],
                "kind": record["kind"],
                "schema": record["payload"]["schema"],
                "campaign_id": record["payload"].get("campaign_id"),
                "route": record["payload"].get("route"),
                "sha256": record["sha256"],
                "source_path": provenance_path(record["path"]),
            }
            for record in evidence
        ],
        "claims": [
            {
                "claim_id": "timing_and_tail_latency",
                "evidence": [record["label"] for record in timing],
                "fields": [
                    "pair_p50_ms", "pair_p95_ms", "pair_p99_ms",
                    "pair_p95_ci95_ms", "pair_p99_ci95_ms",
                    "median_reduction_pct", "median_reduction_ci95_pct",
                    "paired_trials", "wilcoxon_signed_rank_p",
                    "holm_adjusted_p", "holm_family", "holm_family_size",
                    "rank_biserial_effect", "rank_biserial_ci95",
                ],
                "assets": [
                    "timing_summary.csv", "paired_effects.csv",
                    "paper_results.tex",
                ],
            },
            {
                "claim_id": "throughput_goodput_and_system_resources",
                "evidence": [record["label"] for record in timing],
                "fields": [
                    "median_completed_pairs_per_second",
                    "median_application_goodput_mbps",
                    "median_client_cpu_pct", "median_server_cpu_pct",
                    "median_client_cpu_seconds_per_workload",
                    "median_server_cpu_seconds_per_workload",
                    "median_total_cpu_seconds_per_workload",
                    "median_client_cpu_ms_per_completed_pair",
                    "median_server_cpu_ms_per_completed_pair",
                    "median_total_cpu_ms_per_completed_pair",
                    "median_client_process_peak_rss_sum_kb",
                    "median_server_process_peak_rss_sum_kb",
                    "median_client_context_switches",
                    "median_server_context_switches",
                ],
                "assets": [
                    "timing_summary.csv", "figures/systems_profile.png",
                    "paper_results.tex",
                ],
            },
            {
                "claim_id": "paired_statistical_inference",
                "evidence": [record["label"] for record in timing],
                "fields": [
                    "paired_trials", "median_difference_ms",
                    "median_difference_ci95_ms", "median_reduction_pct",
                    "median_reduction_ci95_pct", "wilcoxon_signed_rank_p",
                    "holm_adjusted_p", "holm_family", "holm_family_size",
                    "rank_biserial_effect", "rank_biserial_ci95",
                ],
                "assets": ["paired_effects.csv", "FINAL_EVIDENCE_REPORT.md"],
            },
            {
                "claim_id": "isolated_profiler_counts",
                "evidence": [record["label"] for record in systems],
                "fields": ["profiling_mode", "summary"],
                "assets": ["systems_profiles.csv"],
            },
            {
                "claim_id": "transport_packet_accounting",
                "evidence": [record["label"] for record in pcaps],
                "fields": ["tcp_segments", "payload_bytes", "retransmissions"],
                "assets": [],
            },
            {
                "claim_id": "cloud_experiment_cost",
                "evidence": [record["label"] for record in costs],
                "fields": [
                    "compute_usd", "storage_usd", "data_transfer_usd",
                    "grand_total_usd", "warmup_runs", "failed_runs",
                ],
                "assets": ["FINAL_EVIDENCE_REPORT.md"],
            },
        ],
    }
    manifest_path = out / "CLAIM_TO_EVIDENCE.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    assets.append(manifest_path)
    checksum_path = out / "SHA256SUMS.txt"
    checksum_path.write_text(
        "\n".join(
            f"{sha256(path)}  {path.relative_to(out)}" for path in sorted(assets)
        ) + "\n",
        encoding="utf-8",
    )
    print(f"report={report_path}")
    print(f"latex={latex_path}")
    print(f"manifest={manifest_path}")
    print(f"figures={len(generated_figures)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
