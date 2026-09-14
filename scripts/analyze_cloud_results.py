#!/usr/bin/env python3
"""Validate and summarize paired native Pre-swap cloud evidence."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import random
import statistics
from bisect import bisect_right
from collections import defaultdict
from pathlib import Path

from scipy.stats import rankdata, wilcoxon


BOOTSTRAP_ROUNDS = 10_000
TAIL_BOOTSTRAP_ROUNDS = 2_000
BOOTSTRAP_SEED_DOMAIN = "OASIS-STATISTICS-v1"
CLOUD_SCHEMA = "oasis-preswap-cloud-v8"
RANDOMIZATION_DOMAIN = "OASIS-CLOUD-MODE-ORDER-v2"
EXPERIMENT_ID_DOMAIN = "OASIS-CLOUD-EXPERIMENT-ID-v1"
EXPECTED_AWS_REGIONS = {
    "eu_to_us": {"client": "eu-central-1", "server": "us-east-1"},
    "sg_to_us": {"client": "ap-southeast-1", "server": "us-east-1"},
}


COMPARISONS = {
    "complete_method_vs_reference": (
        "reference-itemwise",
        "batch-joint-presigning-batch-verification",
    ),
    "phase_coalescing_vs_reference": (
        "reference-itemwise", "phase-coalesced-itemwise"
    ),
    "batch_joint_presigning_vs_phase_coalesced_itemwise": (
        "phase-coalesced-itemwise", "batch-joint-presigning-itemwise"
    ),
    "batch_joint_presigning_vs_reference": (
        "reference-itemwise", "batch-joint-presigning-itemwise"
    ),
    "batch_verification_with_batch_joint_presigning": (
        "batch-joint-presigning-itemwise",
        "batch-joint-presigning-batch-verification",
    ),
    "batch_verification_with_phase_coalescing": (
        "phase-coalesced-itemwise", "phase-coalesced-batch-verification"
    ),
    "batch_joint_presigning_vs_phase_coalesced_aggregate": (
        "phase-coalesced-batch-verification",
        "batch-joint-presigning-batch-verification",
    ),
}


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * fraction) - 1))
    return ordered[index]


def jain_fairness(values: list[float]) -> float:
    if not values or any(value < 0 for value in values):
        raise ValueError("fairness inputs must be non-negative and non-empty")
    squared_sum = sum(value * value for value in values)
    return (sum(values) ** 2 / (len(values) * squared_sum)
            if squared_sum > 0 else 1.0)


def complete_counter_sum(values):
    values = list(values)
    return None if not values or any(value is None for value in values) else sum(values)


def bootstrap_seed(*fields: object) -> int:
    """Derive a reproducible, workload-specific bootstrap seed."""
    preimage = "\x1f".join(
        (BOOTSTRAP_SEED_DOMAIN, *(str(field) for field in fields))
    ).encode("utf-8")
    return int.from_bytes(hashlib.sha256(preimage).digest()[:8], "big")


def bootstrap_ci(
    values: list[float], statistic, seed: int,
    rounds: int = BOOTSTRAP_ROUNDS,
) -> list[float]:
    if not values:
        raise ValueError("bootstrap input must be non-empty")
    generator = random.Random(seed)
    estimates = [
        float(statistic(generator.choices(values, k=len(values))))
        for _ in range(rounds)
    ]
    return [percentile(estimates, 0.025), percentile(estimates, 0.975)]


def bootstrap_median_ci(
    values: list[float], seed: int, rounds: int = BOOTSTRAP_ROUNDS,
) -> list[float]:
    return bootstrap_ci(values, statistics.median, seed, rounds)


def bootstrap_block_percentile_ci(
    blocks: list[list[float]], fraction: float, seed: int,
    rounds: int = TAIL_BOOTSTRAP_ROUNDS,
) -> list[float]:
    """Bootstrap a percentile while preserving each trial as one block.

    At p>1, pair observations from one trial share a scheduler and network
    realization. Resampling complete trial blocks avoids treating them as
    independent observations when estimating tail uncertainty.
    """
    if not blocks or any(not block for block in blocks):
        raise ValueError("bootstrap blocks must be non-empty")
    sorted_blocks = [sorted(block) for block in blocks]
    all_values = sorted(value for block in sorted_blocks for value in block)
    generator = random.Random(seed)
    estimates = []
    target_index = max(0, math.ceil(len(all_values) * fraction) - 1)
    for _ in range(rounds):
        selected_indices = generator.choices(
            range(len(sorted_blocks)), k=len(sorted_blocks)
        )
        multiplicities = [0] * len(sorted_blocks)
        for index in selected_indices:
            multiplicities[index] += 1
        low, high = 0, len(all_values) - 1
        while low < high:
            middle = (low + high) // 2
            candidate = all_values[middle]
            rank = sum(
                multiplicity * bisect_right(block, candidate)
                for multiplicity, block in zip(multiplicities, sorted_blocks)
            )
            if rank > target_index:
                high = middle
            else:
                low = middle + 1
        estimates.append(all_values[low])
    return [percentile(estimates, 0.025), percentile(estimates, 0.975)]


def rank_biserial(values: list[float]) -> float:
    nonzero = [float(value) for value in values if value != 0]
    if not nonzero:
        return 0.0
    ranks = rankdata([abs(value) for value in nonzero], method="average")
    positive = sum(rank for rank, value in zip(ranks, nonzero) if value > 0)
    negative = sum(rank for rank, value in zip(ranks, nonzero) if value < 0)
    total = positive + negative
    return float((positive - negative) / total) if total else 0.0


def signed_rank(values: list[float]) -> tuple[float, float]:
    nonzero = [float(value) for value in values if value != 0]
    if not nonzero:
        return 1.0, 0.0
    result = wilcoxon(
        values, zero_method="wilcox", correction=False,
        alternative="two-sided", method="auto",
    )
    return float(result.pvalue), rank_biserial(values)


def holm_adjust_family(rows: list[dict[str, object]]) -> None:
    ordered = sorted(
        enumerate(rows), key=lambda item: float(item[1]["wilcoxon_signed_rank_p"])
    )
    adjusted = [1.0] * len(rows)
    running = 0.0
    total = len(rows)
    for rank, (original_index, row) in enumerate(ordered):
        candidate = min(
            1.0, (total - rank) * float(row["wilcoxon_signed_rank_p"])
        )
        running = max(running, candidate)
        adjusted[original_index] = running
    for row, value in zip(rows, adjusted):
        row["holm_adjusted_p"] = value
        row["holm_family_size"] = total


def apply_holm_families(rows: list[dict[str, object]]) -> None:
    families: dict[tuple[object, ...], list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        # p=1 is the one-pair primary estimand; only p>1 belongs to load.
        if int(row["concurrent_pairs"]) == 1:
            family = ("primary", row["comparison"])
        else:
            family = ("load", int(row["participants"]), row["comparison"])
        row["holm_family"] = ":".join(str(value) for value in family)
        families[family].append(row)
    for family_rows in families.values():
        holm_adjust_family(family_rows)


def sample_key(row: dict[str, object]) -> tuple[int, int, str, int]:
    return (
        int(row["participants"]), int(row["concurrent_pairs"]),
        str(row["mode"]), int(row["trial"]),
    )


def expected_randomization_block_id(
    campaign: str, route: str, participants: int, concurrent_pairs: int
) -> str:
    material = (
        f"{EXPERIMENT_ID_DOMAIN}|block|{campaign}|{route}|measured|"
        f"{participants}|{2 * participants - 1}|{concurrent_pairs}"
    ).encode("ascii")
    return hashlib.sha256(material).hexdigest()


def expected_paired_trial_id(
    campaign: str, route: str, participants: int,
    concurrent_pairs: int, trial: int,
) -> str:
    material = (
        f"{EXPERIMENT_ID_DOMAIN}|trial|{campaign}|{route}|measured|"
        f"{participants}|{2 * participants - 1}|{concurrent_pairs}|{trial}"
    ).encode("ascii")
    return hashlib.sha256(material).hexdigest()


def expected_mode_order(
    campaign: str, participants: int, concurrent_pairs: int,
    modes: list[str], trial: int,
) -> list[str]:
    base = sorted(
        modes,
        key=lambda mode: hashlib.sha256(
            (
                f"{RANDOMIZATION_DOMAIN}|{campaign}|trial|{participants}|"
                f"{concurrent_pairs}|{mode}"
            ).encode("ascii")
        ).digest(),
    )
    offset = trial % len(base)
    return base[offset:] + base[:offset]


def validate_role(payload: dict[str, object], role: str,
                  expected_profile: str = "timing") -> None:
    if payload.get("schema") != CLOUD_SCHEMA:
        raise ValueError(f"unexpected {role} schema")
    if payload.get("role") != role:
        raise ValueError(f"expected {role} evidence")
    if payload.get("transport") != "ZeroMQ CURVE over TCP":
        raise ValueError(f"unexpected {role} transport")
    if payload.get("authenticated_transport") is not True:
        raise ValueError(f"unauthenticated {role} transport")
    runtime = payload.get("runtime")
    if not isinstance(runtime, dict) or runtime.get("profiling_mode") != expected_profile:
        raise ValueError(
            f"{role} evidence has profiling mode "
            f"{runtime.get('profiling_mode') if isinstance(runtime, dict) else None}; "
            f"expected {expected_profile}"
        )
    service_port = runtime.get("service_port") if isinstance(runtime, dict) else None
    if not isinstance(service_port, int) or not 1024 <= service_port <= 65535:
        raise ValueError(f"invalid {role} service port")
    if runtime.get("public_listener_count") != 1:
        raise ValueError(f"{role} evidence does not use one public listener")
    if runtime.get("session_routing_key") != (
        "authenticated connection + pair_id + execution_id"
    ):
        raise ValueError(f"invalid {role} gateway routing key")
    if runtime.get("connection_lifecycle") != (
        "one connection per participant-pair execution; shared across all "
        "item phases and never shared across participant pairs"
    ):
        raise ValueError(f"invalid {role} connection-lifecycle metadata")
    security = payload.get("transport_security")
    if not isinstance(security, dict) or (
        security.get("mechanism") != "ZeroMQ CURVE"
        or security.get("authorization") != "ZAP public-key allowlist"
        or security.get("zap_domain") != "PARASWAP-OASIS-PRESWAP-v1"
        or security.get("tls_records") != "not-applicable"
        or security.get("tls_session_reuse")
        != "not-applicable-native-transport-is-not-tls"
        or security.get("curve_connection_lifecycle")
        != (
            "one mutually authenticated CURVE/TCP connection per "
            "participant-pair execution, reused for every logical frame "
            "of that execution"
        )
    ):
        raise ValueError(f"invalid {role} transport-security metadata")
    for field in (
        "initiator_public_key_sha256", "responder_public_key_sha256"
    ):
        value = security.get(field)
        if not isinstance(value, str) or len(value) != 64:
            raise ValueError(f"invalid {role} {field}")
    randomization = payload.get("randomization")
    if not isinstance(randomization, dict) or (
        randomization.get("domain") != RANDOMIZATION_DOMAIN
        or randomization.get("route_is_campaign_constant") is not True
        or randomization.get("block_factors") != [
            "campaign_id", "route", "warmup_status", "participants",
            "items_per_arc", "concurrent_pairs",
        ]
        or len(str(randomization.get("schedule_sha256", ""))) != 64
    ):
        raise ValueError(f"invalid {role} randomization metadata")
    identity = payload.get("experiment_identity")
    if not isinstance(identity, dict) or (
        identity.get("domain") != EXPERIMENT_ID_DOMAIN
        or identity.get("campaign_id") != payload.get("campaign_id")
        or identity.get("route") != payload.get("route")
        or identity.get("schedule_sha256")
        != randomization.get("schedule_sha256")
    ):
        raise ValueError(f"invalid {role} experiment identity")
    route = str(payload.get("route", ""))
    expected_region = EXPECTED_AWS_REGIONS.get(route, {}).get(role)
    if expected_region is not None:
        environment = payload.get("environment")
        placement = (
            environment.get("placement_validation")
            if isinstance(environment, dict) else None
        )
        if not isinstance(placement, dict) or (
            placement.get("route") != route
            or placement.get("role") != role
            or placement.get("expected_region") != expected_region
            or placement.get("observed_region") != expected_region
            or placement.get("matched") is not True
        ):
            raise ValueError(f"invalid {role} AWS regional placement")


def indexed_samples(
    payload: dict[str, object], role: str
) -> dict[tuple[int, int, str, int], dict[str, object]]:
    samples = payload.get("samples")
    if not isinstance(samples, list):
        raise ValueError(f"{role} samples must be a list")
    indexed = {sample_key(row): row for row in samples}
    if len(indexed) != len(samples):
        raise ValueError(f"duplicate {role} sample key")
    expected = {
        (int(n), int(p), str(mode), trial)
        for n in payload["participants"]
        for p in (payload["concurrent_pair_values"] or [n])
        for mode in payload["modes"]
        for trial in range(int(payload["trials"]))
    }
    if set(indexed) != expected:
        missing = sorted(expected - set(indexed))
        extra = sorted(set(indexed) - expected)
        raise ValueError(
            f"{role} sample schedule mismatch: missing={missing[:5]} "
            f"extra={extra[:5]}"
        )
    return indexed


def validate_audit(client_row: dict[str, object], server_row: dict[str, object]) -> None:
    n = int(client_row["participants"])
    p = int(client_row["concurrent_pairs"])
    mode = str(client_row["mode"])
    uses_msm = mode.endswith("-batch-verification")
    expected_items = 2 * n - 1
    if int(client_row.get("service_port", -1)) != int(
        server_row.get("service_port", -2)
    ) or not 1024 <= int(client_row.get("service_port", -1)) <= 65535:
        raise ValueError(f"service-port mismatch for {sample_key(client_row)}")
    if int(client_row["items_per_arc"]) != expected_items or int(
        server_row["items_per_arc"]
    ) != expected_items:
        raise ValueError(f"item-count mismatch for {sample_key(client_row)}")
    expected_client_calls = p if uses_msm else 0
    expected_server_calls = 2 * p if uses_msm else 0
    if int(client_row["verifier_msm_calls"]) != expected_client_calls:
        raise ValueError(
            "client multi-scalar-call mismatch for "
            f"{sample_key(client_row)}"
        )
    if int(server_row["verifier_msm_calls"]) != expected_server_calls:
        raise ValueError(
            "server multi-scalar-call mismatch for "
            f"{sample_key(server_row)}"
        )
    if int(client_row["verifier_fallbacks"]) != 0:
        raise ValueError(f"client fallback for {sample_key(client_row)}")
    if int(server_row["verifier_fallbacks"]) != 0:
        raise ValueError(f"server fallback for {sample_key(server_row)}")
    client_arcs = {
        (int(arc["pair_id"]), int(arc["execution_id"]))
        for arc in client_row["arcs"]
    }
    server_arcs = {
        (int(arc["pair_id"]), int(arc["execution_id"]))
        for arc in server_row["arcs"]
    }
    expected_pairs = set(range(p))
    if (
        client_arcs != server_arcs
        or len(client_arcs) != p
        or {pair_id for pair_id, _ in client_arcs} != expected_pairs
    ):
        raise ValueError(f"arc/execution mismatch for {sample_key(client_row)}")
    if any(execution_id == 0 for _, execution_id in client_arcs):
        raise ValueError(f"zero execution ID for {sample_key(client_row)}")
    client_contexts = {
        int(arc["pair_id"]): str(arc.get("host_context_seed", ""))
        for arc in client_row["arcs"]
    }
    server_contexts = {
        int(arc["pair_id"]): str(arc.get("host_context_seed", ""))
        for arc in server_row["arcs"]
    }
    if client_contexts != server_contexts or any(
        len(seed) != 64 for seed in client_contexts.values()
    ):
        raise ValueError(f"host-context mismatch for {sample_key(client_row)}")
    if uses_msm:
        client_by_pair = {int(arc["pair_id"]): arc for arc in client_row["arcs"]}
        server_by_pair = {int(arc["pair_id"]): arc for arc in server_row["arcs"]}
        for pair_id in expected_pairs:
            client_arc = client_by_pair[pair_id]
            server_arc = server_by_pair[pair_id]
            audit_values = (
                str(client_arc.get("server_partial_verifier_salt", "")),
                str(server_arc.get("client_partial_verifier_salt", "")),
                str(server_arc.get("full_presignature_verifier_salt", "")),
            )
            if any(len(value) != 64 for value in audit_values) or (
                len(set(audit_values)) != len(audit_values)
            ):
                raise ValueError(
                    f"invalid verifier salts for {sample_key(client_row)} "
                    f"pair={pair_id}"
                )
            client_digest = str(client_arc.get("verifier_batch_digest", ""))
            server_digest = str(server_arc.get("verifier_batch_digest", ""))
            if len(client_digest) != 64 or client_digest != server_digest:
                raise ValueError(
                    f"verifier batch-digest mismatch for "
                    f"{sample_key(client_row)} pair={pair_id}"
                )
    if mode == "reference-itemwise":
        expected_client_sent = 3 * p * expected_items
        expected_client_received = p * (2 * expected_items + 1)
        expected_server_sent = expected_client_received
        expected_server_received = expected_client_sent
    elif mode.endswith("-batch-verification"):
        expected_client_sent = 3 * p
        expected_client_received = 4 * p
        expected_server_sent = expected_client_received
        expected_server_received = expected_client_sent
    else:
        expected_client_sent = expected_client_received = 3 * p
        expected_server_sent = expected_server_received = 3 * p
    expected_frame_counts = (
        (client_row, "client", expected_client_sent, expected_client_received),
        (server_row, "server", expected_server_sent, expected_server_received),
    )
    for row, role, sent, received in expected_frame_counts:
        if int(row["sent_frames"]) != sent:
            raise ValueError(f"{role} sent_frames mismatch for {sample_key(row)}")
        if int(row["received_frames"]) != received:
            raise ValueError(
                f"{role} received_frames mismatch for {sample_key(row)}"
            )
    if int(client_row["sent_bytes"]) != int(server_row["received_bytes"]) or int(
        client_row["received_bytes"]
    ) != int(server_row["sent_bytes"]):
        raise ValueError(f"client/server application-byte mismatch for {sample_key(client_row)}")
    for field in (
        "randomization_block_id", "paired_trial_id", "mode_position",
        "schedule_position",
    ):
        if client_row.get(field) != server_row.get(field):
            raise ValueError(
                f"client/server {field} mismatch for {sample_key(client_row)}"
            )
    server_profile = server_row.get("process_profile")
    gateway = (
        server_profile.get("gateway")
        if isinstance(server_profile, dict) else None
    )
    if not isinstance(gateway, dict):
        raise ValueError(f"missing gateway profile for {sample_key(server_row)}")
    expected_gateway = {
        "expected_sessions": p,
        "completed_sessions": p,
        "assignments": p,
        "rejected_sessions": 0,
        "frontend_received_frames": int(client_row["sent_frames"]),
        "frontend_sent_frames": int(client_row["received_frames"]),
        "backend_received_frames": int(server_row["sent_frames"]),
        "backend_sent_frames": int(server_row["received_frames"]),
        "bytes_from_clients": int(client_row["sent_bytes"]),
        "bytes_to_clients": int(client_row["received_bytes"]),
    }
    for field, expected in expected_gateway.items():
        if int(gateway.get(field, -1)) != expected:
            raise ValueError(
                f"gateway {field} mismatch for {sample_key(server_row)}"
            )
    worker_count = int(gateway.get("worker_count", 0))
    queue_capacity = int(gateway.get("queue_capacity", -1))
    peak_queue_depth = int(gateway.get("peak_queue_depth", -1))
    if not 1 <= worker_count <= p or int(
        gateway.get("registered_workers", 0)
    ) != worker_count or not 1 <= int(
        gateway.get("peak_busy_workers", 0)
    ) <= worker_count or not 0 <= peak_queue_depth <= queue_capacity:
        raise ValueError(f"invalid worker pool for {sample_key(server_row)}")
    worker_pool = server_profile.get("worker_pool")
    if not isinstance(worker_pool, dict) or int(
        worker_pool.get("configured_workers", 0)
    ) != worker_count or int(
        worker_pool.get("completed_sessions", -1)
    ) != p:
        raise ValueError(f"incomplete worker-pool evidence for {sample_key(server_row)}")
    workers = worker_pool.get("workers")
    if not isinstance(workers, list) or len(workers) != worker_count or {
        int(worker.get("worker_index", -1))
        for worker in workers if isinstance(worker, dict)
    } != set(range(worker_count)) or any(
        not isinstance(worker, dict) or
        int(worker.get("completed_sessions", -1)) < 0 or
        int(worker.get("setup_ns", -1)) < 0 or
        int(worker.get("user_cpu_ns", -1)) < 0 or
        int(worker.get("system_cpu_ns", -1)) < 0 or
        int(worker.get("max_rss_kb", 0)) <= 0
        for worker in workers
    ):
        raise ValueError(f"invalid worker telemetry for {sample_key(server_row)}")
    if sum(int(worker["completed_sessions"]) for worker in workers) != p or int(
        worker_pool.get("sum_setup_ns", -1)
    ) != sum(int(worker["setup_ns"]) for worker in workers) or int(
        worker_pool.get("sum_user_cpu_ns", -1)
    ) != sum(int(worker["user_cpu_ns"]) for worker in workers) or int(
        worker_pool.get("sum_system_cpu_ns", -1)
    ) != sum(int(worker["system_cpu_ns"]) for worker in workers):
        raise ValueError(f"worker telemetry totals mismatch for {sample_key(server_row)}")
    if any(
        not 0 <= int(arc.get("worker_index", -1)) < worker_count
        for arc in server_row["arcs"]
    ):
        raise ValueError(f"invalid worker assignment for {sample_key(server_row)}")
    for row, role in ((client_row, "client"), (server_row, "server")):
        if int(row["send_calls"]) != int(row["sent_frames"]) or int(
            row["receive_calls"]
        ) != int(row["received_frames"]):
            raise ValueError(f"{role} call/frame mismatch for {sample_key(row)}")
        if int(row["sum_user_cpu_ns"]) < 0 or int(
            row["sum_system_cpu_ns"]
        ) < 0 or (
            int(row["sum_user_cpu_ns"]) + int(row["sum_system_cpu_ns"])
        ) <= 0 or int(row["sum_process_peak_rss_kb"]) <= 0:
            raise ValueError(f"invalid {role} resource telemetry for {sample_key(row)}")
        if int(row["voluntary_context_switches"]) < 0 or int(
            row["involuntary_context_switches"]
        ) < 0 or int(row["scheduler_wait_ns"]) < 0 or int(
            row["scheduler_slices"]
        ) < 0:
            raise ValueError(f"invalid {role} context-switch telemetry")
    if int(client_row["critical_arc_wall_ns"]) <= 0 or int(
        client_row["stage_wall_ns"]
    ) < int(client_row["critical_arc_wall_ns"]):
        raise ValueError(f"invalid timing for {sample_key(client_row)}")


def validate_paired_contexts(
    samples: list[dict[str, object]], modes: list[str],
    campaign: str, route: str,
) -> None:
    if not modes:
        raise ValueError("paired campaign has no modes")
    execution_ids: dict[tuple[int, int, int, int], set[int]] = defaultdict(set)
    context_seeds: dict[tuple[int, int, int, int], set[str]] = defaultdict(set)
    block_ids: dict[tuple[int, int, int], set[str]] = defaultdict(set)
    trial_ids: dict[tuple[int, int, int], set[str]] = defaultdict(set)
    mode_positions: dict[tuple[int, int, int], set[int]] = defaultdict(set)
    for row in samples:
        n = int(row["participants"])
        p = int(row["concurrent_pairs"])
        trial = int(row["trial"])
        trial_key = (n, p, trial)
        block_id = str(row.get("randomization_block_id", ""))
        trial_id = str(row.get("paired_trial_id", ""))
        mode_position = int(row.get("mode_position", -1))
        if block_id != expected_randomization_block_id(campaign, route, n, p):
            raise ValueError("invalid randomization block identifier")
        if trial_id != expected_paired_trial_id(campaign, route, n, p, trial):
            raise ValueError("invalid paired-trial identifier")
        order = expected_mode_order(campaign, n, p, modes, trial)
        if mode_position < 0 or mode_position >= len(order) or order[
            mode_position
        ] != str(row["mode"]):
            raise ValueError("invalid position-counterbalanced mode order")
        block_ids[trial_key].add(block_id)
        trial_ids[trial_key].add(trial_id)
        mode_positions[trial_key].add(mode_position)
        for arc in row["arcs"]:
            key = (n, p, trial, int(arc["pair_id"]))
            execution_ids[key].add(int(arc["execution_id"]))
            context_seeds[key].add(str(arc["host_context_seed"]))
    if any(len(values) != len(modes) for values in execution_ids.values()):
        raise ValueError("paired modes do not use distinct execution IDs")
    if any(len(values) != 1 for values in context_seeds.values()):
        raise ValueError("paired modes do not share one host-context seed")
    if any(
        len(values) != 1 or len(next(iter(values), "")) != 64
        for values in block_ids.values()
    ):
        raise ValueError("paired modes do not share one randomization block")
    if any(
        len(values) != 1 or len(next(iter(values), "")) != 64
        for values in trial_ids.values()
    ):
        raise ValueError("paired modes do not share one paired-trial identifier")
    expected_positions = set(range(len(modes)))
    if any(values != expected_positions for values in mode_positions.values()):
        raise ValueError("paired modes are not position-counterbalanced")


def validate_environment_pair(client: dict[str, object],
                              server: dict[str, object]) -> None:
    client_environment = client.get("environment")
    server_environment = server.get("environment")
    if not isinstance(client_environment, dict) or not isinstance(
        server_environment, dict
    ):
        raise ValueError("missing endpoint environment manifest")
    for field in (
        "compiler", "zeromq", "cmake_build_type", "cmake_c_flags",
        "cmake_release_c_flags", "relic_build", "transport_tls_cipher",
    ):
        if client_environment.get(field) != server_environment.get(field):
            raise ValueError(f"client/server build environment differs: {field}")


def normalized_environment(environment: dict[str, object]) -> dict[str, object]:
    """Recover the effective Release mode omitted by an empty cache entry."""
    normalized = copy.deepcopy(environment)
    build_type = str(normalized.get("cmake_build_type", "")).strip()
    if build_type:
        return normalized
    release_flags = str(normalized.get("cmake_release_c_flags", ""))
    if "-O3" not in release_flags or "-DNDEBUG" not in release_flags:
        raise ValueError(
            "empty CMake build type without Release compilation evidence"
        )
    normalized["cmake_build_type"] = "Release"
    normalized["cmake_build_type_source"] = (
        "derived from the artifact's CMake default and captured Release flags"
    )
    return normalized


def display_counter(value):
    return "N/A" if value is None else str(value)


def render_markdown(report: dict[str, object]) -> str:
    lines = [
        "# Native Pre-swap cloud benchmark",
        "",
        f"Campaign: `{report['campaign_id']}`. Route: `{report['route']}`. ",
        "All configurations use the same native C/RELIC implementation and mutually authenticated ZeroMQ CURVE transport.",
        "",
        "## Distribution summary",
        "",
        "| n | k | p | Configuration | Trials | Pair P50/P95/P99 (ms) | Stage P50/P95/P99 (ms) | Pairs/s | Items/s | App goodput (Mbps) | Jain fairness |",
        "|---:|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in report["summary"]:
        lines.append(
            f"| {row['participants']} | {row['items_per_arc']} | {row['concurrent_pairs']} | "
            f"{row['mode']} | {row['trials']} | "
            f"{row['pair_p50_ms']:.3f}/{row['pair_p95_ms']:.3f}/{row['pair_p99_ms']:.3f} | "
            f"{row['median_stage_wall_ms']:.3f}/{row['p95_stage_wall_ms']:.3f}/{row['p99_stage_wall_ms']:.3f} | "
            f"{row['median_completed_pairs_per_second']:.3f} | "
            f"{row['median_completed_items_per_second']:.3f} | "
            f"{row['median_application_goodput_mbps']:.6f} | "
            f"{row['median_pair_jain_fairness']:.5f} |"
        )
    lines.extend(
        [
            "",
            "## Systems profile",
            "",
            "Client/server values are separated by `/`. Scheduler wait is Linux run-queue wait reported by `/proc/self/schedstat`, normalized per concurrent pair.",
            "N/A means the cgroup counter was unavailable or reset during at least one measured interval; it does not mean zero throttling.",
            "",
        "| n | k | p | Configuration | Process CPU (%) | CPU seconds (client/server) | Host CPU (%) | CPU steal (%) | Cgroup throttle periods | Peak RSS sum (KiB) | Scheduler wait/pair (ms) | Context switches | Run queue P50/Max | Interface traffic (Mbps) | Host TCP counter delta/retrans |",
        "|---:|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in report["summary"]:
        lines.append(
            f"| {row['participants']} | {row['items_per_arc']} | {row['concurrent_pairs']} | "
            f"{row['mode']} | "
            f"{row['median_client_cpu_pct']:.2f}/{row['median_server_cpu_pct']:.2f} | "
            f"{row['median_client_cpu_seconds_per_workload']:.6f}/{row['median_server_cpu_seconds_per_workload']:.6f} | "
            f"{row['median_client_host_cpu_pct']:.2f}/{row['median_server_host_cpu_pct']:.2f} | "
            f"{row['median_client_host_cpu_steal_pct']:.3f}/{row['median_server_host_cpu_steal_pct']:.3f} | "
            f"{display_counter(row['total_client_cgroup_throttled_periods'])}/{display_counter(row['total_server_cgroup_throttled_periods'])} | "
            f"{row['median_client_process_peak_rss_sum_kb']:.0f}/{row['median_server_process_peak_rss_sum_kb']:.0f} | "
            f"{row['median_client_scheduler_wait_ms_per_pair']:.3f}/{row['median_server_scheduler_wait_ms_per_pair']:.3f} | "
            f"{row['median_client_context_switches']:.0f}/{row['median_server_context_switches']:.0f} | "
            f"{row['median_client_run_queue_depth']:.1f}/{row['median_client_max_run_queue_depth']:.0f}"
            f"/{row['median_server_run_queue_depth']:.1f}/{row['median_server_max_run_queue_depth']:.0f} | "
            f"{row['median_client_interface_mbps']:.3f}/{row['median_server_interface_mbps']:.3f} | "
            f"{row['median_client_tcp_segments']:.0f}/{row['median_server_tcp_segments']:.0f}"
            f"/{row['median_client_tcp_retransmissions']:.0f}/{row['median_server_tcp_retransmissions']:.0f} |"
        )
    lines.extend(
        [
            "",
            "## Responder worker-queue profile",
            "",
            "Queue occupancy is measured inside the campaign gateway. Zero "
            "queued sessions means the fixed worker pool accepted every "
            "session immediately.",
            "",
            "| n | k | p | Configuration | Peak queue depth | Peak occupancy (%) | Queued sessions | Rejected sessions | Median wait/queued session (ms) | Max wait (ms) |",
            "|---:|---:|---:|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in report["summary"]:
        lines.append(
            f"| {row['participants']} | {row['items_per_arc']} | "
            f"{row['concurrent_pairs']} | {row['mode']} | "
            f"{row['median_server_gateway_peak_queue_depth']:.1f} | "
            f"{row['median_server_gateway_peak_queue_utilization_pct']:.2f} | "
            f"{row['total_server_gateway_queued_sessions']} | "
            f"{row['total_server_gateway_rejected_sessions']} | "
            f"{row['median_server_gateway_queue_wait_ms_per_queued_session']:.3f} | "
            f"{row['max_server_gateway_queue_wait_ms']:.3f} |"
        )
    lines.extend(
        [
            "",
            "## Paired effects",
            "",
            "Positive reduction means the candidate is faster than the baseline.",
            "",
        "| n | k | p | Comparison | Metric | Paired trials | Median difference [95% CI] (ms) | Median reduction [95% CI] | Mean reduction | Rank-biserial [95% CI] | Holm Wilcoxon p |",
        "|---:|---:|---:|---|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in report["paired_effects"]:
        low, high = row["median_reduction_ci95_pct"]
        difference_low, difference_high = row["median_difference_ci95_ms"]
        effect_low, effect_high = row["rank_biserial_ci95"]
        lines.append(
            f"| {row['participants']} | {row['items_per_arc']} | {row['concurrent_pairs']} | "
            f"{row['comparison']} | {row['effect_metric']} | {row['paired_trials']} | "
            f"{row['median_difference_ms']:.3f} "
            f"[{difference_low:.3f}, {difference_high:.3f}] | "
            f"{row['median_reduction_pct']:.2f}% [{low:.2f}%, {high:.2f}%] | "
            f"{row['mean_reduction_pct']:.2f}% | "
            f"{row['rank_biserial_effect']:.3f} "
            f"[{effect_low:.3f}, {effect_high:.3f}] | "
            f"{row['holm_adjusted_p']:.4g} |"
        )
    lines.extend(
        [
            "",
            "## Analysis specification",
            "",
            f"- Bootstrap resamples: {report['analysis_plan']['bootstrap_rounds']}.",
            f"- Tail bootstrap resamples: {report['analysis_plan']['tail_bootstrap_rounds']}.",
            f"- Tail intervals: {report['analysis_plan']['tail_interval']}.",
            f"- Bootstrap seed derivation: `{report['analysis_plan']['bootstrap_seed_derivation']}`.",
            f"- Holm families: {report['analysis_plan']['holm_families']}.",
            "- Raw paired trial differences are retained in the JSON analysis artifact.",
            "",
            "## Integrity audit",
            "",
            f"- Matched samples: {report['integrity']['matched_samples']}",
            f"- Verifier fallbacks: {report['integrity']['verifier_fallbacks']}",
            f"- Protocol source SHA-256: `{report['integrity']['protocol_source_sha256']}`",
            "- Transport authentication: ZeroMQ CURVE with responder-key pinning and ZAP initiator-key allowlisting.",
            f"- Initiator public-key fingerprint: `{report['integrity']['initiator_public_key_sha256']}`",
            f"- Responder public-key fingerprint: `{report['integrity']['responder_public_key_sha256']}`",
            "- Interface and TCP values above are host-counter deltas and may include unrelated host traffic. Use the separate campaign-scoped PCAP profile for exact TCP evidence.",
            "",
            "## Environment",
            "",
        ]
    )
    for endpoint in ("client", "server"):
        environment = report[f"{endpoint}_environment"]
        imds = environment.get("aws_imds", {})
        cpu = environment.get("cpu", {})
        scheduler = environment.get("scheduler", {})
        lines.extend([
            f"- {endpoint.capitalize()}: instance `{imds.get('instance_type', 'unknown')}`, "
            f"AZ `{imds.get('availability_zone', 'unknown')}`, "
            f"CPU `{cpu.get('model_name', 'unknown')}` "
            f"(family/model/stepping {cpu.get('cpu_family', 'unknown')}/"
            f"{cpu.get('model', 'unknown')}/{cpu.get('stepping', 'unknown')}), "
            f"kernel `{environment.get('kernel', 'unknown')}`.",
            f"- {endpoint.capitalize()} scheduler: `{scheduler.get('policy', 'unknown')}`, "
            f"affinity `{scheduler.get('affinity_cpu_list', 'unknown')}`, "
            f"burstable `{imds.get('burstable_instance', 'unknown')}`, "
            f"flex scheduled `{imds.get('flex_scheduled_instance', 'unknown')}`, "
            f"fixed performance `{imds.get('fixed_performance_instance', 'unknown')}`, "
            f"credit state `{imds.get('cpu_credit_state', 'unknown')}`.",
        ])
    lines.extend(
        [
            f"- Compiler: `{report['client_environment'].get('compiler', 'unknown')}`; "
            f"ZeroMQ: `{report['client_environment'].get('zeromq', 'unknown')}`; "
            "transport TLS cipher: not applicable (ZeroMQ CURVE).",
            "",
        ]
    )
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
    validate_role(client, "client")
    validate_role(server, "server")
    for field in (
        "campaign_id",
        "route",
        "participants",
        "concurrent_pair_values",
        "modes",
        "trials",
        "warmup",
        "runtime",
        "provenance",
        "transport_security",
        "experiment_identity",
        "randomization",
    ):
        if client.get(field) != server.get(field):
            raise ValueError(f"client/server {field} mismatch")
    client_source = client["environment"]["protocol_source_sha256"]
    server_source = server["environment"]["protocol_source_sha256"]
    if client_source != server_source:
        raise ValueError("client/server protocol source hashes differ")
    validate_environment_pair(client, server)
    client_rows = indexed_samples(client, "client")
    server_rows = indexed_samples(server, "server")
    if set(client_rows) != set(server_rows):
        raise ValueError("client/server sample sets differ")
    for key in sorted(client_rows):
        validate_audit(client_rows[key], server_rows[key])
    validate_paired_contexts(
        client["samples"], client["modes"],
        str(client["campaign_id"]), str(client["route"]),
    )

    grouped: dict[tuple[int, int, str], list[dict[str, object]]] = defaultdict(list)
    grouped_server: dict[tuple[int, int, str], list[dict[str, object]]] = defaultdict(list)
    for row in client["samples"]:
        grouped[(int(row["participants"]), int(row["concurrent_pairs"]),
                 str(row["mode"]))].append(row)
    for row in server["samples"]:
        grouped_server[(int(row["participants"]), int(row["concurrent_pairs"]),
                        str(row["mode"]))].append(row)
    summary = []
    for (n, p, mode), rows in sorted(grouped.items()):
        server_by_trial = {
            int(row["trial"]): row for row in grouped_server[(n, p, mode)]
        }
        critical = [float(row["critical_arc_wall_ns"]) / 1e6 for row in rows]
        stage = [float(row["stage_wall_ns"]) / 1e6 for row in rows]
        critical_blocks = [[
            float(row["critical_arc_wall_ns"]) / 1e6
        ] for row in rows]
        stage_blocks = [[
            float(row["stage_wall_ns"]) / 1e6
        ] for row in rows]
        pair_wall = [
            float(arc["wall_ns"]) / 1e6
            for row in rows for arc in row["arcs"]
        ]
        pair_blocks = [
            [float(arc["wall_ns"]) / 1e6 for arc in row["arcs"]]
            for row in rows
        ]
        pair_rates = [p * 1e9 / float(row["stage_wall_ns"]) for row in rows]
        item_rates = [p * (2 * n - 1) * 1e9 / float(row["stage_wall_ns"]) for row in rows]
        goodput = [
            (int(row["sent_bytes"]) + int(row["received_bytes"])) * 8e3
            / float(row["stage_wall_ns"])
            for row in rows
        ]
        client_cpu = [
            100.0 * (int(row["sum_user_cpu_ns"]) + int(row["sum_system_cpu_ns"]))
            / float(row["stage_wall_ns"])
            for row in rows
        ]
        server_cpu = [
            100.0 * (
                int(server_by_trial[int(row["trial"])]["sum_user_cpu_ns"])
                + int(server_by_trial[int(row["trial"])]["sum_system_cpu_ns"])
            ) / float(server_by_trial[int(row["trial"])]["stage_wall_ns"])
            for row in rows
        ]
        client_cpu_seconds = [
            (int(row["sum_user_cpu_ns"]) + int(row["sum_system_cpu_ns"]))
            / 1e9 for row in rows
        ]
        server_cpu_seconds = [
            (
                int(server_by_trial[int(row["trial"])] ["sum_user_cpu_ns"])
                + int(server_by_trial[int(row["trial"])] ["sum_system_cpu_ns"])
            ) / 1e9 for row in rows
        ]
        total_cpu_seconds = [
            client_value + server_value
            for client_value, server_value in zip(
                client_cpu_seconds, server_cpu_seconds
            )
        ]
        fairness = [
            jain_fairness([
                1e9 / float(arc["wall_ns"]) for arc in row["arcs"]
            ]) for row in rows
        ]
        client_host_cpu = [
            float(row["host_profile"]["host_cpu_utilization_pct"])
            for row in rows
        ]
        server_host_cpu = [
            float(server_by_trial[int(row["trial"])]["host_profile"]
                  ["host_cpu_utilization_pct"])
            for row in rows
        ]
        client_steal = [
            float(row["host_profile"]["host_cpu_steal_pct"])
            for row in rows
        ]
        server_steal = [
            float(server_by_trial[int(row["trial"])]
                  ["host_profile"]["host_cpu_steal_pct"])
            for row in rows
        ]

        def interface_mbps(row: dict[str, object]) -> float:
            host = row["host_profile"]
            return (int(host["rx_bytes"]) + int(host["tx_bytes"])) * 8e3 / float(
                row["stage_wall_ns"]
            )

        def tcp_segments(row: dict[str, object]) -> int:
            host = row["host_profile"]
            return int(host["tcp_in_segments"]) + int(host["tcp_out_segments"])
        summary.append(
            {
                "participants": n,
                "items_per_arc": 2 * n - 1,
                "concurrent_pairs": p,
                "mode": mode,
                "trials": len(rows),
                "median_critical_arc_ms": statistics.median(critical),
                "p95_critical_arc_ms": percentile(critical, 0.95),
                "p99_critical_arc_ms": percentile(critical, 0.99),
                "critical_p95_ci95_ms": bootstrap_block_percentile_ci(
                    critical_blocks, 0.95,
                    bootstrap_seed(client["campaign_id"], client["route"], n,
                                   p, mode, "critical-p95")
                ),
                "critical_p99_ci95_ms": bootstrap_block_percentile_ci(
                    critical_blocks, 0.99,
                    bootstrap_seed(client["campaign_id"], client["route"], n,
                                   p, mode, "critical-p99")
                ),
                "median_stage_wall_ms": statistics.median(stage),
                "p95_stage_wall_ms": percentile(stage, 0.95),
                "p99_stage_wall_ms": percentile(stage, 0.99),
                "stage_p95_ci95_ms": bootstrap_block_percentile_ci(
                    stage_blocks, 0.95,
                    bootstrap_seed(client["campaign_id"], client["route"], n,
                                   p, mode, "stage-p95")
                ),
                "stage_p99_ci95_ms": bootstrap_block_percentile_ci(
                    stage_blocks, 0.99,
                    bootstrap_seed(client["campaign_id"], client["route"], n,
                                   p, mode, "stage-p99")
                ),
                "pair_p50_ms": percentile(pair_wall, 0.50),
                "pair_p95_ms": percentile(pair_wall, 0.95),
                "pair_p99_ms": percentile(pair_wall, 0.99),
                "pair_p95_ci95_ms": bootstrap_block_percentile_ci(
                    pair_blocks, 0.95,
                    bootstrap_seed(client["campaign_id"], client["route"], n,
                                   p, mode, "pair-p95")
                ),
                "pair_p99_ci95_ms": bootstrap_block_percentile_ci(
                    pair_blocks, 0.99,
                    bootstrap_seed(client["campaign_id"], client["route"], n,
                                   p, mode, "pair-p99")
                ),
                "median_completed_pairs_per_second": statistics.median(pair_rates),
                "median_completed_items_per_second": statistics.median(item_rates),
                "median_application_goodput_mbps": statistics.median(goodput),
                "median_pair_jain_fairness": statistics.median(fairness),
                "median_client_cpu_pct": statistics.median(client_cpu),
                "median_server_cpu_pct": statistics.median(server_cpu),
                "median_client_cpu_seconds_per_workload": statistics.median(
                    client_cpu_seconds
                ),
                "median_server_cpu_seconds_per_workload": statistics.median(
                    server_cpu_seconds
                ),
                "median_total_cpu_seconds_per_workload": statistics.median(
                    total_cpu_seconds
                ),
                "median_client_cpu_ms_per_completed_pair": statistics.median(
                    value * 1000.0 / p for value in client_cpu_seconds
                ),
                "median_server_cpu_ms_per_completed_pair": statistics.median(
                    value * 1000.0 / p for value in server_cpu_seconds
                ),
                "median_total_cpu_ms_per_completed_pair": statistics.median(
                    value * 1000.0 / p for value in total_cpu_seconds
                ),
                "median_client_host_cpu_pct": statistics.median(client_host_cpu),
                "median_server_host_cpu_pct": statistics.median(server_host_cpu),
                "median_client_host_cpu_steal_pct": statistics.median(client_steal),
                "median_server_host_cpu_steal_pct": statistics.median(server_steal),
                "total_client_cgroup_throttled_periods": complete_counter_sum(
                    row["host_profile"].get("cgroup_cpu_nr_throttled")
                    for row in rows
                ),
                "total_server_cgroup_throttled_periods": complete_counter_sum(
                    server_by_trial[int(row["trial"])]
                        ["host_profile"].get("cgroup_cpu_nr_throttled")
                    for row in rows
                ),
                "total_client_cgroup_throttled_usec": complete_counter_sum(
                    row["host_profile"].get("cgroup_cpu_throttled_usec")
                    for row in rows
                ),
                "total_server_cgroup_throttled_usec": complete_counter_sum(
                    server_by_trial[int(row["trial"])]
                        ["host_profile"].get("cgroup_cpu_throttled_usec")
                    for row in rows
                ),
                "median_client_process_peak_rss_sum_kb": statistics.median(
                    int(row["sum_process_peak_rss_kb"]) for row in rows
                ),
                "median_server_process_peak_rss_sum_kb": statistics.median(
                    int(server_by_trial[int(row["trial"])]["sum_process_peak_rss_kb"])
                    for row in rows
                ),
                "median_client_voluntary_context_switches": statistics.median(
                    int(row["voluntary_context_switches"]) for row in rows
                ),
                "median_client_involuntary_context_switches": statistics.median(
                    int(row["involuntary_context_switches"]) for row in rows
                ),
                "median_client_context_switches": statistics.median(
                    int(row["voluntary_context_switches"]) +
                    int(row["involuntary_context_switches"]) for row in rows
                ),
                "median_server_context_switches": statistics.median(
                    int(server_by_trial[int(row["trial"])]
                        ["voluntary_context_switches"]) +
                    int(server_by_trial[int(row["trial"])]
                        ["involuntary_context_switches"]) for row in rows
                ),
                "median_client_scheduler_wait_ms_per_pair": statistics.median(
                    int(row["scheduler_wait_ns"]) / p / 1e6 for row in rows
                ),
                "median_server_scheduler_wait_ms_per_pair": statistics.median(
                    int(server_by_trial[int(row["trial"])]
                        ["scheduler_wait_ns"]) / p / 1e6 for row in rows
                ),
                "median_client_launch_skew_ms": statistics.median(
                    (max(int(arc["spawn_offset_ns"]) for arc in row["arcs"]) -
                     min(int(arc["spawn_offset_ns"]) for arc in row["arcs"])) / 1e6
                    for row in rows
                ),
                "median_client_run_queue_depth": statistics.median(
                    float(row["process_profile"]["median_run_queue_depth"])
                    for row in rows
                ),
                "median_client_max_run_queue_depth": statistics.median(
                    int(row["process_profile"]["max_run_queue_depth"])
                    for row in rows
                ),
                "median_server_run_queue_depth": statistics.median(
                    float(server_by_trial[int(row["trial"])]
                          ["process_profile"]["median_run_queue_depth"])
                    for row in rows
                ),
                "median_server_max_run_queue_depth": statistics.median(
                    int(server_by_trial[int(row["trial"])]
                        ["process_profile"]["max_run_queue_depth"])
                    for row in rows
                ),
                "median_server_gateway_peak_queue_depth": statistics.median(
                    int(server_by_trial[int(row["trial"])]
                        ["process_profile"]["gateway"]["peak_queue_depth"])
                    for row in rows
                ),
                "median_server_gateway_peak_queue_utilization_pct": statistics.median(
                    100.0 * int(server_by_trial[int(row["trial"])]
                                ["process_profile"]["gateway"]
                                ["peak_queue_depth"])
                    / max(1, int(server_by_trial[int(row["trial"])]
                                 ["process_profile"]["gateway"]
                                 ["queue_capacity"]))
                    for row in rows
                ),
                "total_server_gateway_queued_sessions": sum(
                    int(server_by_trial[int(row["trial"])]
                        ["process_profile"]["gateway"]["queued_sessions"])
                    for row in rows
                ),
                "total_server_gateway_rejected_sessions": sum(
                    int(server_by_trial[int(row["trial"])]
                        ["process_profile"]["gateway"]["rejected_sessions"])
                    for row in rows
                ),
                "median_server_gateway_queue_wait_ms_per_queued_session": statistics.median(
                    int(server_by_trial[int(row["trial"])]
                        ["process_profile"]["gateway"]["total_queue_wait_ns"])
                    / max(1, int(server_by_trial[int(row["trial"])]
                                 ["process_profile"]["gateway"]
                                 ["queued_sessions"])) / 1e6
                    for row in rows
                ),
                "max_server_gateway_queue_wait_ms": max(
                    int(server_by_trial[int(row["trial"])]
                        ["process_profile"]["gateway"]["max_queue_wait_ns"])
                    / 1e6 for row in rows
                ),
                "median_client_interface_mbps": statistics.median(
                    interface_mbps(row) for row in rows
                ),
                "median_server_interface_mbps": statistics.median(
                    interface_mbps(server_by_trial[int(row["trial"])])
                    for row in rows
                ),
                "median_client_tcp_segments": statistics.median(
                    tcp_segments(row) for row in rows
                ),
                "median_server_tcp_segments": statistics.median(
                    tcp_segments(server_by_trial[int(row["trial"])])
                    for row in rows
                ),
                "median_client_tcp_retransmissions": statistics.median(
                    int(row["host_profile"]["tcp_retransmitted_segments"])
                    for row in rows
                ),
                "median_server_tcp_retransmissions": statistics.median(
                    int(server_by_trial[int(row["trial"])]
                        ["host_profile"]["tcp_retransmitted_segments"])
                    for row in rows
                ),
                "median_sent_frames": statistics.median(
                    int(row["sent_frames"]) for row in rows
                ),
                "median_received_frames": statistics.median(
                    int(row["received_frames"]) for row in rows
                ),
                "median_sent_bytes": statistics.median(
                    int(row["sent_bytes"]) for row in rows
                ),
                "median_received_bytes": statistics.median(
                    int(row["received_bytes"]) for row in rows
                ),
            }
        )

    effects = []
    workload_values = sorted({
        (int(row["participants"]), int(row["concurrent_pairs"]))
        for row in client["samples"]
    })
    available_modes = set(client["modes"])
    for n, p in workload_values:
        for index, (name, (baseline, candidate)) in enumerate(COMPARISONS.items()):
            if baseline not in available_modes or candidate not in available_modes:
                continue
            metric = "critical_arc_wall_ns" if p == 1 else "stage_wall_ns"
            baseline_trials = {
                int(row["trial"]): float(row[metric])
                for row in grouped[(n, p, baseline)]
            }
            candidate_trials = {
                int(row["trial"]): float(row[metric])
                for row in grouped[(n, p, candidate)]
            }
            trials = sorted(set(baseline_trials) & set(candidate_trials))
            reductions = [
                100.0 * (baseline_trials[trial] - candidate_trials[trial])
                / baseline_trials[trial]
                for trial in trials
            ]
            differences_ns = [
                baseline_trials[trial] - candidate_trials[trial]
                for trial in trials
            ]
            differences_ms = [value / 1e6 for value in differences_ns]
            signed_rank_p, rank_biserial_effect = signed_rank(differences_ns)
            seed_prefix = (
                client["campaign_id"], client["route"], n, p, name, metric
            )
            reduction_seed = bootstrap_seed(*seed_prefix, "median-reduction")
            difference_seed = bootstrap_seed(*seed_prefix, "median-difference")
            rank_seed = bootstrap_seed(*seed_prefix, "rank-biserial")
            effects.append(
                {
                    "participants": n,
                    "items_per_arc": 2 * n - 1,
                    "concurrent_pairs": p,
                    "comparison": name,
                    "baseline": baseline,
                    "candidate": candidate,
                    "effect_metric": (
                        "critical-pair-wall" if p == 1 else "stage-wall"
                    ),
                    "paired_trials": len(trials),
                    "trial_ids": trials,
                    "raw_paired_differences_ms": differences_ms,
                    "median_difference_ms": statistics.median(differences_ms),
                    "median_difference_ci95_ms": bootstrap_median_ci(
                        differences_ms, seed=difference_seed
                    ),
                    "median_reduction_pct": statistics.median(reductions),
                    "median_reduction_ci95_pct": bootstrap_median_ci(
                        reductions, seed=reduction_seed
                    ),
                    "mean_reduction_pct": statistics.fmean(reductions),
                    "wilcoxon_signed_rank_p": signed_rank_p,
                    "rank_biserial_effect": rank_biserial_effect,
                    "rank_biserial_ci95": bootstrap_ci(
                        differences_ns, rank_biserial, seed=rank_seed
                    ),
                    "bootstrap_seeds": {
                        "median_reduction": reduction_seed,
                        "median_difference": difference_seed,
                        "rank_biserial": rank_seed,
                    },
                }
            )

        factorial_modes = {
            "independent_itemwise": "phase-coalesced-itemwise",
            "independent_aggregate": "phase-coalesced-batch-verification",
            "shared_itemwise": "batch-joint-presigning-itemwise",
            "shared_aggregate": "batch-joint-presigning-batch-verification",
        }
        if set(factorial_modes.values()).issubset(available_modes):
            metric = "critical_arc_wall_ns" if p == 1 else "stage_wall_ns"
            by_cell = {
                cell: {
                    int(row["trial"]): float(row[metric])
                    for row in grouped[(n, p, mode)]
                }
                for cell, mode in factorial_modes.items()
            }
            trials = sorted(set.intersection(
                *(set(values) for values in by_cell.values())
            ))
            interaction_ns = [
                by_cell["shared_itemwise"][trial]
                + by_cell["independent_aggregate"][trial]
                - by_cell["independent_itemwise"][trial]
                - by_cell["shared_aggregate"][trial]
                for trial in trials
            ]
            interaction_ms = [value / 1e6 for value in interaction_ns]
            interaction_pct = [
                100.0 * value / by_cell["independent_itemwise"][trial]
                for value, trial in zip(interaction_ns, trials)
            ]
            name = "session_verification_interaction"
            seed_prefix = (
                client["campaign_id"], client["route"], n, p, name, metric
            )
            percentage_seed = bootstrap_seed(*seed_prefix, "median-reduction")
            difference_seed = bootstrap_seed(*seed_prefix, "median-difference")
            rank_seed = bootstrap_seed(*seed_prefix, "rank-biserial")
            signed_rank_p, rank_biserial_effect = signed_rank(interaction_ns)
            effects.append({
                "participants": n,
                "items_per_arc": 2 * n - 1,
                "concurrent_pairs": p,
                "comparison": name,
                "baseline": "additive_session_and_verification_main_effects",
                "candidate": "observed_combined_shared_aggregate_effect",
                "effect_metric": (
                    "critical-pair-wall-interaction"
                    if p == 1 else "stage-wall-interaction"
                ),
                "interaction_definition": (
                    "shared_itemwise + independent_aggregate - "
                    "independent_itemwise - shared_aggregate; positive values "
                    "mean the combined method saves more wall time than the "
                    "sum of the two isolated main effects"
                ),
                "paired_trials": len(trials),
                "trial_ids": trials,
                "raw_paired_differences_ms": interaction_ms,
                "median_difference_ms": statistics.median(interaction_ms),
                "median_difference_ci95_ms": bootstrap_median_ci(
                    interaction_ms, seed=difference_seed
                ),
                "median_reduction_pct": statistics.median(interaction_pct),
                "median_reduction_ci95_pct": bootstrap_median_ci(
                    interaction_pct, seed=percentage_seed
                ),
                "mean_reduction_pct": statistics.fmean(interaction_pct),
                "wilcoxon_signed_rank_p": signed_rank_p,
                "rank_biserial_effect": rank_biserial_effect,
                "rank_biserial_ci95": bootstrap_ci(
                    interaction_ns, rank_biserial, seed=rank_seed
                ),
                "bootstrap_seeds": {
                    "median_reduction": percentage_seed,
                    "median_difference": difference_seed,
                    "rank_biserial": rank_seed,
                },
            })
    apply_holm_families(effects)
    report = {
        "schema": "oasis-preswap-cloud-analysis-v5",
        "campaign_id": client["campaign_id"],
        "route": client["route"],
        "analysis_plan": {
            "bootstrap_rounds": BOOTSTRAP_ROUNDS,
            "tail_bootstrap_rounds": TAIL_BOOTSTRAP_ROUNDS,
            "bootstrap_seed_domain": BOOTSTRAP_SEED_DOMAIN,
            "bootstrap_seed_derivation": (
                "first 64 bits of SHA-256 over domain-separated campaign, route, "
                "workload, comparison, metric, and estimand fields"
            ),
            "bootstrap_interval": "unadjusted percentile 95% paired bootstrap",
            "tail_interval": (
                "unadjusted percentile 95% hierarchical bootstrap resampling "
                "complete trial blocks; pair observations within a trial are "
                "not treated as independent"
            ),
            "paired_test": (
                "two-sided Wilcoxon signed-rank; zero_method=wilcox; "
                "correction=false; method=auto"
            ),
            "holm_families": (
                "primary: one comparison across n within a route; load: one "
                "comparison across p for fixed route and n"
            ),
            "effect_size": (
                "matched-pairs rank-biserial correlation with paired-bootstrap "
                "95% interval"
            ),
            "sample_size_policy": {
                "primary": "100 measured paired trials after 10 warm-ups",
                "load": "20 measured paired trials after 5 warm-ups",
                "rationale": (
                    "fixed publication matrix chosen before inspection of final "
                    "outcomes; primary uses more trials for inference and load "
                    "uses fewer because each trial executes up to 1024 pairs"
                ),
            },
        },
        "experiment_identity": client["experiment_identity"],
        "randomization": client["randomization"],
        "transport_security": client["transport_security"],
        "summary": summary,
        "paired_effects": effects,
        "integrity": {
            "matched_samples": len(client_rows),
            "verifier_fallbacks": sum(
                int(row["verifier_fallbacks"]) for row in client["samples"]
            ) + sum(
                int(row["verifier_fallbacks"]) for row in server["samples"]
            ),
            "protocol_source_sha256": client_source,
            "client_binary_sha256": client["environment"]["binary_sha256"],
            "server_binary_sha256": server["environment"]["binary_sha256"],
            "initiator_public_key_sha256": client["transport_security"][
                "initiator_public_key_sha256"
            ],
            "responder_public_key_sha256": client["transport_security"][
                "responder_public_key_sha256"
            ],
        },
        "client_environment": normalized_environment(client["environment"]),
        "server_environment": normalized_environment(server["environment"]),
    }
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    args.md_out.write_text(render_markdown(report), encoding="utf-8")
    print(f"wrote={args.json_out}")
    print(f"wrote={args.md_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
