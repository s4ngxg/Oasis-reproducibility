#!/usr/bin/env python3
"""Exercise native C/RELIC rejection paths over authenticated TCP."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import statistics
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TPC = ROOT / "vendor" / "paraswap" / "two-party computation"
CLIENT = TPC / "bin" / "preswap_client"
SERVER = TPC / "bin" / "preswap_server"
KEYGEN = TPC / "bin" / "curve_keygen"
MODE = "batch-joint-presigning-batch-verification"
ZAP_DOMAIN = "PARASWAP-OASIS-PRESWAP-v1"
SCENARIOS = (
    "control",
    "invalid-preparation-proof",
    "invalid-responder-opening",
    "invalid-responder-partial",
    "invalid-initiator-partial",
)
PROTOCOL_SOURCES = (
    TPC / "include" / "preswap_protocol.h",
    TPC / "src" / "preswap_common.c",
    TPC / "src" / "preswap_joint.c",
    TPC / "src" / "preswap_client_v4.c",
    TPC / "src" / "preswap_server_v4.c",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def percentile(values: list[float], percentile_value: float) -> float:
    ordered = sorted(values)
    index = (len(ordered) - 1) * percentile_value
    lower = int(index)
    upper = min(lower + 1, len(ordered) - 1)
    weight = index - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def scenario_order(campaign: str, n: int, trial: int,
                   warmup: bool) -> list[str]:
    phase = "warmup" if warmup else "measured"
    seed = int.from_bytes(
        hashlib.sha256(
            f"OASIS-NATIVE-FAULT-ORDER-v1|{campaign}|{phase}|{n}|{trial}".encode(
                "ascii"
            )
        ).digest()[:8],
        "big",
    )
    result = list(SCENARIOS)
    random.Random(seed).shuffle(result)
    return result


def outcome_is_correct(scenario: str, client_returncode: int,
                       server_returncode: int) -> bool:
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown fault scenario: {scenario}")
    if scenario == "control":
        return client_returncode == 0 and server_returncode == 0
    return client_returncode != 0 and server_returncode != 0


def common_arguments(n: int, port: int, execution_id: int,
                     context_seed: str) -> list[str]:
    return [
        "--mode", MODE,
        "--count", str(2 * n - 1),
        "--pair-id", "0",
        "--port", str(port),
        "--execution-id", str(execution_id),
        "--context-participants", str(n),
        "--context-epoch", "1",
        "--context-expiry", "3600",
        "--context-arc-index", "1",
        "--context-seed-hex", context_seed,
        "--io-timeout-ms", "10000",
        "--transport", "tcp",
        "--zap-domain", ZAP_DOMAIN,
    ]


def execute_case(auth: Path, campaign: str, n: int, trial: int,
                 warmup: bool, scenario: str, port: int) -> dict[str, object]:
    phase = "warmup" if warmup else "measured"
    material = f"{campaign}|{phase}|{n}|{trial}|{scenario}".encode("ascii")
    digest = hashlib.sha256(material).digest()
    execution_id = int.from_bytes(digest[:8], "big")
    context_seed = hashlib.sha256(b"OASIS-FAULT-CONTEXT-v1|" + material).hexdigest()
    common = common_arguments(n, port, execution_id, context_seed)
    server_command = [
        str(SERVER), *common,
        "--bind", "127.0.0.1",
        "--curve-secret-key", str(auth / "responder_secret.key"),
        "--curve-allowed-client-key", str(auth / "initiator_public.key"),
    ]
    client_command = [
        str(CLIENT), *common,
        "--host", "127.0.0.1",
        "--curve-public-key", str(auth / "initiator_public.key"),
        "--curve-secret-key", str(auth / "initiator_secret.key"),
        "--curve-server-key", str(auth / "responder_public.key"),
    ]
    if scenario == "invalid-preparation-proof":
        client_command.append("--inject-bad-preparation-proof")
    elif scenario == "invalid-responder-opening":
        server_command.append("--inject-bad-open")
    elif scenario == "invalid-responder-partial":
        server_command.append("--inject-bad-server-partial")
    elif scenario == "invalid-initiator-partial":
        client_command.append("--inject-bad-final")
    started = time.monotonic_ns()
    server = subprocess.Popen(
        server_command, cwd=TPC, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True
    )
    try:
        time.sleep(0.15)
        client = subprocess.run(
            client_command, cwd=TPC, capture_output=True, text=True,
            timeout=15, check=False
        )
        server_stdout, server_stderr = server.communicate(timeout=15)
    except Exception:
        server.kill()
        server.communicate()
        raise
    elapsed_ms = (time.monotonic_ns() - started) / 1_000_000
    expected_success = scenario == "control"
    observed_success = client.returncode == 0 and server.returncode == 0
    observed_bilateral_abort = client.returncode != 0 and server.returncode != 0
    accepted = outcome_is_correct(
        scenario, client.returncode, server.returncode
    )
    return {
        "participants": n,
        "items_per_arc": 2 * n - 1,
        "trial": trial,
        "warmup": warmup,
        "scenario": scenario,
        "expected_success": expected_success,
        "client_returncode": client.returncode,
        "server_returncode": server.returncode,
        "observed_bilateral_abort": observed_bilateral_abort,
        "outcome_correct": accepted,
        "wall_ms": elapsed_ms,
        "client_stdout_sha256": hashlib.sha256(
            client.stdout.encode("utf-8")
        ).hexdigest(),
        "client_stderr_sha256": hashlib.sha256(
            client.stderr.encode("utf-8")
        ).hexdigest(),
        "server_stdout_sha256": hashlib.sha256(
            server_stdout.encode("utf-8")
        ).hexdigest(),
        "server_stderr_sha256": hashlib.sha256(
            server_stderr.encode("utf-8")
        ).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--participants", default="3,5,8,16")
    parser.add_argument("--trials", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--base-port", type=int, default=19000)
    parser.add_argument("--campaign-id", default="native-fault-final")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        participants = [int(value) for value in args.participants.split(",")]
    except ValueError:
        parser.error("--participants must be comma-separated integers")
    if not participants or min(participants) < 3:
        parser.error("participants must contain values >= 3")
    if args.trials <= 0 or args.warmup < 0:
        parser.error("trials must be positive and warmup non-negative")
    if not 1024 <= args.base_port <= 64536:
        parser.error("base port must be in [1024, 64536]")
    for binary in (CLIENT, SERVER, KEYGEN):
        if not binary.is_file() or not os.access(binary, os.X_OK):
            parser.error(f"missing native executable: {binary}")
    started_utc = utc_now()
    measured: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="oasis-native-fault-") as raw:
        auth = Path(raw) / "auth"
        subprocess.run([str(KEYGEN), str(auth)], cwd=TPC, check=True,
                       capture_output=True, text=True)
        credential_fingerprints = {
            "initiator_public_key_sha256": sha256(
                auth / "initiator_public.key"
            ),
            "responder_public_key_sha256": sha256(
                auth / "responder_public.key"
            ),
        }
        stage = 0
        for n in participants:
            for warmup in (True, False):
                count = args.warmup if warmup else args.trials
                for trial in range(count):
                    for scenario in scenario_order(
                        args.campaign_id, n, trial, warmup
                    ):
                        row = execute_case(
                            auth, args.campaign_id, n, trial, warmup,
                            scenario, args.base_port + stage % 1000
                        )
                        stage += 1
                        if not row["outcome_correct"]:
                            raise RuntimeError(f"unexpected fault outcome: {row}")
                        if not warmup:
                            measured.append(row)
    summary = []
    for n in participants:
        for scenario in SCENARIOS:
            values = [
                float(row["wall_ms"]) for row in measured
                if row["participants"] == n and row["scenario"] == scenario
            ]
            summary.append({
                "participants": n,
                "items_per_arc": 2 * n - 1,
                "scenario": scenario,
                "trials": len(values),
                "median_wall_ms": statistics.median(values),
                "p95_wall_ms": percentile(values, 0.95),
                "unexpected_outcomes": 0,
            })
    result = {
        "schema": "oasis-native-fault-campaign-v1",
        "campaign_id": args.campaign_id,
        "backend": "native-c11-relic",
        "transport": "ZeroMQ CURVE over TCP loopback",
        "authenticated_transport": True,
        "transport_security": {
            "mechanism": "ZeroMQ CURVE",
            "responder_authentication": "initiator pins responder public key",
            "initiator_authorization": "responder allowlists initiator public key",
            **credential_fingerprints,
        },
        "fault_policy": "full parent-session abort at both endpoints",
        "randomization": {
            "domain": "OASIS-NATIVE-FAULT-ORDER-v1",
            "algorithm": "SHA-256-derived deterministic permutation",
        },
        "configuration": {
            "participants": participants,
            "scenarios": list(SCENARIOS),
            "trials": args.trials,
            "warmup": args.warmup,
        },
        "started_utc": started_utc,
        "finished_utc": utc_now(),
        "binary_sha256": {
            "client": sha256(CLIENT),
            "server": sha256(SERVER),
            "keygen": sha256(KEYGEN),
        },
        "source_sha256": {
            str(path.relative_to(ROOT)): sha256(path)
            for path in PROTOCOL_SOURCES
        },
        "runner_sha256": sha256(Path(__file__)),
        "measured_executions": len(measured),
        "unexpected_outcomes": 0,
        "summary": summary,
        "samples": measured,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"wrote={args.out}")
    print(f"measured_executions={len(measured)} unexpected_outcomes=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
