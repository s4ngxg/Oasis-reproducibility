#!/usr/bin/env python3
"""Auditable ParaSwap lifecycle over native and conformance backends."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Protocol


ROOT = Path(__file__).resolve().parents[1]
TPC_ROOT = ROOT / "vendor" / "paraswap" / "two-party computation"
CLIENT = TPC_ROOT / "bin" / "preswap_client"
SERVER = TPC_ROOT / "bin" / "preswap_server"
OASIS_ARC = ROOT / "vendor" / "oasis-linear" / "bin" / "oasis_arc_adapter"
OASIS_TRANSPORT = ROOT / "vendor" / "oasis-linear" / "bin" / "oasis_transport"
OASIS_CONFIGURATIONS = {
    "persistent-pipelined-itemwise",
    "batch-joint-presigning-itemwise",
    "phase-coalesced-batch-verification",
    "batch-joint-presigning-batch-verification",
    "phase-coalesced-itemwise",
}
NATIVE_PRESWAP_MODES = {
    "reference-itemwise",
    "phase-coalesced-itemwise",
    "batch-joint-presigning-itemwise",
    "phase-coalesced-batch-verification",
    "batch-joint-presigning-batch-verification",
}
NATIVE_MODE_ALIASES: dict[str, str] = {}


def canonical_native_mode(mode: str) -> str:
    return NATIVE_MODE_ALIASES.get(mode, mode)


class Phase(str, Enum):
    INITIAL = "initial"
    PREPARATION = "preparation"
    PRE_SWAP = "pre_swap"
    WITNESS_SHARING = "witness_sharing"
    SWAP = "swap"
    REFUND = "refund"
    COMPLETE = "complete"


class AssetState(str, Enum):
    UNLOCKED = "unlocked"
    LOCKED = "locked"
    WITHDRAWN = "withdrawn"
    REFUNDED = "refunded"


@dataclass(frozen=True)
class Config:
    participants: int
    mode: str
    backend: str = "native"
    configuration: str = ""
    base_port: int = 19600
    delta_seconds: int = 15
    epsilon_seconds: int = 5
    key_epoch: int = 1
    seed: str = "oasis-preswap-integration-v1"
    fault: str = "none"
    timeout_seconds: int = 120
    pre_swap_budget_seconds: float = 120.0
    preparation_digest: str = ""

    @property
    def items_per_arc(self) -> int:
        return 2 * self.participants - 1

    @property
    def phase_window_seconds(self) -> int:
        return self.delta_seconds + 3 * self.epsilon_seconds

    @property
    def refund_after_seconds(self) -> int:
        return self.phase_window_seconds + self.participants * self.delta_seconds


@dataclass
class Arc:
    index: int
    sender: str
    receiver: str
    asset: str
    chain_id: str
    joint_addresses: list[str]
    vtd_records: list[dict[str, object]]
    asset_state: AssetState = AssetState.UNLOCKED
    relock_level: int = 0


@dataclass
class ArcPreSwapResult:
    arc_index: int
    accepted: bool
    mode: str
    item_count: int
    withdraw_items: int
    relock_items: int
    execution_id: int = 0
    sent_frames: int = 0
    received_frames: int = 0
    sent_bytes: int = 0
    received_bytes: int = 0
    wall_ns: int = 0
    crypto_ns: int = 0
    server_crypto_ns: int = 0
    scheme: str = "joint-schnorr-adaptor-itemwise-verification"
    logical_messages: int = 0
    logical_sessions: int = 0
    itemwise_audit_checks: int = 0
    aggregate_verification_requested: bool = False
    aggregate_verification_active: bool = False
    aggregate_reverification_performed: bool = False
    aggregate_audit_valid: bool = False
    aggregate_reverification_ms: float = 0.0
    aggregate_reverification_checks: int = 0
    audit_pippenger_calls: int = 0
    audit_pippenger_terms: int = 0
    native_msm_calls: int = 0
    native_msm_terms: int = 0
    aggregate_soundness_bound: str = "not-applicable"
    adaptation_checks: int = 0
    retries: int = 0
    opening_failures: int = 0
    partial_failures: int = 0
    client_partial_failures: int = 0
    preparation_digest: str = ""
    paraswap_statement_mapping_valid: bool = False
    transport: str = "none"
    transport_completed: bool = False
    transport_authenticated: bool = False
    transport_retries: int = 0
    tls_cipher: str = ""
    verifier_ns: int = 0
    verifier_challenge_ns: int = 0
    verifier_msm_ns: int = 0
    verifier_equations: int = 0
    verifier_msm_calls: int = 0
    verifier_fallbacks: int = 0
    server_verifier_challenge_ns: int = 0
    server_verifier_msm_ns: int = 0
    server_verifier_equations: int = 0
    server_verifier_msm_calls: int = 0
    server_verifier_fallbacks: int = 0
    application_write_calls: int = 0
    application_read_calls: int = 0
    transport_write_ops: int = 0
    transport_read_ops: int = 0
    retransmissions: int = 0
    tcp_rtt_ms: float = 0.0
    tcp_rttvar_ms: float = 0.0
    snd_cwnd_segments: float = 0.0
    error: str = ""


class PreSigningBackend(Protocol):
    def execute_arc(self, arc_index: int, config: Config) -> ArcPreSwapResult:
        ...


class NativePreSigningBackend:
    """Runs the pinned native Pre-swap implementation in separate processes."""

    @staticmethod
    def _parse_client(stdout: str) -> dict[str, int]:
        parsed: dict[str, int] = {}
        for line in stdout.splitlines():
            fields = line.split("\t")
            if fields[0] == "RESULT" and len(fields) == 10:
                parsed.update(
                    wall_ns=int(fields[4]),
                    sent_bytes=int(fields[6]),
                    received_bytes=int(fields[7]),
                    sent_frames=int(fields[8]),
                    received_frames=int(fields[9]),
                )
            elif fields[0] == "CRYPTO_RESULT" and len(fields) == 8:
                parsed["crypto_ns"] = int(fields[4])
            elif fields[0] == "VERIFIER_RESULT" and len(fields) == 9:
                parsed.update(
                    verifier_challenge_ns=int(fields[4]),
                    verifier_msm_ns=int(fields[5]),
                    verifier_equations=int(fields[6]),
                    verifier_msm_calls=int(fields[7]),
                    verifier_fallbacks=int(fields[8]),
                )
        required = {
            "wall_ns",
            "sent_bytes",
            "received_bytes",
            "sent_frames",
            "received_frames",
            "crypto_ns",
            "verifier_challenge_ns",
            "verifier_msm_ns",
            "verifier_equations",
            "verifier_msm_calls",
            "verifier_fallbacks",
        }
        if not required.issubset(parsed):
            raise ValueError(f"incomplete client output: {stdout!r}")
        return parsed

    @staticmethod
    def _parse_server(stdout: str) -> dict[str, int]:
        parsed: dict[str, int] = {}
        for line in stdout.splitlines():
            fields = line.split("\t")
            if fields[0] == "SERVER_RESULT" and len(fields) == 8:
                parsed["server_crypto_ns"] = sum(
                    int(value) for value in fields[5:8]
                )
            elif fields[0] == "SERVER_VERIFIER_RESULT" and len(fields) == 9:
                parsed.update(
                    server_verifier_challenge_ns=int(fields[4]),
                    server_verifier_msm_ns=int(fields[5]),
                    server_verifier_equations=int(fields[6]),
                    server_verifier_msm_calls=int(fields[7]),
                    server_verifier_fallbacks=int(fields[8]),
                )
        required = {
            "server_crypto_ns",
            "server_verifier_challenge_ns",
            "server_verifier_msm_ns",
            "server_verifier_equations",
            "server_verifier_msm_calls",
            "server_verifier_fallbacks",
        }
        if not required.issubset(parsed):
            raise ValueError(f"incomplete server output: {stdout!r}")
        return parsed

    def execute_arc(self, arc_index: int, config: Config) -> ArcPreSwapResult:
        native_mode = canonical_native_mode(config.mode)
        result = ArcPreSwapResult(
            arc_index=arc_index,
            accepted=False,
            mode=native_mode,
            item_count=config.items_per_arc,
            withdraw_items=config.participants,
            relock_items=config.participants - 1,
        )
        execution_id = int.from_bytes(
            hashlib.sha256(
                f"{config.preparation_digest or config.seed}|arc|{arc_index}".encode(
                    "ascii"
                )
            ).digest()[:8],
            "big",
        )
        result.execution_id = execution_id
        if config.fault == "peer-abort" and arc_index == 0:
            result.error = "injected peer abort before completion"
            return result
        port = config.base_port + arc_index
        common = [
            "--mode",
            native_mode,
            "--count",
            str(config.items_per_arc),
            "--pair-id",
            str(arc_index),
            "--port",
            str(port),
            "--execution-id",
            str(execution_id),
            "--context-participants",
            str(config.participants),
            "--context-epoch",
            str(config.key_epoch),
            "--context-expiry",
            str(config.refund_after_seconds),
            "--context-arc-index",
            str(arc_index + 1),
            "--context-seed-hex",
            str(config.preparation_digest),
        ]
        if config.fault == "preswap" and arc_index == 0:
            common.append("--inject-bad-open")
        if config.fault == "invalid-final" and arc_index == 0:
            common.append("--inject-bad-final")
        socket_path = Path(f"/tmp/oasis-preswap-{port}.sock")
        socket_path.unlink(missing_ok=True)
        server = subprocess.Popen(
            [str(SERVER), *common],
            cwd=TPC_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            readiness_deadline = time.monotonic() + 5
            while not socket_path.exists():
                if server.poll() is not None:
                    server_stdout, server_stderr = server.communicate()
                    result.error = (
                        f"server exited before bind: {server.returncode}; "
                        f"{server_stdout.strip()} {server_stderr.strip()}"
                    )
                    return result
                if time.monotonic() >= readiness_deadline:
                    raise subprocess.TimeoutExpired(str(SERVER), 5)
                time.sleep(0.01)
            client = subprocess.run(
                [str(CLIENT), *common],
                cwd=TPC_ROOT,
                capture_output=True,
                text=True,
                timeout=config.timeout_seconds,
                check=False,
            )
            if client.returncode != 0:
                server.kill()
                server_stdout, server_stderr = server.communicate()
                result.error = (
                    f"client rejected transcript rc={client.returncode}: "
                    f"{client.stderr.strip()}; server: "
                    f"{server_stdout.strip()} {server_stderr.strip()}"
                )
                return result
            server_stdout, server_stderr = server.communicate(
                timeout=config.timeout_seconds
            )
            if server.returncode != 0:
                result.error = (
                    f"server rc={server.returncode}: {server_stderr.strip()}"
                )
                return result
            result.__dict__.update(self._parse_client(client.stdout))
            result.__dict__.update(self._parse_server(server_stdout))
            is_bjp = native_mode.startswith("batch-joint-presigning-")
            is_reference = native_mode == "reference-itemwise"
            uses_msm = native_mode.endswith("-batch-verification")
            if is_reference:
                result.logical_messages = 5 * config.items_per_arc + 1
            else:
                result.logical_messages = 7 if uses_msm else 6
            result.logical_sessions = 1 if is_bjp else config.items_per_arc
            result.scheme = (
                "joint-schnorr-adaptor-batch-verification"
                if uses_msm else "joint-schnorr-adaptor-itemwise-verification"
            )
            result.aggregate_verification_requested = uses_msm
            result.aggregate_verification_active = uses_msm
            result.itemwise_audit_checks = (
                0 if uses_msm or is_reference
                else result.verifier_equations + result.server_verifier_equations
            )
            result.native_msm_calls = (
                result.verifier_msm_calls + result.server_verifier_msm_calls
            )
            result.native_msm_terms = (
                0 if not uses_msm else 6 * config.items_per_arc + 3
            )
            result.aggregate_soundness_bound = (
                "min(1,Q*2^-254)" if uses_msm else "not-applicable"
            )
            result.verifier_ns = (
                result.verifier_challenge_ns + result.verifier_msm_ns
            )
            result.accepted = True
            return result
        except (subprocess.TimeoutExpired, ValueError) as error:
            server.kill()
            server.communicate()
            result.error = str(error)
            return result


class OasisConformanceBackend:
    """Checks algebra, Adapt/Extract, retry, and MSM outside timing results."""

    def execute_arc(self, arc_index: int, config: Config) -> ArcPreSwapResult:
        configuration = (
            config.configuration
            or "batch-joint-presigning-batch-verification"
        )
        result = ArcPreSwapResult(
            arc_index=arc_index,
            accepted=False,
            mode=configuration,
            item_count=config.items_per_arc,
            withdraw_items=config.participants,
            relock_items=config.participants - 1,
            scheme="linear-schnorr-adaptor",
        )
        execution_id = int.from_bytes(
            hashlib.sha256(
                f"{config.preparation_digest}|arc|{arc_index}".encode("ascii")
            ).digest()[:8],
            "big",
        )
        result.execution_id = execution_id
        if config.fault == "peer-abort" and arc_index == 0:
            result.error = "injected peer abort before completion"
            return result
        command = [
            str(OASIS_ARC),
            "--n",
            str(config.participants),
            "--arc-id",
            str(arc_index),
            "--execution-id",
            str(execution_id),
            "--key-epoch",
            str(config.key_epoch),
            "--expiry",
            str(config.refund_after_seconds),
            "--preparation-digest",
            config.preparation_digest,
            "--variant",
            configuration,
        ]
        if config.fault == "opening-retry" and arc_index == 0:
            command.extend(("--bad-opening", "0"))
        if config.fault == "partial-retry" and arc_index == 0:
            command.extend(("--bad-partial", "0"))
        try:
            process = subprocess.run(
                command,
                cwd=ROOT / "vendor" / "oasis-linear",
                capture_output=True,
                text=True,
                timeout=config.timeout_seconds,
                check=False,
            )
            if process.returncode != 0:
                result.error = (
                    f"OASIS adapter rc={process.returncode}: "
                    f"{process.stderr.strip()}"
                )
                return result
            parsed = json.loads(process.stdout)
            if parsed.get("schema") != "oasis-preswap-arc-v1":
                raise ValueError("unexpected OASIS adapter schema")
            if int(parsed["k"]) != config.items_per_arc:
                raise ValueError("OASIS adapter returned incorrect item count")
            if int(parsed["arc_id"]) != arc_index:
                raise ValueError("OASIS adapter returned incorrect arc id")
            if int(parsed["execution_id"]) != execution_id:
                raise ValueError("OASIS adapter returned incorrect execution id")
            if parsed["preparation_digest"] != config.preparation_digest:
                raise ValueError("OASIS adapter preparation digest mismatch")
            if not bool(parsed["paraswap_statement_mapping_valid"]):
                raise ValueError("OASIS adapter statement mapping is invalid")
            result.accepted = bool(parsed["accepted"])
            result.wall_ns = int(float(parsed["wall_ms"]) * 1_000_000)
            result.crypto_ns = int(float(parsed["cpu_ms"]) * 1_000_000)
            result.logical_messages = int(parsed["logical_messages"])
            result.logical_sessions = int(parsed["logical_sessions"])
            result.itemwise_audit_checks = int(parsed["itemwise_audit_checks"])
            result.aggregate_verification_requested = bool(
                parsed["aggregate_verification_requested"]
            )
            result.aggregate_verification_active = bool(
                parsed["aggregate_verification_active"]
            )
            result.aggregate_reverification_performed = bool(
                parsed["aggregate_reverification_performed"]
            )
            result.aggregate_audit_valid = bool(parsed["aggregate_audit_valid"])
            result.aggregate_reverification_ms = float(
                parsed["aggregate_reverification_ms"]
            )
            result.aggregate_reverification_checks = int(
                parsed["aggregate_reverification_checks"]
            )
            result.audit_pippenger_calls = int(
                parsed["audit_pippenger_calls"]
            )
            result.audit_pippenger_terms = int(
                parsed["audit_pippenger_terms"]
            )
            result.aggregate_soundness_bound = str(
                parsed["aggregate_soundness_bound"]
            )
            result.adaptation_checks = int(parsed["adapt_extract_checks"])
            result.retries = int(parsed["retries"])
            result.opening_failures = int(parsed["opening_failures"])
            result.partial_failures = int(parsed["partial_failures"])
            result.preparation_digest = str(parsed["preparation_digest"])
            result.paraswap_statement_mapping_valid = bool(
                parsed["paraswap_statement_mapping_valid"]
            )
            return result
        except (json.JSONDecodeError, KeyError, TypeError, ValueError,
                subprocess.TimeoutExpired) as error:
            result.error = str(error)
            return result


class OasisLinearBackend:
    """Runs OASIS over separate native TCP peers plus conformance checks."""

    requires_authenticated_transport = True

    VARIANTS = {
        "persistent-pipelined-itemwise": "persistent-pipelined-itemwise",
        "batch-joint-presigning-itemwise": (
            "batch-joint-presigning-itemwise"
        ),
        "phase-coalesced-batch-verification": (
            "phase-coalesced-batch-verification"
        ),
        "batch-joint-presigning-batch-verification": (
            "batch-joint-presigning-batch-verification"
        ),
        "phase-coalesced-itemwise": "phase-coalesced-itemwise",
    }

    def __init__(self) -> None:
        self.conformance = OasisConformanceBackend()
        self._pki = tempfile.TemporaryDirectory(
            prefix="oasis-preswap-mtls-"
        )
        self.pki_dir = Path(self._pki.name)
        self._generate_test_pki()

    def _openssl(self, *arguments: str) -> None:
        process = subprocess.run(
            ["openssl", *arguments],
            cwd=self.pki_dir,
            capture_output=True,
            text=True,
            check=False,
        )
        if process.returncode != 0:
            raise RuntimeError(
                f"OpenSSL PKI setup failed: {process.stderr.strip()}"
            )

    def _generate_test_pki(self) -> None:
        self._openssl(
            "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", "ca.key", "-out", "ca.crt", "-days", "1",
            "-subj", "/CN=ParaSwap-OASIS-Test-CA",
        )
        (self.pki_dir / "server.ext").write_text(
            "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n",
            encoding="ascii",
        )
        self._openssl(
            "req", "-newkey", "rsa:2048", "-nodes",
            "-keyout", "server.key", "-out", "server.csr",
            "-subj", "/CN=127.0.0.1",
        )
        self._openssl(
            "x509", "-req", "-in", "server.csr", "-CA", "ca.crt",
            "-CAkey", "ca.key", "-CAcreateserial", "-out", "server.crt",
            "-days", "1", "-sha256", "-extfile", "server.ext",
        )
        (self.pki_dir / "client.ext").write_text(
            "extendedKeyUsage=clientAuth\n",
            encoding="ascii",
        )
        self._openssl(
            "req", "-newkey", "rsa:2048", "-nodes",
            "-keyout", "client.key", "-out", "client.csr",
            "-subj", "/CN=oasis-preswap-initiator",
        )
        self._openssl(
            "x509", "-req", "-in", "client.csr", "-CA", "ca.crt",
            "-CAkey", "ca.key", "-CAserial", "ca.srl", "-out", "client.crt",
            "-days", "1", "-sha256", "-extfile", "client.ext",
        )

    def execute_arc(self, arc_index: int, config: Config) -> ArcPreSwapResult:
        if config.fault == "peer-abort" and arc_index == 0:
            return self.conformance.execute_arc(arc_index, config)

        configuration = (
            config.configuration
            or "batch-joint-presigning-batch-verification"
        )
        execution_id = int.from_bytes(
            hashlib.sha256(
                f"{config.preparation_digest}|arc|{arc_index}".encode("ascii")
            ).digest()[:8],
            "big",
        )
        port = config.base_port + arc_index
        timeout = max(1, math.ceil(config.timeout_seconds))
        output = Path(
            f"/tmp/oasis-preswap-transport-{execution_id}-{arc_index}.json"
        )
        output.unlink(missing_ok=True)
        server_command = [
            str(OASIS_TRANSPORT),
            "server",
            "--bind", "127.0.0.1",
            "--port", str(port),
            "--threads", "2",
            "--io-timeout-seconds", str(timeout),
            "--tls", "--mutual-tls",
            "--cert", str(self.pki_dir / "server.crt"),
            "--key", str(self.pki_dir / "server.key"),
            "--ca", str(self.pki_dir / "ca.crt"),
        ]
        if config.fault == "opening-retry" and arc_index == 0:
            server_command.extend(("--inject-bad-openings", "1"))
        if config.fault == "partial-retry" and arc_index == 0:
            server_command.extend(("--inject-bad-partials", "1"))

        server = subprocess.Popen(
            server_command,
            cwd=ROOT / "vendor" / "oasis-linear",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            readiness_deadline = time.monotonic() + min(5.0, timeout)
            while True:
                if server.poll() is not None:
                    stdout, stderr = server.communicate()
                    raise RuntimeError(
                        f"OASIS server exited before client: {stdout} {stderr}"
                    )
                # Binding is complete once the port appears in /proc/net/tcp.
                port_hex = f"{port:04X}"
                listeners = Path("/proc/net/tcp").read_text(encoding="ascii")
                if any(
                    row.split()[1].endswith(f":{port_hex}") and
                    row.split()[3] == "0A"
                    for row in listeners.splitlines()[1:]
                ):
                    break
                if time.monotonic() >= readiness_deadline:
                    raise subprocess.TimeoutExpired(server_command, timeout)
                time.sleep(0.01)

            client_command = [
                str(OASIS_TRANSPORT),
                "client",
                "--host", "127.0.0.1",
                "--port", str(port),
                "--n-values", str(config.participants),
                "--variants", self.VARIANTS[configuration],
                "--trials", "1",
                "--warmup", "0",
                "--pairs", "1",
                "--threads", "1",
                "--io-timeout-seconds", str(timeout),
                "--tls", "--mutual-tls",
                "--cert", str(self.pki_dir / "client.crt"),
                "--key", str(self.pki_dir / "client.key"),
                "--ca", str(self.pki_dir / "ca.crt"),
                "--server-name", "127.0.0.1",
                "--campaign-id", "paraswap-full-integration",
                "--route", f"loopback-arc-{arc_index}",
                "--context-seed", config.preparation_digest,
                "--context-key-epoch", str(config.key_epoch),
                "--context-expiry", str(config.refund_after_seconds),
                "--context-pair-id", str(arc_index),
                "--context-execution-id", str(execution_id),
                "--context-arc-index", str(arc_index + 1),
                "--out", str(output),
            ]
            if config.fault == "client-partial-retry" and arc_index == 0:
                client_command.extend(("--inject-bad-client-partials", "1"))
            client = subprocess.run(
                client_command,
                cwd=ROOT / "vendor" / "oasis-linear",
                capture_output=True,
                text=True,
                timeout=config.timeout_seconds,
                check=False,
            )
            if client.returncode != 0:
                raise RuntimeError(
                    f"OASIS client rc={client.returncode}: {client.stderr.strip()}"
                )
            payload = json.loads(output.read_text(encoding="utf-8"))
            if payload.get("schema") != "oasis-conformance-transport-v1":
                raise ValueError("unexpected OASIS transport schema")
            samples = payload.get("samples", [])
            if len(samples) != 1:
                raise ValueError("OASIS arc transport must return one sample")
            sample = samples[0]
            if int(sample["failures"]) != 0:
                raise ValueError("OASIS transport recorded a failed pair")

            result = self.conformance.execute_arc(arc_index, config)
            if not result.accepted:
                return result
            transport_retries = int(sample["fault_count"])
            expected_retries = (
                1
                if config.fault == "client-partial-retry" and arc_index == 0
                else result.retries
            )
            if transport_retries != expected_retries:
                raise ValueError(
                    "transport/conformance retry-count mismatch: "
                    f"{transport_retries} != {expected_retries}"
                )
            result.retries = transport_retries
            result.client_partial_failures = (
                transport_retries
                if config.fault == "client-partial-retry" else 0
            )
            result.wall_ns = int(float(sample["wall_ms"]) * 1_000_000)
            result.crypto_ns = int(float(sample["cpu_ms"]) * 1_000_000)
            result.sent_frames = int(sample["frames_sent"])
            result.received_frames = int(sample["frames_received"])
            result.sent_bytes = int(sample["bytes_sent"])
            result.received_bytes = int(sample["bytes_received"])
            result.logical_messages = int(sample["application_messages"])
            result.logical_sessions = int(sample["logical_sessions"])
            result.transport = "native TCP client/server loopback"
            result.transport_completed = True
            result.transport_authenticated = True
            result.transport_retries = transport_retries
            result.tls_cipher = str(sample["tls_cipher"])
            result.verifier_ns = int(float(sample["verifier_ms"]) * 1_000_000)
            result.application_write_calls = int(
                sample["application_write_calls"]
            )
            result.application_read_calls = int(
                sample["application_read_calls"]
            )
            result.transport_write_ops = int(sample["transport_write_ops"])
            result.transport_read_ops = int(sample["transport_read_ops"])
            result.retransmissions = int(sample["retransmissions"])
            result.tcp_rtt_ms = float(sample["tcp_rtt_ms"])
            result.tcp_rttvar_ms = float(sample["tcp_rttvar_ms"])
            result.snd_cwnd_segments = float(sample["snd_cwnd_segments"])
            if not result.tls_cipher.startswith("TLS_"):
                raise ValueError("OASIS transport did not negotiate TLS 1.3")
            return result
        except (
            json.JSONDecodeError,
            KeyError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
            subprocess.TimeoutExpired,
        ) as error:
            return ArcPreSwapResult(
                arc_index=arc_index,
                accepted=False,
                mode=configuration,
                item_count=config.items_per_arc,
                withdraw_items=config.participants,
                relock_items=config.participants - 1,
                execution_id=execution_id,
                scheme="linear-schnorr-adaptor",
                preparation_digest=config.preparation_digest,
                transport="native TCP client/server loopback",
                error=str(error),
            )
        finally:
            output.unlink(missing_ok=True)
            if server.poll() is None:
                server.terminate()
            try:
                server.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                server.kill()
                server.communicate()


class DeterministicBackend:
    """Test double for lifecycle invariants; never used for measurements."""

    def execute_arc(self, arc_index: int, config: Config) -> ArcPreSwapResult:
        accepted = not (
            config.fault in {"preswap", "invalid-final", "peer-abort"}
            and arc_index == 0
        )
        reference_native = False
        if config.backend == "oasis":
            configuration = (
                config.configuration
                or "batch-joint-presigning-batch-verification"
            )
            shared_batch = configuration.startswith(
                "batch-joint-presigning-"
            )
            phase_coalesced = configuration.startswith("phase-coalesced-")
            uses_msm = configuration.endswith("-batch-verification")
            msm_active = uses_msm and config.items_per_arc >= 8
            sessions = 1 if shared_batch else config.items_per_arc
            messages = (
                (
                    7
                    if configuration
                    == "batch-joint-presigning-batch-verification"
                    else 6
                )
                if shared_batch
                else 5 * config.items_per_arc + 1
            )
            retries = (
                1
                if config.fault in {
                    "opening-retry", "partial-retry", "client-partial-retry"
                }
                and arc_index == 0 else 0
            )
            if retries:
                sessions += 1
                messages += 6
            mode = configuration
            scheme = "linear-schnorr-adaptor"
        else:
            native_mode = canonical_native_mode(config.mode)
            reference_native = native_mode == "reference-itemwise"
            shared_batch = native_mode.startswith("batch-joint-presigning-")
            phase_coalesced = native_mode.startswith("phase-coalesced-")
            uses_msm = native_mode.endswith("-batch-verification")
            sessions = 1 if shared_batch else config.items_per_arc
            messages = (
                5 * config.items_per_arc + 1
                if reference_native
                else (7 if uses_msm else 6)
            )
            retries = 0
            msm_active = uses_msm
            mode = native_mode
            scheme = (
                "joint-schnorr-adaptor-batch-verification"
                if uses_msm else "joint-schnorr-adaptor-itemwise-verification"
            )
        if config.fault == "peer-abort" and arc_index == 0:
            sessions = 0
            messages = 0
            retries = 0
            uses_msm = False
            msm_active = False
        return ArcPreSwapResult(
            arc_index=arc_index,
            accepted=accepted,
            mode=mode,
            item_count=config.items_per_arc,
            withdraw_items=config.participants,
            relock_items=config.participants - 1,
            execution_id=int.from_bytes(
                hashlib.sha256(
                    f"{config.preparation_digest or config.seed}|arc|{arc_index}".encode(
                        "ascii"
                    )
                ).digest()[:8],
                "big",
            ),
            sent_frames=(3 if phase_coalesced or shared_batch else 3 * sessions),
            received_frames=(
                2 * sessions + 1
                if reference_native
                else (3 if phase_coalesced or shared_batch else 3 * sessions)
            ),
            scheme=scheme,
            logical_messages=messages,
            logical_sessions=sessions,
            aggregate_verification_active=msm_active,
            itemwise_audit_checks=(
                config.items_per_arc if accepted else 0
            ),
            aggregate_verification_requested=uses_msm,
            aggregate_reverification_performed=msm_active and retries == 0,
            aggregate_audit_valid=msm_active and retries == 0,
            aggregate_reverification_checks=(
                3 if msm_active and retries == 0 else 0
            ),
            audit_pippenger_calls=3 if msm_active and retries == 0 else 0,
            audit_pippenger_terms=(
                6 * config.items_per_arc
                if msm_active and retries == 0 else 0
            ),
            aggregate_soundness_bound=(
                "min(1,Q*2^-254)" if msm_active else "not-applicable"
            ),
            adaptation_checks=config.items_per_arc if accepted else 0,
            retries=retries,
            opening_failures=(
                retries if config.fault == "opening-retry" else 0
            ),
            partial_failures=(
                retries if config.fault == "partial-retry" else 0
            ),
            client_partial_failures=(
                retries if config.fault == "client-partial-retry" else 0
            ),
            preparation_digest=config.preparation_digest,
            paraswap_statement_mapping_valid=(config.backend == "oasis"),
            error="" if accepted else "injected pre-swap failure",
        )


class Lifecycle:
    def __init__(self, config: Config, backend: PreSigningBackend) -> None:
        if config.participants < 3:
            raise ValueError("ParaSwap cycle requires at least three participants")
        if config.items_per_arc > 4096:
            raise ValueError("2n-1 exceeds the native adapter limit of 4096 items")
        if config.base_port < 1 or config.base_port + config.participants > 65535:
            raise ValueError("base port does not leave one valid port per arc")
        if config.backend not in {"native", "oasis"}:
            raise ValueError("backend must be native or oasis")
        if config.backend == "native":
            if canonical_native_mode(config.mode) not in NATIVE_PRESWAP_MODES:
                raise ValueError("unsupported native Pre-swap mode")
            if config.configuration:
                raise ValueError("configuration applies only to the OASIS backend")
            if config.fault in {
                "opening-retry", "partial-retry", "client-partial-retry"
            }:
                raise ValueError("retry fault injection applies only to OASIS")
        else:
            if config.participants > 1024:
                raise ValueError("OASIS adapter supports at most 1024 participants")
            configuration = (
                config.configuration
                or "batch-joint-presigning-batch-verification"
            )
            if configuration not in OASIS_CONFIGURATIONS:
                raise ValueError("unsupported OASIS configuration")
            if config.fault == "preswap":
                raise ValueError(
                    "use an OASIS retry fault for transcript mutation; "
                    "preswap is the reference unrecoverable mutation"
                )
            if config.fault == "invalid-final":
                raise ValueError("invalid-final applies only to the native backend")
        if config.fault not in {
            "none", "preswap", "invalid-final", "opening-retry", "partial-retry",
            "client-partial-retry",
            "peer-abort", "witness",
        }:
            raise ValueError(
                "unsupported fault injection"
            )
        if config.delta_seconds <= 0 or config.epsilon_seconds < 0:
            raise ValueError("delta must be positive and epsilon non-negative")
        if config.key_epoch <= 0:
            raise ValueError("key epoch must be positive")
        if config.timeout_seconds <= 0 or config.pre_swap_budget_seconds <= 0:
            raise ValueError("process timeout and pre-swap budget must be positive")
        self.config = config
        self.backend = backend
        self.phase = Phase.INITIAL
        self.arcs: list[Arc] = []
        self.preswap_results: list[ArcPreSwapResult] = []
        self.outputs_exported = False
        self.events: list[dict[str, object]] = []
        self.witnesses: dict[str, str] = {}
        self.preparation_digest = ""

    def _derive(self, domain: str, *values: object) -> str:
        encoded = "|".join([domain, self.config.seed, *map(str, values)])
        return hashlib.sha256(encoded.encode("ascii")).hexdigest()

    def _event(self, action: str, **details: object) -> None:
        self.events.append(
            {"sequence": len(self.events), "phase": self.phase.value,
             "action": action, **details}
        )

    def prepare(self) -> None:
        if self.phase != Phase.INITIAL:
            raise RuntimeError("preparation can only start from initial state")
        self.phase = Phase.PREPARATION
        n = self.config.participants
        for index in range(n):
            addresses = [self._derive("joint-address", index, level)
                         for level in range(n)]
            vtd_records = [
                {
                    "id": self._derive("vtd", index, level),
                    "opens_at": self.config.phase_window_seconds +
                    (level + 1) * self.config.delta_seconds,
                    "purpose": "relock" if level < n - 1 else "refund-key-share",
                    "adapter": "ParaSwap VTD interface model",
                }
                for level in range(n)
            ]
            self.arcs.append(
                Arc(
                    index=index,
                    sender=f"v{index}",
                    receiver=f"v{(index + 1) % n}",
                    asset=f"asset-{index}",
                    chain_id=f"chain-{index}",
                    joint_addresses=addresses,
                    vtd_records=vtd_records,
                )
            )
        canonical = {
            "domain": "PARASWAP-OASIS-PREPARATION-v1",
            "swap_id": self.config.seed,
            "participants": n,
            "key_epoch": self.config.key_epoch,
            "delta_seconds": self.config.delta_seconds,
            "epsilon_seconds": self.config.epsilon_seconds,
            "phase_window_seconds": self.config.phase_window_seconds,
            "refund_after_seconds": self.config.refund_after_seconds,
            "arcs": [
                {
                    "index": arc.index,
                    "sender": arc.sender,
                    "receiver": arc.receiver,
                    "asset": arc.asset,
                    "chain_id": arc.chain_id,
                    "joint_addresses": arc.joint_addresses,
                    "vtd_records": arc.vtd_records,
                }
                for arc in self.arcs
            ],
        }
        encoded = json.dumps(
            canonical,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        self.preparation_digest = hashlib.sha256(encoded).hexdigest()
        self._event("prepared", participants=n, arcs=n,
                    joint_addresses=n * n, vtd_records=n * n,
                    preparation_digest=self.preparation_digest)

    def pre_swap(self) -> bool:
        if self.phase != Phase.PREPARATION:
            raise RuntimeError("pre-swap requires completed preparation")
        self.phase = Phase.PRE_SWAP
        started = time.monotonic()
        deadline = started + self.config.pre_swap_budget_seconds
        execution_config = replace(
            self.config,
            preparation_digest=self.preparation_digest,
            timeout_seconds=max(
                0.001,
                min(
                    self.config.timeout_seconds,
                    self.config.pre_swap_budget_seconds,
                ),
            ),
        )
        for arc in self.arcs:
            arc.asset_state = AssetState.LOCKED
        self._event("assets_locked", count=len(self.arcs))

        with ThreadPoolExecutor(max_workers=len(self.arcs)) as executor:
            futures = {
                executor.submit(self.backend.execute_arc, arc.index,
                                execution_config): arc.index
                for arc in self.arcs
            }
            for future in as_completed(futures):
                arc_index = futures[future]
                try:
                    self.preswap_results.append(future.result())
                except Exception as error:  # backend isolation boundary
                    self.preswap_results.append(
                        ArcPreSwapResult(
                            arc_index=arc_index,
                            accepted=False,
                            mode=self.config.mode,
                            item_count=self.config.items_per_arc,
                            withdraw_items=self.config.participants,
                            relock_items=self.config.participants - 1,
                            error=f"backend exception: {error}",
                        )
                    )
        self.preswap_results.sort(key=lambda result: result.arc_index)
        completed_at = time.monotonic()
        deadline_live = completed_at <= deadline
        authenticated_transport_required = bool(
            getattr(self.backend, "requires_authenticated_transport", False)
        )
        valid_results = []
        for expected_arc, result in enumerate(self.preswap_results):
            structurally_valid = (
                result.arc_index == expected_arc and
                result.item_count == self.config.items_per_arc and
                result.withdraw_items == self.config.participants and
                result.relock_items == self.config.participants - 1
            )
            if authenticated_transport_required:
                structurally_valid = structurally_valid and (
                    result.preparation_digest == self.preparation_digest and
                    result.paraswap_statement_mapping_valid and
                    result.transport_completed and
                    result.transport_authenticated and
                    result.tls_cipher.startswith("TLS_")
                )
            valid_results.append(result.accepted and structurally_valid)
        accepted = (
            deadline_live and
            len(self.preswap_results) == len(self.arcs) and
            all(valid_results)
        )
        self.outputs_exported = accepted
        self._event(
            "presignature_vector_export" if accepted else "presignature_export_blocked",
            accepted_arcs=sum(result.accepted for result in self.preswap_results),
            required_arcs=len(self.arcs),
            items_per_arc=self.config.items_per_arc,
            deadline_live=deadline_live,
            elapsed_seconds=completed_at - started,
            budget_seconds=self.config.pre_swap_budget_seconds,
            structurally_valid_arcs=sum(valid_results),
            authenticated_transport_required=authenticated_transport_required,
        )
        return accepted

    def share_witnesses(self) -> bool:
        if self.phase != Phase.PRE_SWAP or not self.outputs_exported:
            raise RuntimeError("witness sharing requires exported pre-swap vectors")
        self.phase = Phase.WITNESS_SHARING
        limit = self.config.participants
        if self.config.fault == "witness":
            limit -= 1
        for participant in range(limit):
            self.witnesses[f"v{participant}"] = self._derive(
                "witness", participant
            )
        complete = len(self.witnesses) == self.config.participants
        self._event("witnesses_shared", count=len(self.witnesses),
                    complete=complete)
        return complete

    def swap(self) -> None:
        if self.phase != Phase.WITNESS_SHARING or (
            len(self.witnesses) != self.config.participants
        ):
            raise RuntimeError("swap requires all participant witnesses")
        self.phase = Phase.SWAP
        for arc in self.arcs:
            arc.asset_state = AssetState.WITHDRAWN
        self._event("assets_withdrawn", count=len(self.arcs))
        self.phase = Phase.COMPLETE

    def relock_until_refund(self) -> None:
        if self.phase != Phase.WITNESS_SHARING:
            raise RuntimeError("re-lock recovery requires witness-sharing state")
        if any(arc.asset_state != AssetState.LOCKED for arc in self.arcs):
            raise RuntimeError("re-lock recovery requires locked assets")
        self.phase = Phase.SWAP
        for level in range(1, self.config.participants):
            for arc in self.arcs:
                arc.relock_level = level
            self._event(
                "assets_relocked",
                level=level,
                count=len(self.arcs),
                at_seconds=level * self.config.delta_seconds,
                host_time_seconds=self.config.phase_window_seconds +
                level * self.config.delta_seconds,
            )

    def refund(self, reason: str) -> None:
        if any(arc.asset_state != AssetState.LOCKED for arc in self.arcs):
            raise RuntimeError("refund requires locked assets")
        self.phase = Phase.REFUND
        for arc in self.arcs:
            arc.asset_state = AssetState.REFUNDED
        self._event("assets_refunded", count=len(self.arcs), reason=reason,
                    after_seconds=self.config.refund_after_seconds)
        self.phase = Phase.COMPLETE

    def run(self) -> dict[str, object]:
        started = time.monotonic_ns()
        self.prepare()
        if not self.pre_swap():
            self.refund("pre-swap vector incomplete")
        elif not self.share_witnesses():
            self.relock_until_refund()
            self.refund("witness sharing incomplete")
        else:
            self.swap()
        report = self.report()
        report["lifecycle_wall_ns"] = time.monotonic_ns() - started
        return report

    def report(self) -> dict[str, object]:
        terminal_states = {arc.asset_state for arc in self.arcs}
        if self.phase == Phase.COMPLETE and terminal_states not in (
            {AssetState.WITHDRAWN}, {AssetState.REFUNDED}
        ):
            raise AssertionError("atomic terminal asset-state invariant violated")
        if self.config.backend == "oasis":
            configuration = (
                self.config.configuration
                or "batch-joint-presigning-batch-verification"
            )
            scope = {
                "lifecycle": "five-phase state-machine conformance with native Pre-swap",
                "full_cryptographic_lifecycle": False,
                "phase_implementation": {
                    "preparation": "deterministic host-context model",
                    "pre_swap": "native two-party cryptographic execution",
                    "witness_sharing": "deterministic witness model",
                    "swap": "ledger state-transition model",
                    "refund": "ledger and VTD interface model",
                },
                "pre_swap_crypto": (
                    "OASIS linear Schnorr adaptor-signature instantiation"
                ),
                "coordination": (
                    "Batch Joint Pre-signing"
                    if configuration.startswith("batch-joint-presigning-")
                    else "independent persistent pre-signing sessions"
                ),
                "verification": (
                    "randomized aggregate verification with Pippenger "
                    "multi-scalar multiplication"
                    if configuration.endswith("-batch-verification")
                    else "item-wise Schnorr equation verification"
                ),
                "transport": (
                    "separate native client/server processes over mutually "
                    "authenticated TLS 1.3 on TCP loopback; no WAN claim"
                ),
                "ledger": "deterministic state-machine adapter; not a public testnet",
                "vtd": (
                    "ParaSwap verifiable timed discrete logarithm interface "
                    "model; the upstream implementation remains separately "
                    "auditable"
                ),
                "keys": (
                    "random process-local transport master shares with "
                    "role/address/arc derivation; not production key management"
                ),
                "conformance": (
                    "separate untimed deterministic workload proving exact "
                    "ParaSwap statement structure, three aggregate equations, "
                    "and Adapt/Extract compatibility; not the live transcript"
                ),
                "measurement": (
                    "arc wall/CPU/byte/frame fields come from the live transport; "
                    "itemwise_audit, aggregate_reverification, Pippenger-audit, "
                    "and adaptation fields come from the separate conformance run"
                ),
            }
        else:
            native_mode = canonical_native_mode(self.config.mode)
            scope = {
                "lifecycle": "five-phase ParaSwap artifact harness",
                "pre_swap_crypto": (
                    "joint Schnorr adaptor partials with combined candidates "
                    "checked by the published ParaSwap verifier"
                ),
                "coordination": (
                    "one ordered-vector Batch Joint Pre-signing parent session"
                    if native_mode.startswith("batch-joint-presigning-")
                    else "independent item sessions"
                ),
                "verification": (
                    "fresh-salted randomized verification via native multi-scalar multiplication"
                    if native_mode.endswith("-batch-verification")
                    else "item-wise Schnorr-equation verification"
                ),
                "transport": (
                    "same native ZeroMQ IPC adapter for every configuration"
                ),
                "ledger": "deterministic state-machine adapter; not a public testnet",
                "vtd": (
                    "ParaSwap verifiable timed discrete logarithm interface "
                    "model; the upstream implementation remains separately "
                    "auditable"
                ),
                "keys": (
                    "role-, pair-, and item-separated benchmark keys derived "
                    "deterministically from the published Bob/Tumbler fixture "
                    "master keys; not production wallet provisioning"
                ),
                "measurement": (
                    "live native client/server wall, byte, frame, challenge, "
                    "multi-scalar multiplication, equation, and fallback "
                    "telemetry; no secondary mutual-TLS conformance pass"
                ),
            }
        public_config = asdict(self.config)
        public_config.pop("preparation_digest", None)
        return {
            "schema": "oasis-preswap-lifecycle-v1",
            "scope": scope,
            "config": public_config,
            "preparation_digest": self.preparation_digest,
            "phase": self.phase.value,
            "outputs_exported": self.outputs_exported,
            "witness_count": len(self.witnesses),
            "arcs": [
                {**asdict(arc), "asset_state": arc.asset_state.value}
                for arc in self.arcs
            ],
            "pre_swap": [asdict(result) for result in self.preswap_results],
            "events": self.events,
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run ParaSwap-compatible five-phase lifecycle conformance"
    )
    parser.add_argument("--participants", type=int, default=3)
    parser.add_argument("--backend", choices=("native", "oasis"),
                        default="native",
                        help="native is primary; oasis is the conformance backend")
    parser.add_argument(
        "--mode",
        choices=tuple(sorted(NATIVE_PRESWAP_MODES | set(NATIVE_MODE_ALIASES))),
        default="batch-joint-presigning-batch-verification",
    )
    parser.add_argument(
        "--configuration",
        choices=tuple(sorted(OASIS_CONFIGURATIONS)),
        default="",
        help=(
            "conformance ablation configuration; defaults to "
            "batch-joint-presigning-batch-verification"
        ),
    )
    parser.add_argument("--base-port", type=int, default=19600)
    parser.add_argument("--delta-seconds", type=int, default=15)
    parser.add_argument("--epsilon-seconds", type=int, default=5)
    parser.add_argument("--key-epoch", type=int, default=1)
    parser.add_argument("--seed", default="oasis-preswap-integration-v1")
    parser.add_argument("--fault",
                        choices=("none", "preswap", "invalid-final", "opening-retry",
                                 "partial-retry", "client-partial-retry",
                                 "peer-abort", "witness"),
                        default="none")
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--pre-swap-budget-seconds", type=float, default=120.0)
    parser.add_argument("--deterministic-backend", action="store_true",
                        help="Use only for lifecycle unit tests; no crypto")
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config = Config(
        participants=args.participants,
        mode=args.mode,
        backend=args.backend,
        configuration=args.configuration,
        base_port=args.base_port,
        delta_seconds=args.delta_seconds,
        epsilon_seconds=args.epsilon_seconds,
        key_epoch=args.key_epoch,
        seed=args.seed,
        fault=args.fault,
        timeout_seconds=args.timeout_seconds,
        pre_swap_budget_seconds=args.pre_swap_budget_seconds,
    )
    if args.deterministic_backend:
        backend: PreSigningBackend = DeterministicBackend()
    elif args.backend == "oasis":
        backend = OasisLinearBackend()
    else:
        backend = NativePreSigningBackend()
    report = Lifecycle(config, backend).run()
    rendered = json.dumps(report, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
        print(f"wrote={args.output}")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
