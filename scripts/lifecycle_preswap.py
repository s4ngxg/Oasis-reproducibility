#!/usr/bin/env python3
"""Authenticated TCP Pre-swap runner for the retained lifecycle harness.

This module is a correctness-path adapter. It deliberately requires an
absolute host monotonic deadline supplied by the lifecycle coordinator; it
never manufactures a fresh cutoff from a retry/process timeout. The local
coordinator uses CURVE/ZAP over TCP loopback so transport/authentication code
matches the native WAN path without claiming loopback measurements are WAN
latency evidence.
"""
from __future__ import annotations

import contextlib
import fcntl
import math
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

from run_native_handoff import (
    HANDOFF_HEADER_BYTES,
    HANDOFF_RECORD_BYTES,
    TPC,
    _pair_options,
    validate_registry_handoff,
)


DOMAIN = "PARASWAP-OASIS-PRESWAP-v1"
KEYGEN = TPC / "bin" / "curve_keygen"
CLIENT = TPC / "bin" / "preswap_client"
SERVER = TPC / "bin" / "preswap_server"
PORT_LOCK = Path("/tmp/oasis-preswap-port-pool.lock")


def _replace_option(options: list[str], name: str, value: object) -> None:
    index = options.index(name)
    options[index + 1] = str(value)


def _remaining_seconds(deadline_ns: int, cap_seconds: float) -> float:
    if type(deadline_ns) is not int or deadline_ns <= 0:
        raise ValueError("host deadline must be a positive monotonic-ns value")
    if not math.isfinite(cap_seconds) or cap_seconds <= 0:
        raise ValueError("process timeout must be finite and positive")
    remaining = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
    if remaining <= 0:
        raise TimeoutError("host lifecycle deadline expired")
    return min(float(cap_seconds), remaining)


def _remaining_ms(deadline_ns: int, cap_ms: int) -> int:
    if type(deadline_ns) is not int or deadline_ns <= 0:
        raise ValueError("host deadline must be a positive monotonic-ns value")
    if type(cap_ms) is not int or cap_ms <= 0:
        raise ValueError("I/O timeout must be positive")
    remaining_ns = deadline_ns - time.monotonic_ns()
    if remaining_ns <= 0:
        raise TimeoutError("host lifecycle deadline expired")
    # Never let a native socket timeout extend beyond the lifecycle cutoff.
    remaining_ms = remaining_ns // 1_000_000
    if remaining_ms == 0:
        raise TimeoutError("insufficient lifecycle budget for millisecond I/O")
    return min(int(cap_ms), int(remaining_ms))


@contextlib.contextmanager
def curve_credentials(prefix: str = "oasis-retained-curve-"):
    """Create one short-lived CURVE identity pair outside measured Pre-swap."""
    if not KEYGEN.is_file():
        raise RuntimeError("curve_keygen missing; run make native-build")
    with tempfile.TemporaryDirectory(prefix=prefix) as temporary:
        root = Path(temporary)
        result = subprocess.run(
            [str(KEYGEN), str(root)], cwd=TPC, capture_output=True, text=True,
            timeout=30, check=False,
        )
        if result.returncode:
            raise RuntimeError(f"CURVE credential generation failed, exit={result.returncode}")
        required = (
            "initiator_public.key", "initiator_secret.key",
            "responder_public.key", "responder_secret.key",
        )
        if not all((root / name).is_file() for name in required):
            raise RuntimeError("CURVE credential generation produced an incomplete identity")
        yield root


@contextlib.contextmanager
def _serialized_free_tcp_port(bind: str = "127.0.0.1", *, deadline_ns: int):
    """Reserve a kernel-selected port and serialize the close->bind handoff.

    The global flock is intentionally held until the caller confirms that the
    native server is actually listening. This removes the old PID-modulo
    collision class and avoids releasing the allocator merely because Popen()
    returned before ZeroMQ completed its bind.
    """
    lock_fd = os.open(PORT_LOCK, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
    try:
        while True:
            _remaining_seconds(deadline_ns, 1)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                time.sleep(_remaining_seconds(deadline_ns, 0.005))
        _remaining_seconds(deadline_ns, 1)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind((bind, 0))
            port = int(probe.getsockname()[1])
        yield port
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def _wait_listener_ready(host: str, port: int, deadline_ns: int,
                         server: subprocess.Popen, poll_interval: float = 0.005) -> None:
    """Wait until the spawned TCP server has bound its endpoint.

    This runs while the allocator flock is held. A process exit is surfaced
    immediately; the lifecycle deadline remains authoritative.
    """
    while True:
        if server.poll() is not None:
            raise RuntimeError(
                f"authenticated TCP Pre-swap server exited before bind: exit={server.returncode}"
            )
        remaining = _remaining_seconds(deadline_ns, 1.0)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(min(0.05, remaining))
            if probe.connect_ex((host, port)) == 0:
                return
        time.sleep(min(poll_interval, _remaining_seconds(deadline_ns, poll_interval)))


def _tcp_common_options(n: int, arc: int, mode: str, public_fd: int,
                        seed: str, execution: int, client_public: int,
                        server_public: int, port: int, io_timeout_ms: int) -> list[str]:
    common = _pair_options(
        n, arc, mode, public_fd, seed, execution, client_public, server_public
    )
    _replace_option(common, "--port", port)
    _replace_option(common, "--io-timeout-ms", io_timeout_ms)
    return common


def run_lifecycle_preswap(
    n: int,
    arc: int,
    mode: str,
    public_fd: int,
    output_fd: int,
    seed: str,
    execution: int,
    client_key: int,
    server_key: int,
    client_public: int,
    server_public: int,
    *,
    credentials: Path,
    host_export_deadline_ns: int,
    registry=None,
    host: str = "127.0.0.1",
    bind: str = "127.0.0.1",
    io_timeout_ms: int = 30000,
    completion_ack_timeout_ms: int = 10000,
    process_timeout_seconds: float = 120.0,
):
    """Run one native pair under one immutable lifecycle deadline.

    ``host_export_deadline_ns`` is authoritative for this attempt and any
    caller retry. Process and socket timeouts are only tighter safety bounds;
    they cannot extend the lifecycle cutoff.
    """
    credentials = Path(credentials)
    required = (
        credentials / "initiator_public.key",
        credentials / "initiator_secret.key",
        credentials / "responder_public.key",
        credentials / "responder_secret.key",
    )
    if not all(path.is_file() for path in required):
        raise ValueError("missing CURVE credentials")

    start_ns = time.monotonic_ns()
    _remaining_seconds(host_export_deadline_ns, process_timeout_seconds)
    effective_io_ms = _remaining_ms(host_export_deadline_ns, io_timeout_ms)
    effective_ack_ms = _remaining_ms(host_export_deadline_ns, completion_ack_timeout_ms)

    server = None
    try:
        with _serialized_free_tcp_port(bind, deadline_ns=host_export_deadline_ns) as port:
            common = _tcp_common_options(
                n, arc, mode, public_fd, seed, execution,
                client_public, server_public, port, effective_io_ms,
            )
            _replace_option(common, "--completion-ack-timeout-ms", effective_ack_ms)
            server_args = [
                str(SERVER), *common,
                "--transport", "tcp", "--bind", bind,
                "--curve-secret-key", str(credentials / "responder_secret.key"),
                "--curve-allowed-client-key", str(credentials / "initiator_public.key"),
                "--zap-domain", DOMAIN,
                "--host-address-keys-fd", str(server_key),
            ]
            server = subprocess.Popen(
                server_args, cwd=TPC, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, pass_fds=(public_fd, server_key, client_public, server_public),
            )
            _wait_listener_ready(bind, port, host_export_deadline_ns, server)

        common = _tcp_common_options(
            n, arc, mode, public_fd, seed, execution,
            client_public, server_public, port,
            _remaining_ms(host_export_deadline_ns, io_timeout_ms),
        )
        _replace_option(
            common, "--completion-ack-timeout-ms",
            _remaining_ms(host_export_deadline_ns, completion_ack_timeout_ms),
        )
        client_args = [
            str(CLIENT), *common,
            "--transport", "tcp", "--host", host,
            "--curve-public-key", str(credentials / "initiator_public.key"),
            "--curve-secret-key", str(credentials / "initiator_secret.key"),
            "--curve-server-key", str(credentials / "responder_public.key"),
            "--zap-domain", DOMAIN,
            "--host-address-keys-fd", str(client_key),
            "--host-output-fd", str(output_fd),
            "--host-export-deadline-ns", str(host_export_deadline_ns),
        ]
        client = subprocess.run(
            client_args, cwd=TPC,
            pass_fds=(public_fd, output_fd, client_key, server_public, client_public),
            capture_output=True, text=True,
            timeout=_remaining_seconds(host_export_deadline_ns, process_timeout_seconds),
            check=False,
        )
        server_stdout, _server_stderr = server.communicate(
            timeout=_remaining_seconds(host_export_deadline_ns, process_timeout_seconds)
        )
        if client.returncode or server.returncode:
            os.ftruncate(output_fd, 0)
            raise RuntimeError(
                f"authenticated TCP Pre-swap rejected: arc={arc} "
                f"client_exit={client.returncode} server_exit={server.returncode}"
            )
        if time.monotonic_ns() >= host_export_deadline_ns:
            os.ftruncate(output_fd, 0)
            raise TimeoutError("host lifecycle deadline expired before handoff admission")
        if registry is not None:
            try:
                validate_registry_handoff(
                    registry,
                    os.pread(
                        output_fd,
                        HANDOFF_HEADER_BYTES + HANDOFF_RECORD_BYTES * (2 * n - 1),
                        0,
                    ),
                )
            except ValueError:
                os.ftruncate(output_fd, 0)
                raise

        result = next(
            (line.split("\t") for line in client.stdout.splitlines()
             if line.startswith("RESULT\t")), None
        )
        if result is None or len(result) != 10:
            os.ftruncate(output_fd, 0)
            raise RuntimeError("missing native timing record")
        finish_ns = time.monotonic_ns()
        return {
            "preswap_wall_ns": int(result[4]),
            "prepared_registry_matches_handoff": registry is not None,
            "transport": "tcp",
            "transport_authenticated": True,
            "transport_scope": "loopback-correctness",
            "endpoint_port": port,
            "host_export_deadline_ns": host_export_deadline_ns,
            "deadline_remaining_ms_at_start": (host_export_deadline_ns - start_ns) / 1e6,
            "deadline_remaining_ms_at_finish": (host_export_deadline_ns - finish_ns) / 1e6,
            "io_timeout_ms": effective_io_ms,
            "completion_ack_timeout_ms": effective_ack_ms,
            "process_timeout_seconds": process_timeout_seconds,
            "worker_started_ns": start_ns,
            "worker_finished_ns": finish_ns,
            "server_resource_record_present": "SERVER_RESOURCE_RESULT" in server_stdout,
        }
    except subprocess.TimeoutExpired as exc:
        os.ftruncate(output_fd, 0)
        raise TimeoutError("Pre-swap exceeded the host lifecycle deadline") from exc
    finally:
        if server is not None:
            if server.poll() is None:
                server.kill()
            try:
                server.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.communicate()
