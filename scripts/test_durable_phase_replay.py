#!/usr/bin/env python3
"""Verify phase replay after the OASIS server process is restarted."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from paraswap_lifecycle import OasisLinearBackend, OASIS_TRANSPORT
from test_mtls_rejection import wait_for_listener


ROOT = Path(__file__).resolve().parents[1]


def start_server(backend: OasisLinearBackend, port: int,
                 journal: Path) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [
            str(OASIS_TRANSPORT), "server", "--bind", "127.0.0.1",
            "--port", str(port), "--threads", "2",
            "--io-timeout-seconds", "10", "--replay-journal", str(journal),
            "--tls", "--mutual-tls",
            "--cert", str(backend.pki_dir / "server.crt"),
            "--key", str(backend.pki_dir / "server.key"),
            "--ca", str(backend.pki_dir / "ca.crt"),
        ],
        cwd=ROOT / "vendor" / "oasis-linear",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def run_client(backend: OasisLinearBackend, port: int,
               journal: Path, transcript: Path) -> None:
    result = subprocess.run(
        [
            str(OASIS_TRANSPORT), "client", "--host", "127.0.0.1",
            "--port", str(port), "--n-values", "3",
            "--variants", "persistent-sequential", "--trials", "1",
            "--warmup", "0", "--pairs", "1", "--threads", "1",
            "--io-timeout-seconds", "10", "--durable-replay-probe",
            str(transcript), "--tls", "--mutual-tls",
            "--cert", str(backend.pki_dir / "client.crt"),
            "--key", str(backend.pki_dir / "client.key"),
            "--ca", str(backend.pki_dir / "ca.crt"),
            "--server-name", "127.0.0.1", "--campaign-id",
            "durable-phase-replay", "--route", "loopback",
        ],
        cwd=ROOT / "vendor" / "oasis-linear",
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"durable replay client failed: {result.stdout} {result.stderr}"
        )
    if "durable_replay_probe=pass" not in result.stdout:
        raise AssertionError("durable replay success marker missing")
    if len(list(journal.glob("*.journal"))) != 3:
        raise AssertionError("expected INIT, CLIENT_NONCE, CLIENT_FINAL records")


def stop_server(server: subprocess.Popen[str]) -> None:
    if server.poll() is None:
        server.terminate()
    try:
        server.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        server.kill()
        server.communicate()


def main() -> int:
    backend = OasisLinearBackend()
    port = 23993
    with tempfile.TemporaryDirectory(prefix="oasis-durable-replay-") as temp:
        root = Path(temp)
        journal = root / "journal"
        transcript = root / "transcript.bin"
        server = start_server(backend, port, journal)
        try:
            wait_for_listener(port, server)
            run_client(backend, port, journal, transcript)
        finally:
            stop_server(server)
        time.sleep(0.1)
        server = start_server(backend, port, journal)
        try:
            wait_for_listener(port, server)
            run_client(backend, port, journal, transcript)
        finally:
            stop_server(server)
    print("durable phase replay after process restart: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
