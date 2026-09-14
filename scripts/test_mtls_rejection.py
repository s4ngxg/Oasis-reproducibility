#!/usr/bin/env python3
"""Prove that the integration server rejects an unauthenticated TLS client."""

from __future__ import annotations

import hashlib
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from paraswap_lifecycle import OASIS_TRANSPORT, OasisLinearBackend  # noqa: E402


def wait_for_listener(port: int, process: subprocess.Popen[str]) -> None:
    port_hex = f"{port:04X}"
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise RuntimeError(f"server exited early: {stdout} {stderr}")
        rows = Path("/proc/net/tcp").read_text(encoding="ascii").splitlines()[1:]
        if any(
            row.split()[1].endswith(f":{port_hex}") and
            row.split()[3] == "0A"
            for row in rows
        ):
            return
        time.sleep(0.01)
    raise RuntimeError("server did not listen")


def main() -> int:
    backend = OasisLinearBackend()
    port = 23991
    seed = hashlib.sha256(b"mtls-negative-test").hexdigest()
    output = Path("/tmp/oasis-preswap-mtls-negative.json")
    output.unlink(missing_ok=True)
    server = subprocess.Popen(
        [
            str(OASIS_TRANSPORT), "server",
            "--bind", "127.0.0.1", "--port", str(port), "--threads", "1",
            "--io-timeout-seconds", "5", "--tls", "--mutual-tls",
            "--cert", str(backend.pki_dir / "server.crt"),
            "--key", str(backend.pki_dir / "server.key"),
            "--ca", str(backend.pki_dir / "ca.crt"),
        ],
        cwd=ROOT / "vendor" / "oasis-linear",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        wait_for_listener(port, server)
        client = subprocess.run(
            [
                str(OASIS_TRANSPORT), "client",
                "--host", "127.0.0.1", "--port", str(port),
                "--n-values", "3", "--variants", "batch-joint-presigning-batch-verification",
                "--trials", "1", "--warmup", "0", "--pairs", "1",
                "--threads", "1", "--io-timeout-seconds", "5",
                "--tls", "--ca", str(backend.pki_dir / "ca.crt"),
                "--server-name", "127.0.0.1",
                "--context-seed", seed,
                "--context-key-epoch", "1", "--context-expiry", "76",
                "--context-pair-id", "0", "--context-execution-id", "1",
                "--context-arc-index", "1",
                "--campaign-id", "mtls-negative", "--route", "loopback",
                "--out", str(output),
            ],
            cwd=ROOT / "vendor" / "oasis-linear",
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if client.returncode == 0:
            raise AssertionError("server accepted a client without a certificate")
        print("mutual TLS unauthenticated-client rejection: PASS")
        return 0
    finally:
        output.unlink(missing_ok=True)
        if server.poll() is None:
            server.terminate()
        try:
            server.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            server.kill()
            server.communicate()


if __name__ == "__main__":
    raise SystemExit(main())
