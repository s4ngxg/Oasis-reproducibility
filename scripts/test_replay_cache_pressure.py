#!/usr/bin/env python3
"""Exercise bounded replay-cache pressure and post-pressure recovery."""

from __future__ import annotations

import concurrent.futures
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from paraswap_lifecycle import OASIS_TRANSPORT, OasisLinearBackend  # noqa: E402
from test_mtls_rejection import wait_for_listener  # noqa: E402


def main() -> int:
    backend = OasisLinearBackend()
    port = 23992
    server = subprocess.Popen(
        [
            str(OASIS_TRANSPORT), "server",
            "--bind", "127.0.0.1", "--port", str(port),
            "--threads", "16", "--io-timeout-seconds", "10",
            "--session-cache-capacity", "1",
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

    def client_command(identifier: int, output: Path) -> list[str]:
        seed = hashlib.sha256(f"cache-pressure-{identifier}".encode()).hexdigest()
        return [
            str(OASIS_TRANSPORT), "client",
            "--host", "127.0.0.1", "--port", str(port),
            "--n-values", "16", "--variants", "batch-joint-presigning-batch-verification",
            "--trials", "1", "--warmup", "0", "--pairs", "1",
            "--threads", "1", "--io-timeout-seconds", "10",
            "--tls", "--mutual-tls",
            "--cert", str(backend.pki_dir / "client.crt"),
            "--key", str(backend.pki_dir / "client.key"),
            "--ca", str(backend.pki_dir / "ca.crt"),
            "--server-name", "127.0.0.1",
            "--context-seed", seed,
            "--context-key-epoch", "1", "--context-expiry", "286",
            "--context-pair-id", str(identifier),
            "--context-execution-id", str(identifier + 1),
            "--context-arc-index", str(identifier % 16 + 1),
            "--campaign-id", "cache-pressure", "--route", "loopback",
            "--out", str(output),
        ]

    try:
        wait_for_listener(port, server)
        with tempfile.TemporaryDirectory(prefix="oasis-cache-pressure-") as temp:
            directory = Path(temp)

            def run_one(identifier: int) -> int:
                process = subprocess.run(
                    client_command(identifier, directory / f"{identifier}.json"),
                    cwd=ROOT / "vendor" / "oasis-linear",
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=False,
                )
                return process.returncode

            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                return_codes = list(pool.map(run_one, range(16)))
            if not any(code != 0 for code in return_codes):
                raise AssertionError("cache pressure did not reach the configured bound")
            if server.poll() is not None:
                raise AssertionError("server terminated under cache pressure")

            recovery = subprocess.run(
                client_command(1000, directory / "recovery.json"),
                cwd=ROOT / "vendor" / "oasis-linear",
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            if recovery.returncode != 0:
                raise AssertionError(
                    "server did not recover after cache pressure: "
                    f"{recovery.stderr.strip()}"
                )
        print("bounded replay-cache pressure and recovery: PASS")
        return 0
    finally:
        if server.poll() is None:
            server.terminate()
        try:
            server.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            server.kill()
            server.communicate()


if __name__ == "__main__":
    raise SystemExit(main())
