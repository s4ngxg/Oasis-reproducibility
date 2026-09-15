#!/usr/bin/env python3
"""Exercise exact and conflicting replay after forced hot-cache eviction."""

from __future__ import annotations

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
            "--threads", "4", "--io-timeout-seconds", "10",
            "--session-cache-capacity", "1",
            "--replay-retention-capacity", "16",
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

    def client_command(output: Path) -> list[str]:
        seed = hashlib.sha256(b"forced-cache-eviction-replay").hexdigest()
        return [
            str(OASIS_TRANSPORT), "client",
            "--host", "127.0.0.1", "--port", str(port),
            "--n-values", "3", "--variants", "persistent-sequential",
            "--trials", "1", "--warmup", "0", "--pairs", "1",
            "--threads", "1", "--io-timeout-seconds", "10",
            "--eviction-replay-probe",
            "--tls", "--mutual-tls",
            "--cert", str(backend.pki_dir / "client.crt"),
            "--key", str(backend.pki_dir / "client.key"),
            "--ca", str(backend.pki_dir / "ca.crt"),
            "--server-name", "127.0.0.1",
            "--context-seed", seed,
            "--context-key-epoch", "1", "--context-expiry", "286",
            "--context-pair-id", "1000",
            "--context-execution-id", "1001",
            "--context-arc-index", "1",
            "--campaign-id", "cache-pressure", "--route", "loopback",
            "--out", str(output),
        ]

    try:
        wait_for_listener(port, server)
        with tempfile.TemporaryDirectory(prefix="oasis-cache-pressure-") as temp:
            directory = Path(temp)

            probe = subprocess.run(
                client_command(directory / "eviction-replay.json"),
                cwd=ROOT / "vendor" / "oasis-linear",
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if probe.returncode != 0:
                raise AssertionError(
                    "eviction replay probe failed: "
                    f"{probe.stderr.strip()}"
                )
            if "eviction_replay_probe=pass" not in probe.stdout:
                raise AssertionError("eviction replay success marker is missing")
            if server.poll() is not None:
                raise AssertionError("server terminated during replay probe")
        print("forced eviction exact/conflicting replay: PASS")
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
