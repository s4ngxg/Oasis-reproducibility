#!/usr/bin/env python3
"""End-to-end zero-loss regression for the native two-role loss runner."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TPC = ROOT / "vendor" / "paraswap" / "two-party computation"
KEYGEN = TPC / "bin" / "curve_keygen"
PREPARE_CREDENTIALS = ROOT / "scripts" / "prepare_curve_credentials.sh"
ROLE_RUNNER = ROOT / "scripts" / "run_native_loss_role.sh"
ANALYZER = ROOT / "scripts" / "analyze_native_loss_results.py"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
        stream.bind(("127.0.0.1", 0))
        return int(stream.getsockname()[1])


def main() -> int:
    if not KEYGEN.is_file():
        raise RuntimeError(f"missing native key generator: {KEYGEN}")
    with tempfile.TemporaryDirectory(prefix="oasis-native-loss-test-") as raw:
        directory = Path(raw)
        auth = directory / "auth"
        output = directory / "evidence"
        subprocess.run(
            [str(PREPARE_CREDENTIALS), str(auth)], cwd=ROOT, check=True,
            capture_output=True, text=True
        )
        # Completion journals are intentionally durable, so every regression run
        # needs a fresh campaign identity rather than colliding with prior DONE data.
        campaign = f"native-loss-runner-regression-{directory.name}"
        environment = os.environ.copy()
        environment.update({
            "LOSS_VALUES": "0",
            "PARTICIPANTS": "3",
            "PAIRS": "1",
            "TRIALS": "1",
            "WARMUP": "0",
            "MODES": "batch-joint-presigning-batch-verification",
            "BASE_PORT": str(free_port()),
            "WORKER_COUNT": "2",
            "OUTPUT_DIR": str(output),
            "NETWORK_INTERFACE": "lo",
            "SKIP_BUILD": "1",
        })
        server_command = [
            str(ROLE_RUNNER), "server", "eu_to_us", campaign,
            str(auth / "responder"),
        ]
        client_command = [
            str(ROLE_RUNNER), "client", "eu_to_us", campaign,
            str(auth / "initiator"), "127.0.0.1",
        ]
        server = subprocess.Popen(
            server_command, cwd=ROOT, env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        try:
            time.sleep(1)
            client = subprocess.run(
                client_command, cwd=ROOT, env=environment,
                capture_output=True, text=True, timeout=120, check=False
            )
            server_stdout, server_stderr = server.communicate(timeout=120)
        except Exception:
            server.kill()
            server.communicate()
            raise
        if client.returncode != 0 or server.returncode != 0:
            raise RuntimeError(
                "native loss runner failed\n"
                f"client stdout:\n{client.stdout}\nclient stderr:\n"
                f"{client.stderr}\nserver stdout:\n{server_stdout}\n"
                f"server stderr:\n{server_stderr}"
            )
        prefix = f"{campaign}-loss0"
        client_manifest = output / f"{prefix}-client-manifest.json"
        server_manifest = output / f"{prefix}-server-manifest.json"
        analysis = directory / "analysis.json"
        markdown = directory / "analysis.md"
        subprocess.run(
            [
                "python3", str(ANALYZER), str(client_manifest),
                str(server_manifest), "--json-out", str(analysis),
                "--md-out", str(markdown),
            ],
            cwd=ROOT, check=True, capture_output=True, text=True,
        )
        payload = json.loads(analysis.read_text(encoding="utf-8"))
        if (
            payload.get("schema") != "oasis-native-loss-analysis-v1"
            or payload.get("matched_campaigns") != 1
            or len(payload.get("summary", [])) != 1
            or payload["summary"][0].get("verifier_fallbacks") != 0
        ):
            raise RuntimeError(f"invalid native loss analysis: {payload}")
    print("native loss role pairing and zero-loss evidence: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
