#!/usr/bin/env python3
"""Exercise standalone and fixed-worker-pool CURVE/ZAP security paths."""

from __future__ import annotations

import hashlib
import os
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TPC = ROOT / "vendor" / "paraswap" / "two-party computation"
CLIENT = TPC / "bin" / "preswap_client"
SERVER = TPC / "bin" / "preswap_server"
GATEWAY = TPC / "bin" / "preswap_gateway"
KEYGEN = TPC / "bin" / "curve_keygen"
DOMAIN = "PARASWAP-OASIS-PRESWAP-v1"
MODE = "batch-joint-presigning-batch-verification"
COUNT = 5
PARTICIPANTS = 3


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def seed(execution: int, pair_id: int) -> str:
    material = f"CURVE-POOL-TEST-v1|{execution}|{pair_id}".encode("ascii")
    return hashlib.sha256(material).hexdigest()


def protocol_args(execution: int, pair_id: int) -> list[str]:
    return [
        "--mode", MODE,
        "--count", str(COUNT),
        "--pair-id", str(pair_id),
        "--execution-id", str(execution),
        "--io-timeout-ms", "2500",
        "--context-participants", str(PARTICIPANTS),
        "--context-epoch", "1",
        "--context-expiry", "3600",
        "--context-arc-index", str(pair_id + 1),
        "--context-seed-hex", seed(execution, pair_id),
    ]


def standalone_server_command(keys: Path, port: int, execution: int) -> list[str]:
    return [
        str(SERVER), *protocol_args(execution, 0),
        "--port", str(port),
        "--transport", "tcp",
        "--bind", "127.0.0.1",
        "--curve-secret-key", str(keys / "responder_secret.key"),
        "--curve-allowed-client-key", str(keys / "initiator_public.key"),
        "--zap-domain", DOMAIN,
    ]


def client_command(identity: Path, pinned_server: Path, port: int,
                   execution: int, pair_id: int = 0) -> list[str]:
    return [
        str(CLIENT), *protocol_args(execution, pair_id),
        "--port", str(port),
        "--transport", "tcp",
        "--host", "127.0.0.1",
        "--curve-public-key", str(identity / "initiator_public.key"),
        "--curve-secret-key", str(identity / "initiator_secret.key"),
        "--curve-server-key", str(pinned_server / "responder_public.key"),
        "--zap-domain", DOMAIN,
    ]


def standalone_exchange(server_keys: Path, client_identity: Path,
                        pinned_server: Path, should_succeed: bool,
                        execution: int) -> None:
    port = free_port()
    server = subprocess.Popen(
        standalone_server_command(server_keys, port, execution),
        cwd=TPC, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        time.sleep(0.15)
        client = subprocess.run(
            client_command(client_identity, pinned_server, port, execution),
            cwd=TPC, capture_output=True, text=True, timeout=10, check=False,
        )
        server_stdout, server_stderr = server.communicate(timeout=10)
        if should_succeed:
            assert client.returncode == 0, client.stderr
            assert server.returncode == 0, server_stderr
            assert "RESOURCE_RESULT" in client.stdout
            assert "SERVER_RESOURCE_RESULT" in server_stdout
        else:
            assert client.returncode != 0
            assert server.returncode != 0
    finally:
        terminate([server])


def write_manifest(path: Path, execution_base: int, pair_count: int) -> None:
    rows = [
        f"{pair_id} {execution_base + pair_id} {pair_id + 1} "
        f"{seed(execution_base + pair_id, pair_id)}"
        for pair_id in range(pair_count)
    ]
    path.write_text("\n".join(rows) + "\n", encoding="ascii")


def gateway_command(keys: Path, port: int, backend: str, manifest: Path,
                    pair_count: int, worker_count: int,
                    max_queue: int | None = None,
                    extra: tuple[str, ...] = ()) -> list[str]:
    return [
        str(GATEWAY),
        "--bind", "127.0.0.1",
        "--port", str(port),
        "--backend", backend,
        "--expected-sessions", str(pair_count),
        "--worker-count", str(worker_count),
        "--max-queue", str(pair_count if max_queue is None else max_queue),
        "--mode", MODE,
        "--count", str(COUNT),
        "--context-participants", str(PARTICIPANTS),
        "--context-epoch", "1",
        "--context-expiry", "3600",
        "--session-manifest", str(manifest),
        "--completion-dir", str(
            manifest.parent / f"completion-{manifest.stem}"
        ),
        "--io-timeout-ms", "3000",
        "--curve-secret-key", str(keys / "responder_secret.key"),
        "--curve-allowed-client-key", str(keys / "initiator_public.key"),
        "--zap-domain", DOMAIN,
        *extra,
    ]


def pool_worker_command(backend: str, worker_index: int,
                        extra: tuple[str, ...]) -> list[str]:
    execution = 1 + worker_index
    return [
        str(SERVER), *protocol_args(execution, worker_index),
        "--port", "9000",
        "--transport", "ipc",
        "--gateway-backend", backend,
        "--pool-worker-index", str(worker_index),
        *extra,
    ]


def terminate(processes: list[subprocess.Popen[str]]) -> None:
    for process in processes:
        if process.poll() is None:
            process.kill()
    for process in processes:
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()


def gateway_exchange(root: Path, trusted: Path, client_identity: Path,
                     *, pair_count: int, execution_base: int,
                     should_succeed: bool,
                     client_execution_offset: int = 0,
                     worker_extra: tuple[str, ...] = (),
                     client_extra: tuple[str, ...] = (),
                     gateway_extra: tuple[str, ...] = (),
                     gateway_should_succeed: bool | None = None) -> None:
    port = free_port()
    worker_count = min(2, pair_count)
    backend = f"ipc://{root / ('gateway-' + str(execution_base) + '.sock')}"
    manifest = root / f"manifest-{execution_base}.txt"
    write_manifest(manifest, execution_base, pair_count)
    gateway = subprocess.Popen(
        gateway_command(
            trusted, port, backend, manifest, pair_count, worker_count,
            extra=gateway_extra,
        ),
        cwd=TPC, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    workers = [
        subprocess.Popen(
            pool_worker_command(backend, worker_index, worker_extra),
            cwd=TPC, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        for worker_index in range(worker_count)
    ]
    clients: list[subprocess.Popen[str]] = []
    processes = [gateway, *workers]
    try:
        time.sleep(0.3)
        clients = [
            subprocess.Popen(
                client_command(
                    client_identity, trusted, port,
                    execution_base + pair_id + client_execution_offset,
                    pair_id,
                ) + list(client_extra),
                cwd=TPC, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True,
            )
            for pair_id in range(pair_count)
        ]
        processes.extend(clients)
        client_results = [client.communicate(timeout=15) for client in clients]
        worker_results = [worker.communicate(timeout=15) for worker in workers]
        gateway_stdout, gateway_stderr = gateway.communicate(timeout=15)
        expected_gateway_success = (
            should_succeed
            if gateway_should_succeed is None
            else gateway_should_succeed
        )
        if should_succeed:
            assert all(client.returncode == 0 for client in clients), client_results
            assert all(worker.returncode == 0 for worker in workers), worker_results
            assert gateway.returncode == 0, gateway_stderr
            assert f"GATEWAY_READY\t{worker_count}\t" in gateway_stdout
            assert f"GATEWAY_RESULT\t{pair_count}\t{pair_count}\t" in gateway_stdout
            assert (
                f"GATEWAY_POOL_RESULT\t{worker_count}\t" in gateway_stdout
            )
            assert sum(
                stdout.count("SERVER_RESOURCE_RESULT")
                for stdout, _ in worker_results
            ) == pair_count
            assert all("RESOURCE_RESULT" in stdout for stdout, _ in client_results)
        else:
            if expected_gateway_success:
                assert gateway.returncode == 0, gateway_stderr
                assert f"GATEWAY_RESULT\t{pair_count}\t{pair_count}\t" in gateway_stdout
            else:
                assert gateway.returncode != 0
            assert all(client.returncode != 0 for client in clients)
            assert all(worker.returncode != 0 for worker in workers)
    finally:
        terminate(processes)


def overload_rejection(root: Path, trusted: Path) -> None:
    """Prove that a full bounded queue rejects instead of spawning workers."""
    pair_count = 4
    execution_base = 700
    port = free_port()
    backend = f"ipc://{root / 'gateway-overload.sock'}"
    manifest = root / "manifest-overload.txt"
    write_manifest(manifest, execution_base, pair_count)
    gateway = subprocess.Popen(
        gateway_command(
            trusted, port, backend, manifest, pair_count, 1, max_queue=1
        ),
        cwd=TPC, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    worker = subprocess.Popen(
        pool_worker_command(backend, 0, ()),
        cwd=TPC, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    clients: list[subprocess.Popen[str]] = []
    processes = [gateway, worker]
    try:
        time.sleep(0.3)
        os.kill(worker.pid, signal.SIGSTOP)
        clients = [
            subprocess.Popen(
                client_command(
                    trusted, trusted, port, execution_base + pair_id, pair_id
                ),
                cwd=TPC, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True,
            )
            for pair_id in range(pair_count)
        ]
        processes.extend(clients)
        time.sleep(0.3)
        os.kill(worker.pid, signal.SIGCONT)
        client_results = [client.communicate(timeout=15) for client in clients]
        worker_stdout, worker_stderr = worker.communicate(timeout=15)
        gateway_stdout, gateway_stderr = gateway.communicate(timeout=15)
        successes = sum(client.returncode == 0 for client in clients)
        assert 1 <= successes < pair_count, client_results
        assert worker.returncode == 0, worker_stderr
        assert worker_stdout.count("SERVER_RESOURCE_RESULT") == successes
        assert gateway.returncode == 3, gateway_stderr
        pool_line = next(
            line for line in gateway_stdout.splitlines()
            if line.startswith("GATEWAY_POOL_RESULT\t")
        )
        fields = pool_line.split("\t")
        assert int(fields[2]) == 1
        assert int(fields[5]) == successes
        assert int(fields[7]) == pair_count - successes
    finally:
        if worker.poll() is None:
            os.kill(worker.pid, signal.SIGCONT)
        terminate(processes)


def completion_recovery_after_gateway_restart(root: Path, trusted: Path,
                                             corrupt_count: bool = False) -> None:
    """Recover a persisted DONE after the serving gateway is replaced."""
    execution = 800
    port = free_port()
    name = "manifest-restart-invalid" if corrupt_count else "manifest-restart"
    manifest = root / f"{name}.txt"
    completion_dir = root / f"completion-{name}"
    first_backend = f"ipc://{root / 'gateway-restart-first.sock'}"
    second_backend = f"ipc://{root / 'gateway-restart-second.sock'}"
    write_manifest(manifest, execution, 1)

    first_gateway = subprocess.Popen(
        gateway_command(
            trusted, port, first_backend, manifest, 1, 1,
            extra=(
                "--test-drop-first-done-after-persist",
                "--completion-grace-ms", "10000",
            ),
        ),
        cwd=TPC, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    first_worker = subprocess.Popen(
        pool_worker_command(first_backend, 0, ()), cwd=TPC,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    client: subprocess.Popen[str] | None = None
    second_gateway: subprocess.Popen[str] | None = None
    second_worker: subprocess.Popen[str] | None = None
    processes = [first_gateway, first_worker]
    try:
        time.sleep(0.3)
        client = subprocess.Popen(
            client_command(trusted, trusted, port, execution) + [
                "--completion-ack-timeout-ms", "400",
                "--completion-retries", "20",
                "--completion-retry-delay-ms", "200",
            ],
            cwd=TPC, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        processes.append(client)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and not list(completion_dir.glob("*.done")):
            time.sleep(0.05)
        records = list(completion_dir.glob("*.done"))
        assert len(records) == 1, "gateway did not persist DONE before timeout"

        first_gateway.kill()
        first_worker.kill()
        first_gateway.communicate(timeout=5)
        first_worker.communicate(timeout=5)
        if corrupt_count:
            frame = bytearray(records[0].read_bytes())
            # Canonical header stores the big-endian item count at offset 12.
            frame[12:16] = (COUNT + 1).to_bytes(4, "big")
            records[0].write_bytes(frame)
        time.sleep(0.2)

        second_gateway = subprocess.Popen(
            gateway_command(
                trusted, port, second_backend, manifest, 1, 1,
            ),
            cwd=TPC, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        second_worker = subprocess.Popen(
            pool_worker_command(second_backend, 0, ()), cwd=TPC,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        processes.extend((second_gateway, second_worker))

        client_stdout, client_stderr = client.communicate(timeout=20)
        gateway_stdout, gateway_stderr = second_gateway.communicate(timeout=10)
        worker_stdout, worker_stderr = second_worker.communicate(timeout=10)
        if corrupt_count:
            assert client.returncode != 0, client_stdout
            assert "RESOURCE_RESULT" not in client_stdout
            assert second_gateway.returncode != 0, gateway_stdout
            return
        assert client.returncode == 0, client_stderr
        assert "RESOURCE_RESULT" in client_stdout
        assert second_gateway.returncode == 0, gateway_stderr
        assert second_worker.returncode == 0, worker_stderr
        assert "SERVER_POOL_RESULT\t0\t0\t" in worker_stdout
        pool_line = next(
            line for line in gateway_stdout.splitlines()
            if line.startswith("GATEWAY_POOL_RESULT\t")
        )
        fields = pool_line.split("\t")
        assert int(fields[11]) == 0
        assert int(fields[12]) >= 1
        assert int(fields[13]) == 1
        assert int(fields[14]) == 0
    finally:
        terminate(processes)


def main() -> int:
    if not all(path.is_file() for path in (CLIENT, SERVER, GATEWAY, KEYGEN)):
        raise SystemExit("native binaries missing; run make native-build")
    with tempfile.TemporaryDirectory(prefix="oasis-curve-pool-test-") as temporary:
        root = Path(temporary)
        trusted = root / "trusted"
        untrusted = root / "untrusted"
        subprocess.run([str(KEYGEN), str(trusted)], check=True)
        subprocess.run([str(KEYGEN), str(untrusted)], check=True)

        standalone_exchange(trusted, trusted, trusted, True, 101)
        standalone_exchange(trusted, untrusted, trusted, False, 102)
        standalone_exchange(trusted, trusted, untrusted, False, 103)

        gateway_exchange(
            root, trusted, trusted, pair_count=4,
            execution_base=200, should_succeed=True,
        )
        gateway_exchange(
            root, trusted, trusted, pair_count=1,
            execution_base=250, should_succeed=True,
            gateway_extra=(
                "--test-drop-first-done-after-persist",
                "--completion-grace-ms", "1000",
            ),
            client_extra=(
                "--completion-ack-timeout-ms", "200",
                "--completion-retries", "5",
                "--completion-retry-delay-ms", "100",
            ),
        )
        gateway_exchange(
            root, trusted, untrusted, pair_count=1,
            execution_base=300, should_succeed=False,
        )
        gateway_exchange(
            root, trusted, trusted, pair_count=1,
            execution_base=400, client_execution_offset=1,
            should_succeed=False,
        )
        gateway_exchange(
            root, trusted, trusted, pair_count=1,
            execution_base=500, should_succeed=False,
            worker_extra=("--inject-bad-open",),
            gateway_should_succeed=True,
        )
        gateway_exchange(
            root, trusted, trusted, pair_count=1,
            execution_base=550, should_succeed=False,
            worker_extra=("--inject-bad-server-partial",),
            gateway_should_succeed=True,
        )
        gateway_exchange(
            root, trusted, trusted, pair_count=1,
            execution_base=600, should_succeed=False,
            client_extra=("--inject-bad-final",),
            gateway_should_succeed=True,
        )
        overload_rejection(root, trusted)
        completion_recovery_after_gateway_restart(root, trusted)
        completion_recovery_after_gateway_restart(root, trusted, corrupt_count=True)

        missing = [
            str(CLIENT), *protocol_args(104, 0), "--port", str(free_port()),
            "--transport", "tcp", "--host", "127.0.0.1",
        ]
        result = subprocess.run(
            missing, cwd=TPC, capture_output=True, text=True,
            timeout=5, check=False,
        )
        assert result.returncode != 0
    print("native CURVE/ZAP fixed-worker-pool authentication and rejection: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
