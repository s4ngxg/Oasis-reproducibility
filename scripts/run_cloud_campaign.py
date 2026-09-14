#!/usr/bin/env python3
"""Run a synchronized two-host native Pre-swap campaign over ZeroMQ.

Start the server role first on the US host, then start the client role with the
same campaign arguments on one remote client host. Each measured sample runs
all directed arcs concurrently. The two roles derive identical execution IDs,
so a schedule mismatch is rejected by the native protocol.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import resource
import shutil
import statistics
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO


ROOT = Path(__file__).resolve().parents[1]
TPC_ROOT = ROOT / "vendor" / "paraswap" / "two-party computation"
CLIENT = TPC_ROOT / "bin" / "preswap_client"
SERVER = TPC_ROOT / "bin" / "preswap_server"
GATEWAY = TPC_ROOT / "bin" / "preswap_gateway"
ALLOCATION_CLIENT = TPC_ROOT / "bin" / "preswap_client_allocation_profile"
ALLOCATION_SERVER = TPC_ROOT / "bin" / "preswap_server_allocation_profile"
KEYGEN = TPC_ROOT / "bin" / "curve_keygen"
UPSTREAM_LOCK = ROOT / "vendor" / "paraswap-artifact.lock.json"
RELIC_SOURCE = ROOT / ".deps" / "relic-src"
RELIC_COMMIT = "e8b13783dbbe120cff5a68ff460f3bb9bec69666"
ZAP_DOMAIN = "PARASWAP-OASIS-PRESWAP-v1"
RANDOMIZATION_DOMAIN = "OASIS-CLOUD-MODE-ORDER-v2"
EXPERIMENT_ID_DOMAIN = "OASIS-CLOUD-EXPERIMENT-ID-v1"
EXPECTED_AWS_REGIONS = {
    "eu_to_us": {"client": "eu-central-1", "server": "us-east-1"},
    "sg_to_us": {"client": "ap-southeast-1", "server": "us-east-1"},
}
DEFAULT_MODES = (
    "reference-itemwise",
    "phase-coalesced-itemwise",
    "batch-joint-presigning-itemwise",
    "phase-coalesced-batch-verification",
    "batch-joint-presigning-batch-verification",
)
PROTOCOL_SOURCES = (
    TPC_ROOT / "CMakeLists.txt",
    TPC_ROOT / "src" / "CMakeLists.txt",
    TPC_ROOT / "include" / "bob.h",
    TPC_ROOT / "include" / "preswap_protocol.h",
    TPC_ROOT / "include" / "completion_journal.h",
    TPC_ROOT / "include" / "transport_auth.h",
    TPC_ROOT / "include" / "allocation_counter.h",
    TPC_ROOT / "include" / "tumbler.h",
    TPC_ROOT / "include" / "types.h",
    TPC_ROOT / "include" / "util.h",
    TPC_ROOT / "keys" / "alice.key",
    TPC_ROOT / "keys" / "bob.key",
    TPC_ROOT / "keys" / "tumbler.key",
    TPC_ROOT / "src" / "preswap_common.c",
    TPC_ROOT / "src" / "batch_verifier.c",
    TPC_ROOT / "src" / "preswap_client_v4.c",
    TPC_ROOT / "src" / "preswap_server_v4.c",
    TPC_ROOT / "src" / "preswap_gateway.c",
    TPC_ROOT / "src" / "completion_journal.c",
    TPC_ROOT / "src" / "preswap_joint.c",
    TPC_ROOT / "src" / "transport_auth.c",
    TPC_ROOT / "src" / "curve_keygen.c",
    TPC_ROOT / "src" / "allocation_counter.c",
    TPC_ROOT / "src" / "util_profile.c",
    TPC_ROOT / "src" / "util.c",
    UPSTREAM_LOCK,
    Path(__file__).resolve(),
)


@dataclass(frozen=True)
class Stage:
    participants: int
    concurrent_pairs: int
    mode: str
    trial: int
    warmup: bool

    @property
    def items(self) -> int:
        return 2 * self.participants - 1


class StageProcessSampler:
    """Sample aggregate RSS, active processes, and host run queue."""

    def __init__(self, interval_ms: int):
        self.interval_seconds = interval_ms / 1000.0
        self._pids: set[int] = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._samples: list[dict[str, float]] = []
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def add(self, pid: int) -> None:
        with self._lock:
            self._pids.add(pid)

    @staticmethod
    def _rss_kb(pid: int) -> int | None:
        try:
            for line in Path(f"/proc/{pid}/status").read_text(
                encoding="ascii"
            ).splitlines():
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            return None
        return None

    def _sample(self) -> None:
        with self._lock:
            pids = tuple(self._pids)
        rss_values = [
            value for pid in pids
            if (value := self._rss_kb(pid)) is not None
        ]
        if not rss_values:
            return
        try:
            load_fields = Path("/proc/loadavg").read_text(encoding="ascii").split()
            load1 = float(load_fields[0])
            runnable = int(load_fields[3].split("/", 1)[0])
        except (OSError, ValueError, IndexError):
            load1 = 0.0
            runnable = 0
        self._samples.append({
            "aggregate_rss_kb": float(sum(rss_values)),
            "active_processes": float(len(rss_values)),
            "load1": load1,
            "runnable_tasks": float(runnable),
        })

    def _run(self) -> None:
        while not self._stop.is_set():
            self._sample()
            self._stop.wait(self.interval_seconds)

    def finish(self) -> dict[str, float | int]:
        self._stop.set()
        self._thread.join()
        self._sample()
        samples = self._samples or [{
            "aggregate_rss_kb": 0.0,
            "active_processes": 0.0,
            "load1": 0.0,
            "runnable_tasks": 0.0,
        }]
        return {
            "sampling_interval_ms": int(self.interval_seconds * 1000),
            "sample_count": len(samples),
            "median_aggregate_rss_kb": statistics.median(
                row["aggregate_rss_kb"] for row in samples
            ),
            "peak_aggregate_rss_kb": int(max(
                row["aggregate_rss_kb"] for row in samples
            )),
            "max_active_processes": int(max(
                row["active_processes"] for row in samples
            )),
            "median_run_queue_depth": statistics.median(
                row["runnable_tasks"] for row in samples
            ),
            "max_run_queue_depth": int(max(
                row["runnable_tasks"] for row in samples
            )),
            "median_load1": statistics.median(row["load1"] for row in samples),
        }


def parse_csv(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def ordered_modes(
    campaign: str, participants: int, concurrent_pairs: int,
    modes: list[str], trial: int, warmup: bool
) -> list[str]:
    """Return a reproducible, position-counterbalanced campaign permutation."""
    phase = "warmup" if warmup else "trial"
    base = sorted(
        modes,
        key=lambda mode: hashlib.sha256(
            (
                f"{RANDOMIZATION_DOMAIN}|{campaign}|{phase}|{participants}|"
                f"{concurrent_pairs}|{mode}"
            ).encode("ascii")
        ).digest(),
    )
    offset = trial % len(base)
    return base[offset:] + base[:offset]


def make_stages(
    campaign: str, participants: list[int],
    concurrent_pairs: list[int] | None, modes: list[str], trials: int,
    warmup: int
) -> list[Stage]:
    stages: list[Stage] = []
    for n in participants:
        for p in concurrent_pairs or [n]:
            for index in range(warmup):
                for mode in ordered_modes(campaign, n, p, modes, index, True):
                    stages.append(Stage(n, p, mode, index, True))
            for trial in range(trials):
                for mode in ordered_modes(campaign, n, p, modes, trial, False):
                    stages.append(Stage(n, p, mode, trial, False))
    return stages


def execution_id(campaign: str, stage: Stage, pair_id: int) -> int:
    phase = "warmup" if stage.warmup else "trial"
    material = (
        f"{campaign}|{phase}|{stage.participants}|{stage.trial}|"
        f"{stage.concurrent_pairs}|{stage.mode}|{pair_id}"
    ).encode("ascii")
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big")


def context_seed(campaign: str, stage: Stage, pair_id: int) -> str:
    """Return one host-context seed shared by every mode in a paired trial."""
    phase = "warmup" if stage.warmup else "trial"
    material = (
        f"OASIS-CLOUD-CONTEXT-v1|{campaign}|{phase}|{stage.participants}|"
        f"{stage.trial}|{stage.concurrent_pairs}|{pair_id}"
    ).encode("ascii")
    return hashlib.sha256(material).hexdigest()


def randomization_block_id(
    campaign: str, route: str, stage: Stage
) -> str:
    phase = "warmup" if stage.warmup else "measured"
    material = (
        f"{EXPERIMENT_ID_DOMAIN}|block|{campaign}|{route}|{phase}|"
        f"{stage.participants}|{stage.items}|{stage.concurrent_pairs}"
    ).encode("ascii")
    return hashlib.sha256(material).hexdigest()


def paired_trial_id(campaign: str, route: str, stage: Stage) -> str:
    phase = "warmup" if stage.warmup else "measured"
    material = (
        f"{EXPERIMENT_ID_DOMAIN}|trial|{campaign}|{route}|{phase}|"
        f"{stage.participants}|{stage.items}|{stage.concurrent_pairs}|"
        f"{stage.trial}"
    ).encode("ascii")
    return hashlib.sha256(material).hexdigest()


def stage_schedule_digest(campaign: str, route: str, stages: list[Stage]) -> str:
    rows = [
        {
            "block_id": randomization_block_id(campaign, route, stage),
            "trial_id": paired_trial_id(campaign, route, stage),
            "participants": stage.participants,
            "concurrent_pairs": stage.concurrent_pairs,
            "mode": stage.mode,
            "trial": stage.trial,
            "warmup": stage.warmup,
        }
        for stage in stages
    ]
    encoded = json.dumps(
        rows, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def public_key_fingerprint(path: Path) -> str:
    key = path.read_text(encoding="ascii").strip()
    if len(key) != 40:
        raise RuntimeError(f"invalid CURVE public key: {path}")
    return hashlib.sha256(key.encode("ascii")).hexdigest()


def auth_paths(auth_dir: Path) -> dict[str, Path]:
    return {
        "initiator_public": auth_dir / "initiator_public.key",
        "initiator_secret": auth_dir / "initiator_secret.key",
        "responder_public": auth_dir / "responder_public.key",
        "responder_secret": auth_dir / "responder_secret.key",
    }


def validate_auth_files(role: str, paths: dict[str, Path]) -> None:
    required = (
        ("initiator_public", "initiator_secret", "responder_public")
        if role == "client"
        else ("initiator_public", "responder_public", "responder_secret")
    )
    for name in required:
        path = paths[name]
        if not path.is_file():
            raise RuntimeError(f"missing {name} CURVE key: {path}")
    secret = paths["initiator_secret" if role == "client" else "responder_secret"]
    if secret.stat().st_mode & 0o077:
        raise RuntimeError(f"CURVE secret key must have mode 0600: {secret}")
    public_key_fingerprint(paths["initiator_public"])
    public_key_fingerprint(paths["responder_public"])


def source_digest() -> str:
    digest = hashlib.sha256()
    for path in PROTOCOL_SOURCES:
        digest.update(path.relative_to(ROOT).as_posix().encode("ascii"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def verify_upstream() -> dict[str, object]:
    manifest = json.loads(UPSTREAM_LOCK.read_text(encoding="utf-8"))
    failures = []
    for relative, expected in manifest["upstream_files"].items():
        path = ROOT / relative
        actual = sha256(path) if path.is_file() else "missing"
        if actual != expected:
            failures.append({
                "file": relative,
                "expected": expected,
                "actual": actual,
            })
    adapted = manifest.get("adapted_upstream_files", {})
    for relative, record in adapted.items():
        path = ROOT / relative
        actual = sha256(path) if path.is_file() else "missing"
        expected = record.get("integrated_sha256")
        upstream = record.get("upstream_sha256")
        purpose = record.get("purpose")
        if (
            actual != expected
            or not isinstance(upstream, str)
            or len(upstream) != 64
            or upstream == expected
            or not isinstance(purpose, str)
            or not purpose.strip()
        ):
            failures.append({
                "classification": "adapted-upstream",
                "file": relative,
                "upstream": upstream,
                "expected_integrated": expected,
                "actual": actual,
                "purpose": purpose,
            })
    if failures:
        raise RuntimeError(
            "pinned ParaSwap source verification failed: "
            + json.dumps(failures, separators=(",", ":"))
        )
    return {
        "doi": manifest["doi"],
        "source_commit": manifest["source_commit"],
        "verified_unchanged_files": len(manifest["upstream_files"]),
        "verified_adapted_files": len(adapted),
    }


def ensure_native_build() -> None:
    subprocess.run(
        ["make", "native-build"],
        cwd=ROOT,
        check=True,
    )


def command_version(command: list[str]) -> str:
    process = subprocess.run(command, capture_output=True, text=True, check=False)
    return (process.stdout or process.stderr).splitlines()[0].strip()


def verified_relic_commit(source: Path = RELIC_SOURCE) -> str:
    try:
        process = subprocess.run(
            ["git", "-C", str(source), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        raise RuntimeError(f"cannot inspect pinned RELIC source: {error}") from error
    actual = process.stdout.strip()
    if process.returncode != 0 or len(actual) != 40:
        detail = process.stderr.strip() or "missing Git source checkout"
        raise RuntimeError(f"cannot verify RELIC source commit: {detail}")
    if actual != RELIC_COMMIT:
        raise RuntimeError(
            f"RELIC source commit mismatch: expected {RELIC_COMMIT}, got {actual}"
        )
    return actual


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def cmake_cache_value(name: str, cache: Path | None = None) -> str:
    cache = cache or (TPC_ROOT / "build-full" / "CMakeCache.txt")
    try:
        for line in cache.read_text(encoding="utf-8").splitlines():
            if line.startswith(f"{name}:"):
                return line.split("=", 1)[1]
    except (OSError, IndexError):
        pass
    return "unknown"


def effective_cmake_build_type() -> tuple[str, str]:
    """Report the active CMake configuration, including the project default."""
    cached = cmake_cache_value("CMAKE_BUILD_TYPE")
    if cached.strip() and cached != "unknown":
        return cached, "CMakeCache.txt"
    try:
        project = (TPC_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    except OSError:
        return "unknown", "unavailable"
    default_release = re.search(
        r"if\s*\(\s*NOT\s+CMAKE_BUILD_TYPE\s*\).*?"
        r"set\s*\(\s*CMAKE_BUILD_TYPE\s+Release\s*\).*?endif\s*\(\s*\)",
        project,
        flags=re.DOTALL | re.IGNORECASE,
    )
    if default_release:
        return "Release", "project default in CMakeLists.txt"
    return "unknown", "empty CMake cache without a recognized project default"


def cpu_details() -> dict[str, object]:
    first: dict[str, str] = {}
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="ascii").splitlines():
            if not line.strip():
                break
            if ":" in line:
                key, value = line.split(":", 1)
                first[key.strip()] = value.strip()
    except OSError:
        return {"model_name": "unknown"}
    integer_fields = ("cpu family", "model", "stepping", "siblings", "cpu cores")
    result: dict[str, object] = {
        "model_name": first.get("model name", "unknown"),
    }
    for field in integer_fields:
        try:
            result[field.replace(" ", "_")] = int(first.get(field, ""))
        except ValueError:
            result[field.replace(" ", "_")] = "unknown"
    siblings = result.get("siblings")
    cores = result.get("cpu_cores")
    result["smt_enabled"] = (
        siblings > cores if isinstance(siblings, int) and isinstance(cores, int)
        else "unknown"
    )
    return result


def memory_details() -> dict[str, object]:
    values: dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
            if ":" not in line:
                continue
            name, raw = line.split(":", 1)
            fields = raw.split()
            if fields and fields[0].isdigit():
                values[name] = int(fields[0])
    except OSError:
        pass
    return {
        "mem_total_kb": values.get("MemTotal", 0),
        "swap_total_kb": values.get("SwapTotal", 0),
        "huge_pages_total": values.get("HugePages_Total", 0),
        "huge_page_size_kb": values.get("Hugepagesize", 0),
    }


def scheduler_details() -> dict[str, object]:
    names = {
        getattr(os, "SCHED_OTHER", -1): "SCHED_OTHER",
        getattr(os, "SCHED_FIFO", -2): "SCHED_FIFO",
        getattr(os, "SCHED_RR", -3): "SCHED_RR",
        getattr(os, "SCHED_BATCH", -4): "SCHED_BATCH",
        getattr(os, "SCHED_IDLE", -5): "SCHED_IDLE",
    }
    try:
        policy = os.sched_getscheduler(0)
        priority = os.sched_getparam(0).sched_priority
        affinity = sorted(os.sched_getaffinity(0))
        return {
            "policy": names.get(policy, str(policy)),
            "priority": priority,
            "affinity_cpu_list": affinity,
            "cpu_pinning": len(affinity) < (os.cpu_count() or len(affinity)),
        }
    except (AttributeError, OSError):
        return {"policy": "unknown", "cpu_pinning": "unknown"}


def aws_imds_metadata() -> dict[str, object]:
    endpoint = "http://169.254.169.254/latest"
    token_request = urllib.request.Request(
        f"{endpoint}/api/token", method="PUT",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
    )
    try:
        with urllib.request.urlopen(token_request, timeout=0.25) as response:
            token = response.read().decode("ascii")
        headers = {"X-aws-ec2-metadata-token": token}
        values: dict[str, object] = {"available": True}
        for name, path in {
            "instance_id": "meta-data/instance-id",
            "instance_type": "meta-data/instance-type",
            "ami_id": "meta-data/ami-id",
            "availability_zone": "meta-data/placement/availability-zone",
            "region": "meta-data/placement/region",
        }.items():
            request = urllib.request.Request(f"{endpoint}/{path}", headers=headers)
            with urllib.request.urlopen(request, timeout=0.25) as response:
                values[name] = response.read().decode("ascii").strip()
        instance_type = str(values.get("instance_type", ""))
        burstable = instance_type.startswith(("t2.", "t3.", "t3a.", "t4g."))
        flex_scheduled = "-flex." in instance_type
        values["burstable_instance"] = burstable
        values["flex_scheduled_instance"] = flex_scheduled
        values["fixed_performance_instance"] = not burstable and not flex_scheduled
        values["cpu_credit_state"] = (
            "requires-cloudwatch-verification" if burstable
            else "not-applicable-non-burstable"
        )
        return values
    except (OSError, urllib.error.URLError, UnicodeError):
        return {
            "available": False,
            "instance_type": "unknown",
            "burstable_instance": "unknown",
            "flex_scheduled_instance": "unknown",
            "fixed_performance_instance": "unknown",
            "cpu_credit_state": "unknown",
        }


def read_optional_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="ascii").strip()
    except OSError:
        return "unknown"


def default_network_interface(host: str, role: str) -> str:
    if role == "client" and host in {"127.0.0.1", "localhost", "::1"}:
        return "lo"
    try:
        for line in Path("/proc/net/route").read_text(encoding="ascii").splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 4 and fields[1] == "00000000" and int(fields[3], 16) & 2:
                return fields[0]
    except (OSError, ValueError):
        pass
    raise RuntimeError("cannot determine default network interface")


def network_snapshot(interface: str) -> dict[str, int]:
    base = Path("/sys/class/net") / interface / "statistics"
    result = {}
    for direction in ("rx", "tx"):
        for metric in ("bytes", "packets", "errors", "dropped"):
            path = base / f"{direction}_{metric}"
            try:
                result[f"{direction}_{metric}"] = int(path.read_text(encoding="ascii"))
            except OSError as error:
                raise RuntimeError(f"cannot read network counter {path}") from error
    return result


def tcp_snapshot() -> dict[str, int]:
    lines = Path("/proc/net/snmp").read_text(encoding="ascii").splitlines()
    for index in range(len(lines) - 1):
        if lines[index].startswith("Tcp:") and lines[index + 1].startswith("Tcp:"):
            names = lines[index].split()[1:]
            values = [int(value) for value in lines[index + 1].split()[1:]]
            fields = dict(zip(names, values))
            return {
                "tcp_in_segments": fields.get("InSegs", 0),
                "tcp_out_segments": fields.get("OutSegs", 0),
                "tcp_retransmitted_segments": fields.get("RetransSegs", 0),
                "tcp_active_opens": fields.get("ActiveOpens", 0),
                "tcp_passive_opens": fields.get("PassiveOpens", 0),
                "tcp_attempt_failures": fields.get("AttemptFails", 0),
                "tcp_established_resets": fields.get("EstabResets", 0),
            }
    raise RuntimeError("cannot read TCP counters from /proc/net/snmp")


def cpu_snapshot() -> tuple[int, int, int]:
    lines = Path("/proc/stat").read_text(encoding="ascii").splitlines()
    if not lines or not lines[0].startswith("cpu "):
        raise ValueError("missing aggregate CPU counters")
    fields = lines[0].split()[1:]
    values = [int(value) for value in fields]
    if len(values) < 4 or any(value < 0 for value in values):
        raise ValueError("invalid aggregate CPU counters")
    # Linux includes guest and guest_nice in user and nice already.
    total = sum(values[:8])
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    steal = values[7] if len(values) > 7 else 0
    return total, idle, steal


def cgroup_cpu_stat_path() -> Path:
    memberships = [line.split(":", 2)[2] for line in
                   Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines()
                   if line.startswith("0::")]
    if len(memberships) != 1:
        raise ValueError("no unique cgroup-v2 membership")
    member = Path(memberships[0])
    if not member.is_absolute() or ".." in member.parts:
        raise ValueError("invalid cgroup membership")
    candidates = []
    for line in Path("/proc/self/mountinfo").read_text(encoding="ascii").splitlines():
        before, separator, after = line.partition(" - ")
        if not separator or after.split()[0] != "cgroup2":
            continue
        fields = before.split()
        if len(fields) < 6:
            continue
        # Unsupported escaped mount paths stay unavailable instead of being
        # guessed; ordinary Linux cgroup-v2 mounts need no unescaping.
        if "\\" in fields[3] or "\\" in fields[4]:
            continue
        root = Path(fields[3])
        if member.is_relative_to(root):
            candidates.append(Path(fields[4]) / member.relative_to(root) / "cpu.stat")
    if len(candidates) != 1:
        raise ValueError("no unique visible cgroup-v2 mount")
    return candidates[0]


def cgroup_cpu_snapshot() -> dict[str, object]:
    """Read cgroup-v2 throttling counters when the host exposes them."""
    values: dict[str, int] = {}
    try:
        path = cgroup_cpu_stat_path()
        metadata = path.stat()
        for line in path.read_text(
            encoding="ascii"
        ).splitlines():
            name, raw = line.split()
            values[name] = int(raw)
            if values[name] < 0:
                raise ValueError("negative cgroup counter")
    except (OSError, ValueError):
        return {
            "nr_periods": None,
            "nr_throttled": None,
            "throttled_usec": None,
        }
    return {
        "nr_periods": values.get("nr_periods"),
        "nr_throttled": values.get("nr_throttled"),
        "throttled_usec": values.get("throttled_usec"),
        "source": str(path),
        "source_identity": [metadata.st_dev, metadata.st_ino],
    }


def cgroup_counter_delta(before: dict[str, int | None], after: dict[str, int | None]) -> dict[str, int | None]:
    return {name: (None if before[name] is None or after.get(name) is None
                  or after[name] < before[name] else after[name] - before[name])
            for name in before}


def cgroup_interval(before, after):
    same_source = (before.get("source") is not None and
                   before.get("source_identity") is not None and
                   before.get("source") == after.get("source") and
                   before.get("source_identity") == after.get("source_identity"))
    names = ("nr_periods", "nr_throttled", "throttled_usec")
    counters = cgroup_counter_delta(
        {name: before.get(name) for name in names},
        {name: after.get(name) for name in names}) if same_source else dict.fromkeys(names)
    return counters, same_source


def counter_delta(before: dict[str, int], after: dict[str, int]) -> dict[str, int]:
    return {name: max(0, after[name] - before[name]) for name in before}


def stage_host_delta(interface: str, before: dict[str, object]) -> dict[str, object]:
    network = counter_delta(before["network"], network_snapshot(interface))
    tcp = counter_delta(before["tcp"], tcp_snapshot())
    cpu_total, cpu_idle, cpu_steal = cpu_snapshot()
    after_cgroup = cgroup_cpu_snapshot()
    cgroup_cpu, cgroup_source_stable = cgroup_interval(before["cgroup_cpu"], after_cgroup)
    delta_total = max(0, cpu_total - int(before["cpu_total"]))
    delta_idle = max(0, cpu_idle - int(before["cpu_idle"]))
    delta_steal = max(0, cpu_steal - int(before["cpu_steal"]))
    utilization = (
        100.0 * max(0, delta_total - delta_idle - delta_steal) / delta_total
        if delta_total > 0 else 0.0
    )
    steal_pct = 100.0 * delta_steal / delta_total if delta_total > 0 else 0.0
    return {
        "network_interface": interface,
        **network,
        **tcp,
        "host_cpu_utilization_pct": utilization,
        "host_cpu_steal_pct": steal_pct,
        "cgroup_cpu_nr_periods": cgroup_cpu["nr_periods"],
        "cgroup_cpu_nr_throttled": cgroup_cpu["nr_throttled"],
        "cgroup_cpu_throttled_usec": cgroup_cpu["throttled_usec"],
        "cgroup_cpu_source_before": before["cgroup_cpu"].get("source"),
        "cgroup_cpu_source_after": after_cgroup.get("source"),
        "cgroup_cpu_source_identity_before": before["cgroup_cpu"].get("source_identity"),
        "cgroup_cpu_source_identity_after": after_cgroup.get("source_identity"),
        "cgroup_cpu_source_stable": cgroup_source_stable,
    }


def binary_for(role: str, profiling_mode: str) -> Path:
    if profiling_mode == "allocation":
        return ALLOCATION_CLIENT if role == "client" else ALLOCATION_SERVER
    return CLIENT if role == "client" else SERVER


def parse_strace_summary(path: Path) -> dict[str, object]:
    counts: dict[str, int] = {}
    errors: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) < 5 or not fields[0][0].isdigit():
            continue
        try:
            calls = int(fields[3])
        except ValueError:
            continue
        name = fields[-1]
        if name == "total":
            continue
        counts[name] = calls
        if len(fields) >= 6:
            try:
                error_count = int(fields[4])
            except ValueError:
                error_count = 0
            if error_count:
                errors[name] = error_count
    if not counts:
        raise RuntimeError(f"empty strace summary: {path}")
    return {
        "total_syscalls": sum(counts.values()),
        "total_syscall_errors": sum(errors.values()),
        "syscall_counts": counts,
        "syscall_errors": errors,
    }


def apply_profiler(args: argparse.Namespace, command: list[str], role: str,
                   stage_index: int, pair_id: int) -> tuple[list[str], Path | None]:
    if args.profiling_mode != "syscall":
        return command, None
    path = args.profile_output_dir / (
        f"{role}-stage-{stage_index:06d}-pair-{pair_id:05d}.strace"
    )
    return ["strace", "-qq", "-f", "-c", "-o", str(path), *command], path


def parse_fields(stdout: str, role: str,
                 profiling_mode: str = "timing") -> dict[str, int | str]:
    parsed: dict[str, int | str] = {}
    for line in stdout.splitlines():
        fields = line.split("\t")
        if role == "client" and fields[0] == "RESULT" and len(fields) == 10:
            parsed.update(
                wall_ns=int(fields[4]),
                sent_bytes=int(fields[6]),
                received_bytes=int(fields[7]),
                sent_frames=int(fields[8]),
                received_frames=int(fields[9]),
            )
        elif role == "client" and fields[0] == "CRYPTO_RESULT" and len(fields) == 8:
            parsed["crypto_ns"] = int(fields[4])
        elif role == "client" and fields[0] == "VERIFIER_RESULT" and len(fields) == 9:
            parsed.update(
                verifier_challenge_ns=int(fields[4]),
                verifier_msm_ns=int(fields[5]),
                verifier_equations=int(fields[6]),
                verifier_msm_calls=int(fields[7]),
                verifier_fallbacks=int(fields[8]),
            )
        elif role == "client" and fields[0] == "RESOURCE_RESULT" and len(fields) == 14:
            parsed.update(
                setup_ns=int(fields[4]),
                user_cpu_ns=int(fields[5]),
                system_cpu_ns=int(fields[6]),
                max_rss_kb=int(fields[7]),
                voluntary_context_switches=int(fields[8]),
                involuntary_context_switches=int(fields[9]),
                scheduler_wait_ns=int(fields[10]),
                scheduler_slices=int(fields[11]),
                send_calls=int(fields[12]),
                receive_calls=int(fields[13]),
            )
        elif role == "server" and fields[0] == "SERVER_RESULT" and len(fields) == 8:
            parsed.update(
                verify_request_ns=int(fields[5]),
                generate_response_ns=int(fields[6]),
                verify_final_ns=int(fields[7]),
            )
        elif role == "server" and fields[0] == "SERVER_VERIFIER_RESULT" and len(fields) == 9:
            parsed.update(
                verifier_challenge_ns=int(fields[4]),
                verifier_msm_ns=int(fields[5]),
                verifier_equations=int(fields[6]),
                verifier_msm_calls=int(fields[7]),
                verifier_fallbacks=int(fields[8]),
            )
        elif role == "server" and fields[0] == "SERVER_RESOURCE_RESULT" and len(fields) == 13:
            parsed.update(
                protocol_wall_ns=int(fields[4]),
                setup_ns=int(fields[5]),
                user_cpu_ns=int(fields[6]),
                system_cpu_ns=int(fields[7]),
                max_rss_kb=int(fields[8]),
                voluntary_context_switches=int(fields[9]),
                involuntary_context_switches=int(fields[10]),
                scheduler_wait_ns=int(fields[11]),
                scheduler_slices=int(fields[12]),
            )
        elif role == "server" and fields[0] == "SERVER_TRANSPORT_RESULT" and len(fields) == 10:
            parsed.update(
                sent_bytes=int(fields[4]),
                received_bytes=int(fields[5]),
                sent_frames=int(fields[6]),
                received_frames=int(fields[7]),
                send_calls=int(fields[8]),
                receive_calls=int(fields[9]),
            )
        elif role == "client" and fields[0] == "CLIENT_VERIFIER_AUDIT" and len(fields) == 6:
            parsed.update(
                server_partial_verifier_salt=fields[4],
                verifier_batch_digest=fields[5],
            )
        elif role == "server" and fields[0] == "SERVER_VERIFIER_AUDIT" and len(fields) == 7:
            parsed.update(
                client_partial_verifier_salt=fields[4],
                full_presignature_verifier_salt=fields[5],
                verifier_batch_digest=fields[6],
            )
        elif role == "client" and fields[0] == "ALLOCATION_RESULT" and len(fields) == 9:
            parsed.update(
                malloc_calls=int(fields[4]),
                calloc_calls=int(fields[5]),
                realloc_calls=int(fields[6]),
                free_calls=int(fields[7]),
                requested_allocation_bytes=int(fields[8]),
            )
        elif role == "server" and fields[0] == "SERVER_ALLOCATION_RESULT" and len(fields) == 9:
            parsed.update(
                malloc_calls=int(fields[4]),
                calloc_calls=int(fields[5]),
                realloc_calls=int(fields[6]),
                free_calls=int(fields[7]),
                requested_allocation_bytes=int(fields[8]),
            )
    required = (
        {
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
            "setup_ns",
            "user_cpu_ns",
            "system_cpu_ns",
            "max_rss_kb",
            "voluntary_context_switches",
            "involuntary_context_switches",
            "scheduler_wait_ns",
            "scheduler_slices",
            "send_calls",
            "receive_calls",
        }
        if role == "client"
        else {
            "verify_request_ns",
            "generate_response_ns",
            "verify_final_ns",
            "verifier_challenge_ns",
            "verifier_msm_ns",
            "verifier_equations",
            "verifier_msm_calls",
            "verifier_fallbacks",
            "protocol_wall_ns",
            "setup_ns",
            "user_cpu_ns",
            "system_cpu_ns",
            "max_rss_kb",
            "voluntary_context_switches",
            "involuntary_context_switches",
            "scheduler_wait_ns",
            "scheduler_slices",
            "sent_bytes",
            "received_bytes",
            "sent_frames",
            "received_frames",
            "send_calls",
            "receive_calls",
        }
    )
    if not required.issubset(parsed):
        raise RuntimeError(f"incomplete {role} output: {stdout!r}")
    allocation_fields = {
        "malloc_calls", "calloc_calls", "realloc_calls", "free_calls",
        "requested_allocation_bytes",
    }
    if profiling_mode == "allocation" and not allocation_fields.issubset(parsed):
        raise RuntimeError(f"missing {role} allocation profile: {stdout!r}")
    return parsed


def parse_pool_worker_output(
    stdout: str, profiling_mode: str,
) -> tuple[dict[int, dict[str, int | str]], dict[str, int]]:
    grouped: dict[int, list[str]] = {}
    pool: dict[str, int] = {}
    for line in stdout.splitlines():
        fields = line.split("\t")
        if fields[0] == "SERVER_POOL_RESULT" and len(fields) == 11:
            pool = {
                "worker_index": int(fields[1]),
                "completed_sessions": int(fields[2]),
                "setup_ns": int(fields[3]),
                "user_cpu_ns": int(fields[4]),
                "system_cpu_ns": int(fields[5]),
                "max_rss_kb": int(fields[6]),
                "voluntary_context_switches": int(fields[7]),
                "involuntary_context_switches": int(fields[8]),
                "scheduler_wait_ns": int(fields[9]),
                "scheduler_slices": int(fields[10]),
            }
        elif fields[0].startswith("SERVER_") and len(fields) >= 3:
            pair_id = int(fields[2])
            grouped.setdefault(pair_id, []).append(line)
    required_pool_fields = {
        "worker_index", "completed_sessions", "setup_ns", "user_cpu_ns",
        "system_cpu_ns", "max_rss_kb", "voluntary_context_switches",
        "involuntary_context_switches", "scheduler_wait_ns",
        "scheduler_slices",
    }
    if not required_pool_fields.issubset(pool):
        raise RuntimeError(f"missing worker-pool summary: {stdout!r}")
    if pool["completed_sessions"] != len(grouped):
        raise RuntimeError(
            "worker-pool session count does not match per-session output"
        )
    return {
        pair_id: parse_fields("\n".join(lines), "server", profiling_mode)
        for pair_id, lines in grouped.items()
    }, pool


def command_for(
    role: str,
    stage: Stage,
    pair_id: int,
    campaign: str,
    host: str,
    bind: str,
    port: int,
    timeout_ms: int,
    keys: dict[str, Path],
    profiling_mode: str,
    gateway_backend: str | None = None,
) -> list[str]:
    binary = binary_for(role, profiling_mode)
    command = [
        str(binary),
        "--mode",
        stage.mode,
        "--count",
        str(stage.items),
        "--pair-id",
        str(pair_id),
        "--port",
        str(port),
        "--execution-id",
        str(execution_id(campaign, stage, pair_id)),
        "--context-participants",
        str(stage.participants),
        "--context-epoch",
        "1",
        "--context-expiry",
        "3600",
        "--context-arc-index",
        str(pair_id + 1),
        "--context-seed-hex",
        context_seed(campaign, stage, pair_id),
        "--io-timeout-ms",
        str(timeout_ms),
    ]
    if role == "client":
        command.extend((
            "--transport", "tcp",
            "--host", host,
            "--curve-public-key", str(keys["initiator_public"]),
            "--curve-secret-key", str(keys["initiator_secret"]),
            "--curve-server-key", str(keys["responder_public"]),
            "--zap-domain", ZAP_DOMAIN,
        ))
    elif gateway_backend is not None:
        command.extend((
            "--transport", "ipc",
            "--gateway-backend", gateway_backend,
        ))
    else:
        command.extend((
            "--transport", "tcp",
            "--bind", bind,
            "--curve-secret-key", str(keys["responder_secret"]),
            "--curve-allowed-client-key", str(keys["initiator_public"]),
            "--zap-domain", ZAP_DOMAIN,
        ))
    return command


def gateway_backend_endpoint(campaign: str, stage_index: int) -> str:
    token = hashlib.sha256(
        f"{campaign}|{stage_index}|{os.getuid()}".encode("ascii")
    ).hexdigest()[:20]
    return f"ipc:///tmp/oasis-preswap-gateway-{token}.sock"


def gateway_manifest_path(campaign: str, stage_index: int) -> Path:
    token = hashlib.sha256(
        f"manifest|{campaign}|{stage_index}|{os.getuid()}".encode("ascii")
    ).hexdigest()[:20]
    return Path(f"/tmp/oasis-preswap-sessions-{token}.txt")


def gateway_completion_dir(campaign: str, stage_index: int) -> Path:
    token = hashlib.sha256(
        f"completion|{campaign}|{stage_index}|{os.getuid()}".encode("ascii")
    ).hexdigest()[:20]
    return ROOT / "results" / "completion-journal" / token


def write_gateway_manifest(path: Path, campaign: str, stage: Stage) -> None:
    rows = ["# pair_id execution_id context_arc_index context_seed_hex"]
    rows.extend(
        f"{pair_id} {execution_id(campaign, stage, pair_id)} "
        f"{pair_id + 1} {context_seed(campaign, stage, pair_id)}"
        for pair_id in range(stage.concurrent_pairs)
    )
    path.write_text("\n".join(rows) + "\n", encoding="ascii")
    path.chmod(0o600)


def stage_worker_count(args: argparse.Namespace, stage: Stage) -> int:
    configured = args.worker_count or max(1, os.cpu_count() or 1)
    return min(configured, stage.concurrent_pairs)


def gateway_command(
    args: argparse.Namespace, stage: Stage, stage_index: int,
    backend: str, manifest: Path, completion_dir: Path,
) -> list[str]:
    workers = stage_worker_count(args, stage)
    return [
        str(GATEWAY),
        "--bind", args.bind,
        "--port", str(args.base_port),
        "--backend", backend,
        "--expected-sessions", str(stage.concurrent_pairs),
        "--worker-count", str(workers),
        "--max-queue", str(args.max_queue or stage.concurrent_pairs),
        "--mode", stage.mode,
        "--count", str(stage.items),
        "--context-participants", str(stage.participants),
        "--context-epoch", "1",
        "--context-expiry", "3600",
        "--session-manifest", str(manifest),
        "--completion-dir", str(completion_dir),
        "--io-timeout-ms", str(args.io_timeout_ms),
        "--curve-secret-key", str(args.auth_paths["responder_secret"]),
        "--curve-allowed-client-key", str(args.auth_paths["initiator_public"]),
        "--zap-domain", ZAP_DOMAIN,
    ]


def pool_worker_command(
    args: argparse.Namespace, stage: Stage, worker_index: int, backend: str,
) -> list[str]:
    command = command_for(
        "server", stage, worker_index, args.campaign_id, args.host, args.bind,
        args.base_port, args.io_timeout_ms, args.auth_paths,
        args.profiling_mode, backend,
    )
    command.extend(("--pool-worker-index", str(worker_index)))
    return command


def parse_gateway_result(stdout: str) -> dict[str, int | str]:
    parsed: dict[str, int | str] = {}
    for line in stdout.splitlines():
        fields = line.split("\t")
        if fields[0] == "GATEWAY_READY" and len(fields) == 3:
            parsed["registered_workers"] = int(fields[1])
            parsed["service_endpoint"] = fields[2]
        elif fields[0] == "GATEWAY_RESULT" and len(fields) == 12:
            parsed.update(
                expected_sessions=int(fields[1]),
                completed_sessions=int(fields[2]),
                frontend_received_frames=int(fields[3]),
                frontend_sent_frames=int(fields[4]),
                backend_received_frames=int(fields[5]),
                backend_sent_frames=int(fields[6]),
                bytes_from_clients=int(fields[7]),
                bytes_to_clients=int(fields[8]),
                user_cpu_ns=int(fields[9]),
                system_cpu_ns=int(fields[10]),
                max_rss_kb=int(fields[11]),
            )
        elif fields[0] == "GATEWAY_POOL_RESULT" and len(fields) == 15:
            parsed.update(
                worker_count=int(fields[1]),
                queue_capacity=int(fields[2]),
                peak_busy_workers=int(fields[3]),
                peak_queue_depth=int(fields[4]),
                assignments=int(fields[5]),
                queued_sessions=int(fields[6]),
                rejected_sessions=int(fields[7]),
                internal_control_frames=int(fields[8]),
                total_queue_wait_ns=int(fields[9]),
                max_queue_wait_ns=int(fields[10]),
                completion_records_written=int(fields[11]),
                completion_replay_requests=int(fields[12]),
                completion_replays=int(fields[13]),
                test_dropped_done_frames=int(fields[14]),
            )
    required = {
        "registered_workers", "service_endpoint", "expected_sessions",
        "completed_sessions", "frontend_received_frames",
        "frontend_sent_frames", "backend_received_frames",
        "backend_sent_frames", "bytes_from_clients", "bytes_to_clients",
        "user_cpu_ns", "system_cpu_ns", "max_rss_kb", "worker_count",
        "queue_capacity",
        "peak_busy_workers", "peak_queue_depth", "assignments",
        "queued_sessions", "rejected_sessions", "internal_control_frames",
        "total_queue_wait_ns", "max_queue_wait_ns",
        "completion_records_written", "completion_replay_requests",
        "completion_replays", "test_dropped_done_frames",
    }
    if not required.issubset(parsed):
        raise RuntimeError(f"incomplete gateway output: {stdout!r}")
    return parsed


def validate_native_row(row: dict[str, object], stage: Stage, role: str) -> None:
    expected_frames = (
        5 * stage.items + 1
        if stage.mode == "reference-itemwise"
        else 7 if stage.mode.endswith("-batch-verification") else 6
    )
    actual_frames = int(row["sent_frames"]) + int(row["received_frames"])
    if actual_frames != expected_frames:
        raise RuntimeError(
            f"{role} logical-frame mismatch for {stage.mode}: "
            f"{actual_frames} != {expected_frames}"
        )
    if stage.mode.endswith("-batch-verification"):
        required = (
            {"server_partial_verifier_salt", "verifier_batch_digest"}
            if role == "client"
            else {
                "client_partial_verifier_salt",
                "full_presignature_verifier_salt",
                "verifier_batch_digest",
            }
        )
        for field in required:
            if len(str(row.get(field, ""))) != 64:
                raise RuntimeError(
                    f"missing or non-canonical {role} verifier audit {field}"
                )


def run_client_stage(
    args: argparse.Namespace, stage: Stage, stage_index: int
) -> tuple[list[dict[str, int]], dict[str, float | int]]:
    processes: list[tuple[int, int, subprocess.Popen[str], Path | None]] = []
    sampler = StageProcessSampler(args.profile_sample_interval_ms)
    sampler.start()
    started = time.monotonic_ns()
    try:
        for pair_id in range(stage.concurrent_pairs):
            command = command_for(
                "client",
                stage,
                pair_id,
                args.campaign_id,
                args.host,
                args.bind,
                args.base_port,
                args.io_timeout_ms,
                args.auth_paths,
                args.profiling_mode,
            )
            command.extend((
                "--completion-ack-timeout-ms",
                str(args.completion_ack_timeout_ms),
                "--completion-retries", str(args.completion_retries),
                "--completion-retry-delay-ms",
                str(args.completion_retry_delay_ms),
            ))
            command, profile_path = apply_profiler(
                args, command, "client", stage_index, pair_id
            )
            process = subprocess.Popen(
                command,
                cwd=TPC_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            sampler.add(process.pid)
            processes.append((
                pair_id, time.monotonic_ns() - started, process, profile_path
            ))
        rows = []
        for pair_id, spawn_offset_ns, process, profile_path in processes:
            stdout, stderr = process.communicate(timeout=args.process_timeout_seconds)
            if process.returncode != 0:
                raise RuntimeError(
                    f"client pair={pair_id} rc={process.returncode}: {stderr.strip()}"
                )
            row = {
                "pair_id": pair_id,
                "execution_id": execution_id(args.campaign_id, stage, pair_id),
                "host_context_seed": context_seed(
                    args.campaign_id, stage, pair_id
                ),
                "spawn_offset_ns": spawn_offset_ns,
                **parse_fields(stdout, "client", args.profiling_mode),
            }
            validate_native_row(row, stage, "client")
            if profile_path is not None:
                row.update(parse_strace_summary(profile_path))
            rows.append(row)
        return rows, sampler.finish()
    except Exception:
        for _, _, process, _ in processes:
            if process.poll() is None:
                process.kill()
            process.communicate()
        sampler.finish()
        raise


def run_server_pool_stage(
    args: argparse.Namespace, stage: Stage, stage_index: int
) -> tuple[list[dict[str, int]], dict[str, object]]:
    processes: list[tuple[
        int, int, subprocess.Popen[str], Path | None, TextIO, TextIO
    ]] = []
    backend = gateway_backend_endpoint(args.campaign_id, stage_index)
    manifest = gateway_manifest_path(args.campaign_id, stage_index)
    completion_dir = gateway_completion_dir(args.campaign_id, stage_index)
    gateway_profile_path: Path | None = None
    gateway_process: subprocess.Popen[str] | None = None
    gateway_communicated = False
    sampler = StageProcessSampler(args.profile_sample_interval_ms)
    sampler.start()
    started = time.monotonic_ns()
    workers = stage_worker_count(args, stage)
    write_gateway_manifest(manifest, args.campaign_id, stage)
    completion_dir.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        gateway_line = gateway_command(
            args, stage, stage_index, backend, manifest, completion_dir
        )
        gateway_line, gateway_profile_path = apply_profiler(
            args, gateway_line, "gateway", stage_index, 0
        )
        gateway_process = subprocess.Popen(
            gateway_line,
            cwd=TPC_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        sampler.add(gateway_process.pid)
        for worker_index in range(workers):
            command = pool_worker_command(
                args, stage, worker_index, backend
            )
            command, profile_path = apply_profiler(
                args, command, "worker", stage_index, worker_index
            )
            stdout_file = tempfile.TemporaryFile(
                mode="w+t", encoding="utf-8"
            )
            stderr_file = tempfile.TemporaryFile(
                mode="w+t", encoding="utf-8"
            )
            try:
                process = subprocess.Popen(
                    command,
                    cwd=TPC_ROOT,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    text=True,
                )
            except Exception:
                stdout_file.close()
                stderr_file.close()
                raise
            sampler.add(process.pid)
            processes.append((
                worker_index, time.monotonic_ns() - started,
                process, profile_path, stdout_file, stderr_file,
            ))
        time.sleep(args.bind_grace_ms / 1000.0)
        rows_by_pair: dict[int, dict[str, int]] = {}
        worker_profiles: list[dict[str, object]] = []
        for (worker_index, spawn_offset_ns, process, profile_path,
             stdout_file, stderr_file) in processes:
            process.wait(timeout=args.process_timeout_seconds)
            stdout_file.flush()
            stderr_file.flush()
            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout = stdout_file.read()
            stderr = stderr_file.read()
            if process.returncode != 0:
                gateway_detail = "gateway still running"
                if gateway_process.poll() is not None:
                    gateway_stdout, gateway_stderr = gateway_process.communicate()
                    gateway_communicated = True
                    gateway_detail = (
                        f"gateway rc={gateway_process.returncode}; "
                        f"stdout={gateway_stdout.strip()!r}; "
                        f"stderr={gateway_stderr.strip()!r}"
                    )
                raise RuntimeError(
                    f"pool worker={worker_index} rc={process.returncode}: "
                    f"{stderr.strip()}; {gateway_detail}"
                )
            parsed_rows, worker_row = parse_pool_worker_output(
                stdout, args.profiling_mode
            )
            if int(worker_row["worker_index"]) != worker_index:
                raise RuntimeError("worker output identity mismatch")
            worker_row["spawn_offset_ns"] = spawn_offset_ns
            if profile_path is not None:
                worker_row.update(parse_strace_summary(profile_path))
            worker_profiles.append(worker_row)
            for pair_id, parsed in parsed_rows.items():
                if pair_id in rows_by_pair or not 0 <= pair_id < stage.concurrent_pairs:
                    raise RuntimeError(f"duplicate or invalid pair_id={pair_id}")
                row = {
                    "pair_id": pair_id,
                    "execution_id": execution_id(
                        args.campaign_id, stage, pair_id
                    ),
                    "host_context_seed": context_seed(
                        args.campaign_id, stage, pair_id
                    ),
                    "worker_index": worker_index,
                    "spawn_offset_ns": spawn_offset_ns,
                    **parsed,
                }
                validate_native_row(row, stage, "server")
                rows_by_pair[pair_id] = row
        if set(rows_by_pair) != set(range(stage.concurrent_pairs)):
            raise RuntimeError("worker pool did not produce every pair result")
        gateway_stdout, gateway_stderr = gateway_process.communicate(
            timeout=args.process_timeout_seconds
        )
        gateway_communicated = True
        if gateway_process.returncode != 0:
            raise RuntimeError(
                f"gateway rc={gateway_process.returncode}: "
                f"{gateway_stderr.strip()}"
            )
        gateway_row = parse_gateway_result(gateway_stdout)
        if int(gateway_row["expected_sessions"]) != stage.concurrent_pairs or \
                int(gateway_row["completed_sessions"]) != stage.concurrent_pairs:
            raise RuntimeError("gateway did not route every participant-pair session")
        if int(gateway_row["worker_count"]) != workers or \
                int(gateway_row["registered_workers"]) != workers:
            raise RuntimeError("gateway worker-pool size mismatch")
        expected_queue_capacity = args.max_queue or stage.concurrent_pairs
        if int(gateway_row["queue_capacity"]) != expected_queue_capacity or \
                int(gateway_row["peak_queue_depth"]) > expected_queue_capacity or \
                int(gateway_row["peak_busy_workers"]) > workers:
            raise RuntimeError("gateway exceeded configured pool or queue bounds")
        if int(gateway_row["assignments"]) != stage.concurrent_pairs or \
                int(gateway_row["rejected_sessions"]) != 0:
            raise RuntimeError("worker pool dropped or rejected a session")
        if int(gateway_row["completion_records_written"]) != stage.concurrent_pairs:
            raise RuntimeError("gateway did not durably record every completion")
        if any(int(gateway_row[field]) != 0 for field in (
            "completion_replay_requests", "completion_replays",
            "test_dropped_done_frames",
        )):
            raise RuntimeError("unexpected completion recovery on primary timing path")
        if gateway_profile_path is not None:
            gateway_row.update(parse_strace_summary(gateway_profile_path))
        profile = sampler.finish()
        profile["gateway"] = gateway_row
        profile["worker_pool"] = {
            "configured_workers": workers,
            "workers": worker_profiles,
            "completed_sessions": sum(
                int(row["completed_sessions"]) for row in worker_profiles
            ),
            "sum_setup_ns": sum(
                int(row["setup_ns"]) for row in worker_profiles
            ),
            "sum_user_cpu_ns": sum(
                int(row["user_cpu_ns"]) for row in worker_profiles
            ),
            "sum_system_cpu_ns": sum(
                int(row["system_cpu_ns"]) for row in worker_profiles
            ),
            "sum_worker_peak_rss_kb": sum(
                int(row["max_rss_kb"]) for row in worker_profiles
            ),
        }
        return [rows_by_pair[index] for index in sorted(rows_by_pair)], profile
    except Exception:
        for _, _, process, _, _, _ in processes:
            if process.poll() is None:
                process.kill()
            process.wait()
        if gateway_process is not None:
            if gateway_process.poll() is None:
                gateway_process.kill()
            if not gateway_communicated:
                gateway_process.communicate()
        sampler.finish()
        raise
    finally:
        for _, _, _, _, stdout_file, stderr_file in processes:
            stdout_file.close()
            stderr_file.close()
        manifest.unlink(missing_ok=True)
        # Retain acknowledgements across runner failure and restart. A new
        # experiment must use a new campaign ID, not delete live replay state.


def summarize_client(rows: list[dict[str, int]]) -> dict[str, int]:
    summary = {
        "critical_arc_wall_ns": max(row["wall_ns"] for row in rows),
        "sum_client_crypto_ns": sum(row["crypto_ns"] for row in rows),
        "sum_verifier_challenge_ns": sum(
            row["verifier_challenge_ns"] for row in rows
        ),
        "sum_verifier_msm_ns": sum(row["verifier_msm_ns"] for row in rows),
        "verifier_equations": sum(row["verifier_equations"] for row in rows),
        "verifier_msm_calls": sum(row["verifier_msm_calls"] for row in rows),
        "verifier_fallbacks": sum(row["verifier_fallbacks"] for row in rows),
        "sent_frames": sum(row["sent_frames"] for row in rows),
        "received_frames": sum(row["received_frames"] for row in rows),
        "sent_bytes": sum(row["sent_bytes"] for row in rows),
        "received_bytes": sum(row["received_bytes"] for row in rows),
        "sum_setup_ns": sum(row["setup_ns"] for row in rows),
        "sum_user_cpu_ns": sum(row["user_cpu_ns"] for row in rows),
        "sum_system_cpu_ns": sum(row["system_cpu_ns"] for row in rows),
        "sum_process_peak_rss_kb": sum(row["max_rss_kb"] for row in rows),
        "voluntary_context_switches": sum(
            row["voluntary_context_switches"] for row in rows
        ),
        "involuntary_context_switches": sum(
            row["involuntary_context_switches"] for row in rows
        ),
        "scheduler_wait_ns": sum(row["scheduler_wait_ns"] for row in rows),
        "scheduler_slices": sum(row["scheduler_slices"] for row in rows),
        "send_calls": sum(row["send_calls"] for row in rows),
        "receive_calls": sum(row["receive_calls"] for row in rows),
    }
    if "malloc_calls" in rows[0]:
        for field in (
            "malloc_calls", "calloc_calls", "realloc_calls", "free_calls",
            "requested_allocation_bytes",
        ):
            summary[field] = sum(row[field] for row in rows)
    if "total_syscalls" in rows[0]:
        summary["total_syscalls"] = sum(row["total_syscalls"] for row in rows)
        summary["total_syscall_errors"] = sum(
            row["total_syscall_errors"] for row in rows
        )
    return summary


def summarize_server(rows: list[dict[str, int]]) -> dict[str, int]:
    summary = {
        "sum_verify_request_ns": sum(row["verify_request_ns"] for row in rows),
        "sum_generate_response_ns": sum(
            row["generate_response_ns"] for row in rows
        ),
        "sum_verify_final_ns": sum(row["verify_final_ns"] for row in rows),
        "sum_verifier_challenge_ns": sum(
            row["verifier_challenge_ns"] for row in rows
        ),
        "sum_verifier_msm_ns": sum(row["verifier_msm_ns"] for row in rows),
        "verifier_equations": sum(row["verifier_equations"] for row in rows),
        "verifier_msm_calls": sum(row["verifier_msm_calls"] for row in rows),
        "verifier_fallbacks": sum(row["verifier_fallbacks"] for row in rows),
        "critical_arc_wall_ns": max(row["protocol_wall_ns"] for row in rows),
        "sent_frames": sum(row["sent_frames"] for row in rows),
        "received_frames": sum(row["received_frames"] for row in rows),
        "sent_bytes": sum(row["sent_bytes"] for row in rows),
        "received_bytes": sum(row["received_bytes"] for row in rows),
        "sum_setup_ns": sum(row["setup_ns"] for row in rows),
        "sum_user_cpu_ns": sum(row["user_cpu_ns"] for row in rows),
        "sum_system_cpu_ns": sum(row["system_cpu_ns"] for row in rows),
        "sum_process_peak_rss_kb": sum(row["max_rss_kb"] for row in rows),
        "voluntary_context_switches": sum(
            row["voluntary_context_switches"] for row in rows
        ),
        "involuntary_context_switches": sum(
            row["involuntary_context_switches"] for row in rows
        ),
        "scheduler_wait_ns": sum(row["scheduler_wait_ns"] for row in rows),
        "scheduler_slices": sum(row["scheduler_slices"] for row in rows),
        "send_calls": sum(row["send_calls"] for row in rows),
        "receive_calls": sum(row["receive_calls"] for row in rows),
    }
    if "malloc_calls" in rows[0]:
        for field in (
            "malloc_calls", "calloc_calls", "realloc_calls", "free_calls",
            "requested_allocation_bytes",
        ):
            summary[field] = sum(row[field] for row in rows)
    if "total_syscalls" in rows[0]:
        summary["total_syscalls"] = sum(row["total_syscalls"] for row in rows)
        summary["total_syscall_errors"] = sum(
            row["total_syscall_errors"] for row in rows
        )
    return summary


def collect_environment(args: argparse.Namespace, binary: Path) -> dict[str, object]:
    relic_cache = ROOT / ".deps" / "relic-build" / "CMakeCache.txt"
    imds = aws_imds_metadata()
    expected_region = EXPECTED_AWS_REGIONS.get(args.route, {}).get(args.role)
    observed_region = str(imds.get("region", "unknown"))
    placement = {
        "provider": "AWS" if expected_region else "not-applicable",
        "route": args.route,
        "role": args.role,
        "expected_region": expected_region or "not-applicable",
        "observed_region": observed_region,
        "matched": (
            observed_region == expected_region
            if expected_region is not None else True
        ),
    }
    cmake_build_type, cmake_build_type_source = effective_cmake_build_type()
    return {
        "platform": platform.platform(),
        "hostname": platform.node(),
        "python": platform.python_version(),
        "binary_sha256": sha256(binary),
        "gateway_binary_sha256": sha256(GATEWAY) if GATEWAY.is_file() else "missing",
        "protocol_source_sha256": source_digest(),
        "cpu_count": os.cpu_count(),
        "cpu": cpu_details(),
        "memory": memory_details(),
        "scheduler": scheduler_details(),
        "aws_imds": imds,
        "placement_validation": placement,
        "compiler": command_version(["cc", "--version"]),
        "zeromq": command_version(["pkg-config", "--modversion", "libzmq"]),
        "libsodium": command_version(
            ["pkg-config", "--modversion", "libsodium"]
        ),
        "transport_tls_cipher": "not-applicable-zero-mq-curve",
        "kernel": platform.release(),
        "instance_type_or_product": read_optional_text(
            "/sys/devices/virtual/dmi/id/product_name"
        ),
        "host_product_uuid": read_optional_text(
            "/sys/devices/virtual/dmi/id/product_uuid"
        ),
        "cpu_governor": read_optional_text(
            "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
        ),
        "cmake_build_type": cmake_build_type,
        "cmake_build_type_source": cmake_build_type_source,
        "cmake_c_flags": cmake_cache_value("CMAKE_C_FLAGS"),
        "cmake_release_c_flags": cmake_cache_value("CMAKE_C_FLAGS_RELEASE"),
        "relic_build": {
            name.lower(): cmake_cache_value(name, relic_cache)
            for name in (
                "ARCH", "ARITH", "FP_PRIME", "FP_METHD", "EP_METHD",
                "EP_CTMAP", "EC_METHD", "WITH",
            )
        },
        "synthetic_point_map": (
            "OASIS domain-separated SHA-256 try-and-increment over secp256k1"
        ),
        "relic_source_commit": args.relic_commit,
        "thread_model": (
            "one event-driven gateway and a fixed pool of long-lived, "
            "process-isolated RELIC workers"
        ),
        "server_architecture": (
            "one CURVE ROUTER event loop with bounded admission queue, "
            "backpressure, and session-affine dispatch to a fixed RELIC "
            "worker-process pool over local IPC"
        ),
        "client_architecture": (
            "one DEALER connection per participant-pair session; all connect "
            "to the same public service port"
        ),
        "tcp_rmem": read_optional_text("/proc/sys/net/ipv4/tcp_rmem"),
        "tcp_wmem": read_optional_text("/proc/sys/net/ipv4/tcp_wmem"),
        "socket_rmem_max": read_optional_text("/proc/sys/net/core/rmem_max"),
        "socket_wmem_max": read_optional_text("/proc/sys/net/core/wmem_max"),
        "somaxconn": read_optional_text("/proc/sys/net/core/somaxconn"),
        "network_interface": args.network_interface,
        "soft_nofile": resource.getrlimit(resource.RLIMIT_NOFILE)[0],
        "hard_nofile": resource.getrlimit(resource.RLIMIT_NOFILE)[1],
        "soft_nproc": resource.getrlimit(resource.RLIMIT_NPROC)[0],
        "hard_nproc": resource.getrlimit(resource.RLIMIT_NPROC)[1],
    }


def write_report(
    args: argparse.Namespace,
    samples: list[dict[str, object]],
    upstream: dict[str, object],
    stage_count: int,
) -> None:
    payload = {
        "schema": "oasis-preswap-cloud-v8",
        "campaign_started_utc": args.campaign_started_utc,
        "generated_at_utc": utc_now(),
        "campaign_id": args.campaign_id,
        "role": args.role,
        "route": args.route,
        "transport": "ZeroMQ CURVE over TCP",
        "authenticated_transport": True,
        "transport_security": {
            "mechanism": "ZeroMQ CURVE",
            "authorization": "ZAP public-key allowlist",
            "zap_domain": ZAP_DOMAIN,
            "initiator_public_key_sha256": public_key_fingerprint(
                args.auth_paths["initiator_public"]
            ),
            "responder_public_key_sha256": public_key_fingerprint(
                args.auth_paths["responder_public"]
            ),
            "tls_records": "not-applicable",
            "tls_session_reuse": "not-applicable-native-transport-is-not-tls",
            "curve_connection_lifecycle": (
                "one mutually authenticated CURVE/TCP connection per "
                "participant-pair execution, reused for every logical frame "
                "of that execution"
            ),
        },
        "experiment_identity": {
            "domain": EXPERIMENT_ID_DOMAIN,
            "campaign_id": args.campaign_id,
            "route": args.route,
            "schedule_sha256": args.schedule_sha256,
            "pairing_key_fields": [
                "campaign_id", "route", "participants", "items_per_arc",
                "concurrent_pairs", "trial", "pair_id",
            ],
            "execution_id_derivation": (
                "first 64 bits of SHA-256 over campaign, warmup/measured "
                "phase, participants, trial, concurrent pairs, mode, and pair"
            ),
        },
        "randomization": {
            "domain": RANDOMIZATION_DOMAIN,
            "algorithm": (
                "SHA-256 deterministic permutation with cyclic "
                "position counterbalancing"
            ),
            "route_is_campaign_constant": True,
            "block_factors": [
                "campaign_id", "route", "warmup_status", "participants",
                "items_per_arc", "concurrent_pairs",
            ],
            "schedule_sha256": args.schedule_sha256,
        },
        "participants": args.participant_values,
        "concurrent_pair_values": args.concurrent_pair_values,
        "modes": args.mode_values,
        "trials": args.trials,
        "warmup": args.warmup,
        "runtime": {
            "service_port": args.base_port,
            "public_listener_count": 1,
            "session_routing_key": "authenticated connection + pair_id + execution_id",
            "connection_lifecycle": (
                "one connection per participant-pair execution; shared across "
                "all item phases and never shared across participant pairs"
            ),
            "stage_count": stage_count,
            "io_timeout_ms": args.io_timeout_ms,
            "completion_ack_timeout_ms": args.completion_ack_timeout_ms,
            "completion_retries": args.completion_retries,
            "completion_retry_delay_ms": args.completion_retry_delay_ms,
            "completion_recovery": (
                "durable responder journal plus SID- and digest-bound replay query"
            ),
            "process_timeout_seconds": args.process_timeout_seconds,
            "bind_grace_ms": args.bind_grace_ms,
            "client_stage_delay_ms": args.client_stage_delay_ms,
            "profile_sample_interval_ms": args.profile_sample_interval_ms,
            "worker_count": args.worker_count,
            "worker_count_policy": (
                "explicit" if args.worker_count else "responder-cpu-count"
            ),
            "max_queue": args.max_queue,
            "max_queue_policy": (
                "explicit" if args.max_queue else "complete-stage-workload"
            ),
            "profiling_mode": args.profiling_mode,
            "context_encoding": "OASIS-CONTEXT-v1",
            "context_epoch": 1,
            "context_expiry": 3600,
            "profile_output_dir": (
                str(args.profile_output_dir) if args.profile_output_dir else None
            ),
        },
        "provenance": {
            "paraswap": upstream,
            "relic_commit": args.relic_commit,
            "upstream_lock_sha256": sha256(UPSTREAM_LOCK),
            "runner_sha256": sha256(Path(__file__).resolve()),
        },
        "environment": args.environment,
        "samples": samples,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temporary.replace(args.output)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", required=True, choices=("server", "client"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--route", required=True)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--participants", default="3,5,8,16")
    parser.add_argument(
        "--concurrent-pairs",
        help="comma-separated p values; omitted means one directed arc per participant",
    )
    parser.add_argument("--modes", default=",".join(DEFAULT_MODES))
    parser.add_argument("--trials", type=int, default=30)
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument("--base-port", type=int, default=9000)
    parser.add_argument("--io-timeout-ms", type=int, default=900000)
    parser.add_argument("--completion-ack-timeout-ms", type=int, default=5000)
    parser.add_argument("--completion-retries", type=int, default=3)
    parser.add_argument("--completion-retry-delay-ms", type=int, default=1000)
    parser.add_argument("--process-timeout-seconds", type=int, default=930)
    parser.add_argument("--bind-grace-ms", type=int, default=250)
    parser.add_argument("--client-stage-delay-ms", type=int, default=500)
    parser.add_argument("--profile-sample-interval-ms", type=int, default=5)
    parser.add_argument(
        "--worker-count", type=int, default=0,
        help="fixed responder worker pool size; 0 selects the responder CPU count",
    )
    parser.add_argument(
        "--max-queue", type=int, default=0,
        help="maximum queued sessions; 0 admits the complete stage workload",
    )
    parser.add_argument(
        "--profiling-mode",
        choices=("timing", "allocation", "syscall"),
        default="timing",
        help="allocation uses separate instrumented binaries and is not timing evidence",
    )
    parser.add_argument(
        "--network-interface",
        default="auto",
        help="interface used for host counters; default resolves the route interface",
    )
    parser.add_argument(
        "--profile-output-dir",
        type=Path,
        help="required output directory for per-process syscall summaries",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--auth-dir",
        type=Path,
        help="role-specific CURVE key directory (required for execution)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate the campaign and print its stage/port allocation",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="use prebuilt native binaries (not recommended for final evidence)",
    )
    args = parser.parse_args()
    try:
        args.participant_values = [
            int(value) for value in parse_csv(args.participants)
        ]
    except ValueError:
        parser.error("participants must be a comma-separated list of integers")
    args.mode_values = parse_csv(args.modes)
    try:
        args.concurrent_pair_values = (
            [int(value) for value in parse_csv(args.concurrent_pairs)]
            if args.concurrent_pairs else None
        )
    except ValueError:
        parser.error("concurrent-pairs must be a comma-separated list of integers")
    if not args.mode_values:
        parser.error("modes must contain at least one configuration")
    unknown = sorted(set(args.mode_values) - set(DEFAULT_MODES))
    if unknown:
        parser.error(f"unsupported modes: {', '.join(unknown)}")
    if not args.participant_values or min(args.participant_values) < 3:
        parser.error("participants must contain integers >= 3 for a ParaSwap cycle")
    if len(args.participant_values) != len(set(args.participant_values)):
        parser.error("participants must not contain duplicates")
    if len(args.mode_values) != len(set(args.mode_values)):
        parser.error("modes must not contain duplicates")
    if args.concurrent_pair_values is not None and (
        not args.concurrent_pair_values
        or min(args.concurrent_pair_values) < 1
        or max(args.concurrent_pair_values) > 4096
        or len(args.concurrent_pair_values) != len(set(args.concurrent_pair_values))
    ):
        parser.error("concurrent-pairs must contain unique integers in [1, 4096]")
    if args.trials <= 0 or args.warmup < 0:
        parser.error("trials must be positive and warmup non-negative")
    if not args.route.strip() or not args.campaign_id.strip():
        parser.error("route and campaign-id must be non-empty")
    if args.io_timeout_ms <= 0 or args.process_timeout_seconds <= 0:
        parser.error("I/O and process timeouts must be positive")
    if args.completion_ack_timeout_ms <= 0:
        parser.error("completion acknowledgement timeout must be positive")
    if not 0 <= args.completion_retries <= 100:
        parser.error("completion retries must be in [0, 100]")
    if args.completion_retry_delay_ms < 0:
        parser.error("completion retry delay must be non-negative")
    if args.process_timeout_seconds * 1000 <= args.io_timeout_ms:
        parser.error("process timeout must exceed the native I/O timeout")
    if args.bind_grace_ms < 0 or args.client_stage_delay_ms < 0:
        parser.error("stage delays must be non-negative")
    if args.profile_sample_interval_ms <= 0:
        parser.error("profile sample interval must be positive")
    if args.worker_count < 0:
        parser.error("worker-count must be non-negative")
    if args.max_queue < 0:
        parser.error("max-queue must be non-negative")
    if args.profiling_mode == "syscall":
        if args.profile_output_dir is None:
            parser.error("--profile-output-dir is required for syscall profiling")
        args.profile_output_dir = args.profile_output_dir.resolve()
        if not args.dry_run:
            if not shutil.which("strace"):
                parser.error("strace is required for syscall profiling")
            args.profile_output_dir.mkdir(parents=True, exist_ok=True)

    samples: list[dict[str, object]] = []
    args.campaign_started_utc = utc_now()
    stages = make_stages(
        args.campaign_id, args.participant_values, args.concurrent_pair_values,
        args.mode_values, args.trials, args.warmup
    )
    args.schedule_sha256 = stage_schedule_digest(
        args.campaign_id, args.route, stages
    )
    maximum_pairs = max(stage.concurrent_pairs for stage in stages)
    required_nofile = 2 * maximum_pairs + 256
    soft_nofile = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    if not args.dry_run and soft_nofile < required_nofile:
        parser.error(
            f"soft nofile={soft_nofile} is below required {required_nofile}; "
            "raise ulimit before this campaign"
        )
    if args.base_port < 1024 or args.base_port > 65535:
        parser.error(
            "service port must be in [1024, 65535]"
        )
    if args.dry_run:
        print(json.dumps({
            "role": args.role,
            "route": args.route,
            "campaign_id": args.campaign_id,
            "participants": args.participant_values,
            "concurrent_pair_values": args.concurrent_pair_values,
            "modes": args.mode_values,
            "measured_trials": args.trials,
            "warmup_trials": args.warmup,
            "stage_count": len(stages),
            "service_port": args.base_port,
            "public_listener_count": 1,
            "connection_model": (
                "one connection per participant-pair session to one shared port"
            ),
            "maximum_parallel_pairs": maximum_pairs,
            "worker_pool_size": (
                min(
                    args.worker_count or max(1, os.cpu_count() or 1),
                    maximum_pairs,
                )
            ),
            "maximum_queue_depth": args.max_queue or maximum_pairs,
            "server_process_upper_bound": (
                min(
                    args.worker_count or max(1, os.cpu_count() or 1),
                    maximum_pairs,
                ) + 1
            ),
            "minimum_soft_nofile": required_nofile,
        }, indent=2))
        return 0
    if args.auth_dir is None:
        parser.error("--auth-dir is required for authenticated TCP execution")
    args.auth_paths = auth_paths(args.auth_dir.resolve())
    try:
        validate_auth_files(args.role, args.auth_paths)
        args.relic_commit = verified_relic_commit()
    except RuntimeError as error:
        parser.error(str(error))
    if args.network_interface == "auto":
        try:
            args.network_interface = default_network_interface(args.host, args.role)
        except RuntimeError as error:
            parser.error(str(error))
    if not (Path("/sys/class/net") / args.network_interface).is_dir():
        parser.error(f"network interface does not exist: {args.network_interface}")
    upstream = verify_upstream()
    if not args.skip_build:
        ensure_native_build()
    required_binary = binary_for(args.role, args.profiling_mode)
    if not required_binary.is_file() or (args.role == "server" and not GATEWAY.is_file()):
        parser.error("native Pre-swap binaries are missing; run make native-build")
    args.environment = collect_environment(args, required_binary)
    for stage_index, stage in enumerate(stages):
        if args.role == "client" and args.client_stage_delay_ms > 0:
            time.sleep(args.client_stage_delay_ms / 1000.0)
        before_network = network_snapshot(args.network_interface)
        before_tcp = tcp_snapshot()
        before_cpu_total, before_cpu_idle, before_cpu_steal = cpu_snapshot()
        before_cgroup_cpu = cgroup_cpu_snapshot()
        stage_started_utc = utc_now()
        started = time.monotonic_ns()
        rows, process_profile = (
            run_client_stage(args, stage, stage_index)
            if args.role == "client"
            else run_server_pool_stage(args, stage, stage_index)
        )
        stage_wall_ns = time.monotonic_ns() - started
        stage_finished_utc = utc_now()
        host_profile = stage_host_delta(args.network_interface, {
            "network": before_network,
            "tcp": before_tcp,
            "cpu_total": before_cpu_total,
            "cpu_idle": before_cpu_idle,
            "cpu_steal": before_cpu_steal,
            "cgroup_cpu": before_cgroup_cpu,
        })
        if not stage.warmup:
            aggregate = (
                summarize_client(rows)
                if args.role == "client"
                else summarize_server(rows)
            )
            if args.role == "server":
                gateway = process_profile.get("gateway")
                if not isinstance(gateway, dict):
                    raise RuntimeError("server sample is missing gateway metrics")
                aggregate["gateway_user_cpu_ns"] = int(gateway["user_cpu_ns"])
                aggregate["gateway_system_cpu_ns"] = int(gateway["system_cpu_ns"])
                aggregate["gateway_max_rss_kb"] = int(gateway["max_rss_kb"])
                for field in (
                    "worker_count", "queue_capacity", "peak_busy_workers", "peak_queue_depth",
                    "assignments", "queued_sessions", "rejected_sessions",
                    "internal_control_frames", "total_queue_wait_ns",
                    "max_queue_wait_ns",
                    "completion_records_written",
                    "completion_replay_requests", "completion_replays",
                    "test_dropped_done_frames",
                ):
                    aggregate[f"gateway_{field}"] = int(gateway[field])
                worker_pool = process_profile.get("worker_pool")
                if not isinstance(worker_pool, dict):
                    raise RuntimeError("server sample is missing worker-pool metrics")
                aggregate["worker_pool_setup_ns"] = int(
                    worker_pool["sum_setup_ns"]
                )
                aggregate["sum_user_cpu_ns"] = (
                    int(gateway["user_cpu_ns"])
                    + int(worker_pool["sum_user_cpu_ns"])
                )
                aggregate["sum_system_cpu_ns"] = (
                    int(gateway["system_cpu_ns"])
                    + int(worker_pool["sum_system_cpu_ns"])
                )
                aggregate["sum_process_peak_rss_kb"] = int(
                    process_profile["peak_aggregate_rss_kb"]
                )
                if "total_syscalls" in gateway:
                    aggregate["total_syscalls"] = int(
                        aggregate.get("total_syscalls", 0)
                    ) + int(gateway["total_syscalls"])
                    aggregate["total_syscall_errors"] = int(
                        aggregate.get("total_syscall_errors", 0)
                    ) + int(gateway["total_syscall_errors"])
                for worker in worker_pool.get("workers", []):
                    if "total_syscalls" in worker:
                        aggregate["total_syscalls"] = int(
                            aggregate.get("total_syscalls", 0)
                        ) + int(worker["total_syscalls"])
                        aggregate["total_syscall_errors"] = int(
                            aggregate.get("total_syscall_errors", 0)
                        ) + int(worker["total_syscall_errors"])
            total_items = stage.items * stage.concurrent_pairs
            application_frames = (
                stage.concurrent_pairs * (5 * stage.items + 1)
                if stage.mode == "reference-itemwise"
                else stage.concurrent_pairs * (
                    7 if stage.mode.endswith("-batch-verification") else 6
                )
            )
            aggregate_cpu_ns = (
                int(aggregate["sum_user_cpu_ns"])
                + int(aggregate["sum_system_cpu_ns"])
            )
            transferred_bytes = (
                int(aggregate["sent_bytes"])
                + int(aggregate["received_bytes"])
            )
            samples.append(
                {
                    "participants": stage.participants,
                    "items_per_arc": stage.items,
                    "concurrent_pairs": stage.concurrent_pairs,
                    "mode": stage.mode,
                    "trial": stage.trial,
                    "randomization_block_id": randomization_block_id(
                        args.campaign_id, args.route, stage
                    ),
                    "paired_trial_id": paired_trial_id(
                        args.campaign_id, args.route, stage
                    ),
                    "mode_position": ordered_modes(
                        args.campaign_id, stage.participants,
                        stage.concurrent_pairs, args.mode_values,
                        stage.trial, stage.warmup,
                    ).index(stage.mode),
                    "schedule_position": stage_index,
                    "service_port": args.base_port,
                    "stage_wall_ns": stage_wall_ns,
                    "stage_started_utc": stage_started_utc,
                    "stage_finished_utc": stage_finished_utc,
                    "total_items": total_items,
                    "logical_sessions": (
                        stage.concurrent_pairs
                        if stage.mode.startswith("batch-joint-presigning-")
                        else total_items
                    ),
                    "application_frames": application_frames,
                    "items_per_second": (
                        total_items * 1_000_000_000.0 / stage_wall_ns
                    ),
                    "pair_sessions_per_second": (
                        stage.concurrent_pairs * 1_000_000_000.0
                        / stage_wall_ns
                    ),
                    "application_goodput_mbps": (
                        transferred_bytes * 8000.0 / stage_wall_ns
                    ),
                    "aggregate_process_cpu_core_pct": (
                        aggregate_cpu_ns * 100.0 / stage_wall_ns
                    ),
                    "aggregate_process_cpu_capacity_pct": (
                        aggregate_cpu_ns * 100.0
                        / (stage_wall_ns * max(1, os.cpu_count() or 1))
                    ),
                    "process_profile": process_profile,
                    "host_profile": host_profile,
                    **aggregate,
                    "arcs": rows,
                }
            )
            write_report(args, samples, upstream, len(stages))
        phase = "warmup" if stage.warmup else "trial"
        print(
            f"completed={stage_index + 1}/{len(stages)} role={args.role} "
            f"n={stage.participants} k={stage.items} p={stage.concurrent_pairs} "
            f"mode={stage.mode} "
            f"{phase}={stage.trial}",
            flush=True,
        )
    print(f"wrote={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
