import contextlib
import os
import signal
import subprocess
import tempfile
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import run_retained_arc_coordinator as coordinator
from run_native_handoff import memory_file


class RetainedSupervisorTests(unittest.TestCase):
    def test_refund_cannot_mix_with_other_cycle_outcomes(self):
        for options in ({"all_honest": True}, {"recover_cycle": True}):
            with self.subTest(options=options), self.assertRaisesRegex(ValueError, "one cycle outcome"):
                coordinator.coordinate(3, "reference-itemwise", -1, -1, -1,
                                       refund_cycle=True, **options)

    def test_preparation_expiry_refuses_funding(self):
        now = [100]

        def prepare(*args, **kwargs):
            now[0] = 201
            return []

        with contextlib.ExitStack() as stack:
            public = stack.enter_context(memory_file("public", b"OASISP01" + bytes(3*5*33)))
            private = stack.enter_context(memory_file("private", b"OASISW01" + bytes(3*5*32)))
            participants = stack.enter_context(memory_file(
                "participants", b"OASISYF1" + (3).to_bytes(4, "big") + bytes(64*3)))
            with patch.object(coordinator.time, "monotonic_ns", side_effect=lambda: now[0]), \
                 patch.object(coordinator, "prepared_pair", side_effect=lambda *args:
                              contextlib.nullcontext((-1, -1, -1, -1, b"registry"))), \
                 patch.object(coordinator, "curve_credentials", side_effect=lambda **kwargs:
                              contextlib.nullcontext("unused")), \
                 patch.object(coordinator, "_prepare_vtd_jobs", side_effect=prepare), \
                 patch.object(coordinator, "_funded_cycle_recovery") as funded_cycle, \
                 patch.object(coordinator, "_funded_ledger") as funded_arc:
                with self.assertRaisesRegex(TimeoutError, "funding refused"):
                    coordinator.coordinate(
                        3, "reference-itemwise", public, private, participants,
                        all_honest=True, lifecycle_deadline_ns=200)
                funded_cycle.assert_not_called()
                funded_arc.assert_not_called()

    def test_timeout_stops_real_descendant_ignoring_term(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            marker = Path(directory) / "descendant.pid"
            arcs = self.arcs(stack, 1)

            def worker(*args, **kwargs):
                descendant = subprocess.Popen([
                    sys.executable, "-c",
                    "import os,signal,time,pathlib; "
                    "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                    f"pathlib.Path({str(marker)!r}).write_text(str(os.getpid())); "
                    "time.sleep(30)",
                ])
                descendant.wait()

            pid = None
            try:
                with patch.object(coordinator, "run_lifecycle_preswap", worker):
                    with self.assertRaises(TimeoutError):
                        coordinator._run_preswap_arcs(
                            3, "mode", arcs, "seed", lambda *_: None,
                            self.deadline(5), worker_timeout_seconds=0.5)
                self.assertTrue(marker.exists(), "descendant did not start")
                pid = int(marker.read_text())
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    try:
                        stat = Path(f"/proc/{pid}/stat").read_text()
                    except (FileNotFoundError, ProcessLookupError):
                        break
                    # Orphans may await reaping by the host's PID 1.
                    if stat.rsplit(")", 1)[1].split()[0] == "Z":
                        break
                    time.sleep(0.01)
                else:
                    self.fail("descendant survived worker timeout")
            finally:
                if pid is None and marker.exists():
                    pid = int(marker.read_text())
                if pid is not None:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_nonfinite_worker_budget_spawns_nothing(self):
        for budget in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(budget=budget), patch.object(coordinator.os, "fork") as fork:
                with self.assertRaises(ValueError):
                    coordinator._run_preswap_arcs(
                        3, "mode", [], "seed", lambda *_: None, self.deadline(),
                        worker_timeout_seconds=budget)
                fork.assert_not_called()

    def test_cleanup_signals_group_after_leader_was_reaped(self):
        with patch.object(coordinator.os, "killpg") as killpg:
            coordinator._terminate_and_reap([
                {"pid": None, "pgid": 123, "read_fd": None}
            ])
        self.assertEqual(killpg.call_args_list, [
            unittest.mock.call(123, signal.SIGTERM),
            unittest.mock.call(123, signal.SIGKILL),
        ])

    def test_worker_has_private_process_group(self):
        with contextlib.ExitStack() as stack:
            arcs = self.arcs(stack, 1)
            def worker(*args, **kwargs):
                return {"pid": os.getpid(), "pgid": os.getpgrp()}
            with patch.object(coordinator, "run_lifecycle_preswap", worker):
                coordinator._run_preswap_arcs(
                    3, "mode", arcs, "seed", lambda *_: None, self.deadline())
            result = arcs[0]["measurement"]
            self.assertEqual(result["pid"], result["pgid"])
            self.assertNotEqual(result["pgid"], os.getpgrp())

    def test_missing_exit_status_is_not_success(self):
        with patch.object(coordinator.os, "waitpid", side_effect=ChildProcessError):
            with self.assertRaisesRegex(RuntimeError, "exit status unavailable"):
                coordinator._wait_worker_exit(123, self.deadline())

    def test_worker_exit_wait_obeys_deadline(self):
        with patch.object(coordinator.os, "waitpid", return_value=(0, 0)):
            with self.assertRaises(TimeoutError):
                coordinator._wait_worker_exit(123, self.deadline(0.01))

    def test_worker_exit_preserves_failure_status(self):
        with patch.object(coordinator.os, "waitpid", return_value=(123, 256)):
            self.assertEqual(coordinator._wait_worker_exit(123, self.deadline()), 256)

    @staticmethod
    def deadline(seconds=2.0):
        return time.monotonic_ns() + int(seconds * 1_000_000_000)

    def arcs(self, stack, count=3):
        rows = []
        for arc in range(count):
            fds = [
                stack.enter_context(memory_file(f"unit-{arc}-{name}"))
                for name in ("points", "output", "ck", "sk", "cb", "sb")
            ]
            rows.append({
                "arc": arc,
                "points": fds[0],
                "output": fds[1],
                "execution": 100 + arc,
                "ck": fds[2],
                "sk": fds[3],
                "cb": fds[4],
                "sb": fds[5],
                "registry": b"registry",
                "curve_credentials": "/tmp/unit-curve",
            })
        return rows

    def test_expired_lifecycle_deadline_spawns_nothing(self):
        with contextlib.ExitStack() as stack:
            arcs = self.arcs(stack)
            with patch.object(coordinator.os, "fork") as fork:
                with self.assertRaises(TimeoutError):
                    coordinator._run_preswap_arcs(
                        3, "mode", arcs, "seed", lambda *_: None,
                        time.monotonic_ns() - 1,
                        worker_timeout_seconds=1,
                    )
                fork.assert_not_called()

    def test_workers_overlap_and_share_one_deadline(self):
        with contextlib.ExitStack() as stack:
            arcs = self.arcs(stack)
            deadline = self.deadline()

            def worker(*args, **kwargs):
                started = time.monotonic_ns()
                time.sleep(0.12)
                finished = time.monotonic_ns()
                return {
                    "worker_started_ns": started,
                    "worker_finished_ns": finished,
                    "host_export_deadline_ns": kwargs["host_export_deadline_ns"],
                }

            with patch.object(coordinator, "run_lifecycle_preswap", worker):
                coordinator._run_preswap_arcs(
                    3, "mode", arcs, "seed", lambda *_: None, deadline,
                    worker_timeout_seconds=1,
                )

            starts = [row["measurement"]["worker_started_ns"] for row in arcs]
            finishes = [row["measurement"]["worker_finished_ns"] for row in arcs]
            self.assertLess(max(starts), min(finishes))
            self.assertEqual(
                {row["measurement"]["host_export_deadline_ns"] for row in arcs},
                {deadline},
            )

    def test_fast_failure_kills_hung_sibling(self):
        with contextlib.ExitStack() as stack:
            arcs = self.arcs(stack, 2)

            def worker(*args, **kwargs):
                if args[1] == 0:
                    raise RuntimeError("fail-fast")
                time.sleep(5)
                return {}

            started = time.monotonic()
            with patch.object(coordinator, "run_lifecycle_preswap", worker):
                with self.assertRaisesRegex(RuntimeError, "fail-fast"):
                    coordinator._run_preswap_arcs(
                        3, "mode", arcs, "seed", lambda *_: None,
                        self.deadline(10), worker_timeout_seconds=8,
                    )
            self.assertLess(time.monotonic() - started, 1.5)

    def test_group_timeout_kills_all_workers(self):
        with contextlib.ExitStack() as stack:
            arcs = self.arcs(stack)

            def worker(*args, **kwargs):
                time.sleep(3)
                return {}

            started = time.monotonic()
            with patch.object(coordinator, "run_lifecycle_preswap", worker):
                with self.assertRaises(TimeoutError):
                    coordinator._run_preswap_arcs(
                        3, "mode", arcs, "seed", lambda *_: None,
                        self.deadline(5), worker_timeout_seconds=0.05,
                    )
            self.assertLess(time.monotonic() - started, 1.5)

    def test_spawn_failure_reaps_already_started_child(self):
        with contextlib.ExitStack() as stack:
            arcs = self.arcs(stack)
            real_fork = os.fork
            calls = 0

            def fail_second():
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("spawn-failure")
                return real_fork()

            def worker(*args, **kwargs):
                time.sleep(3)
                return {}

            started = time.monotonic()
            with patch.object(coordinator.os, "fork", side_effect=fail_second), \
                 patch.object(coordinator, "run_lifecycle_preswap", worker):
                with self.assertRaisesRegex(OSError, "spawn-failure"):
                    coordinator._run_preswap_arcs(
                        3, "mode", arcs, "seed", lambda *_: None,
                        self.deadline(5), worker_timeout_seconds=1,
                    )
            self.assertLess(time.monotonic() - started, 1.5)


if __name__ == "__main__":
    unittest.main()
