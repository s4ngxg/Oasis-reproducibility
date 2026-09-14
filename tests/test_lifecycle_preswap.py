import socket
import sys
import threading
import time
import unittest
import tempfile
from unittest.mock import patch
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import lifecycle_preswap as preswap


class LifecyclePreswapOptionTests(unittest.TestCase):
    def test_submillisecond_budget_does_not_round_up(self):
        with patch.object(preswap.time, "monotonic_ns", return_value=1_000_000):
            with self.assertRaises(TimeoutError):
                preswap._remaining_ms(1_999_999, 1000)
            self.assertEqual(preswap._remaining_ms(2_000_000, 1000), 1)

    def test_io_timeout_rejects_noninteger_inputs(self):
        for value in (True, float("nan"), float("inf"), 1.5):
            with self.subTest(value=value), self.assertRaises(ValueError):
                preswap._remaining_ms(time.monotonic_ns() + 1_000_000_000, value)
            with self.subTest(deadline=value), self.assertRaises(ValueError):
                preswap._remaining_ms(value, 1000)

    def test_port_allocator_wait_is_deadline_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(preswap, "PORT_LOCK", Path(directory) / "port.lock"):
                with preswap._serialized_free_tcp_port(
                        deadline_ns=time.monotonic_ns() + 1_000_000_000):
                    with self.assertRaises(TimeoutError):
                        with preswap._serialized_free_tcp_port(
                                deadline_ns=time.monotonic_ns() + 20_000_000):
                            self.fail("allocator acquired a held lock")
                with preswap._serialized_free_tcp_port(
                        deadline_ns=time.monotonic_ns() + 1_000_000_000) as port:
                    self.assertGreater(port, 0)

    def test_nonfinite_process_timeout_rejected(self):
        for cap in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(cap=cap), self.assertRaises(ValueError):
                preswap._remaining_seconds(time.monotonic_ns() + 1_000_000_000, cap)

    def test_coordinator_rejects_bad_cutoff_before_reading_fixtures(self):
        from run_retained_arc_coordinator import coordinate
        for budget in (float("nan"), float("inf"), 0, -1):
            with self.subTest(budget=budget), self.assertRaises(ValueError):
                coordinate(3, "reference-itemwise", -1, -1, -1,
                           lifecycle_preswap_budget_seconds=budget)
        for deadline in (True, 0, -1, float("nan"), float("inf")):
            with self.subTest(deadline=deadline), self.assertRaises(ValueError):
                coordinate(3, "reference-itemwise", -1, -1, -1,
                           lifecycle_deadline_ns=deadline)
        with self.assertRaises(TimeoutError):
            coordinate(3, "reference-itemwise", -1, -1, -1,
                       lifecycle_deadline_ns=time.monotonic_ns() - 1)

    def test_expired_deadline_rejected(self):
        with self.assertRaises(TimeoutError):
            preswap._remaining_seconds(time.monotonic_ns() - 1, 10)
        with self.assertRaises(TimeoutError):
            preswap._remaining_ms(time.monotonic_ns() - 1, 1000)

    def test_process_timeout_cannot_extend_deadline(self):
        deadline = time.monotonic_ns() + 200_000_000
        remaining = preswap._remaining_seconds(deadline, 30)
        self.assertGreater(remaining, 0)
        self.assertLessEqual(remaining, 0.2)

    def test_io_timeout_is_capped_by_absolute_deadline(self):
        deadline = time.monotonic_ns() + 250_000_000
        value = preswap._remaining_ms(deadline, 30_000)
        self.assertGreater(value, 0)
        self.assertLessEqual(value, 250)

    def test_tcp_common_replaces_pid_modulo_port(self):
        options = preswap._tcp_common_options(
            3, 0, "reference-itemwise", 11,
            "00" * 32, 99, 12, 13, 45678, 4321,
        )
        self.assertEqual(options[options.index("--port") + 1], "45678")
        self.assertEqual(options[options.index("--io-timeout-ms") + 1], "4321")

    def test_invalid_deadline_and_timeout_rejected(self):
        with self.assertRaises(ValueError):
            preswap._remaining_seconds(0, 1)
        with self.assertRaises(ValueError):
            preswap._remaining_seconds(time.monotonic_ns() + 1_000_000, 0)
        with self.assertRaises(ValueError):
            preswap._remaining_ms(time.monotonic_ns() + 1_000_000, 0)

    def test_listener_readiness_waits_for_actual_bind(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("127.0.0.1", 0))
        port = server_socket.getsockname()[1]

        class FakeProcess:
            returncode = None
            def poll(self):
                return self.returncode

        fake = FakeProcess()
        ready = threading.Event()

        def delayed_listen():
            time.sleep(0.03)
            server_socket.listen(1)
            ready.set()

        thread = threading.Thread(target=delayed_listen)
        thread.start()
        try:
            started = time.monotonic()
            preswap._wait_listener_ready(
                "127.0.0.1", port,
                time.monotonic_ns() + 500_000_000,
                fake,
            )
            self.assertTrue(ready.is_set())
            self.assertGreaterEqual(time.monotonic() - started, 0.02)
        finally:
            server_socket.close()
            thread.join(timeout=1)

    def test_listener_readiness_does_not_reset_expired_deadline(self):
        class FakeProcess:
            returncode = None
            def poll(self):
                return self.returncode

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        with self.assertRaises(TimeoutError):
            preswap._wait_listener_ready(
                "127.0.0.1", port,
                time.monotonic_ns() - 1,
                FakeProcess(),
            )


if __name__ == "__main__":
    unittest.main()
