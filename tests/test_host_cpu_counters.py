import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from run_cloud_campaign import cpu_snapshot


class HostCpuCountersTests(unittest.TestCase):
    def test_guest_time_is_not_counted_twice(self):
        with patch.object(Path, "read_text", return_value=
                          "cpu 100 20 30 400 5 6 7 8 40 10\ncpu0 0 0 0 0\n"):
            self.assertEqual(cpu_snapshot(), (576, 405, 8))

    def test_legacy_four_fields(self):
        with patch.object(Path, "read_text", return_value="cpu 10 20 30 40\n"):
            self.assertEqual(cpu_snapshot(), (100, 40, 0))

    def test_invalid_counters_rejected(self):
        for value in ("", "cpu0 1 2 3 4\n", "cpu 1 2\n", "cpu -1 2 3 4\n"):
            with self.subTest(value=value), patch.object(Path, "read_text", return_value=value):
                with self.assertRaises(ValueError):
                    cpu_snapshot()
