import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from run_cloud_campaign import cgroup_cpu_snapshot, cgroup_counter_delta, cgroup_cpu_stat_path, cgroup_interval
from analyze_cloud_results import complete_counter_sum


class CgroupTelemetryTests(unittest.TestCase):
    def test_changed_source_invalidates_interval(self):
        before = {"source": "/cgroup/a/cpu.stat", "source_identity": [1, 2],
                  "nr_periods": 10, "nr_throttled": 3, "throttled_usec": 50}
        counters, stable = cgroup_interval(before, dict(before))
        self.assertTrue(stable)
        self.assertEqual(counters["nr_throttled"], 0)
        for change in ({"source": "/cgroup/b/cpu.stat"}, {"source_identity": [1, 3]}):
            counters, stable = cgroup_interval(before, {**before, **change})
            self.assertFalse(stable)
            self.assertTrue(all(value is None for value in counters.values()))

    def test_nested_membership_uses_its_own_counters(self):
        with patch.object(Path, "read_text", side_effect=[
                "0::/user.slice/session.scope\n",
                "1 0 0:1 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n"]):
            self.assertEqual(cgroup_cpu_stat_path(),
                             Path("/sys/fs/cgroup/user.slice/session.scope/cpu.stat"))

    def test_subtree_mount_mapping(self):
        with patch.object(Path, "read_text", side_effect=[
                "0::/parent/child\n",
                "1 0 0:1 /parent /sys/fs/cgroup rw - cgroup2 cgroup rw\n"]):
            self.assertEqual(cgroup_cpu_stat_path(), Path("/sys/fs/cgroup/child/cpu.stat"))

    def test_unreadable_and_absent_counters_are_unknown(self):
        with patch.object(Path, "read_text", side_effect=OSError("unavailable")):
            self.assertTrue(all(v is None for v in cgroup_cpu_snapshot().values()))
        with patch.object(Path, "read_text", return_value="usage_usec 42\n"):
            self.assertTrue(all(v is None for v in cgroup_cpu_snapshot().values()))

    def test_missing_or_reset_interval_is_not_zero(self):
        for start, end in ((None, 4), (4, None), (8, 4)):
            self.assertIsNone(cgroup_counter_delta({"n": start}, {"n": end})["n"])
        self.assertEqual(cgroup_counter_delta({"n": 4}, {"n": 4})["n"], 0)

    def test_incomplete_total_is_unknown(self):
        self.assertIsNone(complete_counter_sum([0, None, 2]))
        self.assertIsNone(complete_counter_sum([]))
        self.assertEqual(complete_counter_sum([0, 0]), 0)
        self.assertEqual(complete_counter_sum([1, 2]), 3)
