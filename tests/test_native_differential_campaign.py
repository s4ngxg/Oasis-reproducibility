import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "run_native_differential_campaign.py"
SPEC = importlib.util.spec_from_file_location(
    "run_native_differential_campaign", MODULE_PATH
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class NativeDifferentialRangeTests(unittest.TestCase):
    def test_ranges_are_disjoint_contiguous_and_complete(self):
        chunks = MODULE.ranges(100_003, 8)
        self.assertEqual(chunks[0][0], 0)
        self.assertEqual(sum(count for _, count in chunks), 100_003)
        self.assertEqual(
            [offset for offset, _ in chunks[1:]],
            [
                offset + count
                for offset, count in chunks[:-1]
            ],
        )
        self.assertLessEqual(
            max(count for _, count in chunks)
            - min(count for _, count in chunks),
            1,
        )

    def test_more_workers_than_vectors_does_not_create_empty_ranges(self):
        self.assertEqual(MODULE.ranges(3, 8), [(0, 1), (1, 1), (2, 1)])


if __name__ == "__main__":
    unittest.main()
