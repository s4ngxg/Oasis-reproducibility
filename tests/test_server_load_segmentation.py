import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from segment_server_load_metrics import segment_rows  # noqa: E402


class ServerLoadSegmentationTests(unittest.TestCase):
    def test_adds_pair_count_to_checked_sequential_segments(self):
        rows = []
        for pairs in (1, 2):
            for pair_id in range(pairs):
                rows.append({
                    "pair_id": pair_id,
                    "variant": "baseline",
                    "n": 8,
                })

        result = segment_rows(
            rows,
            pair_values=[1, 2],
            n_count=1,
            variant_count=1,
            trials=1,
            warmup=0,
        )

        self.assertEqual([row["pairs"] for row in result], [1, 2, 2])

    def test_rejects_wrong_row_count(self):
        with self.assertRaisesRegex(ValueError, "expected 3 rows"):
            segment_rows(
                [{"pair_id": 0, "variant": "baseline", "n": 8}],
                pair_values=[1, 2],
                n_count=1,
                variant_count=1,
                trials=1,
                warmup=0,
            )

    def test_rejects_reused_pair_id(self):
        rows = [
            {"pair_id": 0, "variant": "baseline", "n": 8},
            {"pair_id": 0, "variant": "baseline", "n": 8},
        ]
        with self.assertRaisesRegex(ValueError, "unique pair IDs"):
            segment_rows(
                rows,
                pair_values=[2],
                n_count=1,
                variant_count=1,
                trials=1,
                warmup=0,
            )


if __name__ == "__main__":
    unittest.main()
