import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from run_ideal_lifecycle import run


class IdealRunnerTests(unittest.TestCase):
    def test_terminal_cases_and_claim_boundaries(self):
        for outcome in ("complete", "funded-abort", "partial-funding-abort"):
            with self.subTest(outcome=outcome):
                report = run(3, outcome)
                self.assertTrue(report["symbolic_terminal_complete"])
                for flag in ("full_lifecycle", "native_execution",
                             "cryptographic_security_established", "performance_measurement"):
                    self.assertFalse(report[flag])
                terminal = report["trace"][-1]["assets"]
                expected = {"complete": ["withdrawn"] * 3,
                            "funded-abort": ["refunded"] * 3,
                            "partial-funding-abort": ["refunded", "refunded", "unfunded"]}
                self.assertEqual(terminal, expected[outcome])

    def test_unknown_case_rejected(self):
        with self.assertRaises(ValueError):
            run(3, "unknown")
