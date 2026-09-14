import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "run_native_fault_campaign.py"
SPEC = importlib.util.spec_from_file_location(
    "run_native_fault_campaign", MODULE_PATH
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class NativeFaultCampaignTests(unittest.TestCase):
    def test_order_is_deterministic_and_complete(self):
        first = MODULE.scenario_order("campaign", 8, 2, False)
        second = MODULE.scenario_order("campaign", 8, 2, False)
        self.assertEqual(first, second)
        self.assertCountEqual(first, MODULE.SCENARIOS)

    def test_control_requires_bilateral_success(self):
        self.assertTrue(MODULE.outcome_is_correct("control", 0, 0))
        self.assertFalse(MODULE.outcome_is_correct("control", 0, 1))
        self.assertFalse(MODULE.outcome_is_correct("control", 1, 0))

    def test_fault_requires_bilateral_abort(self):
        for scenario in MODULE.SCENARIOS[1:]:
            self.assertTrue(MODULE.outcome_is_correct(scenario, 1, 1))
            self.assertFalse(MODULE.outcome_is_correct(scenario, 0, 1))
            self.assertFalse(MODULE.outcome_is_correct(scenario, 1, 0))
            self.assertFalse(MODULE.outcome_is_correct(scenario, 0, 0))

    def test_unknown_scenario_is_rejected(self):
        with self.assertRaises(ValueError):
            MODULE.outcome_is_correct("unknown", 1, 1)


if __name__ == "__main__":
    unittest.main()
