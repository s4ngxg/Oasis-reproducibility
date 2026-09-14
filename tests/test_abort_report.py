import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from run_native_handoff import _validate_abort_report, _funded_cycle_recovery


class AbortReportTests(unittest.TestCase):
    def test_refund_rejects_missing_or_wrong_vtd_job(self):
        for arc in ({}, {"jobs": [(0, 3, None)]},
                    {"jobs": [(None, -1, None)]},
                    {"jobs": [(None, True, None)]}):
            with self.subTest(arc=arc), self.assertRaises(ValueError):
                with _funded_cycle_recovery(3, [arc]*3, -1, refund_cycle=True):
                    self.fail("invalid final-key job accepted")

    def test_refund_rejects_conflicting_modes_before_native_launch(self):
        for options in ({"all_honest": True}, {"retry_test": True}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                with _funded_cycle_recovery(3, [{}, {}, {}], -1,
                                            refund_cycle=True, **options):
                    self.fail("conflicting outcome accepted")

    def test_accepts_complete_state_counts(self):
        report = dict(retained_cycle_abort_observed=True, automatic_refund_performed=False,
                      locked_arcs=3, withdrawn_arcs=0, refunded_arcs=0)
        self.assertEqual(_validate_abort_report(report, 3), report)

    def test_rejects_malformed_or_incomplete_reports(self):
        base = dict(retained_cycle_abort_observed=True, automatic_refund_performed=False,
                    locked_arcs=3, withdrawn_arcs=0, refunded_arcs=0)
        for report in ([], None, {}, {**base, "locked_arcs": 2},
                       {**base, "locked_arcs": True}, {**base, "refunded_arcs": -1},
                       {**base, "automatic_refund_performed": True}):
            with self.subTest(report=report), self.assertRaises(ValueError):
                _validate_abort_report(report, 3)
