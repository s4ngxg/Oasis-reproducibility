import contextlib
import os
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import run_retained_arc_coordinator as coordinator
from run_native_handoff import memory_file


class RefundCoordinatorTests(unittest.TestCase):
    def test_refund_waits_for_all_vtd_results_without_sharing(self):
        events = []
        with contextlib.ExitStack() as stack:
            public = stack.enter_context(memory_file("public", b"OASISP01" + bytes(3*5*33)))
            private = stack.enter_context(memory_file("private", b"OASISW01" + bytes(3*5*32)))
            participants = stack.enter_context(memory_file(
                "participants", b"OASISYF1" + (3).to_bytes(4, "big") + bytes(3*64)))

            def jobs(owner, *args, **kwargs):
                result = []
                for level in (0, 1, None):
                    receipt = owner.enter_context(memory_file("receipt"))
                    def finish(fd=receipt, index=level):
                        if index is not None:
                            os.pwrite(fd, b"OASISK01" + (index+1).to_bytes(32, "big"), 0)
                        events.append("finish")
                        return {"test_double": True}
                    result.append((level, receipt,
                                   (lambda: events.append("start"), finish, time.monotonic_ns())))
                return result

            def preswap(n, mode, arcs, *args):
                events.append("preswap")
                for arc in arcs:
                    arc["measurement"] = {"test_double": True}

            @contextlib.contextmanager
            def funded(n, arcs, participant_fd, **options):
                self.assertEqual(options, {"refund_cycle": True})
                events.append("funding")
                def consume():
                    self.assertEqual(events.count("finish"), 9)
                    self.assertIn("preswap", events)
                    for arc in arcs:
                        self.assertEqual(os.pread(arc["witness"], 32, 8), bytes(32))
                    events.append("refund")
                    return {"retained_cycle_refund": True, "refunded_arcs": 3, "withdrawn_arcs": 0}
                yield consume

            with patch.object(coordinator, "prepared_pair", side_effect=lambda *args:
                              contextlib.nullcontext((-1, -1, -1, -1, b"registry"))), \
                 patch.object(coordinator, "curve_credentials", side_effect=lambda **kwargs:
                              contextlib.nullcontext("unused")), \
                 patch.object(coordinator, "_prepare_vtd_jobs", side_effect=jobs), \
                 patch.object(coordinator, "_run_preswap_arcs", side_effect=preswap), \
                 patch.object(coordinator, "_funded_cycle_recovery", side_effect=funded), \
                 patch.object(coordinator, "receive_live_witness") as share:
                result = coordinator.coordinate(3, "reference-itemwise", public, private,
                                                participants, refund_cycle=True)
                share.assert_not_called()
                self.assertEqual(events[-1], "refund")
                for mode in ("reference-itemwise", "batch-joint-presigning-batch-verification"):
                    for failure in (TimeoutError("Pre-swap cutoff"),
                                    RuntimeError("invalid partial or missing completion")):
                        with self.subTest(mode=mode, failure=type(failure).__name__):
                            failure_events = []

                            @contextlib.contextmanager
                            def failed_cycle(*args, **kwargs):
                                failure_events.append("funded")
                                try:
                                    yield lambda: failure_events.append("consumed")
                                finally:
                                    failure_events.append("closed")

                            with patch.object(coordinator, "_run_preswap_arcs",
                                              side_effect=failure), \
                                 patch.object(coordinator, "_funded_cycle_recovery",
                                              side_effect=failed_cycle):
                                with self.assertRaises(type(failure)) as raised:
                                    coordinator.coordinate(3, mode, public, private,
                                                           participants, refund_cycle=True)
                            self.assertIs(raised.exception, failure)
                            self.assertEqual(failure_events, ["funded", "closed"])
                            share.assert_not_called()
                with patch.object(coordinator, "_prepare_vtd_jobs",
                                  side_effect=ValueError("VTD binding rejected")), \
                     patch.object(coordinator, "_funded_cycle_recovery") as funding:
                    with self.assertRaisesRegex(ValueError, "VTD binding rejected"):
                        coordinator.coordinate(3, "reference-itemwise", public, private,
                                               participants, refund_cycle=True)
                    funding.assert_not_called()
            self.assertIsNone(result["cycle_withdrawal"])
            self.assertIsNone(result["cycle_recovery"])
            self.assertEqual(result["cycle_refund"]["refunded_arcs"], 3)
            self.assertIsNone(result["coordinator_timing"]["preswap_to_withdrawal_receipt_ms"])
            self.assertFalse(result["full_lifecycle"])
