import sys
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from paraswap_lifecycle import (  # noqa: E402
    AssetState,
    Config,
    DeterministicBackend,
    Lifecycle,
)


class SlowDeterministicBackend(DeterministicBackend):
    def __init__(self, delay_seconds):
        self.delay_seconds = delay_seconds

    def execute_arc(self, arc_index, config):
        time.sleep(self.delay_seconds)
        return super().execute_arc(arc_index, config)


class MisreportingBackend(DeterministicBackend):
    def execute_arc(self, arc_index, config):
        result = super().execute_arc(arc_index, config)
        if arc_index == 0:
            result.item_count += 1
        return result


class RaisingBackend(DeterministicBackend):
    def execute_arc(self, arc_index, config):
        if arc_index == 0:
            raise RuntimeError("simulated backend crash")
        return super().execute_arc(arc_index, config)


class LifecycleTests(unittest.TestCase):
    def run_case(self, **overrides):
        values = {
            "participants": 3,
            "mode": "batch-joint-presigning-itemwise",
        }
        values.update(overrides)
        return Lifecycle(Config(**values), DeterministicBackend()).run()

    def test_exact_preswap_workload(self):
        report = self.run_case(participants=5)
        self.assertEqual(len(report["arcs"]), 5)
        self.assertEqual(len(report["pre_swap"]), 5)
        for result in report["pre_swap"]:
            self.assertEqual(result["item_count"], 9)
            self.assertEqual(result["withdraw_items"], 5)
            self.assertEqual(result["relock_items"], 4)

    def test_happy_path_is_atomic(self):
        report = self.run_case()
        self.assertTrue(report["outputs_exported"])
        self.assertEqual(
            {arc["asset_state"] for arc in report["arcs"]},
            {AssetState.WITHDRAWN.value},
        )

    def test_preswap_failure_blocks_export_and_refunds(self):
        report = self.run_case(fault="preswap")
        self.assertFalse(report["outputs_exported"])
        self.assertEqual(
            {arc["asset_state"] for arc in report["arcs"]},
            {AssetState.REFUNDED.value},
        )
        self.assertEqual({arc["relock_level"] for arc in report["arcs"]}, {0})

    def test_invalid_final_blocks_export_and_refunds(self):
        report = self.run_case(fault="invalid-final")
        self.assertFalse(report["outputs_exported"])
        self.assertEqual(
            {arc["asset_state"] for arc in report["arcs"]},
            {AssetState.REFUNDED.value},
        )

    def test_witness_failure_refunds_after_valid_preswap(self):
        report = self.run_case(fault="witness")
        self.assertTrue(report["outputs_exported"])
        self.assertEqual(report["witness_count"], 2)
        self.assertEqual(
            {arc["asset_state"] for arc in report["arcs"]},
            {AssetState.REFUNDED.value},
        )
        self.assertEqual({arc["relock_level"] for arc in report["arcs"]}, {2})
        self.assertEqual(
            len([event for event in report["events"]
                 if event["action"] == "assets_relocked"]),
            2,
        )

    def test_batch_frame_count_is_constant_per_arc(self):
        batch = self.run_case(
            participants=8,
            mode="batch-joint-presigning-itemwise",
        )
        itemwise = self.run_case(participants=8, mode="reference-itemwise")
        self.assertEqual(batch["pre_swap"][0]["sent_frames"], 3)
        self.assertEqual(itemwise["pre_swap"][0]["sent_frames"], 45)
        self.assertEqual(itemwise["pre_swap"][0]["received_frames"], 31)

    def test_execution_context_changes_with_seed(self):
        first = self.run_case(seed="swap-a")
        second = self.run_case(seed="swap-b")
        self.assertNotEqual(
            first["pre_swap"][0]["execution_id"],
            second["pre_swap"][0]["execution_id"],
        )
        self.assertNotEqual(
            first["preparation_digest"], second["preparation_digest"]
        )

    def test_preparation_digest_binds_host_timing(self):
        first = self.run_case(delta_seconds=15, epsilon_seconds=5)
        second = self.run_case(delta_seconds=16, epsilon_seconds=5)
        self.assertNotEqual(
            first["preparation_digest"], second["preparation_digest"]
        )

    def test_vtd_and_refund_use_paraswap_phase_window(self):
        report = self.run_case(
            participants=3, delta_seconds=10, epsilon_seconds=2,
            fault="witness",
        )
        # t = Delta + 3 epsilon = 16; VTDs open at t+x Delta.
        self.assertEqual(
            [record["opens_at"] for record in report["arcs"][0]["vtd_records"]],
            [26, 36, 46],
        )
        relocks = [
            event for event in report["events"]
            if event["action"] == "assets_relocked"
        ]
        self.assertEqual(
            [event["host_time_seconds"] for event in relocks], [26, 36]
        )
        refund = next(
            event for event in report["events"]
            if event["action"] == "assets_refunded"
        )
        self.assertEqual(refund["after_seconds"], 46)

    def test_local_deadline_blocks_late_honest_export(self):
        config = Config(
            participants=3,
            mode="batch-joint-presigning-itemwise",
            pre_swap_budget_seconds=0.005,
        )
        report = Lifecycle(
            config, SlowDeterministicBackend(0.02)
        ).run()
        self.assertFalse(report["outputs_exported"])
        export = next(
            event for event in report["events"]
            if event["action"] == "presignature_export_blocked"
        )
        self.assertFalse(export["deadline_live"])
        self.assertEqual(
            {arc["asset_state"] for arc in report["arcs"]},
            {AssetState.REFUNDED.value},
        )

    def test_malformed_backend_result_cannot_authorize_export(self):
        report = Lifecycle(
            Config(
                participants=3,
                mode="batch-joint-presigning-itemwise",
            ),
            MisreportingBackend(),
        ).run()
        self.assertFalse(report["outputs_exported"])
        export = next(
            event for event in report["events"]
            if event["action"] == "presignature_export_blocked"
        )
        self.assertEqual(export["structurally_valid_arcs"], 2)

    def test_backend_exception_becomes_abort_and_refund(self):
        report = Lifecycle(
            Config(
                participants=3,
                mode="batch-joint-presigning-itemwise",
            ),
            RaisingBackend(),
        ).run()
        self.assertFalse(report["outputs_exported"])
        self.assertIn("backend exception", report["pre_swap"][0]["error"])
        self.assertEqual(
            {arc["asset_state"] for arc in report["arcs"]},
            {AssetState.REFUNDED.value},
        )

    def test_native_batch_limit_is_enforced(self):
        with self.assertRaises(ValueError):
            Lifecycle(
                Config(
                    participants=2049,
                    mode="batch-joint-presigning-itemwise",
                ),
                DeterministicBackend(),
            )

    def test_batch_joint_presigning_runs_full_workload(self):
        report = self.run_case(
            participants=5,
            backend="oasis",
            configuration="batch-joint-presigning-batch-verification",
        )
        self.assertTrue(report["outputs_exported"])
        self.assertEqual(
            {arc["asset_state"] for arc in report["arcs"]},
            {AssetState.WITHDRAWN.value},
        )
        for result in report["pre_swap"]:
            self.assertEqual(result["item_count"], 9)
            self.assertEqual(result["logical_messages"], 7)
            self.assertEqual(result["logical_sessions"], 1)
            self.assertEqual(result["itemwise_audit_checks"], 9)
            self.assertTrue(result["aggregate_verification_requested"])
            self.assertTrue(result["aggregate_verification_active"])
            self.assertTrue(result["aggregate_reverification_performed"])
            self.assertEqual(result["aggregate_reverification_checks"], 3)
            self.assertEqual(result["audit_pippenger_calls"], 3)
            self.assertEqual(result["audit_pippenger_terms"], 54)
            self.assertEqual(
                result["aggregate_soundness_bound"], "min(1,Q*2^-254)"
            )
            self.assertEqual(result["adaptation_checks"], 9)
            self.assertTrue(result["paraswap_statement_mapping_valid"])
            self.assertEqual(
                result["preparation_digest"], report["preparation_digest"]
            )

    def test_secondary_conformance_small_batch_uses_itemwise_fallback(self):
        report = self.run_case(
            participants=3,
            backend="oasis",
            configuration="batch-joint-presigning-batch-verification",
        )
        result = report["pre_swap"][0]
        self.assertEqual(result["item_count"], 5)
        self.assertEqual(result["logical_messages"], 7)
        self.assertFalse(result["aggregate_verification_active"])
        self.assertEqual(result["audit_pippenger_calls"], 0)

    def test_oasis_opening_fault_is_localized_and_retried(self):
        report = self.run_case(
            participants=5,
            backend="oasis",
            configuration="batch-joint-presigning-batch-verification",
            fault="opening-retry",
        )
        self.assertTrue(report["outputs_exported"])
        self.assertEqual(report["pre_swap"][0]["opening_failures"], 1)
        self.assertEqual(report["pre_swap"][0]["retries"], 1)
        self.assertEqual(report["pre_swap"][0]["logical_sessions"], 2)
        self.assertFalse(
            report["pre_swap"][0]["aggregate_reverification_performed"]
        )
        self.assertTrue(all(row["accepted"] for row in report["pre_swap"]))

    def test_oasis_partial_fault_is_localized_and_retried(self):
        report = self.run_case(
            participants=5,
            backend="oasis",
            configuration="batch-joint-presigning-batch-verification",
            fault="partial-retry",
        )
        self.assertTrue(report["outputs_exported"])
        self.assertEqual(report["pre_swap"][0]["partial_failures"], 1)
        self.assertEqual(report["pre_swap"][0]["retries"], 1)
        self.assertTrue(all(row["accepted"] for row in report["pre_swap"]))

    def test_oasis_client_partial_fault_uses_responder_retry_path(self):
        report = self.run_case(
            participants=5,
            backend="oasis",
            configuration="batch-joint-presigning-batch-verification",
            fault="client-partial-retry",
        )
        self.assertTrue(report["outputs_exported"])
        self.assertEqual(report["pre_swap"][0]["client_partial_failures"], 1)
        self.assertEqual(report["pre_swap"][0]["retries"], 1)

    def test_oasis_peer_abort_blocks_export(self):
        report = self.run_case(
            participants=5,
            backend="oasis",
            configuration="batch-joint-presigning-batch-verification",
            fault="peer-abort",
        )
        self.assertFalse(report["outputs_exported"])
        self.assertEqual(
            {arc["asset_state"] for arc in report["arcs"]},
            {AssetState.REFUNDED.value},
        )

    def test_oasis_ablation_has_expected_session_accounting(self):
        expected = {
            "persistent-pipelined-itemwise": (46, 9, False),
            "phase-coalesced-itemwise": (46, 9, False),
            "batch-joint-presigning-itemwise": (6, 1, False),
            "phase-coalesced-batch-verification": (46, 9, True),
            "batch-joint-presigning-batch-verification": (7, 1, True),
        }
        for configuration, values in expected.items():
            with self.subTest(configuration=configuration):
                report = self.run_case(
                    participants=5,
                    backend="oasis",
                    configuration=configuration,
                )
                result = report["pre_swap"][0]
                self.assertEqual(
                    (
                        result["logical_messages"],
                        result["logical_sessions"],
                        result["aggregate_verification_active"],
                    ),
                    values,
                )

    def test_backend_specific_faults_cannot_be_mislabelled(self):
        with self.assertRaises(ValueError):
            Lifecycle(
                Config(
                    participants=5,
                    mode="batch-joint-presigning-itemwise",
                    backend="oasis",
                    configuration="batch-joint-presigning-batch-verification",
                    fault="preswap",
                ),
                DeterministicBackend(),
            )


if __name__ == "__main__":
    unittest.main()
