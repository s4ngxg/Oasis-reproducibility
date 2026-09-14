import json
import tempfile
import unittest
from pathlib import Path

from scripts.validate_cloud_result import REQUIRED_VARIANTS, validate


class LoadAccountingTests(unittest.TestCase):
    def write_result(
        self,
        logical_sessions_by_variant,
        *,
        fault_count=0,
        fault_scope="none",
        omit_batch_audit=False,
    ):
        samples = []
        for variant in sorted(REQUIRED_VARIANTS):
            sample = {
                "campaign_id": "load-test",
                "route": "eu_to_us",
                "loss_pct": 0,
                "n": 8,
                "k": 15,
                "pairs": 64,
                "fault_count": fault_count,
                "fault_scope": fault_scope,
                "trial": 0,
                "variant": variant,
                "tls": True,
                "tls_cipher": "TLS_AES_256_GCM_SHA384",
                "failures": 0,
                "logical_sessions": logical_sessions_by_variant[variant],
                "application_messages": 100 if variant == "persistent-pipelined-itemwise" else 20,
                "application_write_calls": 100,
            }
            if variant == "phase-coalesced-itemwise":
                sample["application_messages"] = 100
                sample["application_write_calls"] = 10
            if variant in {
                "batch-joint-presigning-batch-verification",
                "phase-coalesced-batch-verification",
            } and not (omit_batch_audit and variant == "batch-joint-presigning-batch-verification"):
                sample["verifier_audit"] = [
                    {"salt": "a" * 64, "transcript_digest": "b" * 64}
                ]
            samples.append(sample)

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "result.json"
        path.write_text(
            json.dumps({
                "schema": "oasis-conformance-transport-v1",
                "samples": samples,
            }),
            encoding="utf-8",
        )
        return path

    def test_multi_pair_session_counts_are_aggregated(self):
        path = self.write_result(
            {
                "persistent-pipelined-itemwise": 64 * 15,
                "batch-joint-presigning-itemwise": 64,
                "batch-joint-presigning-batch-verification": 64,
                "phase-coalesced-batch-verification": 64 * 15,
                "phase-coalesced-itemwise": 64 * 15,
            }
        )
        report = validate(path, allow_failures=False, required_variants=REQUIRED_VARIANTS)
        self.assertEqual(report["paired_trials"], 1)

    def test_multi_pair_session_count_mismatch_is_rejected(self):
        path = self.write_result(
            {
                "persistent-pipelined-itemwise": 15,
                "batch-joint-presigning-itemwise": 64,
                "batch-joint-presigning-batch-verification": 64,
                "phase-coalesced-batch-verification": 64 * 15,
                "phase-coalesced-itemwise": 64 * 15,
            }
        )
        with self.assertRaises(SystemExit):
            validate(path, allow_failures=False, required_variants=REQUIRED_VARIANTS)

    def test_opening_fault_may_precede_aggregate_verification(self):
        path = self.write_result(
            {
                "persistent-pipelined-itemwise": 64 * 15,
                "batch-joint-presigning-itemwise": 64,
                "batch-joint-presigning-batch-verification": 64,
                "phase-coalesced-batch-verification": 64 * 15,
                "phase-coalesced-itemwise": 64 * 15,
            },
            fault_count=1,
            fault_scope="responder-opening",
            omit_batch_audit=True,
        )
        report = validate(path, allow_failures=False, required_variants=REQUIRED_VARIANTS)
        self.assertEqual(report["failures"], 0)

    def test_missing_audit_without_opening_fault_is_rejected(self):
        path = self.write_result(
            {
                "persistent-pipelined-itemwise": 64 * 15,
                "batch-joint-presigning-itemwise": 64,
                "batch-joint-presigning-batch-verification": 64,
                "phase-coalesced-batch-verification": 64 * 15,
                "phase-coalesced-itemwise": 64 * 15,
            },
            omit_batch_audit=True,
        )
        with self.assertRaises(SystemExit):
            validate(path, allow_failures=False, required_variants=REQUIRED_VARIANTS)


if __name__ == "__main__":
    unittest.main()
