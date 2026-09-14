import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "analyze_native_loss_results.py"
SPEC = importlib.util.spec_from_file_location(
    "analyze_native_loss_results", MODULE_PATH
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def manifest(role):
    return {
        "backend": "native-c11-relic",
        "role": role,
        "service_port": 9000,
        "protocol_source_sha256": "source",
        "campaign_runner_sha256": "runner",
        "loss_role_runner_sha256": "loss-runner",
        "netem_runner_sha256": "netem-runner",
        "manifest_writer_sha256": "manifest-writer",
    }


def result(role):
    return {
        "schema": "oasis-preswap-cloud-v8",
        "role": role,
        "authenticated_transport": True,
        "experiment_identity": {"schedule_sha256": "schedule"},
        "randomization": {"schedule_sha256": "schedule"},
        "samples": [{
            "participants": 8,
            "items_per_arc": 15,
            "concurrent_pairs": 1,
            "mode": "batch-joint-presigning-batch-verification",
            "trial": 0,
            "paired_trial_id": "trial-0",
        }],
    }


class NativeLossAnalysisTests(unittest.TestCase):
    def test_matching_endpoints_are_accepted(self):
        client_rows, server_rows = MODULE.validate_endpoint_pair(
            "campaign", manifest("client"), result("client"),
            manifest("server"), result("server")
        )
        self.assertEqual(client_rows.keys(), server_rows.keys())

    def test_source_or_port_mismatch_is_rejected(self):
        server_manifest = manifest("server")
        server_manifest["protocol_source_sha256"] = "different"
        with self.assertRaisesRegex(ValueError, "provenance mismatch"):
            MODULE.validate_endpoint_pair(
                "campaign", manifest("client"), result("client"),
                server_manifest, result("server")
            )

    def test_duplicate_or_missing_samples_are_rejected(self):
        server_result = result("server")
        server_result["samples"] = []
        with self.assertRaisesRegex(ValueError, "sample mismatch"):
            MODULE.validate_endpoint_pair(
                "campaign", manifest("client"), result("client"),
                manifest("server"), server_result
            )

    def test_unauthenticated_result_is_rejected(self):
        server_result = result("server")
        server_result["authenticated_transport"] = False
        with self.assertRaisesRegex(ValueError, "invalid native result"):
            MODULE.validate_endpoint_pair(
                "campaign", manifest("client"), result("client"),
                manifest("server"), server_result
            )


if __name__ == "__main__":
    unittest.main()
