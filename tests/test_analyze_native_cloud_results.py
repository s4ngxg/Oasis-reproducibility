import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import analyze_cloud_results  # noqa: E402


def audit_row(mode, calls, participants=3, pairs=None, role="client"):
    pairs = participants if pairs is None else pairs
    items = 2 * participants - 1
    if mode == "reference-itemwise":
        client_sent = 3 * pairs * items
        client_received = pairs * (2 * items + 1)
        sent_frames, received_frames = (
            (client_sent, client_received)
            if role == "client" else (client_received, client_sent)
        )
    elif mode.endswith("-batch-verification"):
        sent_frames, received_frames = (
            (3 * pairs, 4 * pairs)
            if role == "client" else (4 * pairs, 3 * pairs)
        )
    else:
        sent_frames = received_frames = 3 * pairs
    arcs = []
    for index in range(pairs):
        arc = {
            "pair_id": index,
            "execution_id": 100 + index,
            "host_context_seed": "c" * 64,
        }
        if role == "server":
            arc["worker_index"] = index % min(2, pairs)
        if mode.endswith("-batch-verification"):
            arc["verifier_batch_digest"] = "d" * 64
            if role == "client":
                arc["server_partial_verifier_salt"] = "1" * 64
            else:
                arc["client_partial_verifier_salt"] = "2" * 64
                arc["full_presignature_verifier_salt"] = "3" * 64
        arcs.append(arc)
    row = {
        "participants": participants,
        "concurrent_pairs": pairs,
        "items_per_arc": items,
        "mode": mode,
        "trial": 0,
        "randomization_block_id": "4" * 64,
        "paired_trial_id": "5" * 64,
        "mode_position": [
            "reference-itemwise",
            "phase-coalesced-itemwise",
            "batch-joint-presigning-itemwise",
            "phase-coalesced-batch-verification",
            "batch-joint-presigning-batch-verification",
        ].index(mode),
        "schedule_position": [
            "reference-itemwise",
            "phase-coalesced-itemwise",
            "batch-joint-presigning-itemwise",
            "phase-coalesced-batch-verification",
            "batch-joint-presigning-batch-verification",
        ].index(mode),
        "service_port": 30000,
        "verifier_msm_calls": calls,
        "verifier_fallbacks": 0,
        "sent_frames": sent_frames,
        "received_frames": received_frames,
        "sent_bytes": 1000,
        "received_bytes": 1000,
        "send_calls": sent_frames,
        "receive_calls": received_frames,
        "sum_user_cpu_ns": 50,
        "sum_system_cpu_ns": 10,
        "sum_process_peak_rss_kb": 1024,
        "voluntary_context_switches": 1,
        "involuntary_context_switches": 1,
        "scheduler_wait_ns": 1,
        "scheduler_slices": 1,
        "critical_arc_wall_ns": 100,
        "stage_wall_ns": 200,
        "arcs": arcs,
    }
    if role == "server":
        workers = min(2, pairs)
        row["process_profile"] = {"gateway": {
            "expected_sessions": pairs,
            "completed_sessions": pairs,
            "registered_workers": workers,
            "worker_count": workers,
            "queue_capacity": pairs,
            "peak_queue_depth": max(0, pairs - workers),
            "peak_busy_workers": workers,
            "assignments": pairs,
            "rejected_sessions": 0,
            "frontend_received_frames": received_frames,
            "frontend_sent_frames": sent_frames,
            "backend_received_frames": sent_frames,
            "backend_sent_frames": received_frames,
            "bytes_from_clients": row["received_bytes"],
            "bytes_to_clients": row["sent_bytes"],
        }, "worker_pool": {
            "configured_workers": workers,
            "completed_sessions": pairs,
            "workers": [
                {
                    "worker_index": index,
                    "completed_sessions": (
                        pairs // workers + (1 if index < pairs % workers else 0)
                    ),
                    "setup_ns": 10,
                    "user_cpu_ns": 20,
                    "system_cpu_ns": 5,
                    "max_rss_kb": 512,
                }
                for index in range(workers)
            ],
            "sum_setup_ns": 10 * workers,
            "sum_user_cpu_ns": 20 * workers,
            "sum_system_cpu_ns": 5 * workers,
        }}
    return row


class NativeAuditTests(unittest.TestCase):
    @staticmethod
    def role_payload(role="client"):
        return {
            "schema": "oasis-preswap-cloud-v8",
            "role": role,
            "campaign_id": "loopback-campaign",
            "route": "loopback",
            "transport": "ZeroMQ CURVE over TCP",
            "authenticated_transport": True,
            "runtime": {
                "profiling_mode": "timing",
                "service_port": 30000,
                "public_listener_count": 1,
                "session_routing_key": (
                    "authenticated connection + pair_id + execution_id"
                ),
                "connection_lifecycle": (
                    "one connection per participant-pair execution; shared "
                    "across all item phases and never shared across "
                    "participant pairs"
                ),
            },
            "transport_security": {
                "mechanism": "ZeroMQ CURVE",
                "authorization": "ZAP public-key allowlist",
                "zap_domain": "PARASWAP-OASIS-PRESWAP-v1",
                "tls_records": "not-applicable",
                "tls_session_reuse": (
                    "not-applicable-native-transport-is-not-tls"
                ),
                "curve_connection_lifecycle": (
                    "one mutually authenticated CURVE/TCP connection per "
                    "participant-pair execution, reused for every logical "
                    "frame of that execution"
                ),
                "initiator_public_key_sha256": "a" * 64,
                "responder_public_key_sha256": "b" * 64,
            },
            "experiment_identity": {
                "domain": "OASIS-CLOUD-EXPERIMENT-ID-v1",
                "campaign_id": "loopback-campaign",
                "route": "loopback",
                "schedule_sha256": "c" * 64,
            },
            "randomization": {
                "domain": "OASIS-CLOUD-MODE-ORDER-v2",
                "algorithm": "test",
                "route_is_campaign_constant": True,
                "block_factors": [
                    "campaign_id", "route", "warmup_status", "participants",
                    "items_per_arc", "concurrent_pairs",
                ],
                "schedule_sha256": "c" * 64,
            },
        }

    def test_authenticated_timing_role_is_accepted(self):
        analyze_cloud_results.validate_role(self.role_payload(), "client")

    def test_unauthenticated_role_is_rejected(self):
        payload = self.role_payload()
        payload["authenticated_transport"] = False
        with self.assertRaisesRegex(ValueError, "unauthenticated"):
            analyze_cloud_results.validate_role(payload, "client")

    def test_profiled_campaign_cannot_enter_timing_analysis(self):
        payload = self.role_payload()
        payload["runtime"]["profiling_mode"] = "syscall"
        with self.assertRaisesRegex(ValueError, "expected timing"):
            analyze_cloud_results.validate_role(payload, "client")

    def test_multiple_public_listeners_are_rejected(self):
        payload = self.role_payload()
        payload["runtime"]["public_listener_count"] = 2
        with self.assertRaisesRegex(ValueError, "one public listener"):
            analyze_cloud_results.validate_role(payload, "client")

    def test_missing_randomization_metadata_is_rejected(self):
        payload = self.role_payload()
        del payload["randomization"]
        with self.assertRaisesRegex(ValueError, "randomization metadata"):
            analyze_cloud_results.validate_role(payload, "client")

    def test_jain_fairness(self):
        self.assertEqual(analyze_cloud_results.jain_fairness([1, 1, 1]), 1.0)
        self.assertAlmostEqual(
            analyze_cloud_results.jain_fairness([1, 2]), 0.9
        )

    def test_bootstrap_seeds_are_reproducible_and_workload_specific(self):
        first = analyze_cloud_results.bootstrap_seed(
            "campaign", "eu_to_us", 8, 1, "comparison", "median"
        )
        self.assertEqual(
            first,
            analyze_cloud_results.bootstrap_seed(
                "campaign", "eu_to_us", 8, 1, "comparison", "median"
            ),
        )
        self.assertNotEqual(
            first,
            analyze_cloud_results.bootstrap_seed(
                "campaign", "eu_to_us", 16, 1, "comparison", "median"
            ),
        )

    def test_rank_biserial_uses_paired_signed_ranks(self):
        self.assertEqual(analyze_cloud_results.rank_biserial([1, 2, 3]), 1.0)
        self.assertEqual(analyze_cloud_results.rank_biserial([-1, -2, -3]), -1.0)
        self.assertEqual(analyze_cloud_results.rank_biserial([0, 0]), 0.0)

    def test_holm_uses_scientific_families(self):
        rows = [
            {"participants": 8, "concurrent_pairs": 1,
             "comparison": "complete_method_vs_reference",
             "wilcoxon_signed_rank_p": 0.01},
            {"participants": 8, "concurrent_pairs": 64,
             "comparison": "complete_method_vs_reference",
             "wilcoxon_signed_rank_p": 0.02},
            {"participants": 8, "concurrent_pairs": 1,
             "comparison": "batch_verification_with_batch_joint_presigning",
             "wilcoxon_signed_rank_p": 0.03},
        ]
        analyze_cloud_results.apply_holm_families(rows)
        self.assertEqual(rows[0]["holm_family"],
                         "primary:H3-secondary-system-contrast")
        self.assertEqual(rows[1]["holm_family"],
                         "high-load:H3-secondary-system-contrast")
        self.assertEqual(rows[2]["holm_family"],
                         "primary:H1-aggregate-within-shared")
        self.assertEqual(rows[0]["holm_family_size"], 1)
        self.assertEqual(rows[1]["holm_family_size"], 1)

    def test_factorial_comparisons_isolate_both_session_effects(self):
        comparisons = analyze_cloud_results.COMPARISONS
        self.assertEqual(
            comparisons["batch_joint_presigning_vs_phase_coalesced_itemwise"],
            ("phase-coalesced-itemwise", "batch-joint-presigning-itemwise"),
        )
        self.assertEqual(
            comparisons["batch_joint_presigning_vs_phase_coalesced_aggregate"],
            (
                "phase-coalesced-batch-verification",
                "batch-joint-presigning-batch-verification",
            ),
        )

    def test_build_environment_mismatch_is_rejected(self):
        client = {"environment": {"compiler": "cc-a"}}
        server = {"environment": {"compiler": "cc-b"}}
        with self.assertRaisesRegex(ValueError, "compiler"):
            analyze_cloud_results.validate_environment_pair(client, server)

    def test_batch_verification_requires_multiscalar_calls(self):
        analyze_cloud_results.validate_audit(
            audit_row(
                "batch-joint-presigning-batch-verification",
                calls=3,
                role="client",
            ),
            audit_row(
                "batch-joint-presigning-batch-verification",
                calls=6,
                role="server",
            ),
        )

    def test_itemwise_verification_requires_zero_multiscalar_calls(self):
        analyze_cloud_results.validate_audit(
            audit_row("batch-joint-presigning-itemwise", calls=0),
            audit_row(
                "batch-joint-presigning-itemwise", calls=0, role="server"
            ),
        )

    def test_pipelined_reference_uses_five_k_plus_one_frames(self):
        analyze_cloud_results.validate_audit(
            audit_row("reference-itemwise", calls=0, role="client"),
            audit_row("reference-itemwise", calls=0, role="server"),
        )

    def test_gateway_frame_mismatch_is_rejected(self):
        client = audit_row("batch-joint-presigning-itemwise", calls=0)
        server = audit_row(
            "batch-joint-presigning-itemwise", calls=0, role="server"
        )
        server["process_profile"]["gateway"]["frontend_received_frames"] += 1
        with self.assertRaisesRegex(
            ValueError, "gateway frontend_received_frames"
        ):
            analyze_cloud_results.validate_audit(client, server)

    def test_gateway_queue_bound_is_enforced(self):
        client = audit_row("batch-joint-presigning-itemwise", calls=0)
        server = audit_row(
            "batch-joint-presigning-itemwise", calls=0, role="server"
        )
        server["process_profile"]["gateway"]["queue_capacity"] = 1
        server["process_profile"]["gateway"]["peak_queue_depth"] = 2
        with self.assertRaisesRegex(ValueError, "invalid worker pool"):
            analyze_cloud_results.validate_audit(client, server)

    def test_worker_pool_total_mismatch_is_rejected(self):
        client = audit_row("batch-joint-presigning-itemwise", calls=0)
        server = audit_row(
            "batch-joint-presigning-itemwise", calls=0, role="server"
        )
        server["process_profile"]["worker_pool"]["workers"][0][
            "completed_sessions"
        ] += 1
        with self.assertRaisesRegex(ValueError, "worker telemetry totals"):
            analyze_cloud_results.validate_audit(client, server)

    def test_endpoint_context_seed_mismatch_is_rejected(self):
        client = audit_row("batch-joint-presigning-itemwise", calls=0)
        server = audit_row(
            "batch-joint-presigning-itemwise", calls=0, role="server"
        )
        server["arcs"][0]["host_context_seed"] = "d" * 64
        with self.assertRaisesRegex(ValueError, "host-context mismatch"):
            analyze_cloud_results.validate_audit(client, server)

    def test_paired_modes_require_shared_seed_and_distinct_execution_ids(self):
        modes = ["phase-coalesced-itemwise", "batch-joint-presigning-itemwise"]
        rows = [audit_row(mode, calls=0, pairs=1) for mode in modes]
        campaign = "campaign-a"
        route = "loopback"
        order = analyze_cloud_results.expected_mode_order(
            campaign, 3, 1, modes, 0
        )
        for row in rows:
            row["randomization_block_id"] = (
                analyze_cloud_results.expected_randomization_block_id(
                    campaign, route, 3, 1
                )
            )
            row["paired_trial_id"] = (
                analyze_cloud_results.expected_paired_trial_id(
                    campaign, route, 3, 1, 0
                )
            )
            row["mode_position"] = order.index(row["mode"])
        rows[1]["arcs"][0]["execution_id"] = 200
        analyze_cloud_results.validate_paired_contexts(
            rows, modes, campaign, route
        )
        rows[1]["arcs"][0]["execution_id"] = 100
        with self.assertRaisesRegex(ValueError, "distinct execution IDs"):
            analyze_cloud_results.validate_paired_contexts(
                rows, modes, campaign, route
            )
        rows[1]["arcs"][0]["execution_id"] = 200
        rows[1]["arcs"][0]["host_context_seed"] = "d" * 64
        with self.assertRaisesRegex(ValueError, "one host-context seed"):
            analyze_cloud_results.validate_paired_contexts(
                rows, modes, campaign, route
            )

    def test_missing_paired_sample_is_rejected(self):
        payload = {
            "participants": [3],
            "concurrent_pair_values": None,
            "modes": ["batch-joint-presigning-itemwise"],
            "trials": 2,
            "samples": [audit_row("batch-joint-presigning-itemwise", 0)],
        }
        with self.assertRaisesRegex(ValueError, "sample schedule mismatch"):
            analyze_cloud_results.indexed_samples(payload, "client")

    def test_duplicate_sample_key_is_rejected(self):
        row = audit_row("batch-joint-presigning-itemwise", 0)
        payload = {
            "participants": [3],
            "concurrent_pair_values": None,
            "modes": ["batch-joint-presigning-itemwise"],
            "trials": 1,
            "samples": [row, dict(row)],
        }
        with self.assertRaisesRegex(ValueError, "duplicate client sample"):
            analyze_cloud_results.indexed_samples(payload, "client")


if __name__ == "__main__":
    unittest.main()
