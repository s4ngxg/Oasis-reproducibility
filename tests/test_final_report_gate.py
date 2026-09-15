import copy
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_final_experiment_report as report_builder  # noqa: E402


def timing_record(route, profile):
    summary = []
    workloads = (
        report_builder.PRIMARY_WORKLOADS
        if profile == "primary"
        else report_builder.LOAD_WORKLOADS
    )
    expected_trials = 100 if profile == "primary" else 20
    for n, pairs in workloads:
        for mode in report_builder.MODES:
            summary.append({
                "participants": n,
                "concurrent_pairs": pairs,
                "mode": mode,
                "trials": expected_trials,
                "median_client_host_cpu_steal_pct": 0.0,
                "median_server_host_cpu_steal_pct": 0.0,
                "total_client_cgroup_throttled_periods": 0,
                "total_server_cgroup_throttled_periods": 0,
                "median_server_gateway_peak_queue_depth": 0.0,
                "median_server_gateway_peak_queue_utilization_pct": 0.0,
                "total_server_gateway_queued_sessions": 0,
                "total_server_gateway_rejected_sessions": 0,
                "median_server_gateway_queue_wait_ms_per_queued_session": 0.0,
                "max_server_gateway_queue_wait_ms": 0.0,
            })
    effects = []
    for n, pairs in workloads:
        for index, comparison in enumerate(report_builder.REQUIRED_COMPARISONS):
            effects.append({
                "participants": n,
                "concurrent_pairs": pairs,
                "comparison": comparison,
                "paired_trials": expected_trials,
                "trial_ids": list(range(expected_trials)),
                "raw_paired_differences_ms": [1.0] * expected_trials,
                "median_difference_ci95_ms": [0.9, 1.1],
                "median_reduction_ci95_pct": [4.0, 6.0],
                "rank_biserial_ci95": [0.8, 1.0],
                "holm_adjusted_p": 0.01,
                "bootstrap_seeds": {
                    "median_reduction": 1000 + 3 * index,
                    "median_difference": 1001 + 3 * index,
                    "rank_biserial": 1002 + 3 * index,
                },
            })
    environment = {
        "cpu_count": 2,
        "cpu": {"model_name": "Synthetic fixed-performance CPU"},
        "memory": {"mem_total_kb": 8 * 1024 * 1024},
        "compiler": "cc 13.2.0",
        "kernel": "6.8.0-test",
        "zeromq": "4.3.5",
        "libsodium": "1.0.18",
        "cmake_build_type": "Release",
        "cmake_release_c_flags": "-O3 -DNDEBUG",
        "thread_model": "one native process per directed pair",
        "aws_imds": {
            "instance_type": "c7i.large",
            "availability_zone": "test-1a",
            "burstable_instance": False,
            "flex_scheduled_instance": False,
            "fixed_performance_instance": True,
        }
    }
    client_region = (
        "eu-central-1" if route == "eu_to_us" else "ap-southeast-1"
    )
    client_environment = copy.deepcopy(environment)
    server_environment = copy.deepcopy(environment)
    for role, region, target in (
        ("client", client_region, client_environment),
        ("server", "us-east-1", server_environment),
    ):
        target["aws_imds"]["region"] = region
        target["aws_imds"]["availability_zone"] = f"{region}a"
        target["placement_validation"] = {
            "provider": "AWS",
            "route": route,
            "role": role,
            "expected_region": region,
            "observed_region": region,
            "matched": True,
        }
    campaign_id = f"oasis-{route}-{profile}-v4"
    schedule_sha256 = ("1" if profile == "primary" else "2") * 64
    return {
        "label": f"{route}_{profile}",
        "payload": {
            "campaign_id": campaign_id,
            "route": route,
            "experiment_identity": {
                "campaign_id": campaign_id,
                "route": route,
                "schedule_sha256": schedule_sha256,
            },
            "randomization": {
                "route_is_campaign_constant": True,
                "block_factors": [
                    "campaign_id", "route", "warmup_status", "participants",
                    "items_per_arc", "concurrent_pairs",
                ],
                "schedule_sha256": schedule_sha256,
            },
            "transport_security": {
                "tls_session_reuse": (
                    "not-applicable-native-transport-is-not-tls"
                ),
            },
            "analysis_plan": {
                "bootstrap_rounds": 10000,
                "bootstrap_seed_domain": "OASIS-STATISTICS-v1",
                "bootstrap_seed_derivation": "sha256",
                "bootstrap_interval": "paired percentile",
                "paired_test": "wilcoxon",
                "holm_families": "prespecified",
                "effect_size": "rank-biserial with CI",
                "sample_size_policy": {"profile": profile},
            },
            "summary": summary,
            "paired_effects": effects,
            "client_environment": client_environment,
            "server_environment": server_environment,
            "integrity": {
                "protocol_source_sha256": "source-hash",
                "client_binary_sha256": "client-hash",
                "server_binary_sha256": "server-hash",
                "initiator_public_key_sha256": f"{route}-initiator-key-hash",
                "responder_public_key_sha256": f"{route}-responder-key-hash",
            },
        },
    }


def system_record(mode):
    return {
        "label": mode,
        "payload": {
            "profiling_mode": mode,
            "summary": [
                {"configuration": value} for value in report_builder.MODES
            ],
        },
    }


def cost_record(campaign_ids):
    campaign_ids = sorted(campaign_ids)
    line_items = []
    for campaign_id in campaign_ids:
        client_region = (
            "eu-central-1" if "eu_to_us" in campaign_id
            else "ap-southeast-1"
        )
        for region in (client_region, "us-east-1"):
            line_items.append({
                "campaign_id": campaign_id,
                "category": "compute",
                "region": region,
                "quantity": 0.5,
                "unit": "instance-hour",
                "unit_price_usd": 0.25,
                "subtotal_usd": 0.125,
            })
        line_items.extend([
            {
                "campaign_id": campaign_id,
                "category": "storage",
                "region": "all",
                "quantity": 0.1,
                "unit": "GB-month",
                "unit_price_usd": 0.1,
                "subtotal_usd": 0.01,
            },
            {
                "campaign_id": campaign_id,
                "category": "data_transfer",
                "region": "all",
                "quantity": 0.05,
                "unit": "GB",
                "unit_price_usd": 0.2,
                "subtotal_usd": 0.01,
            },
        ])
    return {
        "label": "cloud_cost",
        "payload": {
            "pricing_source_url": "https://example.test/aws-pricing",
            "pricing_retrieved_at_utc": "2026-09-03T00:00:00Z",
            "covered_campaign_ids": campaign_ids,
            "campaigns": [
                {
                    "campaign_id": campaign_id,
                    "route": (
                        "eu_to_us" if "eu_to_us" in campaign_id
                        else "sg_to_us"
                    ),
                    "measured_runs": (
                        2000 if "primary" in campaign_id else 800
                    ),
                    "warmup_runs": 200,
                    "failed_runs": 0,
                    "compute_usd": 0.25,
                    "storage_usd": 0.01,
                    "data_transfer_usd": 0.01,
                    "total_usd": 0.27,
                }
                for campaign_id in campaign_ids
            ],
            "line_items": line_items,
            "totals": {
                "compute_usd": 1.0,
                "storage_usd": 0.04,
                "data_transfer_usd": 0.04,
                "grand_total_usd": 1.08,
                "measured_runs": 5600,
                "warmup_runs": 800,
                "failed_runs": 0,
            },
        },
    }


class FinalReportGateTests(unittest.TestCase):
    def test_report_holm_families_follow_scientific_hypotheses(self):
        rows = []
        for route in ("eu_to_us", "sg_to_us"):
            for participants in (8, 16):
                for pairs in (64, 128, 1024):
                    rows.append({
                        "route": route,
                        "campaign_profile": "load",
                        "participants": participants,
                        "concurrent_pairs": pairs,
                        "comparison": (
                            "batch_verification_with_batch_joint_presigning"
                        ),
                        "wilcoxon_signed_rank_p": 0.01,
                    })
                    rows.append({
                        "route": route,
                        "campaign_profile": "load",
                        "participants": participants,
                        "concurrent_pairs": pairs,
                        "comparison": "phase_coalescing_vs_reference",
                        "wilcoxon_signed_rank_p": 0.02,
                    })

        report_builder.apply_scientific_holm_families(rows)

        h1_rows = [
            row for row in rows
            if row["comparison"] ==
            "batch_verification_with_batch_joint_presigning"
        ]
        exploratory_rows = [
            row for row in rows
            if row["comparison"] == "phase_coalescing_vs_reference"
        ]
        self.assertEqual({row["holm_family_size"] for row in h1_rows}, {12})
        self.assertEqual(
            {row["holm_family"] for row in h1_rows},
            {"high-load:H1-aggregate-within-shared"},
        )
        self.assertEqual(
            {row["holm_family_size"] for row in exploratory_rows}, {12}
        )
        self.assertEqual(
            {row["holm_family"] for row in exploratory_rows},
            {"high-load:exploratory"},
        )

    def complete_inputs(self):
        timing = [
            timing_record(route, profile)
            for route in report_builder.FINAL_ROUTES
            for profile in ("primary", "load")
        ]
        systems = [system_record("allocation"), system_record("syscall")]
        pcaps = [
            {
                "label": role,
                "payload": {
                    "role": role,
                    "campaign_id": f"oasis-{route}-pcap-v4",
                    "route": route,
                    "service_port": 35000,
                    "transport": "ZeroMQ CURVE over TCP",
                    "tls_session_reuse": (
                        "not-applicable-native-transport-is-not-tls"
                    ),
                    "metrics": {
                        "tcp_connections": 1,
                        "tcp_segments": 10,
                        "tcp_ack_rtt_sample_count": 10,
                        "tcp_ack_rtt_min_ms": 10.0,
                        "tcp_ack_rtt_p50_ms": 20.0,
                        "tcp_ack_rtt_p95_ms": 30.0,
                        "tcp_ack_rtt_p99_ms": 35.0,
                        "tcp_ack_rtt_max_ms": 40.0,
                    },
                },
            }
            for route in report_builder.FINAL_ROUTES
            for role in ("client", "server")
        ]
        costs = [cost_record(
            record["payload"]["campaign_id"] for record in timing
        )]
        return timing, systems, pcaps, costs

    def test_complete_matrix_is_accepted(self):
        report_builder.validate_final_evidence_matrix(*self.complete_inputs())

    def test_missing_cmake_build_type_is_rejected(self):
        timing, systems, pcaps, costs = self.complete_inputs()
        timing[0]["payload"]["client_environment"]["cmake_build_type"] = ""
        with self.assertRaisesRegex(ValueError, "CMake build type"):
            report_builder.validate_final_evidence_matrix(
                timing, systems, pcaps, costs
            )

    def test_unavailable_or_invalid_throttling_is_rejected(self):
        for value in (None, -1, True, "0", 0.5):
            with self.subTest(value=value):
                timing, systems, pcaps, costs = self.complete_inputs()
                timing[0]["payload"]["summary"][0]["total_client_cgroup_throttled_periods"] = value
                with self.assertRaisesRegex(ValueError, "throttling evidence"):
                    report_builder.validate_final_evidence_matrix(timing, systems, pcaps, costs)

    def test_invalid_systems_measurements_rejected(self):
        fields = (
            "median_client_host_cpu_steal_pct",
            "median_server_gateway_peak_queue_depth",
            "max_server_gateway_queue_wait_ms",
            "total_server_gateway_queued_sessions",
        )
        for field in fields:
            for value in (None, True, "0", -1, float("nan"), float("inf")):
                with self.subTest(field=field, value=value):
                    timing, systems, pcaps, costs = self.complete_inputs()
                    timing[0]["payload"]["summary"][0][field] = value
                    with self.assertRaisesRegex(ValueError, "invalid systems evidence"):
                        report_builder.validate_final_evidence_matrix(timing, systems, pcaps, costs)
        for field, value in (
                ("median_client_host_cpu_steal_pct", 101),
                ("median_server_gateway_peak_queue_utilization_pct", 101),
                ("total_server_gateway_queued_sessions", 0.5)):
            with self.subTest(field=field, value=value):
                timing, systems, pcaps, costs = self.complete_inputs()
                timing[0]["payload"]["summary"][0][field] = value
                with self.assertRaisesRegex(ValueError, "invalid systems evidence"):
                    report_builder.validate_final_evidence_matrix(timing, systems, pcaps, costs)

    def test_matching_alternate_pcap_service_port_is_accepted(self):
        timing, systems, pcaps, costs = self.complete_inputs()
        for record in pcaps:
            record["payload"]["service_port"] = 9000
        report_builder.validate_final_evidence_matrix(timing, systems, pcaps, costs)

    def test_invalid_pcap_service_port_is_rejected(self):
        timing, systems, pcaps, costs = self.complete_inputs()
        for record in pcaps:
            record["payload"]["service_port"] = 0
        with self.assertRaisesRegex(ValueError, "packet-capture route or service port"):
            report_builder.validate_final_evidence_matrix(
                timing, systems, pcaps, costs
            )

    def test_missing_route_is_rejected(self):
        timing, systems, pcaps, costs = self.complete_inputs()
        with self.assertRaisesRegex(ValueError, "timing routes"):
            report_builder.validate_final_evidence_matrix(
                timing[:2], systems, pcaps, costs
            )

    def test_missing_or_mixed_timing_profile_is_rejected(self):
        timing, systems, pcaps, costs = self.complete_inputs()
        timing.pop(0)
        with self.assertRaisesRegex(ValueError, "one primary and one load"):
            report_builder.validate_final_evidence_matrix(timing, systems, pcaps, costs)

        timing, systems, pcaps, costs = self.complete_inputs()
        timing[0]["payload"]["summary"].extend(
            timing[1]["payload"]["summary"]
        )
        with self.assertRaisesRegex(ValueError, "one primary and one load"):
            report_builder.validate_final_evidence_matrix(timing, systems, pcaps, costs)

    def test_missing_factorial_effect_is_rejected(self):
        timing, systems, pcaps, costs = self.complete_inputs()
        timing[0]["payload"]["paired_effects"].pop()
        with self.assertRaisesRegex(ValueError, "factorial effects"):
            report_builder.validate_final_evidence_matrix(
                timing, systems, pcaps, costs
            )

    def test_burstable_vm_is_rejected(self):
        timing, systems, pcaps, costs = self.complete_inputs()
        timing[0]["payload"]["client_environment"]["aws_imds"][
            "burstable_instance"
        ] = True
        with self.assertRaisesRegex(ValueError, "non-burstable"):
            report_builder.validate_final_evidence_matrix(
                timing, systems, pcaps, costs
            )

    def test_flex_scheduled_vm_is_rejected(self):
        timing, systems, pcaps, costs = self.complete_inputs()
        imds = timing[0]["payload"]["client_environment"]["aws_imds"]
        imds["instance_type"] = "m7i-flex.large"
        imds["flex_scheduled_instance"] = True
        imds["fixed_performance_instance"] = False
        with self.assertRaisesRegex(ValueError, "fixed-performance"):
            report_builder.validate_final_evidence_matrix(
                timing, systems, pcaps, costs
            )

    def test_wrong_trial_count_is_rejected(self):
        timing, systems, pcaps, costs = self.complete_inputs()
        timing[0]["payload"]["summary"][0]["trials"] = 99
        with self.assertRaisesRegex(ValueError, "exactly 100 measured trials"):
            report_builder.validate_final_evidence_matrix(
                timing, systems, pcaps, costs
            )

    def test_missing_raw_paired_evidence_is_rejected(self):
        timing, systems, pcaps, costs = self.complete_inputs()
        timing[0]["payload"]["paired_effects"][0][
            "raw_paired_differences_ms"
        ] = []
        with self.assertRaisesRegex(ValueError, "raw trial evidence"):
            report_builder.validate_final_evidence_matrix(
                timing, systems, pcaps, costs
            )

    def test_incomplete_analysis_plan_is_rejected(self):
        timing, systems, pcaps, costs = self.complete_inputs()
        timing[0]["payload"]["analysis_plan"] = {}
        with self.assertRaisesRegex(ValueError, "analysis plan"):
            report_builder.validate_final_evidence_matrix(
                timing, systems, pcaps, costs
            )

    def test_missing_physical_memory_metadata_is_rejected(self):
        timing, systems, pcaps, costs = self.complete_inputs()
        timing[0]["payload"]["server_environment"]["memory"] = {}
        with self.assertRaisesRegex(ValueError, "physical-memory"):
            report_builder.validate_final_evidence_matrix(
                timing, systems, pcaps, costs
            )

    def test_wrong_regional_placement_is_rejected(self):
        timing, systems, pcaps, costs = self.complete_inputs()
        timing[0]["payload"]["client_environment"]["aws_imds"][
            "region"
        ] = "us-west-2"
        with self.assertRaisesRegex(ValueError, "placement"):
            report_builder.validate_final_evidence_matrix(
                timing, systems, pcaps, costs
            )

    def test_cross_campaign_artifact_mismatch_is_rejected(self):
        timing, systems, pcaps, costs = self.complete_inputs()
        timing[-1]["payload"]["integrity"][
            "protocol_source_sha256"
        ] = "different-source-hash"
        with self.assertRaisesRegex(ValueError, "protocol_source_sha256"):
            report_builder.validate_final_evidence_matrix(
                timing, systems, pcaps, costs
            )

    def test_cross_route_authentication_keys_may_differ(self):
        report_builder.validate_final_evidence_matrix(*self.complete_inputs())

    def test_within_route_authentication_key_mismatch_is_rejected(self):
        timing, systems, pcaps, costs = self.complete_inputs()
        eu_record = next(
            record for record in timing
            if record["payload"]["route"] == "eu_to_us"
        )
        eu_record["payload"]["integrity"][
            "initiator_public_key_sha256"
        ] = "different-initiator-key-hash"
        with self.assertRaisesRegex(
            ValueError, "eu_to_us.*initiator_public_key_sha256"
        ):
            report_builder.validate_final_evidence_matrix(
                timing, systems, pcaps, costs
            )

    def test_missing_profile_or_capture_is_rejected(self):
        timing, systems, pcaps, costs = self.complete_inputs()
        with self.assertRaisesRegex(ValueError, "allocation and syscall"):
            report_builder.validate_final_evidence_matrix(
                timing, systems[:1], pcaps, costs
            )
        with self.assertRaisesRegex(ValueError, "both endpoints"):
            report_builder.validate_final_evidence_matrix(
                timing, systems, pcaps[:1], costs
            )

    def test_packet_capture_without_rtt_is_rejected(self):
        timing, systems, pcaps, costs = self.complete_inputs()
        pcaps[0]["payload"]["metrics"]["tcp_ack_rtt_sample_count"] = 0
        with self.assertRaisesRegex(ValueError, "RTT distribution"):
            report_builder.validate_final_evidence_matrix(
                timing, systems, pcaps, costs
            )

    def test_missing_or_incomplete_cost_report_is_rejected(self):
        timing, systems, pcaps, costs = self.complete_inputs()
        with self.assertRaisesRegex(ValueError, "cloud-cost report"):
            report_builder.validate_final_evidence_matrix(
                timing, systems, pcaps, []
            )
        costs[0]["payload"]["covered_campaign_ids"].pop()
        with self.assertRaisesRegex(ValueError, "does not cover"):
            report_builder.validate_final_evidence_matrix(
                timing, systems, pcaps, costs
            )

    def test_zero_compute_hours_or_cost_is_rejected(self):
        timing, systems, pcaps, costs = self.complete_inputs()
        costs[0]["payload"]["line_items"][0]["quantity"] = 0
        costs[0]["payload"]["line_items"][0]["subtotal_usd"] = 0
        with self.assertRaisesRegex(ValueError, "route instance-hours"):
            report_builder.validate_final_evidence_matrix(
                timing, systems, pcaps, costs
            )

        timing, systems, pcaps, costs = self.complete_inputs()
        costs[0]["payload"]["totals"]["grand_total_usd"] = 0
        with self.assertRaisesRegex(ValueError, "positive measured cost"):
            report_builder.validate_final_evidence_matrix(
                timing, systems, pcaps, costs
            )

    def test_cost_campaign_rows_must_match_route_and_run_counts(self):
        timing, systems, pcaps, costs = self.complete_inputs()
        costs[0]["payload"]["campaigns"][0]["route"] = "wrong_route"
        with self.assertRaisesRegex(ValueError, "route mismatch"):
            report_builder.validate_final_evidence_matrix(
                timing, systems, pcaps, costs
            )

        timing, systems, pcaps, costs = self.complete_inputs()
        costs[0]["payload"]["campaigns"][0]["warmup_runs"] = 0
        with self.assertRaisesRegex(ValueError, "run counts do not match"):
            report_builder.validate_final_evidence_matrix(
                timing, systems, pcaps, costs
            )

        timing, systems, pcaps, costs = self.complete_inputs()
        costs[0]["payload"]["campaigns"].pop()
        with self.assertRaisesRegex(ValueError, "campaign rows"):
            report_builder.validate_final_evidence_matrix(
                timing, systems, pcaps, costs
            )

    def test_cost_line_item_tampering_is_rejected(self):
        timing, systems, pcaps, costs = self.complete_inputs()
        costs[0]["payload"]["line_items"][0]["subtotal_usd"] = 99
        with self.assertRaisesRegex(ValueError, "subtotal is inconsistent"):
            report_builder.validate_final_evidence_matrix(
                timing, systems, pcaps, costs
            )

        timing, systems, pcaps, costs = self.complete_inputs()
        costs[0]["payload"]["line_items"][0]["campaign_id"] = "unknown"
        with self.assertRaisesRegex(ValueError, "invalid campaign/category"):
            report_builder.validate_final_evidence_matrix(
                timing, systems, pcaps, costs
            )

        timing, systems, pcaps, costs = self.complete_inputs()
        costs[0]["payload"]["totals"]["storage_usd"] = 0.05
        with self.assertRaisesRegex(ValueError, "does not match line items"):
            report_builder.validate_final_evidence_matrix(
                timing, systems, pcaps, costs
            )

    def test_latex_table_uses_objective_names_and_generated_cells(self):
        common = {
            "evidence_label": "eu_primary",
            "campaign_profile": "primary",
            "route": "eu_to_us",
            "participants": 3,
            "items_per_arc": 5,
            "concurrent_pairs": 1,
            "pair_p50_ms": 10.0,
        }
        summaries = [
            {**common, "mode": report_builder.REFERENCE},
            {**common, "mode": report_builder.COMPLETE, "pair_p50_ms": 8.0},
        ]
        effects = [{
            **common,
            "comparison": "complete_method_vs_reference",
            "median_reduction_pct": 20.0,
            "median_reduction_ci95_pct": [18.0, 22.0],
            "holm_adjusted_p": 0.001,
        }]
        evidence = [{
            "kind": "timing",
            "payload": {"integrity": {"matched_samples": 2000}},
        }]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "paper_results.tex"
            report_builder.write_latex_tables(
                output, summaries, effects, evidence
            )
            generated = output.read_text()
        self.assertIn("OasisFinalMatchedSamples}{2,000}", generated)
        self.assertIn("EU--US & 3 & 5 & 10.000 & 8.000", generated)
        self.assertIn("20.00\\% [18.00, 22.00]", generated)
        self.assertNotIn(report_builder.REFERENCE, generated)
        self.assertNotIn(report_builder.COMPLETE, generated)


if __name__ == "__main__":
    unittest.main()
