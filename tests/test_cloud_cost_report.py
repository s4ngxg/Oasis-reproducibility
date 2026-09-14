import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_cloud_cost_report as cost_report  # noqa: E402


def valid_input():
    return {
        "schema": "oasis-cloud-cost-input-v1",
        "currency": "USD",
        "pricing": {
            "source_url": "https://example.test/pricing",
            "retrieved_at_utc": "2026-09-03T00:00:00Z",
        },
        "campaigns": [{
            "campaign_id": "eu-primary-final",
            "route": "eu_to_us",
            "measured_runs": 100,
            "warmup_runs": 10,
            "failed_runs": 2,
            "compute": [{
                "region": "eu-central-1",
                "description": "initiator compute",
                "quantity": 2,
                "unit": "instance-hour",
                "unit_price_usd": 0.25,
            }],
            "storage": [{
                "region": "eu-central-1",
                "description": "campaign storage",
                "quantity": 1,
                "unit": "GB-month",
                "unit_price_usd": 0.1,
            }],
            "data_transfer": [{
                "region": "eu-central-1_to_us-east-1",
                "description": "cross-region transfer",
                "quantity": 3,
                "unit": "GB",
                "unit_price_usd": 0.02,
            }],
        }],
    }


class CloudCostReportTests(unittest.TestCase):
    def test_builds_separate_cost_categories_and_run_counts(self):
        report = cost_report.build_report(valid_input())
        self.assertEqual(report["schema"], "oasis-cloud-cost-report-v1")
        self.assertEqual(report["totals"]["measured_runs"], 100)
        self.assertEqual(report["totals"]["warmup_runs"], 10)
        self.assertEqual(report["totals"]["failed_runs"], 2)
        self.assertAlmostEqual(report["totals"]["compute_usd"], 0.5)
        self.assertAlmostEqual(report["totals"]["storage_usd"], 0.1)
        self.assertAlmostEqual(report["totals"]["data_transfer_usd"], 0.06)
        self.assertAlmostEqual(report["totals"]["grand_total_usd"], 0.66)
        markdown = cost_report.render_markdown(report)
        self.assertIn("eu-primary-final", markdown)
        self.assertIn("Grand total: USD 0.660000", markdown)

    def test_template_and_missing_categories_are_rejected(self):
        payload = valid_input()
        payload["template"] = True
        with self.assertRaisesRegex(ValueError, "template"):
            cost_report.build_report(payload)
        payload = valid_input()
        payload["campaigns"][0]["storage"] = []
        with self.assertRaisesRegex(ValueError, "storage"):
            cost_report.build_report(payload)

    def test_negative_quantity_and_duplicate_campaign_are_rejected(self):
        payload = valid_input()
        payload["campaigns"][0]["compute"][0]["quantity"] = -1
        with self.assertRaisesRegex(ValueError, "non-negative"):
            cost_report.build_report(payload)
        payload = valid_input()
        payload["campaigns"].append(dict(payload["campaigns"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate campaign"):
            cost_report.build_report(payload)

    def test_pricing_timestamp_must_be_valid_utc(self):
        payload = valid_input()
        payload["pricing"]["retrieved_at_utc"] = "2026-09-03"
        with self.assertRaisesRegex(ValueError, "UTC timestamp"):
            cost_report.build_report(payload)
        payload["pricing"]["retrieved_at_utc"] = "not-a-dateZ"
        with self.assertRaisesRegex(ValueError, "valid ISO-8601"):
            cost_report.build_report(payload)


if __name__ == "__main__":
    unittest.main()
