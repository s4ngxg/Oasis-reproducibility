import sys
import unittest
from pathlib import Path

from scipy.stats import wilcoxon


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import analyze_conformance_results  # noqa: E402


def effect_row(
    *,
    campaign_id,
    route="eu_to_us",
    comparison="bjp-batch-vs-persistent-itemwise",
    n=8,
    pairs=1,
    profile="none",
    scope="none",
    p_value=0.01,
):
    return {
        "environment": "cloud-tcp",
        "campaign_id": campaign_id,
        "route": route,
        "fault_profile": profile,
        "fault_scope": scope,
        "n": n,
        "pairs": pairs,
        "fault_count": 0,
        "comparison": comparison,
        "wilcoxon_signed_rank_p": p_value,
    }


class SignedRankTests(unittest.TestCase):
    def test_matches_scipy_with_ties_and_zero(self):
        values = [4.0, 2.0, 2.0, -1.0, -1.0, 0.0]
        expected = wilcoxon(
            values,
            zero_method="wilcox",
            correction=False,
            alternative="two-sided",
            method="auto",
        ).pvalue
        actual, effect = analyze_conformance_results.signed_rank(values)
        self.assertAlmostEqual(actual, expected)
        self.assertGreater(effect, 0.0)

    def test_all_zero_differences_are_neutral(self):
        self.assertEqual(
            analyze_conformance_results.signed_rank([0.0, 0.0]),
            (1.0, 0.0),
        )


class HolmFamilyTests(unittest.TestCase):
    def test_primary_load_and_network_families_are_separate(self):
        rows = [
            effect_row(campaign_id="eu_primary", n=8, p_value=0.01),
            effect_row(campaign_id="eu_primary", n=16, p_value=0.03),
            effect_row(campaign_id="eu_load", n=8, pairs=1, p_value=0.02),
            effect_row(campaign_id="eu_load", n=8, pairs=64, p_value=0.04),
            effect_row(
                campaign_id="eu_fault_loss2",
                profile="loss2",
                scope="client-egress",
                p_value=0.01,
            ),
            effect_row(
                campaign_id="eu_fault_loss5",
                profile="loss5",
                scope="client-egress",
                p_value=0.04,
            ),
        ]
        analyze_conformance_results.apply_holm(rows)

        self.assertEqual([row["holm_family_size"] for row in rows], [2] * 6)
        self.assertTrue(rows[0]["holm_family"].startswith("primary:"))
        self.assertTrue(rows[2]["holm_family"].startswith("load:"))
        self.assertTrue(rows[4]["holm_family"].startswith("network-fault:"))
        self.assertAlmostEqual(rows[0]["holm_adjusted_p"], 0.02)
        self.assertAlmostEqual(rows[1]["holm_adjusted_p"], 0.03)
        self.assertAlmostEqual(rows[2]["holm_adjusted_p"], 0.04)
        self.assertAlmostEqual(rows[3]["holm_adjusted_p"], 0.04)


if __name__ == "__main__":
    unittest.main()
