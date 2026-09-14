import tempfile
import unittest
from pathlib import Path
from unittest import mock
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import run_cloud_campaign as campaign


class CompletionRetentionTests(unittest.TestCase):
    def test_journal_is_stable_and_not_in_temporary_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(campaign, "ROOT", Path(directory)):
                first = campaign.gateway_completion_dir("campaign", 0)
                self.assertEqual(first, campaign.gateway_completion_dir("campaign", 0))
                self.assertEqual(first.parent, Path(directory) / "results/completion-journal")
                self.assertNotEqual(first, campaign.gateway_completion_dir("campaign", 1))
                self.assertNotEqual(first, campaign.gateway_completion_dir("other", 0))

    def test_resolving_existing_journal_preserves_records(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(campaign, "ROOT", Path(directory)):
                path = campaign.gateway_completion_dir("campaign", 0)
                path.mkdir(parents=True)
                record = path / "completion"
                record.write_bytes(b"retained")
                self.assertEqual(path, campaign.gateway_completion_dir("campaign", 0))
                self.assertEqual(record.read_bytes(), b"retained")
