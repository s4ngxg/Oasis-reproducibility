import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class SourcePackageTests(unittest.TestCase):
    def test_repeatable_archive_with_explicit_epoch(self):
        with tempfile.TemporaryDirectory() as temporary:
            archives = [Path(temporary) / f"source-{index}.tar.gz" for index in range(2)]
            environment = {**os.environ, "SOURCE_DATE_EPOCH": "1234567890"}
            for archive in archives:
                subprocess.run(
                    ["bash", "scripts/package_source_release.sh", str(archive)],
                    cwd=ROOT, env=environment, check=True,
                    capture_output=True, text=True)
            self.assertEqual(archives[0].read_bytes(), archives[1].read_bytes())
            with tarfile.open(archives[0], "r:gz") as bundle:
                self.assertTrue(all(member.mtime == 1234567890 for member in bundle))

    def test_invalid_epoch_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "source.tar.gz"
            result = subprocess.run(
                ["bash", "scripts/package_source_release.sh", str(archive)],
                cwd=ROOT, env={**os.environ, "SOURCE_DATE_EPOCH": "yesterday"},
                capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SOURCE_DATE_EPOCH", result.stderr)
            self.assertFalse(archive.exists())

    def test_archive_inside_source_is_refused(self):
        result = subprocess.run(
            ["bash", "scripts/package_source_release.sh", str(ROOT / "nested-source.tar.gz")],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside the repository", result.stderr)

    def test_source_archive_excludes_runtime_and_binary_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "oasis-source.tar.gz"
            subprocess.run(
                ["bash", "scripts/package_source_release.sh", str(archive)],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertTrue(archive.is_file())
            self.assertTrue(Path(f"{archive}.sha256").is_file())

            with tarfile.open(archive, "r:gz") as bundle:
                names = bundle.getnames()

            forbidden_suffixes = (
                ".a", ".o", ".so", ".pem", ".crt", ".pcap",
                ".pcapng", ".log", ".pid", ".pyc",
            )
            forbidden_parts = {
                ".deps", ".git", ".local-deps", ".vscode", "auth",
                "bin", "results", "tls", "__pycache__",
            }
            for name in names:
                path = Path(name)
                self.assertFalse(name.endswith(forbidden_suffixes), name)
                self.assertTrue(forbidden_parts.isdisjoint(path.parts), name)
                self.assertFalse(name.endswith("/vtd/vtd"), name)

            required = {
                "scripts/run_retained_arc_coordinator.py",
                "scripts/validate_lifecycle_evidence.py",
                "docs/FULL_CYCLE_COMPLETION_GATES.md",
                "vendor/paraswap/two-party computation/src/host_ledger.c",
                "vendor/paraswap/two-party computation/src/host_recovery.c",
                "scripts/run_local_smoke.sh",
                "scripts/run_reduced_wan_role.sh",
                "scripts/build_cloud_cost_report.py",
                "vendor/paraswap/two-party computation/src/completion_journal.c",
                "vendor/paraswap/two-party computation/src/completion_journal_test.c",
            }
            relative_names = {
                "/".join(Path(name).parts[1:]) for name in names
            }
            self.assertTrue(required.issubset(relative_names))


if __name__ == "__main__":
    unittest.main()
