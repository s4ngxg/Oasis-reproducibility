import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CompletePackageTests(unittest.TestCase):
    def package(self, archive: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "scripts/package_complete_artifact.sh", str(archive)],
            cwd=ROOT,
            env={**os.environ, "SOURCE_DATE_EPOCH": "0"},
            capture_output=True,
            text=True,
        )

    def test_excluded_build_log_does_not_block_packaging(self) -> None:
        excluded_log = ROOT / ".deps" / "package-test" / "CMakeOutput.log"
        excluded_log.parent.mkdir(parents=True, exist_ok=True)
        excluded_log.write_text("excluded build log\n", encoding="ascii")
        try:
            with tempfile.TemporaryDirectory() as temporary:
                archive = Path(temporary) / "complete.tar.gz"
                result = self.package(archive)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(archive.is_file())
        finally:
            excluded_log.unlink(missing_ok=True)
            try:
                excluded_log.parent.rmdir()
            except OSError:
                pass

    def test_included_runtime_log_is_rejected(self) -> None:
        included_log = ROOT / "tests" / "package-forbidden.log"
        included_log.write_text("must not be released\n", encoding="ascii")
        try:
            with tempfile.TemporaryDirectory() as temporary:
                archive = Path(temporary) / "complete.tar.gz"
                result = self.package(archive)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("forbidden runtime or credential files", result.stderr)
                self.assertFalse(archive.exists())
        finally:
            included_log.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
