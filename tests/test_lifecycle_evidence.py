import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import validate_lifecycle_evidence as evidence


class LifecycleEvidenceTests(unittest.TestCase):
    def test_incomplete_or_extended_binary_manifest_rejected(self):
        valid = dict.fromkeys(evidence.REQUIRED_BINARIES, "a" * 64)
        evidence.validate_binary_manifest(valid)
        missing = dict(valid)
        missing.pop(next(iter(missing)))
        for manifest in (None, {}, missing, {**valid, "unrelated": "a" * 64}):
            with self.subTest(manifest=manifest):
                with self.assertRaises(ValueError):
                    evidence.validate_binary_manifest(manifest)

    def test_invalid_hash_encoding_rejected(self):
        for digest in (None, 1, "a" * 63, "g" * 64, "A" * 64):
            with self.subTest(digest=digest):
                with self.assertRaisesRegex(ValueError, "SHA-256"):
                    evidence.validate_binary_manifest(
                        dict.fromkeys(evidence.REQUIRED_BINARIES, digest))

    def test_empty_directory_is_not_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "missing branch/mode"):
                evidence.validate([directory])

    def test_optimized_interpreter_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, "-O", "-B", evidence.__file__, directory],
                capture_output=True, text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("do not use -O", result.stderr)
