#!/usr/bin/env python3
"""Native integration gate for public host statement vectors, not lifecycle."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TPC = ROOT / "vendor/paraswap/two-party computation"
# Public secp256k1 generator, used only as a parser/protocol test fixture.
GENERATOR = bytes.fromhex(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)
VECTOR = b"OASISP01" + GENERATOR * 5


class HostStatementsTests(unittest.TestCase):
    def run_pair(self, mode, client_vector, server_vector):
        with tempfile.TemporaryDirectory(prefix="oasis-host-test-") as directory:
            directory = Path(directory)
            client_file = directory / "client-public.bin"
            server_file = directory / "server-public.bin"
            client_file.write_bytes(client_vector)
            server_file.write_bytes(server_vector)
            common = [
                "--mode", mode, "--count", "5", "--context-participants", "3",
                "--context-seed-hex", hashlib.sha256(VECTOR).hexdigest(),
                "--execution-id", "111", "--pair-id", "0",
                "--port", str(20000 + os.getpid() % 30000),
                "--io-timeout-ms", "1500",
            ]
            server = subprocess.Popen(
                [str(TPC / "bin/preswap_server"), *common,
                 "--host-statements", str(server_file)],
                cwd=TPC, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True,
            )
            try:
                client = subprocess.run(
                    [str(TPC / "bin/preswap_client"), *common,
                     "--host-statements", str(client_file)],
                    cwd=TPC, capture_output=True, text=True, timeout=20,
                )
                stdout, stderr = server.communicate(timeout=20)
                return client, server.returncode, stdout + stderr
            finally:
                if server.poll() is None:
                    server.kill()
                server.communicate()

    def test_all_five_modes_accept_same_public_vector(self):
        for mode in (
            "reference-itemwise", "phase-coalesced-itemwise",
            "batch-joint-presigning-itemwise", "phase-coalesced-batch-verification",
            "batch-joint-presigning-batch-verification",
        ):
            with self.subTest(mode=mode):
                client, status, server = self.run_pair(mode, VECTOR, VECTOR)
                self.assertEqual(client.returncode, 0, client.stderr + server)
                self.assertEqual(status, 0, server)
                self.assertIn("RESULT\t", client.stdout)

    def test_invalid_encodings_and_mismatched_vector_fail(self):
        invalid = [
            VECTOR[:-1], VECTOR + b"\x00", b"BADMAGIC" + VECTOR[8:],
            b"OASISP01" + bytes(33 * 5),
            b"OASISP01" + bytes([3]) + VECTOR[9:],
        ]
        for value in invalid:
            with self.subTest(size=len(value), prefix=value[:9].hex()):
                client, _, _ = self.run_pair(
                    "batch-joint-presigning-batch-verification", value, VECTOR
                )
                self.assertNotEqual(client.returncode, 0)
                self.assertNotIn("RESULT\t", client.stdout)


if __name__ == "__main__":
    unittest.main()
