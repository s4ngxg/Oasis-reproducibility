import contextlib
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import run_native_handoff as handoff


class VtdAdmissionTests(unittest.TestCase):
    def test_metadata_requires_exact_context_key_and_length(self):
        seed = "12" * 32
        key = b"\x02" + bytes(32)
        metadata = b"OASISVS1" + bytes.fromhex(seed) + key + (32).to_bytes(8, "big")
        handoff._validate_vtd_admission_metadata(metadata, seed, key)
        for offset in (0, 8, 39, 40, 72):
            mutated = bytearray(metadata)
            mutated[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                handoff._validate_vtd_admission_metadata(bytes(mutated), seed, key)
        for invalid in (metadata[:-1], metadata + b"\x00"):
            with self.assertRaises(ValueError):
                handoff._validate_vtd_admission_metadata(invalid, seed, key)
        with self.assertRaises(ValueError):
            handoff._validate_vtd_admission_metadata(metadata, seed, key[:-1])

    def test_expected_keys_follow_registry_levels_and_responder_bundle(self):
        n = 3
        statements = [bytes([i + 1]) * 33 for i in range(5)]
        keys = [bytes([i + 21]) * 33 for i in range(n)]
        registry = (handoff.REGISTRY_MAGIC + (5).to_bytes(4, "big") + bytes(96) +
                    b"".join(bytes(64) + point + bytes(33) for point in statements))
        bundle = (b"OASISAP1" + n.to_bytes(4, "big") +
                  b"".join(key + bytes(97) for key in keys))
        seen = []

        @contextlib.contextmanager
        def prepared(*args):
            seen.append((args[-3], args[-1]))
            yield (None, None, 0)

        with contextlib.ExitStack() as stack:
            public = stack.enter_context(handoff.memory_file("bundle", bundle, sealed=True))
            witness = stack.enter_context(handoff.memory_file("witness", bytes(8 + 32 * 5)))
            with patch.object(handoff, "_prepared_vtd", prepared):
                jobs = handoff._prepare_vtd_jobs(
                    stack, n, -1, -1, -1, "00" * 32, witness,
                    registry=registry, server_bundle=public)
            self.assertEqual(len(jobs), n)
            self.assertEqual(seen, [(0, statements[3]), (1, statements[4]), (None, keys[2])])

    def test_incomplete_admission_inputs_rejected_before_proof(self):
        with contextlib.ExitStack() as stack, patch.object(handoff, "_prepared_vtd") as proof:
            for options in ({"registry": b"bad"}, {"server_bundle": -1},
                            {"registry": b"bad", "server_bundle": -1}):
                with self.subTest(options=options), self.assertRaises(ValueError):
                    handoff._prepare_vtd_jobs(stack, 3, -1, -1, -1, "00" * 32, -1, **options)
            proof.assert_not_called()


if __name__ == "__main__":
    unittest.main()
