#!/usr/bin/env python3
"""Registry equality checks; signature validity is checked by the native path."""
import unittest
from run_native_handoff import (
    CHALLENGE_OFFSET,
    HANDOFF_HEADER_BYTES,
    HANDOFF_MAGIC,
    HANDOFF_RECORD_BYTES,
    ITEM_DIGEST_OFFSET,
    JOINT_KEY_OFFSET,
    REGISTRY_MAGIC,
    REGISTRY_RECORD_BYTES,
    SCALAR_OFFSET,
    STATEMENT_OFFSET,
    validate_registry_handoff,
)


class RegistryTest(unittest.TestCase):
    def setUp(self):
        context=bytes(range(96))
        items=[bytes([i+1])*REGISTRY_RECORD_BYTES for i in range(5)]
        self.registry=REGISTRY_MAGIC+(5).to_bytes(4,"big")+context+b"".join(items)
        self.handoff=HANDOFF_MAGIC+context+b"".join(item+bytes(64) for item in items)

    def test_exact_public_object(self):
        validate_registry_handoff(self.registry,self.handoff)

    def test_changed_bound_fields(self):
        for offset in (
                0, 8, 40, 72,
                HANDOFF_HEADER_BYTES+ITEM_DIGEST_OFFSET,
                HANDOFF_HEADER_BYTES+STATEMENT_OFFSET,
                HANDOFF_HEADER_BYTES+JOINT_KEY_OFFSET,
                HANDOFF_HEADER_BYTES+HANDOFF_RECORD_BYTES+ITEM_DIGEST_OFFSET,
                HANDOFF_HEADER_BYTES+4*HANDOFF_RECORD_BYTES+JOINT_KEY_OFFSET):
            altered=bytearray(self.handoff); altered[offset]^=1
            with self.subTest(offset=offset),self.assertRaises(ValueError):
                validate_registry_handoff(self.registry,altered)

    def test_noncanonical_lengths_and_counts(self):
        for registry,handoff in ((self.registry[:-1],self.handoff),
                (self.registry+b"x",self.handoff),(self.registry,self.handoff[:-1]),
                (self.registry,self.handoff+b"x"),
                (self.registry[:8]+(4).to_bytes(4,"big")+self.registry[12:],self.handoff)):
            with self.assertRaises(ValueError):
                validate_registry_handoff(registry,handoff)

    def test_registry_does_not_claim_signature_verification(self):
        altered=bytearray(self.handoff)
        altered[HANDOFF_HEADER_BYTES+CHALLENGE_OFFSET]=1
        altered[HANDOFF_HEADER_BYTES+SCALAR_OFFSET]=1
        validate_registry_handoff(self.registry,altered)


if __name__=="__main__":
    unittest.main()
