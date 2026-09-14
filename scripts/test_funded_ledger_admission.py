#!/usr/bin/env python3
"""Native funding admission failures; not a protocol or lifecycle benchmark."""
import resource
import subprocess
import unittest
from run_native_handoff import REGISTRY_MAGIC, TPC, _funded_ledger, memory_file


class FundingTest(unittest.TestCase):
    def setUp(self):
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        point=bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        # Repeated public keys are a ledger-admission fixture only, not the
        # independent-address provisioning used by the live protocol runner.
        self.registry=REGISTRY_MAGIC+(5).to_bytes(4,"big")+bytes(range(96))+b"".join(
            bytes([i])*32+bytes([i+8])*32+point+point for i in range(1,6))

    def test_funded_state_does_not_accept_missing_handoff(self):
        with memory_file("unwritten-handoff") as handoff, \
             memory_file("unwritten-witness") as witness, \
             memory_file("unwritten-refund") as refund:
            with _funded_ledger(3,self.registry,handoff,witness,refund) as consume:
                with self.assertRaisesRegex(RuntimeError,"rejected handoff"):
                    consume()

    def test_malformed_registry_never_acknowledges_lock(self):
        bad=[self.registry[:-1],self.registry+b"x",
             b"INVALID!"+self.registry[8:],
             self.registry[:8]+(7).to_bytes(4,"big")+self.registry[12:]]
        for registry in bad:
            with memory_file("unwritten-handoff") as handoff, \
                 memory_file("unwritten-witness") as witness, \
                 memory_file("unwritten-refund") as refund:
                with self.assertRaisesRegex(RuntimeError,"lock admission failed"):
                    with _funded_ledger(3,registry,handoff,witness,refund):
                        self.fail("malformed registry was admitted")

    def test_mutable_registry_never_acknowledges_lock(self):
        with memory_file("mutable-registry",self.registry) as registry, \
             memory_file("wallet",b"OASISK01"+bytes(31)+b"\x01",sealed=True) as wallet, \
             memory_file("handoff") as handoff,memory_file("witness") as witness, \
             memory_file("refund") as refund:
            fds=(registry,wallet,handoff,witness,refund)
            result=subprocess.run([str(TPC/"bin/host_cycle_tool"),"funded-check","5",*map(str,fds)],
                pass_fds=fds,input="C",capture_output=True,text=True,timeout=60)
            self.assertGreater(result.returncode,0)
            self.assertNotIn("LOCK_ACCEPTED",result.stdout)


if __name__=="__main__":
    unittest.main()
