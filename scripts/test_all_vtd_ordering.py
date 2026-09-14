#!/usr/bin/env python3
"""Orchestration regression only; cryptographic coverage is the live VTD gate."""
import contextlib
import json
import os
import subprocess
import unittest
from unittest.mock import patch

import run_native_handoff as runner


class OrderingTest(unittest.TestCase):
    def exercise(self, fail_prepare=None, fail_finish=False,fail_lock=False,fail_witness=False):
        events=[]
        witness=b"OASISW01"+b"".join(i.to_bytes(32,"big") for i in range(1,6))
        # Structural fixtures only; live admission tests check curve points/proofs.
        registry=bytearray(runner.REGISTRY_HEADER_BYTES+runner.REGISTRY_RECORD_BYTES*5)
        registry[:8]=runner.REGISTRY_MAGIC
        registry[8:12]=(5).to_bytes(4,"big")
        expected_points={0:b"\x02"+b"\x11"*32,1:b"\x02"+b"\x22"*32,
                         None:b"\x02"+b"\x33"*32}
        for level in (0,1):
            offset=(runner.REGISTRY_HEADER_BYTES+
                    runner.REGISTRY_RECORD_BYTES*(3+level)+runner.STATEMENT_OFFSET)
            registry[offset:offset+33]=expected_points[level]
        bundle=bytearray(12+65*3)
        bundle[:8]=b"OASISAP1"
        bundle[8:12]=(3).to_bytes(4,"big")
        bundle[12+65*2:12+65*2+33]=expected_points[None]

        @contextlib.contextmanager
        def prepare(n,ck,sk,output,seed,receipt,inputs,level,delayed,expected):
            self.assertEqual(expected,expected_points[level])
            events.append(("prepare",level))
            if level==fail_prepare:
                raise RuntimeError("injected preparation failure")
            def start():
                events.append(("start",level))
            def finish():
                events.append(("finish",level))
                if fail_finish:
                    raise RuntimeError("injected solver failure")
                if level is not None:
                    os.pwrite(receipt,b"OASISK01"+(4+level).to_bytes(32,"big"),0)
                return {"external_solver_check":{"public_input_solver":True}}
            try:
                yield start,finish,0
            finally:
                events.append(("close",level))

        def preswap(*args,**kwargs):
            events.append(("preswap",None))
            return {}

        @contextlib.contextmanager
        def fund(*args):
            events.append(("lock",None))
            if fail_lock:
                raise RuntimeError("injected lock failure")
            def finish():
                events.append(("funded-consume",None))
                return {"retained_funded_ledger":True,"live_refund_checked":True}
            yield finish

        with runner.memory_file("test-witness",witness) as fd, \
             runner.memory_file("test-server-bundle",bytes(bundle),sealed=True) as sb:
            def receive(*args):
                events.append(("witness",None))
                self.assertEqual(os.pread(fd,32,8),bytes(32))
                if fail_witness:
                    raise RuntimeError("injected witness failure")
                os.pwrite(fd,(1).to_bytes(32,"big"),8)
                return {"live_withdrawal_witness":True}
            def consume(*args,**kwargs):
                events.append(("consume",None))
                valid=os.pread(fd,len(witness),0)==witness
                return subprocess.CompletedProcess([],0 if valid else 1,json.dumps({
                    "live_refund_checked":True,"timed_ledger_paths_checked":True}))
            with patch.object(runner,"_prepared_vtd",prepare), \
                 patch.object(runner,"_run_pair",preswap), \
                 patch.object(runner,"_funded_ledger",fund), \
                 patch.object(runner,"receive_live_witness",receive), \
                 patch.object(runner.subprocess,"run",consume):
                try:
                    result=runner._ordered_all_vtd_pair(3,0,"test",-1,-1,"00"*32,1,
                        -1,-1,-1,sb,fd,registry=bytes(registry),participant_fd=99)
                except RuntimeError:
                    if fail_prepare=="none" and not fail_finish and not fail_lock and not fail_witness:
                        raise
                    result=None
        return events,result

    def test_all_preparation_and_starts_precede_one_preswap(self):
        events,result=self.exercise(fail_prepare="none")
        self.assertEqual(events[:8],[("prepare",0),("prepare",1),("prepare",None),("lock",None),
            ("start",0),("start",1),("start",None),("preswap",None)])
        self.assertEqual(events.count(("preswap",None)),1)
        self.assertEqual(result["all_vtds_prepared"],3)
        self.assertEqual(result["mutated_relock_witnesses_rejected"],2)
        self.assertTrue(result["lock_ack_before_preswap"])
        self.assertLess(events.index(("preswap",None)),events.index(("witness",None)))
        self.assertLess(events.index(("witness",None)),events.index(("funded-consume",None)))

    def test_preparation_failure_prevents_preswap_and_solver_start(self):
        events,result=self.exercise(fail_prepare=1)
        self.assertIsNone(result)
        self.assertFalse(any(name in ("start","preswap","consume") for name,_ in events))
        self.assertIn(("close",0),events)

    def test_solver_failure_prevents_ledger_consumption(self):
        events,result=self.exercise(fail_prepare="none",fail_finish=True)
        self.assertIsNone(result)
        self.assertNotIn(("consume",None),events)
        self.assertNotIn(("funded-consume",None),events)
        self.assertEqual(sum(name=="close" for name,_ in events),3)

    def test_lock_failure_prevents_solvers_and_preswap(self):
        events,result=self.exercise(fail_prepare="none",fail_lock=True)
        self.assertIsNone(result)
        self.assertFalse(any(name in ("start","preswap","consume") for name,_ in events))
        self.assertEqual(sum(name=="close" for name,_ in events),3)

    def test_invalid_witness_prevents_happy_path_consumption(self):
        events,result=self.exercise(fail_prepare="none",fail_witness=True)
        self.assertIsNone(result)
        self.assertNotIn(("consume",None),events)
        self.assertNotIn(("funded-consume",None),events)
        self.assertEqual(sum(name=="close" for name,_ in events),3)


if __name__=="__main__":
    unittest.main()
