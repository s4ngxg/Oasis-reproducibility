#!/usr/bin/env python3
"""Coordinator ordering/worker tests; mocks are not cryptographic evidence."""
import contextlib
import os
import time
import unittest
from unittest.mock import patch

import run_retained_arc_coordinator as coordinator
from run_native_handoff import memory_file


class Ordering(unittest.TestCase):
    def test_malformed_preparation_rejected_before_key_admission(self):
        valid=[b"OASISP01"+bytes(3*5*33),b"OASISW01"+bytes(3*5*32),
               b"OASISYF1"+(3).to_bytes(4,"big")+bytes(64*3)]
        for index in range(3):
            for mutation in (lambda v:v[:-1],lambda v:b"X"+v[1:]):
                with self.subTest(index=index),contextlib.ExitStack() as stack:
                    values=list(valid)
                    values[index]=mutation(values[index])
                    fds=[stack.enter_context(memory_file("input",v)) for v in values]
                    with patch.object(coordinator,"prepared_pair") as admit:
                        with self.assertRaises(ValueError):
                            coordinator.coordinate(3,"mode",*fds)
                        admit.assert_not_called()

    def run_case(self, fail_lock=False, fail_proof=False,recover_cycle=False,
                 fail_stage=None,n=3,all_honest=False):
        k=2*n-1
        events=[]
        @contextlib.contextmanager
        def prepared(*args):
            events.append("registry")
            yield 1,2,3,4,b"registry"
        @contextlib.contextmanager
        def credentials(*args,**kwargs):
            yield "/tmp/mock-curve-credentials"
        def jobs(stack,*args,registry=None,server_bundle=None):
            self.assertEqual(registry,b"registry")
            self.assertEqual(server_bundle,4)
            result=[]
            for level in (*range(n-1),None):
                fd=stack.enter_context(memory_file("mock-result"))
                events.append("proof")
                if fail_proof and events.count("proof")==4:
                    raise RuntimeError("injected proof rejection")
                def start():
                    events.append("start")
                    if fail_stage=="start" and events.count("start")==4:
                        raise RuntimeError("injected start rejection")
                def finish(fd=fd,level=level):
                    events.append("finish")
                    if fail_stage=="finish" and events.count("finish")==4:
                        raise RuntimeError("injected finish rejection")
                    if level is not None:
                        if not (fail_stage=="receipt" and events.count("finish")==4):
                            os.pwrite(fd,b"OASISK01"+bytes(31)+b"\x01",0)
                    return {}
                result.append((level,fd,(start,finish,0)))
            return result
        @contextlib.contextmanager
        def funded(*args):
            events.append("lock")
            if fail_lock and events.count("lock")==2:
                raise RuntimeError("injected lock rejection")
            def consume():
                events.append("consume")
                return {}
            try:
                yield consume
            finally:
                events.append("close")
        def preswap(*args,**kwargs):
            arc=args[1]
            if fail_stage=="preswap" and arc==1:
                raise RuntimeError("injected preswap rejection")
            # Child mutations are intentionally process-private.  Parent-side
            # assertions consume returned measurements/progress IPC instead.
            events.append("child-preswap")
            now=time.monotonic_ns()
            return {"arc":arc,"mock":True,"worker_started_ns":now,
                    "worker_finished_ns":now+1,
                    "host_export_deadline_ns":kwargs["host_export_deadline_ns"]}
        def sharing(*args):
            events.append("sharing")
            if fail_stage=="sharing":
                raise RuntimeError("injected sharing rejection")
            return {}
        @contextlib.contextmanager
        def cycle(n,arcs,participant,**kwargs):
            self.assertEqual(kwargs,{"all_honest":True} if all_honest else {})
            events.append("cycle-lock")
            for a in arcs:
                self.assertEqual(os.pread(a["witness"],k*32,8),bytes(k*32))
            def consume():
                self.assertEqual(events.count("finish"),0 if all_honest else n*n)
                for a in arcs:
                    expected=bytes(32*(n-1)) if all_honest else (bytes(31)+b"\x01")*(n-1)
                    self.assertEqual(os.pread(a["witness"],32*(n-1),8+32*n),expected)
                events.append("cycle-consume")
                return {"retained_cycle_recovery":True,"withdrawn_arcs":n}
            try:
                yield consume
            finally:
                events.append("cycle-close")
        def progress(stage,arc):
            if stage in ("preswap_worker_started","preswap_complete"):
                events.append(stage)
        with memory_file("public",b"OASISP01"+bytes(n*k*33)) as public, \
             memory_file("private",b"OASISW01"+bytes(n*k*32)) as private, \
             memory_file("participants",b"OASISYF1"+n.to_bytes(4,"big")+bytes(64*n)) as participants, \
             patch.object(coordinator,"prepared_pair",prepared), \
             patch.object(coordinator,"curve_credentials",credentials), \
             patch.object(coordinator,"_prepare_vtd_jobs",jobs), \
             patch.object(coordinator,"_funded_ledger",funded), \
             patch.object(coordinator,"_funded_cycle_recovery",cycle), \
             patch.object(coordinator,"run_lifecycle_preswap",preswap), \
             patch.object(coordinator,"receive_live_witness",sharing):
            if fail_lock or fail_proof or fail_stage:
                error=AssertionError if fail_stage=="receipt" else RuntimeError
                with self.assertRaises(error):
                    coordinator.coordinate(n,"mode",public,private,participants,
                        progress=progress,recover_cycle=recover_cycle,all_honest=all_honest)
            else:
                result=coordinator.coordinate(n,"mode",public,private,participants,
                    progress=progress,recover_cycle=recover_cycle,all_honest=all_honest)
                self.assertFalse(result["full_lifecycle"])
                self.assertFalse(result["local_retained_full_cycle"])
                self.assertEqual(len(result["arcs"]),n)
                self.assertTrue(all(a["preswap"]["mock"] for a in result["arcs"]))
                deadlines={a["preswap"]["host_export_deadline_ns"] for a in result["arcs"]}
                self.assertEqual(len(deadlines),1)
                if all_honest:
                    self.assertIsNone(result["cycle_recovery"])
                    self.assertIsNotNone(result["cycle_withdrawal"])
                    timing=result["coordinator_timing"]
                    self.assertGreaterEqual(timing["preswap_to_withdrawal_receipt_ms"],0)
                    self.assertGreaterEqual(timing["post_withdrawal_checks_ms"],0)
                    self.assertGreaterEqual(
                        timing["preswap_to_checks_complete_ms"],
                        timing["preswap_to_withdrawal_receipt_ms"])
                    self.assertFalse(timing["comparative_performance_evidence"])
                    self.assertTrue(timing["host_deadline_bound_to_preswap"])
                    self.assertFalse(timing["ledger_monotonic_deadline_bound"])
        return events

    def test_all_honest_uses_one_retained_cycle(self):
        for n in (3,8):
            with self.subTest(n=n):
                events=self.run_case(n=n,all_honest=True)
                self.assertEqual(events.count("cycle-lock"),1)
                self.assertEqual(events.count("sharing"),n)
                self.assertEqual(events.count("preswap_worker_started"),n)
                self.assertEqual(events.count("preswap_complete"),n)
                self.assertNotIn("lock",events)
                self.assertNotIn("consume",events)
                self.assertLess(events.index("cycle-consume"),events.index("finish"))
                self.assertEqual(events[-1],"cycle-close")

    def test_all_honest_sharing_failure_prevents_withdrawal(self):
        events=self.run_case(all_honest=True,fail_stage="sharing")
        self.assertNotIn("cycle-consume",events)
        self.assertEqual(events.count("cycle-close"),1)

    def test_late_solver_failure_does_not_undo_honest_withdrawal(self):
        events=self.run_case(all_honest=True,fail_stage="finish")
        self.assertEqual(events.count("cycle-consume"),1)
        self.assertLess(events.index("cycle-consume"),events.index("finish"))
        self.assertEqual(events.count("cycle-close"),1)

    def test_larger_cycle_ordering(self):
        for n in (8,16):
            with self.subTest(n=n):
                events=self.run_case(n=n,recover_cycle=True)
                prefix=["registry"]*n+["proof"]*(n*n)+["cycle-lock"]
                self.assertEqual(events[:len(prefix)],prefix)
                self.assertEqual(events.count("start"),n*n)
                self.assertEqual(events.count("preswap_worker_started"),n)
                self.assertEqual(events.count("preswap_complete"),n)
                self.assertEqual(events.count("sharing"),1)
                self.assertEqual(events[-2:],["cycle-consume","cycle-close"])

    def test_global_phase_order(self):
        events=self.run_case()
        self.assertEqual(events[:15],["registry"]*3+["proof"]*9+["lock"]*3)
        starts=[i for i,e in enumerate(events) if e=="start"]
        worker_starts=[i for i,e in enumerate(events) if e=="preswap_worker_started"]
        completions=[i for i,e in enumerate(events) if e=="preswap_complete"]
        sharings=[i for i,e in enumerate(events) if e=="sharing"]
        self.assertEqual(len(starts),9)
        self.assertEqual(len(worker_starts),3)
        self.assertEqual(len(completions),3)
        self.assertEqual(len(sharings),3)
        self.assertLess(max(starts),min(worker_starts))
        self.assertLess(max(worker_starts),min(completions))
        self.assertLess(max(completions),min(sharings))
        self.assertEqual(events.count("finish"),9)
        self.assertEqual(events.count("consume"),3)
        self.assertEqual(events[-3:],["close"]*3)
        self.assertNotIn("child-preswap",events)

    def test_lock_failure_prevents_preswap(self):
        events=self.run_case(True)
        self.assertNotIn("start",events)
        self.assertNotIn("preswap_worker_started",events)
        self.assertNotIn("consume",events)
        self.assertEqual(events.count("close"),1)

    def test_proof_failure_prevents_all_funding(self):
        events=self.run_case(fail_proof=True)
        self.assertNotIn("lock",events)
        self.assertNotIn("start",events)
        self.assertNotIn("preswap_worker_started",events)

    def test_recovery_consumes_solver_outputs_after_all_preswap(self):
        events=self.run_case(recover_cycle=True)
        self.assertEqual(events[:13],["registry"]*3+["proof"]*9+["cycle-lock"])
        self.assertEqual(events.count("preswap_complete"),3)
        self.assertEqual(events.count("sharing"),1)
        self.assertEqual(events[-2:],["cycle-consume","cycle-close"])
        self.assertNotIn("consume",events)

    def test_failed_recovery_phases_never_consume_cycle(self):
        for stage in ("start","preswap","sharing","finish","receipt"):
            with self.subTest(stage=stage):
                events=self.run_case(recover_cycle=True,fail_stage=stage)
                self.assertNotIn("cycle-consume",events)
                self.assertNotIn("consume",events)
                self.assertEqual(events.count("cycle-close"),1)
                if stage=="start":
                    self.assertNotIn("preswap_worker_started",events)
                if stage in ("start","preswap","sharing"):
                    self.assertNotIn("finish",events)


class WorkerLifecycle(unittest.TestCase):
    def _arcs(self, stack, count=3):
        arcs=[]
        for arc in range(count):
            fds=[stack.enter_context(memory_file(f"worker-{arc}-{name}"))
                 for name in ("points","output","ck","sk","cb","sb")]
            arcs.append(dict(
                arc=arc, points=fds[0], output=fds[1], execution=arc,
                ck=fds[2], sk=fds[3], cb=fds[4], sb=fds[5], registry=b"registry",
                curve_credentials="/tmp/mock-curve-credentials"))
        return arcs

    @staticmethod
    def _deadline(seconds=2):
        return time.monotonic_ns()+int(seconds*1_000_000_000)

    def test_worker_timeout_is_coordinator_bounded(self):
        with contextlib.ExitStack() as stack:
            arcs=self._arcs(stack)
            def hung(*args,**kwargs):
                time.sleep(2)
                return {}
            started=time.monotonic()
            with patch.object(coordinator,"run_lifecycle_preswap",hung):
                with self.assertRaises(TimeoutError):
                    coordinator._run_preswap_arcs(
                        3,"mode",arcs,"seed",lambda *_:None,self._deadline(),
                        worker_timeout_seconds=0.05)
            self.assertLess(time.monotonic()-started,1.5)

    def test_one_child_failure_tears_down_siblings(self):
        with contextlib.ExitStack() as stack:
            arcs=self._arcs(stack)
            def fail_one(*args,**kwargs):
                if args[1]==1:
                    raise RuntimeError("boom")
                time.sleep(0.05)
                now=time.monotonic_ns()
                return {"arc":args[1],"worker_started_ns":now,"worker_finished_ns":now+1}
            with patch.object(coordinator,"run_lifecycle_preswap",fail_one):
                with self.assertRaisesRegex(RuntimeError,"arc=1.*boom"):
                    coordinator._run_preswap_arcs(
                        3,"mode",arcs,"seed",lambda *_:None,self._deadline(),
                        worker_timeout_seconds=1)

    def test_child_failure_is_fail_fast_against_hung_sibling(self):
        with contextlib.ExitStack() as stack:
            arcs=self._arcs(stack,2)
            def fail_and_hang(*args,**kwargs):
                if args[1]==0:
                    raise RuntimeError("fast-failure")
                time.sleep(5)
                return {}
            started=time.monotonic()
            with patch.object(coordinator,"run_lifecycle_preswap",fail_and_hang):
                with self.assertRaisesRegex(RuntimeError,"fast-failure"):
                    coordinator._run_preswap_arcs(
                        3,"mode",arcs,"seed",lambda *_:None,self._deadline(10),
                        worker_timeout_seconds=8)
            self.assertLess(time.monotonic()-started,1.5)

    def test_workers_really_overlap_using_ipc_returned_timestamps(self):
        with contextlib.ExitStack() as stack:
            arcs=self._arcs(stack)
            def overlapping(*args,**kwargs):
                started=time.monotonic_ns()
                time.sleep(0.12)
                finished=time.monotonic_ns()
                return {"arc":args[1],"worker_started_ns":started,
                        "worker_finished_ns":finished,
                        "host_export_deadline_ns":kwargs["host_export_deadline_ns"]}
            with patch.object(coordinator,"run_lifecycle_preswap",overlapping):
                coordinator._run_preswap_arcs(
                    3,"mode",arcs,"seed",lambda *_:None,self._deadline(),
                    worker_timeout_seconds=1)
            starts=[a["measurement"]["worker_started_ns"] for a in arcs]
            finishes=[a["measurement"]["worker_finished_ns"] for a in arcs]
            self.assertLess(max(starts),min(finishes))
            self.assertEqual(len({a["measurement"]["host_export_deadline_ns"] for a in arcs}),1)

    def test_mid_spawn_failure_reaps_already_started_worker(self):
        with contextlib.ExitStack() as stack:
            arcs=self._arcs(stack)
            real_fork=os.fork
            calls=0
            def fail_second_fork():
                nonlocal calls
                calls+=1
                if calls==2:
                    raise OSError("injected fork failure")
                return real_fork()
            def slow(*args,**kwargs):
                time.sleep(2)
                return {}
            started=time.monotonic()
            with patch.object(coordinator.os,"fork",side_effect=fail_second_fork), \
                 patch.object(coordinator,"run_lifecycle_preswap",slow):
                with self.assertRaisesRegex(OSError,"injected fork failure"):
                    coordinator._run_preswap_arcs(
                        3,"mode",arcs,"seed",lambda *_:None,self._deadline(),
                        worker_timeout_seconds=1)
            self.assertLess(time.monotonic()-started,1.5)

    def test_expired_lifecycle_deadline_spawns_nothing(self):
        with contextlib.ExitStack() as stack:
            arcs=self._arcs(stack)
            with patch.object(coordinator.os,"fork") as fork:
                with self.assertRaises(TimeoutError):
                    coordinator._run_preswap_arcs(
                        3,"mode",arcs,"seed",lambda *_:None,time.monotonic_ns()-1,
                        worker_timeout_seconds=1)
                fork.assert_not_called()


if __name__=="__main__":
    unittest.main()
