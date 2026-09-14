#!/usr/bin/env python3
"""Live Pre-swap to Adapt/Extract gate; never a public-chain benchmark."""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import secrets
import selectors
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
TPC = ROOT / "vendor/paraswap/two-party computation"
HANDOFF_HEADER_BYTES = 104
REGISTRY_HEADER_BYTES = 108
REGISTRY_RECORD_BYTES = 130
HANDOFF_RECORD_BYTES = 194
TX_DIGEST_OFFSET = 0
ITEM_DIGEST_OFFSET = 32
STATEMENT_OFFSET = 64
JOINT_KEY_OFFSET = 97
CHALLENGE_OFFSET = 130
SCALAR_OFFSET = 162
HANDOFF_MAGIC = b"OASISH02"
REGISTRY_MAGIC = b"OASISRG2"
MODES = (
    "reference-itemwise", "phase-coalesced-itemwise",
    "batch-joint-presigning-itemwise", "phase-coalesced-batch-verification",
    "batch-joint-presigning-batch-verification",
)


@contextlib.contextmanager
def memory_file(name, initial=b"", sealed=False):
    fd = os.memfd_create("oasis-" + name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        if initial:
            os.write(fd, initial)
        if sealed:
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS,
                        fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK)
        yield fd
    finally:
        try:
            if not (fcntl.fcntl(fd,fcntl.F_GET_SEALS) & fcntl.F_SEAL_SHRINK):
                os.ftruncate(fd, 0)
        finally:
            os.close(fd)


def crypto_tool(action, count, first_fd, second_fd, expect_success=True):
    process = subprocess.run(
        [str(TPC / "bin/host_cycle_tool"), action, str(count),
         str(first_fd), str(second_fd)], pass_fds=(first_fd, second_fd),
        cwd=TPC, capture_output=True, text=True, timeout=60,
    )
    if expect_success and process.returncode:
        # Do not include native buffers or potential secret-bearing diagnostics.
        raise RuntimeError(f"native {action} failed, exit={process.returncode}")
    return process


@contextlib.contextmanager
def prepared_pair(n, arc, mode, public_fd, seed, execution):
    """Retain admitted keys and registry without starting network Pre-swap.

    Descriptors are borrowed only inside this context. A coordinator can enter
    all arc contexts before admitting locks or starting any Pre-swap session.
    """
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    def key_bytes():
        values=[]
        while len(values)<n:
            value=secrets.randbelow(order-1)+1
            if value not in values:
                values.append(value)
        return b"OASISA01" + n.to_bytes(4,"big") + b"".join(
            value.to_bytes(32,"big") for value in values)
    with memory_file("client-key", key_bytes(), sealed=True) as client_key, \
         memory_file("server-key", key_bytes(), sealed=True) as server_key, \
         memory_file("client-public-key") as client_public, \
         memory_file("server-public-key") as server_public:
        for private,public,role in ((client_key,client_public,"initiator"),
                                    (server_key,server_public,"responder")):
            process=subprocess.run([str(TPC/"bin/host_cycle_tool"),"address-bundle",
                str(n),str(private),str(public),seed,role,str(arc)],
                pass_fds=(private,public),capture_output=True,timeout=60)
            if process.returncode:
                raise RuntimeError("address bundle generation failed")
        # Keep producer descriptors writable for cleanup; only sealed copies are imported.
        with memory_file("client-bundle",os.pread(client_public,20000,0),sealed=True) as cb, \
         memory_file("server-bundle",os.pread(server_public,20000,0),sealed=True) as sb:
            registry=prepare_registry(n,arc,mode,public_fd,seed,execution,client_key,cb,sb)
            yield client_key,server_key,cb,sb,registry


def run_pair(n, arc, mode, public_fd, output_fd, seed, execution, fault=False,
             key_negative_tests=False, vtd_key_check=False, refund_witness_fd=None,
             vtd_relock_level=None, vtd_all=False,participant_fd=None):
    with prepared_pair(n,arc,mode,public_fd,seed,execution) as prepared:
            client_key,server_key,cb,sb,registry=prepared
            if vtd_all:
                if fault or vtd_relock_level is not None or refund_witness_fd is None:
                    raise ValueError("all-VTD gate requires a successful pair and witness storage")
                measured=_ordered_all_vtd_pair(n,arc,mode,public_fd,output_fd,seed,execution,
                    client_key,server_key,cb,sb,refund_witness_fd,registry,participant_fd)
            elif vtd_key_check:
                if fault:
                    raise ValueError("ordered VTD gate expects a successful Pre-swap")
                measured=_ordered_vtd_pair(n,arc,mode,public_fd,output_fd,seed,execution,
                                           client_key,server_key,cb,sb,refund_witness_fd,vtd_relock_level,registry)
            else:
                measured=_run_pair(n, arc, mode, public_fd, output_fd, seed, execution,
                                   client_key, server_key, cb, sb, fault,registry=registry)
            if key_negative_tests:
                # No injected partial faults: rejection must be caused by provisioning.
                wrong_seed=bytes([bytes.fromhex(seed)[0]^1]).hex()+seed[2:]
                for offset,ck,sk,context in (
                    (1,server_key,server_key,seed),
                    (2,client_key,client_key,seed),
                    (3,client_key,server_key,wrong_seed),
                ):
                    with memory_file("rejected-key-output") as rejected:
                        _run_pair(n,arc,mode,public_fd,rejected,context,
                                  20000+execution*4+offset,ck,sk,cb,sb,
                                  expect_reject=True)
                with memory_file("expired-export") as rejected:
                    _run_pair(n,arc,mode,public_fd,rejected,seed,
                              30000+execution,client_key,server_key,cb,sb,
                              export_deadline_ns=1,expect_expired=True)
            return measured


def _ordered_vtd_pair(n,arc,mode,public_fd,output_fd,seed,execution,ck,sk,cb,sb,witness_fd,relock_level=None,registry=None):
    with contextlib.ExitStack() as stack:
        receipt=stack.enter_context(memory_file("refund-receipt"))
        public_inputs=[stack.enter_context(memory_file(name)) for name in
                       ("solver-metadata","solver-setup","solver-proof","solver-result")]
        delayed=None
        if relock_level is not None:
            if witness_fd is None or not 0<=relock_level<n-1:
                raise ValueError("re-lock VTD requires a valid level and witness fixture")
            scalar=os.pread(witness_fd,32,8+32*(n+relock_level))
            if len(scalar)!=32:
                raise ValueError("incomplete delayed witness fixture")
            delayed=stack.enter_context(memory_file("delayed-witness",b"OASISK01"+scalar,sealed=True))
        measured=_ordered_vtd_pair_inner(n,arc,mode,public_fd,output_fd,seed,execution,
                                        ck,sk,cb,sb,receipt,public_inputs,relock_level,delayed,registry)
        if relock_level is not None:
            recovered=os.pread(receipt,41,0)
            if len(recovered)!=40 or recovered[:8]!=b"OASISK01":
                raise AssertionError("missing recovered delayed witness")
            os.pwrite(witness_fd,recovered[8:],8+32*(n+relock_level))
            checked=json.loads(crypto_tool("check",2*n-1,output_fd,witness_fd).stdout)
            if not checked.get("timed_ledger_paths_checked"):
                raise AssertionError("recovered delayed witness was not consumed")
            offset=8+32*(n+relock_level)
            mutated=bytearray(recovered[8:])
            mutated[-1]^=1
            try:
                os.pwrite(witness_fd,mutated,offset)
                rejected=subprocess.run([str(TPC/"bin/host_cycle_tool"),"check",
                    str(2*n-1),str(output_fd),str(witness_fd)],
                    pass_fds=(output_fd,witness_fd),capture_output=True,text=True,timeout=60)
                if rejected.returncode==0:
                    raise AssertionError("mutated recovered delayed witness accepted")
            finally:
                os.pwrite(witness_fd,recovered[8:],offset)
            measured["relock_ledger_check"]=checked
            measured["recovered_relock_level"]=relock_level
            measured["mutated_relock_witness_rejected"]=True
            return measured
        if witness_fd is not None:
            def consume():
                return subprocess.run([str(TPC/"bin/host_cycle_tool"),"check-refund",
                    str(2*n-1),str(output_fd),str(witness_fd),str(receipt)],
                    pass_fds=(output_fd,witness_fd,receipt),capture_output=True,text=True,timeout=60)
            result=consume()
            if result.returncode:
                raise RuntimeError("recovered refund ledger consumption failed")
            checked=json.loads(result.stdout)
            if checked.get("live_refund_checked") is not True:
                raise AssertionError("missing live refund ledger evidence")
            original=os.pread(receipt,1,103)
            os.pwrite(receipt,bytes([original[0]^1]),103)
            if consume().returncode==0:
                raise AssertionError("mutated refund signature accepted")
            os.pwrite(receipt,original,103)
            measured["refund_ledger_check"]=checked
            measured["mutated_refund_rejected"]=True
        return measured


def _ordered_vtd_pair_inner(n,arc,mode,public_fd,output_fd,seed,execution,ck,sk,cb,sb,receipt,public_inputs,
                            relock_level=None,delayed=None,registry=None):
    with _prepared_vtd(n,ck,sk,output_fd,seed,receipt,public_inputs,relock_level,delayed) as job:
        start,finish,prepared=job
        start()
        preswap_start=time.monotonic_ns()
        measured=_run_pair(n,arc,mode,public_fd,output_fd,seed,execution,ck,sk,cb,sb,registry=registry)
        measured.update(finish())
        measured["preparation_before_preswap_verified"]=prepared<=preswap_start
        return measured


def _validate_vtd_admission_metadata(metadata, seed, expected_key):
    if (len(expected_key)!=33 or len(metadata)!=81 or metadata[:8]!=b"OASISVS1" or
            metadata[8:40]!=bytes.fromhex(seed) or metadata[40:73]!=expected_key):
        raise ValueError("prepared VTD does not match admitted context/key")


@contextlib.contextmanager
def _prepared_vtd(n,ck,sk,output_fd,seed,receipt,public_inputs,relock_level=None,delayed=None,expected_key=None):
    solver=None
    seals=fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK
    process=subprocess.Popen([str(TPC/"bin/vtd_integration_test"),str(n),str(ck),
        str(sk if delayed is None else delayed),str(output_fd),seed,str(receipt),*map(str,public_inputs),
        *([] if relock_level is None else [str(relock_level)])],
        pass_fds=(ck,sk if delayed is None else delayed,output_fd,receipt,*public_inputs),stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,text=True,bufsize=1)
    def expect(line):
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout,selectors.EVENT_READ)
            if not selector.select(1800):
                raise TimeoutError(f"VTD timeout awaiting {line}; level={relock_level}")
            observed=process.stdout.readline()
            if not observed:
                raise RuntimeError(f"VTD closed stdout awaiting {line}; "
                                   f"level={relock_level}; exit={process.poll()}")
            if observed.strip()!=line:
                raise RuntimeError(f"VTD unexpected status awaiting {line}; level={relock_level}")
    def start():
        nonlocal solver
        if solver is not None:
            raise RuntimeError("VTD solver already started")
        process.stdin.write("S"); process.stdin.flush()
        expect("VTD_SOLVER_STARTING")
        solver=subprocess.Popen([str(TPC/"bin/vtd_public_solver"),*map(str,public_inputs)],
            pass_fds=tuple(public_inputs),stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)

    def finish():
        if solver is None:
            raise RuntimeError("VTD solver not started")
        solver_stdout,_=solver.communicate(timeout=1800)
        if solver.returncode:
            raise RuntimeError("public-input VTD solver failed")
        solver_evidence=json.loads(solver_stdout)
        if solver_evidence.get("public_input_solver") is not True or solver_evidence.get("squarings")!=32:
            raise AssertionError("missing external solver work evidence")
        fcntl.fcntl(public_inputs[3],fcntl.F_ADD_SEALS,seals)
        stdout,_=process.communicate(input="D",timeout=1800)
        if process.returncode:
            raise RuntimeError("ordered VTD composition gate failed")
        checked=json.loads(stdout.strip().splitlines()[-1])
        binding="live_final_key_binding" if relock_level is None else "live_relock_statement_binding"
        if not checked.get(binding) or not checked.get("prepared_before_preswap"):
            raise AssertionError("missing ordered VTD/key binding evidence")
        if checked.get("decoded_public_proof_used") is not True:
            raise AssertionError("VTD gate did not use the decoded public proof")
        if checked.get("external_solver_used") is not True:
            raise AssertionError("refund did not consume the external solver result")
        return {"external_solver_check":solver_evidence,"vtd_key_composition_check":checked}

    try:
        expect("VTD_PREPARED")
        for fd in public_inputs[:3]:
            fcntl.fcntl(fd,fcntl.F_ADD_SEALS,seals)
        if expected_key is not None:
            _validate_vtd_admission_metadata(os.pread(public_inputs[0],82,0), seed, expected_key)
        yield start,finish,time.monotonic_ns()
    finally:
        if solver is not None:
            if solver.poll() is None:
                solver.kill()
            solver.communicate()
        if process.poll() is None:
            process.kill()
        process.communicate()


@contextlib.contextmanager
def _funded_ledger(n,registry,output_fd,witness_fd,refund_fd):
    order=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    wallet=b"OASISK01"+(secrets.randbelow(order-1)+1).to_bytes(32,"big")
    with memory_file("lock-wallet",wallet,sealed=True) as key, \
         memory_file("funding-registry",registry,sealed=True) as prepared:
        process=subprocess.Popen([str(TPC/"bin/host_cycle_tool"),"funded-check",str(2*n-1),
            str(prepared),str(key),str(output_fd),str(witness_fd),str(refund_fd)],
            pass_fds=(prepared,key,output_fd,witness_fd,refund_fd),stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout,selectors.EVENT_READ)
                if not selector.select(60) or process.stdout.readline().strip()!="LOCK_ACCEPTED":
                    raise RuntimeError("native signed lock admission failed")
            def consume():
                stdout,_=process.communicate(input="C",timeout=60)
                if process.returncode<0:
                    raise RuntimeError("native funded ledger terminated by signal")
                if process.returncode:
                    raise RuntimeError("retained funded ledger rejected handoff")
                checked=json.loads(stdout.strip().splitlines()[-1])
                if not checked.get("retained_funded_ledger") or not checked.get("live_refund_checked"):
                    raise AssertionError("missing funded ledger completion evidence")
                return checked
            yield consume
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate()


def _validate_abort_report(report, n):
    if not isinstance(report, dict):
        raise ValueError("invalid native abort report")
    counts = [report.get(key) for key in ("locked_arcs", "withdrawn_arcs", "refunded_arcs")]
    if (report.get("retained_cycle_abort_observed") is not True or
            report.get("automatic_refund_performed") is not False or
            any(type(value) is not int or value < 0 for value in counts) or
            sum(counts) != n):
        raise ValueError("incomplete native abort report")
    return report


@contextlib.contextmanager
def _funded_cycle_recovery(n,arcs,participant_fd,*,retry_test=False,all_honest=False,refund_cycle=False):
    """Retain one ledger per arc; consume only after all live inputs are ready."""
    order=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    if len(arcs)!=n:
        raise ValueError("incomplete cycle")
    if refund_cycle and (all_honest or retry_test):
        raise ValueError("refund requires a separate cycle outcome")
    if refund_cycle:
        for arc in arcs:
            jobs=arc.get("jobs", [])
            if not jobs or len(jobs[-1])!=3 or jobs[-1][0] is not None:
                raise ValueError("refund requires the final-key VTD receipt")
            receipt=jobs[-1][1]
            if type(receipt) is not int or receipt<0:
                raise ValueError("invalid final-key VTD receipt descriptor")
            os.fstat(receipt)
    with contextlib.ExitStack() as stack:
        fds=[]
        for i,a in enumerate(arcs):
            registry=stack.enter_context(memory_file("cycle-registry",a["registry"],sealed=True))
            wallet=stack.enter_context(memory_file("cycle-wallet",b"OASISK01"+
                (secrets.randbelow(order-1)+1).to_bytes(32,"big"),sealed=True))
            if refund_cycle:
                identity=a["jobs"][-1][1]
            else:
                scalar=os.pread(participant_fd,32,12+64*i+32)
                if len(scalar)!=32:
                    raise ValueError("missing participant identifier")
                identity=stack.enter_context(memory_file("cycle-identifier",b"OASISK01"+scalar,sealed=True))
            fds.extend((registry,wallet,a["output"],a["witness"],identity))
        command="funded-cycle-recovery-retry-test" if retry_test else "funded-cycle-recovery"
        if all_honest:
            command="funded-cycle-withdrawal-retry-test" if retry_test else "funded-cycle-withdrawal"
        if refund_cycle:
            command="funded-cycle-refund"
        process=subprocess.Popen([str(TPC/"bin/host_cycle_tool"),command,
            str(2*n-1),*map(str,fds)],pass_fds=tuple(fds),stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout,selectors.EVENT_READ)
                if not selector.select(60) or process.stdout.readline().strip()!="LOCK_ACCEPTED":
                    raise RuntimeError("native cycle funding rejected")
            def consume():
                for a in arcs:
                    inputs=(a["output"],a["witness"])
                    if refund_cycle:
                        inputs+= (a["jobs"][-1][1],)
                    for fd in inputs:
                        fcntl.fcntl(fd,fcntl.F_ADD_SEALS,
                            fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK)
                stdout,_=process.communicate(input="C",timeout=120)
                if process.returncode:
                    raise RuntimeError(f"native cycle recovery failed: exit={process.returncode}")
                checked=json.loads(stdout)
                evidence_key="retained_cycle_withdrawal" if all_honest else "retained_cycle_recovery"
                if refund_cycle:
                    evidence_key="retained_cycle_refund"
                count_key="refunded_arcs" if refund_cycle else "withdrawn_arcs"
                if not checked.get(evidence_key) or checked.get(count_key)!=n:
                    raise AssertionError("incomplete recovered cycle")
                if refund_cycle and checked.get("withdrawn_arcs")!=0:
                    raise AssertionError("refund cycle unexpectedly contains withdrawals")
                return checked
            try:
                yield consume
            except BaseException:
                if process.poll() is None:
                    try:
                        stdout,_=process.communicate(input="A",timeout=10)
                        if process.returncode!=0:
                            raise ValueError("native abort observation failed")
                        aborted=_validate_abort_report(json.loads(stdout), n)
                        print("retained_cycle_abort="+json.dumps(aborted),file=sys.stderr,flush=True)
                    except (OSError,ValueError,subprocess.TimeoutExpired):
                        print("retained_cycle_abort_state=unavailable",file=sys.stderr,flush=True)
                raise
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate()


def _prepare_vtd_jobs(stack,n,ck,sk,output_fd,seed,witness_fd,registry=None,server_bundle=None):
    if (registry is None) != (server_bundle is None):
        raise ValueError("VTD admission requires both registry and server bundle")
    if registry is not None:
        if (len(registry)!=REGISTRY_HEADER_BYTES+REGISTRY_RECORD_BYTES*(2*n-1) or
                registry[:8]!=REGISTRY_MAGIC or
                int.from_bytes(registry[8:12],"big")!=2*n-1):
            raise ValueError("invalid VTD expected registry")
        bundle_size=os.fstat(server_bundle).st_size
        bundle=os.pread(server_bundle,bundle_size+1,0)
        if (len(bundle)!=bundle_size or bundle_size<12+65*n or (bundle_size-12)%n or
                bundle[:8]!=b"OASISAP1" or
                int.from_bytes(bundle[8:12],"big")!=n):
            raise ValueError("invalid admitted responder bundle")
        # Native admission validates the proof; its scalar width is build-dependent.
        bundle_stride=(bundle_size-12)//n
    jobs=[]
    for level in [*range(n-1),None]:
        receipt=stack.enter_context(memory_file("vtd-consumer-result"))
        inputs=[stack.enter_context(memory_file(name)) for name in
            ("solver-metadata","solver-setup","solver-proof","solver-result")]
        delayed=None
        if level is not None:
            scalar=os.pread(witness_fd,32,8+32*(n+level))
            if len(scalar)!=32:
                raise ValueError("incomplete delayed witness fixture")
            delayed=stack.enter_context(memory_file("delayed-witness",b"OASISK01"+scalar,sealed=True))
        expected=None
        if registry is not None:
            expected=(bundle[12+bundle_stride*(n-1):12+bundle_stride*(n-1)+33] if level is None else
                      registry[REGISTRY_HEADER_BYTES+REGISTRY_RECORD_BYTES*(n+level)+
                              STATEMENT_OFFSET:
                              REGISTRY_HEADER_BYTES+REGISTRY_RECORD_BYTES*(n+level)+
                              STATEMENT_OFFSET+33])
        job=stack.enter_context(_prepared_vtd(n,ck,sk,output_fd,seed,receipt,inputs,level,delayed,expected))
        jobs.append((level,receipt,job))
    return jobs


def _ordered_all_vtd_pair(n,arc,mode,public_fd,output_fd,seed,execution,ck,sk,cb,sb,witness_fd,registry=None,participant_fd=None):
    """All n VTDs around one live pair; controlled ledger, not all-party execution."""
    with contextlib.ExitStack() as stack:
        jobs=_prepare_vtd_jobs(stack,n,ck,sk,output_fd,seed,witness_fd,
                               registry=registry,server_bundle=sb if registry is not None else None)
        funded=stack.enter_context(_funded_ledger(n,registry,output_fd,witness_fd,jobs[-1][1])) \
            if registry is not None else None
        for _,_,(start,_,_) in jobs:
            start()
        preswap_start=time.monotonic_ns()
        measured=_run_pair(n,arc,mode,public_fd,output_fd,seed,execution,ck,sk,cb,sb,registry=registry)
        if participant_fd is not None:
            os.pwrite(witness_fd,bytes(32),8)
            measured["witness_sharing_check"]=receive_live_witness(n,arc,participant_fd,output_fd,witness_fd)
        evidence=[]
        for level,receipt,(_,finish,prepared) in jobs:
            checked=finish()
            checked.update({"relock_level":level,"prepared_before_preswap":prepared<=preswap_start})
            evidence.append(checked)
            if level is not None:
                recovered=os.pread(receipt,41,0)
                if len(recovered)!=40 or recovered[:8]!=b"OASISK01":
                    raise AssertionError("missing recovered delayed witness")
                os.pwrite(witness_fd,recovered[8:],8+32*(n+level))
        refund=jobs[-1][1]
        def consume():
            return subprocess.run([str(TPC/"bin/host_cycle_tool"),"check-refund",
                str(2*n-1),str(output_fd),str(witness_fd),str(refund)],
                pass_fds=(output_fd,witness_fd,refund),capture_output=True,text=True,timeout=60)
        result=consume()
        if result.returncode:
            raise RuntimeError("all-VTD ledger consumption failed")
        ledger=json.loads(result.stdout)
        if not ledger.get("live_refund_checked") or not ledger.get("timed_ledger_paths_checked"):
            raise AssertionError("missing all-VTD ledger evidence")
        if funded is not None:
            measured["funded_ledger_check"]=funded()
            measured["lock_ack_before_preswap"]=True
        for level in range(n-1):
            offset=8+32*(n+level)
            original=os.pread(witness_fd,32,offset)
            mutated=bytearray(original); mutated[-1]^=1
            try:
                os.pwrite(witness_fd,mutated,offset)
                rejection=consume()
                if rejection.returncode<=0:
                    raise AssertionError("invalid re-lock witness was accepted or consumer crashed")
            finally:
                os.pwrite(witness_fd,original,offset)
        measured.update({"all_vtds_prepared":n,"preswap_executions":1,
            "vtd_checks":evidence,"all_vtd_ledger_check":ledger,
            "mutated_relock_witnesses_rejected":n-1,"full_lifecycle":False,
            "timed_privacy_benchmarked":False})
        return measured


def _pair_options(n,arc,mode,public_fd,seed,execution,client_public,server_public):
    # Native IPC has no WAN timing interpretation.
    port = 20000 + os.getpid() % 30000
    return [
        "--mode", mode, "--count", str(2*n-1), "--context-participants", str(n),
        "--context-seed-hex", seed, "--pair-id", str(arc),
        "--context-arc-index", str(arc+1), "--execution-id", str(execution),
        "--port", str(port), "--io-timeout-ms", "3000",
        "--completion-ack-timeout-ms", "1000", "--completion-retries", "0",
        "--host-statements", f"/proc/self/fd/{public_fd}",
        "--host-client-keys-fd",str(client_public),
        "--host-server-keys-fd",str(server_public),
        "--context-epoch","1",
    ]


def prepare_registry(n,arc,mode,public_fd,seed,execution,client_key,client_public,server_public):
    with memory_file("prepared-registry") as output:
        common=_pair_options(n,arc,mode,public_fd,seed,execution,client_public,server_public)
        result=subprocess.run([str(TPC/"bin/host_cycle_tool"),"prepare-registry",*common,
            "--host-address-keys-fd",str(client_key),"--host-output-fd",str(output)],
            pass_fds=(public_fd,client_key,client_public,server_public,output),
            capture_output=True,timeout=60)
        if result.returncode:
            raise RuntimeError("native registry preparation failed")
        registry=os.pread(output,
            REGISTRY_HEADER_BYTES+REGISTRY_RECORD_BYTES*(2*n-1),0)
        if len(registry)!=REGISTRY_HEADER_BYTES+REGISTRY_RECORD_BYTES*(2*n-1) or \
                registry[:8]!=REGISTRY_MAGIC or \
                int.from_bytes(registry[8:12],"big")!=2*n-1:
            raise AssertionError("malformed prepared registry")
        return registry


def validate_registry_handoff(registry,handoff):
    if len(registry)<REGISTRY_HEADER_BYTES or registry[:8]!=REGISTRY_MAGIC:
        raise ValueError("invalid registry header")
    count=int.from_bytes(registry[8:12],"big")
    if count<5 or count>255 or not count%2 or \
            len(registry)!=REGISTRY_HEADER_BYTES+REGISTRY_RECORD_BYTES*count or \
            len(handoff)!=HANDOFF_HEADER_BYTES+HANDOFF_RECORD_BYTES*count or \
            handoff[:8]!=HANDOFF_MAGIC or \
            registry[12:108]!=handoff[8:104]:
        raise ValueError("handoff does not match prepared registry")
    for i in range(count):
        if registry[REGISTRY_HEADER_BYTES+REGISTRY_RECORD_BYTES*i:
                    REGISTRY_HEADER_BYTES+REGISTRY_RECORD_BYTES*(i+1)] != \
                handoff[HANDOFF_HEADER_BYTES+HANDOFF_RECORD_BYTES*i:
                        HANDOFF_HEADER_BYTES+HANDOFF_RECORD_BYTES*i+REGISTRY_RECORD_BYTES]:
            raise ValueError("handoff item does not match prepared registry")


def _run_pair(n, arc, mode, public_fd, output_fd, seed, execution,
              client_key, server_key, client_public, server_public, fault=False,
              expect_reject=False,export_deadline_ns=None,expect_expired=False,registry=None,
              io_timeout_ms=3000,completion_ack_timeout_ms=1000,process_timeout_seconds=60):
    if not (0<io_timeout_ms<=2147483647 and 0<completion_ack_timeout_ms<=2147483647
            and process_timeout_seconds>0):
        raise ValueError("invalid native process or I/O timeout")
    common=_pair_options(n,arc,mode,public_fd,seed,execution,client_public,server_public)
    common[common.index("--io-timeout-ms")+1]=str(io_timeout_ms)
    common[common.index("--completion-ack-timeout-ms")+1]=str(completion_ack_timeout_ms)
    server = subprocess.Popen(
        [str(TPC / "bin/preswap_server"), *common, "--host-address-keys-fd", str(server_key)], cwd=TPC,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        pass_fds=(public_fd, server_key, client_public,server_public),
    )
    try:
        args = [str(TPC / "bin/preswap_client"), *common,
                "--host-address-keys-fd", str(client_key),
                "--host-output-fd", str(output_fd)]
        if export_deadline_ns is None:
            export_deadline_ns=time.monotonic_ns()+int(process_timeout_seconds*1_000_000_000)
        args.extend(["--host-export-deadline-ns",str(export_deadline_ns)])
        if fault:
            args.append("--inject-bad-final")
        client = subprocess.run(
            args, cwd=TPC, pass_fds=(public_fd, output_fd, client_key, server_public,client_public),
            capture_output=True, text=True, timeout=process_timeout_seconds,
        )
        server.communicate(timeout=process_timeout_seconds)
        if fault or expect_reject or expect_expired:
            if client.returncode == 0 or os.fstat(output_fd).st_size != 0:
                raise AssertionError("failed parent exported a host vector")
            if expect_reject and server.returncode == 0:
                raise AssertionError("server accepted invalid key provisioning")
            if expect_expired and server.returncode != 0:
                raise AssertionError("expiry test did not complete the responder protocol")
            return {}
        if client.returncode or server.returncode:
            raise RuntimeError(f"native peer rejected the host session: arc={arc} "
                f"client_exit={client.returncode} server_exit={server.returncode} "
                f"io_timeout_ms={io_timeout_ms} ack_timeout_ms={completion_ack_timeout_ms}")
        if time.monotonic_ns()>=export_deadline_ns:
            os.ftruncate(output_fd,0)
            raise RuntimeError("host admission cutoff expired")
        if registry is not None:
            try:
                validate_registry_handoff(
                    registry,os.pread(output_fd,
                        HANDOFF_HEADER_BYTES+HANDOFF_RECORD_BYTES*(2*n-1),0))
            except ValueError:
                os.ftruncate(output_fd,0)
                raise
        result = next((line.split("\t") for line in client.stdout.splitlines()
                       if line.startswith("RESULT\t")), None)
        if result is None or len(result) != 10:
            raise RuntimeError("missing native timing record")
        return {"preswap_wall_ns": int(result[4]),"prepared_registry_matches_handoff":registry is not None,
                "io_timeout_ms":io_timeout_ms,"completion_ack_timeout_ms":completion_ack_timeout_ms,
                "process_timeout_seconds":process_timeout_seconds}
    finally:
        if server.poll() is None:
            server.kill()
        server.communicate()


def validate_address_keys(output_fd, n):
    for level in range(n-1):
        withdraw = os.pread(output_fd, 33,
                            HANDOFF_HEADER_BYTES+HANDOFF_RECORD_BYTES*level+
                            JOINT_KEY_OFFSET)
        relock = os.pread(output_fd, 33,
                          HANDOFF_HEADER_BYTES+HANDOFF_RECORD_BYTES*(n+level)+
                          JOINT_KEY_OFFSET)
        if len(withdraw) != 33 or withdraw != relock:
            raise AssertionError("withdraw/relock do not share their source address")


def receive_live_witness(n,arc,participant_fd,output_fd,witness_fd):
    """Authenticated senders in one native fixture process, not distributed custody."""
    if not 3<=n<=128 or not 0<=arc<n:
        raise ValueError("invalid live witness participant configuration")
    with memory_file("witness-participants",os.pread(participant_fd,13+64*n,0),sealed=True) as participants, \
         memory_file("witness-handoff",os.pread(
             output_fd,HANDOFF_HEADER_BYTES+HANDOFF_RECORD_BYTES*(2*n-1),0),
             sealed=True) as handoff:
        result=subprocess.run([str(TPC/"bin/host_witness_transport_test"),str(participants),
            str(handoff),str(witness_fd),str((arc+1)%n)],pass_fds=(participants,handoff,witness_fd),
            capture_output=True,text=True,timeout=30)
        if result.returncode<0:
            raise AssertionError("native witness gate terminated by signal")
        if result.returncode:
            stages={"setup","curve-key","scalar","zap","bind","connect","send","receive","impersonation","unknown-key","compose"}
            stage=next((line.split("=",1)[1] for line in result.stderr.splitlines()
                if line.startswith("WITNESS_GATE_STAGE=") and line.split("=",1)[1] in stages),"unknown")
            raise RuntimeError(f"authenticated live witness gate failed: {stage}")
        checked=json.loads(result.stdout.strip().splitlines()[-1])
        if not checked.get("live_withdrawal_witness"):
            raise AssertionError("missing live witness composition evidence")
        return checked


def campaign(n, modes=MODES, negative_tests=False):
    if not 3 <= n <= 128 or not modes or any(mode not in MODES for mode in modes):
        raise ValueError("unsupported native handoff configuration")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    count = 2*n-1
    samples = []
    if negative_tests:
        order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        valid_key = b"OASISK01" + (1).to_bytes(32, "big")
        invalid_keys = (
            (valid_key, False),
            (b"OASISK01" + bytes(32), True),
            (b"OASISK01" + order.to_bytes(32, "big"), True),
            (valid_key[:-1], True), (valid_key + b"\x00", True),
            (b"INVALID!" + valid_key[8:], True),
        )
        for payload, sealed in invalid_keys:
            with memory_file("invalid-key", payload, sealed=sealed) as key, \
                 memory_file("invalid-key-public") as public_key:
                if crypto_tool("key-public", 1, key, public_key, False).returncode == 0:
                    raise AssertionError("invalid or mutable private key accepted")
                if os.fstat(public_key).st_size:
                    raise AssertionError("invalid key produced a public output")
        with tempfile.TemporaryFile() as disk, memory_file("reject-disk") as anonymous:
            if crypto_tool("prepare", n, disk.fileno(), anonymous, False).returncode == 0:
                raise AssertionError("native helper accepted a disk descriptor")
            if os.fstat(disk.fileno()).st_size or os.fstat(anonymous).st_size:
                raise AssertionError("rejected descriptor produced data")
    with memory_file("witnesses") as private, memory_file("public") as public:
        started = time.monotonic_ns()
        crypto_tool("prepare", n, private, public)
        preparation_ns = time.monotonic_ns() - started
        public_vector = os.pread(public, 8+n*count*33, 0)
        if len(public_vector) != 8+n*count*33:
            raise RuntimeError("incomplete preparation vector")
        seed = hashlib.sha256(public_vector).hexdigest()
        for mode_index, mode in enumerate(modes):
            for arc in range(n):
                with memory_file("arc-public", b"OASISP01" +
                                 public_vector[8+arc*count*33:8+(arc+1)*count*33]) as points, \
                     memory_file("arc-witness", b"OASISW01" +
                                 os.pread(private, count*32, 8+arc*count*32)) as witnesses, \
                     memory_file("presignatures") as handoff:
                    measured = run_pair(n, arc, mode, points, handoff, seed,
                                        1+mode_index*n+arc,
                                        key_negative_tests=negative_tests and arc==0)
                    validate_address_keys(handoff, n)
                    checked = json.loads(crypto_tool("check", count, handoff, witnesses).stdout)
                    if checked["verified_items"] != count:
                        raise AssertionError("incomplete adapted vector")
                    if checked.get("signed_ledger_paths_checked") is not True:
                        raise AssertionError("live ledger paths were not checked")
                    if checked.get("accepted_withdrawal_extraction") is not True:
                        raise AssertionError("accepted withdrawal extraction was not checked")
                    if (checked.get("timed_ledger_paths_checked") is not True or
                            checked.get("ledger_clock") != "controlled_fixture"):
                        raise AssertionError("timed ledger conformance evidence missing")
                    samples.append({"mode": mode, "n": n, "k": count, "arc": arc,
                                    **measured, **checked})
                    if negative_tests:
                        original = os.pread(witnesses, 32, 8)
                        os.pwrite(witnesses, bytes(32), 8)
                        if crypto_tool("check", count, handoff, witnesses, False).returncode == 0:
                            raise AssertionError("zero witness accepted")
                        os.pwrite(witnesses, original, 8)
                        original = os.pread(
                            handoff, 1,
                            HANDOFF_HEADER_BYTES+SCALAR_OFFSET+31)
                        os.pwrite(handoff, bytes([original[0] ^ 1]),
                                  HANDOFF_HEADER_BYTES+SCALAR_OFFSET+31)
                        if crypto_tool("check", count, handoff, witnesses, False).returncode == 0:
                            raise AssertionError("mutated pre-signature accepted")
                if negative_tests:
                    with memory_file("arc-public", b"OASISP01" +
                                     public_vector[8+arc*count*33:8+(arc+1)*count*33]) as points, \
                         memory_file("failed-presignatures") as handoff:
                        run_pair(n, arc, mode, points, handoff, seed,
                                 10000+mode_index*n+arc, fault=True)
    return {
        "schema": "oasis-live-handoff-v2", "transport": "local ZeroMQ IPC",
        "purpose": "correctness gate, not a performance campaign",
        "scope": "live Adapt/Extract plus signed withdrawal/relock ledger paths",
        "full_lifecycle": False, "vtd_integrated": False,
        "host_provisioned_independent_address_keys": True,
        "baseline": "same-backend native reference; not unchanged AE TPC execution",
        "secret_handling": "synthetic witnesses in anonymous memory; core dumps disabled",
        "preparation_process_wall_ns": preparation_ns,
        "timing_note": "Pre-swap and post-processing separate; no WAN or full-cycle claim",
        "negative_tests": negative_tests, "samples": samples,
        "live_key_provisioning_negatives": negative_tests,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--participants", type=int, default=3)
    parser.add_argument("--negative-tests", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output exists; use a new evidence path")
    result = campaign(args.participants, negative_tests=args.negative_tests)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(f"wrote={args.output}")


if __name__ == "__main__":
    main()
