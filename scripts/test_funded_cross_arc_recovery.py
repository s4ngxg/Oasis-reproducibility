#!/usr/bin/env python3
"""Live cross-arc recovery retaining signed funding through Pre-swap.

Uses centralized three-participant fixtures and controlled ledger deadlines.
Delayed re-lock witnesses are fixtures here, not VTD solver outputs.
"""
import contextlib
import fcntl
import hashlib
import json
import os
import resource
import secrets
import selectors
import subprocess

from run_native_handoff import TPC,MODES,memory_file,prepared_pair,_run_pair


def main():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    order=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    cases=0
    with memory_file("private") as private,memory_file("public") as public, \
         memory_file("participants") as participants:
        prep=subprocess.run([str(TPC/"bin/host_cycle_tool"),"prepare-participants","3",
            str(private),str(public),str(participants)],pass_fds=(private,public,participants),
            capture_output=True,timeout=60)
        if prep.returncode:
            raise RuntimeError("Preparation failed")
        vector=os.pread(public,503,0)
        seed=hashlib.sha256(vector).hexdigest()
        for mode in MODES:
            for level,fault in ((0,None),(1,None),(0,"handoff"),(0,"identifier")):
                with contextlib.ExitStack() as stack:
                    arcs=[]
                    for arc in (0,1):
                        points=stack.enter_context(memory_file("points",b"OASISP01"+vector[8+165*arc:8+165*(arc+1)]))
                        output=stack.enter_context(memory_file("handoff"))
                        keys=stack.enter_context(prepared_pair(3,arc,mode,points,seed,600000+cases*2+arc))
                        registry=stack.enter_context(memory_file("registry",keys[-1],sealed=True))
                        wallet=stack.enter_context(memory_file("wallet",b"OASISK01"+
                            (secrets.randbelow(order-1)+1).to_bytes(32,"big"),sealed=True))
                        values=os.pread(private,160,8+160*arc)
                        if arc==0:
                            values=bytes(96)+values[96:]
                        witness=stack.enter_context(memory_file("witness",b"OASISW01"+values,sealed=True))
                        arcs.append((points,output,keys,registry,wallet,witness))
                    local=bytearray(os.pread(participants,32,12+64+32))
                    if fault=="identifier":
                        local[-1]^=1
                    identity=stack.enter_context(memory_file("identifier",b"OASISK01"+local,sealed=True))
                    fds=tuple(arcs[i][j] for j in (3,4,1,5) for i in (0,1))+(identity,)
                    process=subprocess.Popen([str(TPC/"bin/host_cycle_tool"),"funded-recovery",
                        "5",str(level),*map(str,fds)],pass_fds=fds,stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
                    try:
                        with selectors.DefaultSelector() as selector:
                            selector.register(process.stdout,selectors.EVENT_READ)
                            if not selector.select(60) or process.stdout.readline().strip()!="LOCK_ACCEPTED":
                                raise RuntimeError("two-arc signed funding rejected")
                        for arc,(points,output,keys,_,_,_) in enumerate(arcs):
                            ck,sk,cb,sb,registry=keys
                            _run_pair(3,arc,mode,points,output,seed,600000+cases*2+arc,
                                ck,sk,cb,sb,registry=registry)
                            if fault=="handoff" and arc==0:
                                value=os.pread(output,1,8)
                                os.pwrite(output,bytes([value[0]^1]),8)
                            fcntl.fcntl(output,fcntl.F_ADD_SEALS,
                                fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK)
                        stdout,_=process.communicate(input="C",timeout=60)
                        if process.returncode<0:
                            raise AssertionError("native recovery crashed")
                        if fault:
                            if process.returncode==0:
                                raise AssertionError("invalid recovery accepted")
                        else:
                            if process.returncode or not json.loads(stdout).get("cross_arc_recovery"):
                                raise AssertionError("funded recovery failed")
                        cases+=1
                    finally:
                        if process.poll() is None:
                            process.kill()
                        process.communicate()
    print(json.dumps(dict(cases=cases,modes=len(MODES),signed_locks_before_preswap=True,
        retained_cross_arc_ledgers=True,incoming_withdrawal_witnesses_zeroed=True,
        mutated_handoff_rejected=True,wrong_identifier_rejected=True,
        vtd_solver_outputs_used=False,full_lifecycle=False)))


if __name__=="__main__":
    main()
