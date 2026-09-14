#!/usr/bin/env python3
"""Isolate live Pre-swap while all arc ledgers retain accepted funding."""
import contextlib
import hashlib
import json
import os
import resource
import subprocess

from run_native_handoff import TPC,MODES,memory_file,prepared_pair,_funded_ledger,_run_pair


def main():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    cases=0
    with memory_file("private") as private,memory_file("public") as public:
        result=subprocess.run([str(TPC/"bin/host_cycle_tool"),"prepare","3",str(private),str(public)],
            pass_fds=(private,public),capture_output=True,timeout=60)
        if result.returncode:
            raise RuntimeError("Preparation failed")
        vector=os.pread(public,8+15*33,0)
        seed=hashlib.sha256(vector).hexdigest()
        for mode in MODES:
            with contextlib.ExitStack() as stack:
                arcs=[]
                for arc in range(3):
                    points=stack.enter_context(memory_file("points",b"OASISP01"+vector[8+165*arc:8+165*(arc+1)]))
                    output=stack.enter_context(memory_file("handoff"))
                    witness=stack.enter_context(memory_file("witness",b"OASISW01"+os.pread(private,160,8+160*arc)))
                    refund=stack.enter_context(memory_file("refund"))
                    keys=stack.enter_context(prepared_pair(3,arc,mode,points,seed,800000+arc))
                    arcs.append((points,output,witness,refund,keys))
                for points,output,witness,refund,keys in arcs:
                    stack.enter_context(_funded_ledger(3,keys[-1],output,witness,refund))
                for arc,(points,output,_,_,keys) in enumerate(arcs):
                    ck,sk,cb,sb,registry=keys
                    _run_pair(3,arc,mode,points,output,seed,800000+arc,ck,sk,cb,sb,registry=registry,
                        io_timeout_ms=30000,completion_ack_timeout_ms=10000,process_timeout_seconds=120)
                    cases+=1
    print(json.dumps(dict(retained_funding_preswap_cases=cases,modes=len(MODES),
        vtd_exercised=False,ledger_consumption_exercised=False,full_lifecycle=False)))


if __name__=="__main__":
    main()
