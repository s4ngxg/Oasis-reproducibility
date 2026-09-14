#!/usr/bin/env python3
"""Native one-ledger-per-arc recovery gate; delayed values remain fixtures."""
import contextlib
import argparse
import hashlib
import json
import os
import resource
import subprocess

from run_native_handoff import TPC,MODES,memory_file,prepared_pair,_funded_cycle_recovery,_run_pair,receive_live_witness


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--participants",type=int,default=3,choices=range(3,129))
    parser.add_argument("--all-honest",action="store_true")
    args=parser.parse_args()
    n=args.participants
    k=2*n-1
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    cases=0
    with memory_file("private") as private,memory_file("public") as public, \
         memory_file("participants") as participants:
        result=subprocess.run([str(TPC/"bin/host_cycle_tool"),"prepare-participants",str(n),
            str(private),str(public),str(participants)],pass_fds=(private,public,participants),
            capture_output=True,timeout=60)
        if result.returncode:
            raise RuntimeError("Preparation failed")
        vector=os.pread(public,8+n*k*33,0)
        if len(vector)!=8+n*k*33 or vector[:8]!=b"OASISP01":
            raise RuntimeError("invalid Preparation point vector")
        seed=hashlib.sha256(vector).hexdigest()
        for mode in MODES:
            for corrupt in (False,True):
                with contextlib.ExitStack() as stack:
                    arcs=[]
                    for i in range(n):
                        points=stack.enter_context(memory_file("points",b"OASISP01"+vector[8+k*33*i:8+k*33*(i+1)]))
                        output=stack.enter_context(memory_file("output"))
                        values=bytearray(os.pread(private,k*32,8+k*32*i))
                        if len(values)!=k*32:
                            raise RuntimeError("incomplete Preparation witness vector")
                        start=32 if i==0 else 0
                        values[start:n*32]=bytes(n*32-start)
                        if corrupt and i==1 and not args.all_honest:
                            values[-1]^=1
                        witness=stack.enter_context(memory_file("witness",b"OASISW01"+values))
                        keys=stack.enter_context(prepared_pair(n,i,mode,points,seed,500000+cases*n+i))
                        arcs.append(dict(points=points,output=output,witness=witness,registry=keys[-1],keys=keys))
                    consume=stack.enter_context(_funded_cycle_recovery(n,arcs,participants,
                        retry_test=not corrupt,all_honest=args.all_honest))
                    for i,a in enumerate(arcs):
                        ck,sk,cb,sb,registry=a["keys"]
                        _run_pair(n,i,mode,a["points"],a["output"],seed,500000+cases*n+i,
                            ck,sk,cb,sb,registry=registry,io_timeout_ms=30000,
                            completion_ack_timeout_ms=10000,process_timeout_seconds=120)
                    if args.all_honest:
                        for i,a in enumerate(arcs):
                            os.pwrite(a["witness"],bytes(32),8)
                            receive_live_witness(n,i,participants,a["output"],a["witness"])
                        if corrupt:
                            os.pwrite(arcs[-1]["witness"],bytes(32),8)
                    if corrupt:
                        try:
                            consume()
                        except RuntimeError as error:
                            if "exit=1" not in str(error):
                                raise
                        else:
                            raise AssertionError("wrong delayed witness accepted")
                    else:
                        evidence=consume()
                        hops=0 if args.all_honest else n-1
                        if evidence["withdrawn_arcs"]!=n or evidence["observed_withdrawal_hops"]!=hops:
                            raise AssertionError("incomplete cycle")
                    cases+=1
    print(json.dumps(dict(participants=n,k=k,cases=cases,modes=len(MODES),one_retained_ledger_per_arc=True,
        all_honest=args.all_honest,network_witnesses=args.all_honest,
        only_initial_withdrawal_witness_supplied=not args.all_honest,
        invalid_witness_rejected=True,retained_partial_failure_retry=True,
        vtd_solver_outputs_used=False,full_lifecycle=False)))


if __name__=="__main__":
    main()
