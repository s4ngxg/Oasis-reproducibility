#!/usr/bin/env python3
"""Observed-withdrawal recovery using live handoffs, not a complete host lifecycle."""
import argparse
import contextlib
import hashlib
import json
import os
import resource
import subprocess
from run_native_handoff import (
    HANDOFF_HEADER_BYTES,
    HANDOFF_RECORD_BYTES,
    TPC, MODES, memory_file, prepared_pair, _run_pair,
)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--participants",type=int,default=3)
    args=parser.parse_args()
    n=args.participants
    if not 3<=n<=128:
        parser.error("participants must be between 3 and 128")
    k=2*n-1
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    checked=0
    with contextlib.ExitStack() as stack:
        private=stack.enter_context(memory_file("preparation-secrets"))
        public=stack.enter_context(memory_file("preparation-public"))
        participants=stack.enter_context(memory_file("participant-secrets"))
        prepared=subprocess.run([str(TPC/"bin/host_cycle_tool"),"prepare-participants",str(n),
            str(private),str(public),str(participants)],pass_fds=(private,public,participants),
            capture_output=True,timeout=60)
        if prepared.returncode:
            raise RuntimeError("preparation failed")
        vector=os.pread(public,8+n*k*33,0)
        seed=hashlib.sha256(vector).hexdigest()
        for mode in MODES:
            with contextlib.ExitStack() as modes:
                handoffs=[]
                admitted=[]
                for arc in range(n):
                    points=modes.enter_context(memory_file("arc-public",
                        b"OASISP01"+vector[8+33*k*arc:8+33*k*(arc+1)]))
                    execution=900000+checked+arc
                    prepared=modes.enter_context(prepared_pair(n,arc,mode,points,seed,execution))
                    admitted.append((points,execution,prepared))
                # No pair starts until every arc's keys and registry are admitted.
                for arc,(points,execution,prepared) in enumerate(admitted):
                    ck,sk,cb,sb,registry=prepared
                    with memory_file("live-handoff") as output:
                        _run_pair(n,arc,mode,points,output,seed,execution,
                            ck,sk,cb,sb,registry=registry)
                        handoffs.append(modes.enter_context(memory_file("sealed-handoff",
                            os.pread(output,
                                HANDOFF_HEADER_BYTES+HANDOFF_RECORD_BYTES*k,0),
                            sealed=True)))
                for observer in range(n):
                    incoming=(observer-1)%n
                    local=os.pread(participants,32,12+64*observer+32)
                    wrong=bytearray(local); wrong[-1]^=1
                    with memory_file("identifier",b"OASISK01"+local,sealed=True) as identity, \
                         memory_file("wrong-identifier",b"OASISK01"+wrong,sealed=True) as wrong_identity, \
                         memory_file("incoming-witness",b"OASISW01"+bytes(32*n)+
                             os.pread(private,32*(n-1),8+32*k*incoming+32*n),sealed=True) as in_witness, \
                         memory_file("outgoing-witness",b"OASISW01"+
                             os.pread(private,32*k,8+32*k*observer),sealed=True) as out_witness:
                        for level in range(n-1):
                            def check(key):
                                fds=(handoffs[incoming],handoffs[observer],key,in_witness,out_witness)
                                return subprocess.run([str(TPC/"bin/host_cycle_tool"),"recover-arc",
                                    str(k),str(level),*map(str,fds)],pass_fds=fds,
                                    capture_output=True,text=True,timeout=60)
                            rejected=check(wrong_identity)
                            if rejected.returncode<=0:
                                raise AssertionError("wrong identifier accepted or process crashed")
                            accepted=check(identity)
                            if accepted.returncode:
                                raise RuntimeError("native cross-arc recovery failed")
                            result=json.loads(accepted.stdout)
                            if not result.get("cross_arc_recovery") or result["destination_level"]!=level+1:
                                raise AssertionError("missing cross-arc recovery evidence")
                            checked+=1
    print(json.dumps({"cross_arc_cases":checked,"participants":n,"modes":len(MODES),
        "incoming_withdrawal_witnesses_zeroed":True,"wrong_identifier_rejected":True,
        "all_arc_registries_precede_preswap":True,
        "full_lifecycle":False,"ledger_clock":"controlled_fixture"}))


if __name__=="__main__":
    main()
