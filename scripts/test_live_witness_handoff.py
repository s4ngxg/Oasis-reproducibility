#!/usr/bin/env python3
"""Live Pre-swap plus authenticated witness composition, no full lifecycle claim."""
import hashlib
import argparse
import json
import os
import resource
import subprocess
from run_native_handoff import MODES,TPC,memory_file,run_pair,receive_live_witness,crypto_tool


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--participants",type=int,default=3,choices=range(3,129))
    n=parser.parse_args().participants
    k=2*n-1
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    checked=0
    blocked_unknown_sends=0
    with memory_file("preparation-secrets") as private, memory_file("preparation-public") as public, \
         memory_file("participant-secrets") as participants:
        prepared=subprocess.run([str(TPC/"bin/host_cycle_tool"),"prepare-participants",str(n),
            str(private),str(public),str(participants)],pass_fds=(private,public,participants),
            capture_output=True,timeout=60)
        if prepared.returncode:
            raise RuntimeError("participant preparation failed")
        vector=os.pread(public,8+n*k*33,0)
        seed=hashlib.sha256(vector).hexdigest()
        for mode in MODES:
            for arc in range(n):
                with memory_file("arc-public",b"OASISP01"+vector[8+k*33*arc:8+k*33*(arc+1)]) as points, \
                     memory_file("arc-witness",b"OASISW01"+bytes(32)+os.pread(private,(k-1)*32,8+k*32*arc+32)) as witness, \
                     memory_file("live-handoff") as output:
                    run_pair(n,arc,mode,points,output,seed,700000+checked)
                    try:
                        receive_live_witness(n,(arc+1)%n,participants,output,witness)
                    except RuntimeError as error:
                        if not str(error).endswith(": compose"):
                            raise
                    else:
                        raise AssertionError("wrong recipient identifier accepted")
                    if os.pread(witness,32,8)!=bytes(32):
                        raise AssertionError("failed witness composition modified output")
                    transport=receive_live_witness(n,arc,participants,output,witness)
                    blocked_unknown_sends+=int(transport["unknown_key_send_blocked"])
                    expected=os.pread(private,32,8+k*32*arc)
                    if os.pread(witness,32,8)!=expected:
                        raise AssertionError("network-composed witness differs from preparation")
                    consumed=json.loads(crypto_tool("check",k,output,witness).stdout)
                    if not consumed.get("accepted_withdrawal_extraction"):
                        raise AssertionError("network witness was not consumed by ledger")
                    checked+=1
    print(json.dumps({"live_witness_vectors":checked,"modes":len(MODES),
        "arcs":n,"initial_withdrawal_witness_zeroed":True,
        "authenticated_transport":True,"full_lifecycle":False,
        "wrong_recipient_rejected_without_output":True,
        "unknown_key_blocked_before_send":blocked_unknown_sends,
        "distributed_participant_custody":False}))


if __name__=="__main__":
    main()
