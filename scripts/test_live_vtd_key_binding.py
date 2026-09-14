#!/usr/bin/env python3
"""Ordered single-arc VTD/key gate, not a full lifecycle or performance campaign."""
import hashlib
import json
import os
import resource
import argparse
import subprocess
from run_native_handoff import TPC,MODES,memory_file, crypto_tool, run_pair


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    selection=parser.add_mutually_exclusive_group()
    selection.add_argument("--relock-level",type=int,choices=(0,1))
    selection.add_argument("--all-vtds",action="store_true")
    parser.add_argument("--mode",choices=MODES,default="batch-joint-presigning-batch-verification")
    args=parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    with memory_file("witnesses") as private, memory_file("public") as public, \
         memory_file("participant-secrets") as participants:
        prepared=subprocess.run([str(TPC/"bin/host_cycle_tool"),"prepare-participants","3",
            str(private),str(public),str(participants)],pass_fds=(private,public,participants),
            capture_output=True,timeout=60)
        if prepared.returncode:
            raise RuntimeError("participant preparation failed")
        vector = os.pread(public, 503, 0)
        if len(vector) != 503:
            raise AssertionError("incomplete preparation fixture")
        with memory_file("arc-public", b"OASISP01" + vector[8:173]) as points, \
             memory_file("arc-witness",b"OASISW01"+os.pread(private,160,8)) as witnesses, \
             memory_file("handoff") as output:
            result = run_pair(3, 0, args.mode,
                              points, output, hashlib.sha256(vector).hexdigest(),
                              450001, vtd_key_check=True,refund_witness_fd=witnesses,
                              vtd_relock_level=args.relock_level,vtd_all=args.all_vtds,
                              participant_fd=participants if args.all_vtds else None)
            print(json.dumps({"full_lifecycle": False,"mode":args.mode,
                              "purpose": ("all single-arc VTDs around one Pre-swap" if args.all_vtds else
                                  "live final-address VTD key binding"
                                  if args.relock_level is None else
                                  "live delayed-witness VTD re-lock binding"), **result}))


if __name__ == "__main__":
    main()
