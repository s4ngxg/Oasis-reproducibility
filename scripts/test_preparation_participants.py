#!/usr/bin/env python3
"""Check retained participant fixture inputs against cyclic withdrawal witnesses.

This is centralized preparation correctness, not distributed Witness Sharing.
Secrets stay in anonymous memory and are never printed or written to results.
"""
import os
import resource
import subprocess

from run_native_handoff import TPC, memory_file


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    checked = 0
    for n in (3, 8, 16):
        k = 2*n-1
        with memory_file("prep-private") as private, \
             memory_file("prep-public") as public, \
             memory_file("prep-participants") as participants:
            result = subprocess.run([
                str(TPC/"bin/host_cycle_tool"), "prepare-participants", str(n),
                str(private), str(public), str(participants)],
                pass_fds=(private, public, participants), capture_output=True, timeout=60)
            if result.returncode:
                raise RuntimeError("participant preparation failed")
            raw = os.pread(participants, 13+64*n, 0)
            assert len(raw) == 12+64*n
            assert raw[:12] == b"OASISYF1"+n.to_bytes(4, "big")
            shares = [int.from_bytes(raw[12+64*i:44+64*i], "big") for i in range(n)]
            identifiers = [int.from_bytes(raw[44+64*i:76+64*i], "big") for i in range(n)]
            assert all(0 < value < order for value in shares+identifiers)
            vector = os.pread(private, 9+32*n*k, 0)
            assert len(vector) == 8+32*n*k and vector[:8] == b"OASISW01"
            assert os.fstat(public).st_size == 8+33*n*k
            for arc in range(n):
                value = sum(shares) % order
                for level in range(n):
                    value = (value+identifiers[(arc+1+level) % n]) % order
                    offset = 8+32*(arc*k+level)
                    assert value == int.from_bytes(vector[offset:offset+32], "big")
                    checked += 1
    print(f"participant preparation: {checked} cyclic withdrawal witnesses PASS")


if __name__ == "__main__":
    main()
