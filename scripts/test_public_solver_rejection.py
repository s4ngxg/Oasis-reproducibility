#!/usr/bin/env python3
"""Public-only solver admission failures must not export a recovered scalar."""
import contextlib
import os
import resource
import subprocess

from run_native_handoff import TPC, memory_file


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    point = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    metadata = b"OASISVS1" + bytes(32) + point + (32).to_bytes(8, "big")
    setup = b"OASISPA1" + b"".join(b"\0\0\0\1"+bytes([v]) for v in (17, 4, 4, 8))
    proof = b"OASISV01" + (256).to_bytes(4, "big") + (128).to_bytes(4, "big")
    cases = [
        (metadata, setup, proof, True),
        (metadata[:-1], setup, proof, True),
        (metadata+b"\0", setup, proof, True),
        (b"INVALID!"+metadata[8:], setup, proof, True),
        (metadata[:73]+bytes(8), setup, proof, True),
        (metadata[:73]+(1000001).to_bytes(8, "big"), setup, proof, True),
        (metadata, setup[:-1], proof, True),
        (metadata, setup+b"\0", proof, True),
        (metadata, setup, proof, False),
    ]
    for meta, params, public_proof, sealed in cases:
        with contextlib.ExitStack() as stack:
            inputs = [stack.enter_context(memory_file(name, data, sealed=sealed))
                      for name, data in (("solver-metadata", meta), ("solver-setup", params),
                                         ("solver-proof", public_proof))]
            output = stack.enter_context(memory_file("solver-result"))
            result = subprocess.run([str(TPC/"bin/vtd_public_solver"),
                                     *map(str, inputs), str(output)],
                                    pass_fds=(*inputs, output), capture_output=True, timeout=10)
            if result.returncode == 0 or os.fstat(output).st_size:
                raise AssertionError("invalid public inputs exported a recovered scalar")
    print(f"public solver rejection: {len(cases)} cases, no scalar export PASS")


if __name__ == "__main__":
    main()
