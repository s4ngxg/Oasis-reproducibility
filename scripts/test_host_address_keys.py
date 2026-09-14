#!/usr/bin/env python3
"""Canonical address-share import gate; no claim of live signing integration."""
import resource
from run_native_handoff import memory_file, crypto_tool
import os


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    def encode(values):
        return b"OASISA01" + len(values).to_bytes(4, "big") + b"".join(
            value.to_bytes(32, "big") for value in values)
    valid = encode([1, 2, 3])
    cases = [(valid, True, True), (valid, False, False),
             (valid[:-1], True, False), (valid+b"\x00", True, False),
             (encode([1, 1, 3]), True, False),
             (encode([1, 2, 0]), True, False),
             (encode([1, 2, q]), True, False),
             (valid[:11]+b"\x04"+valid[12:], True, False)]
    for payload, sealed, expected in cases:
        with memory_file("address-keys", payload, sealed=sealed) as private, \
             memory_file("address-public") as public:
            result = crypto_tool("address-public", 3, private, public, False)
            assert (result.returncode == 0) == expected
            data = os.pread(public, 200, 0)
            if expected:
                assert len(data) == 107 and data[:8] == b"OASISP01"
                assert data[8:41].hex() == (
                    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                assert len({data[8+i*33:41+i*33] for i in range(3)}) == 3
            else:
                assert not data
    with memory_file("proof-keys",valid,sealed=True) as private, \
         memory_file("proof-public") as public:
        crypto_tool("test-address-proofs",3,private,public)
    with memory_file("bundle-keys",valid,sealed=True) as private, \
         memory_file("bundle-public") as public:
        crypto_tool("test-address-bundle-write",3,private,public)
        bundle=os.pread(public,20000,0)
        assert bundle[:12]==b"OASISAP1\x00\x00\x00\x03"
        assert crypto_tool("test-address-bundle-read",3,public,private,False).returncode != 0
        stride=(len(bundle)-12)//3
        mutants=[bundle[:-1],bundle+b"\x00",
                 bundle[:12]+bundle[12+stride:12+2*stride]+bundle[12:12+stride]+bundle[12+2*stride:]]
        # Corrupt the last entry while requesting entry zero: full-vector validation.
        mutants.append(bundle[:-1]+bytes([bundle[-1]^1]))
        for payload in [bundle,*mutants]:
            with memory_file("bundle-import",payload,sealed=True) as imported:
                result=crypto_tool("test-address-bundle-read",3,imported,private,False)
                assert (result.returncode==0)==(payload==bundle)
    print("host independent-address key parser: PASS (not lifecycle integration)")


if __name__ == "__main__":
    main()
