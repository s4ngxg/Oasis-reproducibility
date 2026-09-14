#!/usr/bin/env python3
"""Reject malformed witness-gate descriptors before crypto or network activity."""
import contextlib
import os
import subprocess
import unittest

from run_native_handoff import HANDOFF_HEADER_BYTES, HANDOFF_MAGIC, HANDOFF_RECORD_BYTES, TPC, memory_file


class Inputs(unittest.TestCase):
    def test_invalid_descriptors_preserve_output(self):
        n=8
        k=2*n-1
        original=[b"OASISYF1"+n.to_bytes(4,"big")+bytes(64*n),
                  HANDOFF_MAGIC+bytes(HANDOFF_HEADER_BYTES-8+HANDOFF_RECORD_BYTES*k),
                  b"OASISW01"+bytes(32*k)]
        cases=[]
        for index in range(3):
            for change in (lambda b:b[:-1],lambda b:b+b"X",lambda b:b"X"+b[1:]):
                data=list(original)
                data[index]=change(data[index])
                cases.append((data,True,False,0))
        for count in (0,2,129,0xffffffff):
            data=list(original)
            data[0]=b"OASISYF1"+count.to_bytes(4,"big")+bytes(64*n)
            cases.append((data,True,False,0))
        cases.extend([(original,False,False,0),(original,True,True,0),
                      (original,True,False,n)])
        for number,(data,sealed,output_sealed,receiver) in enumerate(cases):
            with self.subTest(case=number),contextlib.ExitStack() as stack:
                fds=[stack.enter_context(memory_file("gate-input",value,
                     sealed=(sealed if i==0 else True if i==1 else output_sealed)))
                     for i,value in enumerate(data)]
                result=subprocess.run([str(TPC/"bin/host_witness_transport_test"),
                    *map(str,fds),str(receiver)],pass_fds=tuple(fds),
                    capture_output=True,timeout=10)
                self.assertEqual(result.returncode,2)
                self.assertEqual(result.stdout,b"")
                self.assertEqual(os.pread(fds[2],len(data[2])+1,0),data[2])


if __name__=="__main__":
    unittest.main()
