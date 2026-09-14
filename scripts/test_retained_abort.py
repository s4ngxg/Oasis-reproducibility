#!/usr/bin/env python3
"""Check native funded-abort observation, not refund or VTD correctness."""
import contextlib
import hashlib
import io
import json
import os
import subprocess

from run_native_handoff import TPC, memory_file, prepared_pair, _funded_cycle_recovery


def check_mode(mode):
    n, k = 3, 5
    with contextlib.ExitStack() as stack:
        private, public, participants = [stack.enter_context(memory_file(name))
                                         for name in ("private", "public", "participants")]
        subprocess.run([str(TPC / "bin/host_cycle_tool"), "prepare-participants",
                        str(n), str(private), str(public), str(participants)],
                       pass_fds=(private, public, participants), check=True,
                       capture_output=True, timeout=60)
        vector = os.pread(public, 8+n*k*33, 0)
        seed = hashlib.sha256(vector).hexdigest()
        arcs = []
        for arc in range(n):
            points = stack.enter_context(memory_file(
                "points", b"OASISP01" + vector[8+arc*k*33:8+(arc+1)*k*33]))
            *_, registry = stack.enter_context(prepared_pair(
                n, arc, mode, points, seed, 700000+arc))
            arcs.append({"registry": registry,
                         "output": stack.enter_context(memory_file("handoff")),
                         "witness": stack.enter_context(memory_file("witness"))})
        error = RuntimeError("injected-before-preswap")
        log = io.StringIO()
        try:
            with contextlib.redirect_stderr(log), _funded_cycle_recovery(
                    n, arcs, participants, all_honest=True):
                raise error
        except RuntimeError as observed:
            if observed is not error:
                raise AssertionError("abort reporting replaced the original failure") from observed
        else:
            raise AssertionError("abort failure was swallowed")
        lines = [line for line in log.getvalue().splitlines()
                 if line.startswith("retained_cycle_abort=")]
        if len(lines) != 1:
            raise AssertionError(log.getvalue())
        report = json.loads(lines[0].split("=", 1)[1])
        if report != {"retained_cycle_abort_observed": True, "locked_arcs": n,
                          "withdrawn_arcs": 0, "refunded_arcs": 0,
                          "automatic_refund_performed": False}:
            raise AssertionError(report)
        print(json.dumps({"mode": mode, **report}))
        for arc in arcs:
            receipt = stack.enter_context(memory_file("missing-refund-receipt"))
            arc["jobs"] = [(None, receipt, None)]
        try:
            with _funded_cycle_recovery(n, arcs, participants, refund_cycle=True) as consume:
                consume()
        except RuntimeError as rejected:
            if "native cycle recovery failed" not in str(rejected):
                raise AssertionError(str(rejected)) from rejected
        else:
            raise AssertionError("refund accepted missing Pre-swap handoffs")
        print(json.dumps({"mode": mode, "refund_without_handoff_rejected": True}))


if __name__ == "__main__":
    for mode in ("reference-itemwise", "batch-joint-presigning-batch-verification"):
        check_mode(mode)
