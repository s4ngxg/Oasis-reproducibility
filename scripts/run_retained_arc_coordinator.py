#!/usr/bin/env python3
"""Coordinate retained local ParaSwap/OASIS cycle integration.

The same lifecycle harness is used for the baseline
``reference-itemwise`` mode and the OASIS
``batch-joint-presigning-batch-verification`` mode. All arc Pre-swap
sessions are executed concurrently behind a phase barrier.

Participant secrets are still produced by the centralized native Preparation
fixture. This is therefore a retained local cycle correctness harness, not yet
a distributed-custody, timed-privacy, or WAN latency benchmark.
"""
import argparse
import contextlib
import hashlib
import json
import math
import os
import resource
import select
import signal
import subprocess
import sys
import time

from lifecycle_preswap import curve_credentials, run_lifecycle_preswap
from run_native_handoff import (
    MODES, TPC, memory_file, prepared_pair, _prepare_vtd_jobs,
    _funded_ledger, _funded_cycle_recovery, receive_live_witness,
)


DEFAULT_ARC_WORKER_TIMEOUT_SECONDS = 135.0
DEFAULT_LIFECYCLE_PRESWAP_BUDGET_SECONDS = 120.0
WORKER_TERM_GRACE_SECONDS = 1.0


def _elapsed_ms(start_ns, end_ns):
    return (end_ns - start_ns) / 1e6


def _safe_close(fd):
    try:
        os.close(fd)
    except OSError:
        pass


def _close_unrelated_child_fds(keep):
    """Drop coordinator-only descriptors inherited by a forked arc worker."""
    keep = {int(fd) for fd in keep if isinstance(fd, int) and fd >= 0}
    keep.update((0, 1, 2))
    try:
        names = os.listdir("/proc/self/fd")
        candidates = [int(name) for name in names if name.isdigit()]
    except OSError:
        soft_limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        if soft_limit == resource.RLIM_INFINITY:
            soft_limit = 65536
        candidates = range(3, min(int(soft_limit), 65536))
    for fd in candidates:
        if fd not in keep:
            _safe_close(fd)


def _terminate_and_reap(children, grace_seconds=WORKER_TERM_GRACE_SECONDS):
    """Terminate worker process groups, then reap the direct children."""
    pending = {entry["pid"] for entry in children if entry.get("pid")}
    groups = {entry["pgid"] for entry in children if entry.get("pgid")}
    for pgid in groups:
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    for pid in list(pending):
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass

    deadline = time.monotonic() + grace_seconds
    while pending and time.monotonic() < deadline:
        for pid in list(pending):
            try:
                reaped, _ = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                reaped = pid
            if reaped == pid:
                pending.discard(pid)
        if pending:
            time.sleep(0.01)

    # Descendants may survive their group leader (including ignoring SIGTERM).
    for pgid in groups:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    for pid in list(pending):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    for pid in list(pending):
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass

    for entry in children:
        fd = entry.get("read_fd")
        if fd is not None:
            _safe_close(fd)
            entry["read_fd"] = None


def _wait_worker_exit(pid, deadline_ns):
    while True:
        try:
            reaped, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError as exc:
            raise RuntimeError(f"worker {pid} exit status unavailable") from exc
        if reaped == pid:
            return status
        remaining = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
        if remaining <= 0:
            raise TimeoutError(f"worker {pid} did not exit before lifecycle cutoff")
        time.sleep(min(0.01, remaining))


def _decode_worker_payload(entry):
    a = entry["arc"]
    raw = bytes(entry["buffer"])
    if not raw:
        raise RuntimeError(f"arc={a['arc']} child produced no result")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"arc={a['arc']} malformed child result: {exc}") from exc
    if not payload.get("ok"):
        raise RuntimeError(
            f"arc={a['arc']} {payload.get('error_type', 'child-error')}: "
            f"{payload.get('error', 'native pair failed')}")
    return payload


def _run_preswap_arcs(n, mode, arcs, seed, report, host_deadline_ns,
                      worker_timeout_seconds=DEFAULT_ARC_WORKER_TIMEOUT_SECONDS):
    """Fork one authenticated-TCP worker per arc and wait for the phase barrier.

    Results cross the process boundary explicitly through one JSON pipe per
    worker. The coordinator multiplexes those pipes with ``poll`` and enforces
    both one wall-clock supervisor deadline and the immutable lifecycle deadline
    created after lock admission. A child failure is decoded at EOF and tears
    down siblings immediately instead of waiting for the slowest worker.

    Each child asks the kernel for a TCP port while holding the process-wide
    port-allocation flock in ``lifecycle_preswap``. This replaces the old
    PID-modulo IPC socket naming. Loopback TCP is correctness coverage only;
    WAN performance remains a separate cloud campaign.
    """
    if not math.isfinite(worker_timeout_seconds) or worker_timeout_seconds <= 0:
        raise ValueError("worker timeout must be finite and positive")
    if not isinstance(host_deadline_ns, int) or host_deadline_ns <= time.monotonic_ns():
        raise TimeoutError("Pre-swap lifecycle deadline is already expired")

    supervisor_deadline_ns = time.monotonic_ns() + int(
        worker_timeout_seconds * 1_000_000_000)
    group_deadline_ns = min(supervisor_deadline_ns, host_deadline_ns)
    children = []
    poller = select.poll()
    by_fd = {}
    try:
        for a in arcs:
            if time.monotonic_ns() >= group_deadline_ns:
                raise TimeoutError("Pre-swap deadline expired while spawning workers")
            read_fd = write_fd = None
            try:
                read_fd, write_fd = os.pipe()
                pid = os.fork()
            except BaseException:
                if read_fd is not None:
                    _safe_close(read_fd)
                if write_fd is not None:
                    _safe_close(write_fd)
                raise

            if pid == 0:
                status = 1
                try:
                    os.setsid()
                    _safe_close(read_fd)
                    keep = [write_fd, a["points"], a["output"], a["ck"], a["sk"],
                            a["cb"], a["sb"]]
                    if isinstance(a.get("registry"), int):
                        keep.append(a["registry"])
                    _close_unrelated_child_fds(keep)
                    try:
                        measurement = run_lifecycle_preswap(
                            n, a["arc"], mode, a["points"], a["output"], seed,
                            a["execution"], a["ck"], a["sk"], a["cb"], a["sb"],
                            credentials=a["curve_credentials"],
                            host_export_deadline_ns=host_deadline_ns,
                            registry=a["registry"], io_timeout_ms=30000,
                            completion_ack_timeout_ms=10000,
                            process_timeout_seconds=120,
                        )
                        payload = {"ok": True, "measurement": measurement}
                        status = 0
                    except BaseException as exc:
                        payload = {
                            "ok": False,
                            "error_type": type(exc).__name__,
                            "error": str(exc),
                        }
                    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
                    view = memoryview(encoded)
                    while view:
                        written = os.write(write_fd, view)
                        view = view[written:]
                except BaseException:
                    status = 1
                finally:
                    _safe_close(write_fd)
                    os._exit(status)

            _safe_close(write_fd)
            os.set_blocking(read_fd, False)
            entry = {
                "pid": pid,
                "pgid": pid,
                "read_fd": read_fd,
                "arc": a,
                "buffer": bytearray(),
                "payload": None,
            }
            children.append(entry)
            by_fd[read_fd] = entry
            poller.register(read_fd, select.POLLIN | select.POLLHUP | select.POLLERR)
            report("preswap_worker_started", a["arc"])

        pending_fds = set(by_fd)
        while pending_fds:
            remaining_ns = group_deadline_ns - time.monotonic_ns()
            if remaining_ns <= 0:
                pending_arcs = sorted(by_fd[fd]["arc"]["arc"] for fd in pending_fds)
                reason = ("host lifecycle deadline" if group_deadline_ns == host_deadline_ns
                          else "coordinator worker deadline")
                raise TimeoutError(
                    f"concurrent Pre-swap exceeded {reason}; pending_arcs={pending_arcs}")
            events = poller.poll(max(1, int(remaining_ns / 1_000_000)))
            if not events:
                continue
            for fd, mask in events:
                if fd not in pending_fds:
                    continue
                entry = by_fd[fd]
                if mask & select.POLLNVAL:
                    raise RuntimeError(f"arc={entry['arc']['arc']} result pipe became invalid")
                while True:
                    try:
                        chunk = os.read(fd, 65536)
                    except BlockingIOError:
                        break
                    if not chunk:
                        poller.unregister(fd)
                        pending_fds.discard(fd)
                        _safe_close(fd)
                        entry["read_fd"] = None
                        # Decode at EOF so a failed child aborts the whole group
                        # immediately rather than waiting for a hung sibling.
                        entry["payload"] = _decode_worker_payload(entry)
                        break
                    entry["buffer"].extend(chunk)
                    if len(entry["buffer"]) > 8 * 1024 * 1024:
                        raise RuntimeError(
                            f"arc={entry['arc']['arc']} worker result exceeds 8 MiB limit")
                    if len(chunk) < 65536:
                        break

        failures = []
        for entry in children:
            pid = entry["pid"]
            a = entry["arc"]
            wait_status = _wait_worker_exit(pid, group_deadline_ns)
            entry["pid"] = None
            payload = entry["payload"] or _decode_worker_payload(entry)
            exited_cleanly = os.WIFEXITED(wait_status) and os.WEXITSTATUS(wait_status) == 0
            if not exited_cleanly:
                failures.append(
                    f"arc={a['arc']} child exit status={wait_status}")
                continue
            a["measurement"] = payload["measurement"]
            report("preswap_complete", a["arc"])

        if failures:
            raise RuntimeError("concurrent Pre-swap failed: " + "; ".join(failures))
    except BaseException:
        _terminate_and_reap(children)
        raise
    finally:
        for entry in children:
            fd = entry.get("read_fd")
            if fd is not None:
                try:
                    poller.unregister(fd)
                except (KeyError, OSError):
                    pass
                _safe_close(fd)
                entry["read_fd"] = None


def coordinate(n, mode, public_fd, private_fd, participant_fd, progress=None,
               recover_cycle=False, all_honest=False, lifecycle_deadline_ns=None,
               lifecycle_preswap_budget_seconds=DEFAULT_LIFECYCLE_PRESWAP_BUDGET_SECONDS,
               refund_cycle=False):
    def report(stage, arc):
        if progress is not None:
            progress(stage, arc)

    if not 3 <= n <= 128:
        raise ValueError("participant count must be between 3 and 128")
    if sum((recover_cycle, all_honest, refund_cycle)) > 1:
        raise ValueError("select one cycle outcome")
    if lifecycle_deadline_ns is None:
        if not math.isfinite(lifecycle_preswap_budget_seconds) or lifecycle_preswap_budget_seconds <= 0:
            raise ValueError("Pre-swap lifecycle budget must be finite and positive")
    elif type(lifecycle_deadline_ns) is not int or lifecycle_deadline_ns <= 0:
        raise ValueError("host deadline must be a positive monotonic-ns value")
    elif lifecycle_deadline_ns <= time.monotonic_ns():
        raise TimeoutError("host lifecycle deadline expired before Preparation")

    retained_cycle = recover_cycle or all_honest or refund_cycle
    k = 2*n-1
    coordinate_start = time.monotonic_ns()
    vector = os.pread(public_fd, 9+n*k*33, 0)
    if len(vector) != 8+n*k*33 or vector[:8] != b"OASISP01":
        raise ValueError("invalid Preparation statement vector")
    if os.fstat(private_fd).st_size != 8+n*k*32 or os.pread(private_fd, 8, 0) != b"OASISW01":
        raise ValueError("invalid Preparation witness vector")
    if os.fstat(participant_fd).st_size != 12+64*n or \
            os.pread(participant_fd, 12, 0) != b"OASISYF1"+n.to_bytes(4, "big"):
        raise ValueError("invalid participant Preparation fixture")
    seed = hashlib.sha256(vector).hexdigest()

    with contextlib.ExitStack() as stack:
        setup_start = time.monotonic_ns()
        arcs = []
        for arc in range(n):
            points = stack.enter_context(memory_file(
                "arc-public", b"OASISP01"+vector[8+33*k*arc:8+33*k*(arc+1)]))
            witnesses = os.pread(private_fd, 32*k, 8+32*k*arc)
            if len(witnesses) != 32*k:
                raise ValueError("incomplete Preparation witness vector")
            witness = stack.enter_context(memory_file("arc-witness", b"OASISW01"+witnesses))
            output = stack.enter_context(memory_file("arc-handoff"))
            execution = 700000+arc
            ck, sk, cb, sb, registry = stack.enter_context(
                prepared_pair(n, arc, mode, points, seed, execution))
            auth = stack.enter_context(curve_credentials(prefix=f"oasis-retained-arc-{arc}-"))
            arcs.append(dict(
                arc=arc, points=points, witness=witness, output=output,
                execution=execution, ck=ck, sk=sk, cb=cb, sb=sb,
                registry=registry, curve_credentials=auth,
            ))
        setup_done = time.monotonic_ns()

        vtd_prepare_start = setup_done
        for a in arcs:
            report("preparing_vtds", a["arc"])
            a["jobs"] = _prepare_vtd_jobs(
                stack, n, a["ck"], a["sk"], a["output"], seed, a["witness"],
                registry=a["registry"], server_bundle=a["sb"])
            report("vtds_prepared", a["arc"])
        vtd_prepare_done = time.monotonic_ns()

        funding_start = vtd_prepare_done
        if lifecycle_deadline_ns is not None and time.monotonic_ns() >= lifecycle_deadline_ns:
            raise TimeoutError("lifecycle deadline expired during Preparation; funding refused")
        cycle_consume = None
        if retained_cycle:
            for a in arcs:
                os.pwrite(a["witness"], bytes(32*k), 8)
            options = {"all_honest": True} if all_honest else {}
            if refund_cycle:
                options["refund_cycle"] = True
            cycle_consume = stack.enter_context(
                _funded_cycle_recovery(n, arcs, participant_fd, **options))
            report("cycle_locks_accepted", 0)
        else:
            for a in arcs:
                a["consume"] = stack.enter_context(_funded_ledger(
                    n, a["registry"], a["output"], a["witness"], a["jobs"][-1][1]))
                report("lock_accepted", a["arc"])
        funding_done = time.monotonic_ns()

        if lifecycle_deadline_ns is None:
            host_deadline_ns = funding_done + int(
                lifecycle_preswap_budget_seconds * 1_000_000_000)
            deadline_source = "lock-admission-plus-configured-budget"
        else:
            if not isinstance(lifecycle_deadline_ns, int) or lifecycle_deadline_ns <= 0:
                raise ValueError("explicit lifecycle deadline must be positive monotonic ns")
            host_deadline_ns = lifecycle_deadline_ns
            deadline_source = "explicit-host-deadline"
        if host_deadline_ns <= funding_done:
            raise TimeoutError("lifecycle deadline expired at or before lock admission")

        solver_start = funding_done
        for a in arcs:
            for _, _, (start, _, _) in a["jobs"]:
                start()
        solver_started = time.monotonic_ns()

        preswap_start = solver_started
        _run_preswap_arcs(n, mode, arcs, seed, report, host_deadline_ns)
        preswap_done = time.monotonic_ns()

        witness_start = preswap_done
        for a in arcs:
            os.pwrite(a["witness"], bytes(32), 8)
            a["sharing"] = receive_live_witness(
                n, a["arc"], participant_fd, a["output"], a["witness"]
            ) if not refund_cycle and (not recover_cycle or a["arc"] == 0) else {"withheld_in_fixture": True}
        witness_done = time.monotonic_ns()

        terminal_transition_start = witness_done
        recovery = cycle_consume() if all_honest else None
        withdrawal_observed = time.monotonic_ns() if all_honest else None
        terminal_transition_done = withdrawal_observed if all_honest else None
        if all_honest:
            report("cycle_withdrawn_before_solver_join", 0)

        vtd_finish_start = time.monotonic_ns()
        evidence = []
        for a in arcs:
            checks = []
            for level, receipt, (_, finish, prepared) in a["jobs"]:
                if prepared > preswap_start:
                    raise AssertionError("VTD prepared after Pre-swap start")
                checks.append(finish())
                if level is not None:
                    recovered = os.pread(receipt, 41, 0)
                    if len(recovered) != 40 or recovered[:8] != b"OASISK01":
                        raise AssertionError("missing solver-derived delayed witness")
                    if not all_honest:
                        os.pwrite(a["witness"], recovered[8:], 8+32*(n+level))
            evidence.append(dict(
                arc=a["arc"], preswap=a["measurement"],
                witness_sharing=a["sharing"], vtd_checks=checks,
                ledger=None if retained_cycle else a["consume"](),
            ))
            report("vtd_results_consumed" if retained_cycle else "ledger_consumed", a["arc"])
        vtd_finish_done = time.monotonic_ns()

        if recover_cycle:
            terminal_transition_start = vtd_finish_done
            recovery = cycle_consume()
            withdrawal_observed = time.monotonic_ns()
            terminal_transition_done = withdrawal_observed
            report("cycle_recovery_complete", 0)

        refund = None
        if refund_cycle:
            terminal_transition_start = vtd_finish_done
            refund = cycle_consume()
            terminal_transition_done = time.monotonic_ns()
            report("cycle_refund_complete", 0)
        checks_finished = time.monotonic_ns()
        phase_timing = dict(
            arc_key_registry_and_transport_auth_setup_ms=_elapsed_ms(setup_start, setup_done),
            vtd_prepare_and_admit_ms=_elapsed_ms(vtd_prepare_start, vtd_prepare_done),
            funding_and_lock_admission_ms=_elapsed_ms(funding_start, funding_done),
            vtd_solver_launch_ms=_elapsed_ms(solver_start, solver_started),
            preswap_all_arcs_wall_ms=_elapsed_ms(preswap_start, preswap_done),
            witness_sharing_ms=_elapsed_ms(witness_start, witness_done),
            vtd_solver_join_and_conformance_ms=_elapsed_ms(vtd_finish_start, vtd_finish_done),
            terminal_transition_ms=(None if terminal_transition_done is None else
                _elapsed_ms(terminal_transition_start, terminal_transition_done)),
            retained_cycle_to_terminal_ms=(None if terminal_transition_done is None else
                _elapsed_ms(coordinate_start, terminal_transition_done)),
            retained_cycle_with_conformance_ms=_elapsed_ms(coordinate_start, checks_finished),
        )
        timing = dict(
            scope="local retained lifecycle correctness harness",
            preparation_fixture_included=False,
            funding_included=True,
            all_arcs_preswap_concurrent=True,
            preswap_transport="curve-tcp",
            preswap_transport_scope="authenticated TCP loopback correctness",
            network_authentication_negative_checks_included=False,
            comparative_performance_evidence=False,
            transaction_latency_claim=False,
            host_deadline_bound_to_preswap=True,
            host_deadline_source=deadline_source,
            host_deadline_ns=host_deadline_ns,
            ledger_monotonic_deadline_bound=False,
            preswap_to_withdrawal_receipt_ms=None if withdrawal_observed is None else
                _elapsed_ms(preswap_start, withdrawal_observed),
            post_withdrawal_checks_ms=None if withdrawal_observed is None else
                _elapsed_ms(withdrawal_observed, checks_finished),
            preswap_to_checks_complete_ms=_elapsed_ms(preswap_start, checks_finished),
            phases_ms=phase_timing,
        )
        return dict(
            mode=mode, participants=n, arcs=evidence, vtd_count=n*n,
            all_proofs_before_locks=True, all_locks_before_preswap=True,
            vtd_expected_context_and_keys_checked_before_locks=True,
            all_arcs_preswap_concurrent=True,
            retained_funded_ledgers=retained_cycle,
            local_retained_cycle_exercised=retained_cycle,
            local_retained_full_cycle=False,
            full_lifecycle=False,
            distributed_participant_custody=False, timed_privacy=False,
            cycle_recovery=recovery if recover_cycle else None,
            cycle_withdrawal=recovery if all_honest else None,
            cycle_refund=refund,
            withdrawal_precedes_solver_join=all_honest,
            coordinator_timing=timing,
            ledger_paths=("single retained all-honest withdrawal" if all_honest else
                "single retained cycle recovery" if recover_cycle else
                "single retained cycle refund" if refund_cycle else
                "alternative per-arc withdrawal and relock/refund branches"),
        )


def run_local_cycle(n, mode, recover_cycle=False, all_honest=False, progress=None,
                    lifecycle_deadline_ns=None,
                    lifecycle_preswap_budget_seconds=DEFAULT_LIFECYCLE_PRESWAP_BUDGET_SECONDS,
                    refund_cycle=False):
    """Create fresh Preparation fixtures and execute exactly one local cycle."""
    invocation_start = time.monotonic_ns()
    with memory_file("preparation-private") as private, \
         memory_file("preparation-public") as public, \
         memory_file("participant-secrets") as participants:
        preparation_start = time.monotonic_ns()
        result = subprocess.run(
            [str(TPC/"bin/host_cycle_tool"), "prepare-participants", str(n),
             str(private), str(public), str(participants)],
            pass_fds=(private, public, participants), capture_output=True, timeout=60,
        )
        preparation_done = time.monotonic_ns()
        if result.returncode:
            raise RuntimeError("native Preparation failed")
        checked = coordinate(
            n, mode, public, private, participants, progress,
            recover_cycle=recover_cycle, all_honest=all_honest,
            refund_cycle=refund_cycle,
            lifecycle_deadline_ns=lifecycle_deadline_ns,
            lifecycle_preswap_budget_seconds=lifecycle_preswap_budget_seconds,
        )
    invocation_done = time.monotonic_ns()

    timing = checked["coordinator_timing"]
    timing["preparation_fixture_ms"] = _elapsed_ms(preparation_start, preparation_done)
    timing["end_to_end_runner_ms"] = _elapsed_ms(invocation_start, invocation_done)
    timing["preparation_fixture_included_in_end_to_end"] = True
    timing["end_to_end_runner_includes_setup_and_conformance"] = True
    timing["end_to_end_runner_is_transaction_latency"] = False
    return checked


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=MODES, default=MODES[-1])
    outcome = parser.add_mutually_exclusive_group()
    outcome.add_argument("--recover-cycle", action="store_true")
    outcome.add_argument("--all-honest", action="store_true")
    outcome.add_argument("--refund-cycle", action="store_true")
    parser.add_argument("--participants", type=int, default=3, choices=range(3, 129))
    parser.add_argument(
        "--preswap-budget-seconds", type=float,
        default=DEFAULT_LIFECYCLE_PRESWAP_BUDGET_SECONDS,
        help="absolute lifecycle Pre-swap budget measured from lock admission",
    )
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    def progress(stage, arc):
        print(f"stage={stage} arc={arc}", file=sys.stderr, flush=True)

    print(json.dumps(run_local_cycle(
        args.participants, args.mode,
        recover_cycle=args.recover_cycle, all_honest=args.all_honest,
        refund_cycle=args.refund_cycle,
        progress=progress,
        lifecycle_preswap_budget_seconds=args.preswap_budget_seconds,
    )))


if __name__ == "__main__":
    main()
