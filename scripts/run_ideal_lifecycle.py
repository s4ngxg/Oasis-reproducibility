#!/usr/bin/env python3
"""Run symbolic lifecycle cases under an ideal shared decision authority."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from ideal_lifecycle_decision import IdealCycle


def run(participants, outcome):
    if outcome not in ("complete", "funded-abort", "partial-funding-abort"):
        raise ValueError("unknown outcome")
    state = IdealCycle.create("symbolic-lifecycle", participants)
    trace = []

    def step(action, arc=None):
        nonlocal state
        state = state.step(state.session, action, arc)
        trace.append({"action": action, "arc": arc,
                      "decision": state.decision, "assets": list(state.assets)})

    funded = participants - 1 if outcome == "partial-funding-abort" else participants
    for arc in range(funded):
        step("fund", arc)
    if outcome == "complete":
        for arc in range(participants):
            step("ready", arc)
        step("commit")
        for arc in range(participants):
            step("withdraw", arc)
    else:
        step("abort")
        for arc in range(funded):
            step("refund", arc)
    terminal = all(asset in ("unfunded", "withdrawn", "refunded")
                   for asset in state.assets)
    return {
        "schema": "oasis-ideal-lifecycle-v1",
        "backend": "symbolic-shared-decision",
        "outcome": outcome,
        "participants": participants,
        "symbolic_terminal_complete": terminal,
        "full_lifecycle": False,
        "native_execution": False,
        "cryptographic_security_established": False,
        "performance_measurement": False,
        "assumptions": ["trusted globally consistent available decision authority",
                        "ideal readiness validation",
                        "ideal refund authorization; no transaction signatures"],
        "trace": trace,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--participants", type=int, default=3, choices=range(3, 129))
    parser.add_argument("--outcome", required=True,
                        choices=("complete", "funded-abort", "partial-funding-abort"))
    args = parser.parse_args()
    print(json.dumps(run(args.participants, args.outcome), indent=2))
