#!/usr/bin/env python3
"""Validate three local lifecycle branches without claiming funded-abort safety."""
import argparse
import hashlib
import json
from pathlib import Path

from test_retained_full_cycle import MODES, OUTCOMES, _assert_report

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_BINARIES = {
    f"vendor/paraswap/two-party computation/bin/{name}"
    for name in ("host_cycle_tool", "preswap_client", "preswap_server",
                 "curve_keygen", "vtd_integration_test", "vtd_public_solver")
}


def validate_binary_manifest(manifest):
    if not isinstance(manifest, dict) or set(manifest) != REQUIRED_BINARIES:
        raise ValueError("binary provenance must contain exactly the six lifecycle binaries")
    for digest in manifest.values():
        if (not isinstance(digest, str) or len(digest) != 64 or
                any(char not in "0123456789abcdef" for char in digest)):
            raise ValueError("invalid binary SHA-256 encoding")


def validate(directories):
    if not __debug__:
        raise RuntimeError("validation requires assertions; do not use -O")
    reports = {}
    for directory in directories:
        for path in sorted(Path(directory).glob("*.json")):
            data = json.loads(path.read_text())
            report = data["report"]
            branches = [name for name, field in (
                ("--all-honest", "cycle_withdrawal"),
                ("--recover-cycle", "cycle_recovery"),
                ("--refund-cycle", "cycle_refund")) if report.get(field) is not None]
            if len(branches) != 1:
                raise ValueError(f"ambiguous terminal branch: {path}")
            outcome = branches[0]
            mode = report["mode"]
            if mode not in MODES:
                raise ValueError(f"unsupported mode: {mode}")
            _assert_report(report, mode, outcome, report["participants"])
            terminal = report[{"--all-honest": "cycle_withdrawal",
                               "--recover-cycle": "cycle_recovery",
                               "--refund-cycle": "cycle_refund"}[outcome]]
            count = "refunded_arcs" if outcome == "--refund-cycle" else "withdrawn_arcs"
            if terminal.get(count) != report["participants"]:
                raise ValueError(f"incomplete terminal state: {path}")
            provenance = data["provenance"]
            validate_binary_manifest(provenance.get("binary_sha256"))
            for relative, expected in provenance["binary_sha256"].items():
                target = (ROOT / relative).resolve()
                if not target.is_relative_to(ROOT.resolve()):
                    raise ValueError("binary path escapes repository")
                if hashlib.sha256(target.read_bytes()).hexdigest() != expected:
                    raise ValueError(f"binary differs from evidence: {relative}")
            key = (outcome, mode)
            if key in reports:
                raise ValueError(f"duplicate branch/mode: {key}")
            reports[key] = (report, provenance, str(path))
    required = {(outcome, mode) for outcome in OUTCOMES for mode in MODES}
    if set(reports) != required:
        raise ValueError(f"missing branch/mode evidence: {sorted(required - set(reports))}")
    if len({item[0]["participants"] for item in reports.values()}) != 1:
        raise ValueError("participant counts differ")
    for outcome in OUTCOMES:
        if reports[outcome, MODES[0]][1] != reports[outcome, MODES[1]][1]:
            raise ValueError(f"mode provenance differs within branch: {outcome}")
    return {
        "local_lifecycle_branch_coverage_complete": True,
        "scope": "retained ledger adapter, local correctness, three terminal branches",
        "full_lifecycle": False,
        "funded_early_abort_refund_supported": False,
        "public_blockchain_execution": False,
        "cloud_performance_evidence": False,
        "current_binary_hashes_match": True,
        "current_source_tree_validated": False,
        "reports": [reports[key][2] for key in sorted(reports)],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directories", nargs="+", type=Path)
    args = parser.parse_args()
    print(json.dumps(validate(args.directories), indent=2))
