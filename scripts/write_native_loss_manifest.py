#!/usr/bin/env python3
"""Bind native loss results to their campaign-scoped netem evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOSS_ROLE_RUNNER = ROOT / "scripts" / "run_native_loss_role.sh"
NETEM_RUNNER = ROOT / "scripts" / "cloud_netem_loss.sh"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=("client", "server"), required=True)
    parser.add_argument("--route", required=True)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--loss-pct", type=float, required=True)
    parser.add_argument("--service-port", type=int, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--tc-evidence", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if not 0 <= args.loss_pct <= 100:
        parser.error("loss percentage must be in [0, 100]")
    if not 1 <= args.service_port <= 65535:
        parser.error("service port must be in [1, 65535]")
    result = json.loads(args.result.read_text(encoding="utf-8"))
    if (
        result.get("schema") != "oasis-preswap-cloud-v8"
        or result.get("role") != args.role
        or result.get("route") != args.route
        or result.get("campaign_id") != args.campaign_id
    ):
        parser.error("result identity does not match loss manifest arguments")
    if (
        result.get("authenticated_transport") is not True
        or result.get("transport_security", {}).get("mechanism")
        != "ZeroMQ CURVE"
    ):
        parser.error("loss result is not an authenticated native campaign")
    environment = result.get("environment", {})
    provenance = result.get("provenance", {})
    source_hash = environment.get("protocol_source_sha256")
    runner_hash = provenance.get("runner_sha256")
    if not source_hash or not runner_hash:
        parser.error("loss result lacks source or runner provenance")
    evidence = args.tc_evidence.read_text(encoding="utf-8")
    if args.role == "client":
        action = "observe" if args.loss_pct == 0 else "apply"
        marker = (
            f"oasis_netem_action={action} "
            f"device="
        )
        suffix = (
            f" loss_pct={args.loss_pct:g} "
            f"service_port={args.service_port}"
        )
        evidence_lines = evidence.splitlines()
        first_line = evidence_lines[0] if evidence_lines else ""
        observed_tc = "\n".join(evidence_lines[1:]).lower()
        if not first_line.startswith(marker) or not first_line.endswith(suffix):
            parser.error("client tc evidence does not match impairment request")
        if args.loss_pct == 0 and "netem" in observed_tc:
            parser.error("zero-loss control still has a netem qdisc")
        if args.loss_pct > 0 and "netem" not in observed_tc:
            parser.error("nonzero-loss evidence does not show a netem qdisc")
    else:
        expected = (
            "role=server\n"
            "loss_applied_at=client-egress\n"
            f"loss_pct={args.loss_pct:g}\n"
        )
        if evidence != expected:
            parser.error("server loss evidence does not match campaign request")
    payload = {
        "schema": "oasis-native-loss-evidence-v1",
        "backend": "native-c11-relic",
        "role": args.role,
        "route": args.route,
        "campaign_id": args.campaign_id,
        "loss_pct": args.loss_pct,
        "impairment_scope": "client-egress-service-port",
        "service_port": args.service_port,
        "result_schema": result["schema"],
        "protocol_source_sha256": source_hash,
        "campaign_runner_sha256": runner_hash,
        "loss_role_runner_sha256": sha256(LOSS_ROLE_RUNNER),
        "netem_runner_sha256": sha256(NETEM_RUNNER),
        "manifest_writer_sha256": sha256(Path(__file__)),
        "result_file": args.result.name,
        "result_sha256": sha256(args.result),
        "tc_evidence_file": args.tc_evidence.name,
        "tc_evidence_sha256": sha256(args.tc_evidence),
        "sample_count": len(result.get("samples", [])),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote={args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
