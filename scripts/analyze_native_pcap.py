#!/usr/bin/env python3
"""Summarize campaign-scoped TCP packet evidence produced by tcpdump."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import subprocess
from collections import defaultdict
from pathlib import Path


FIELDS = (
    "frame.time_epoch",
    "ip.src",
    "tcp.srcport",
    "ip.dst",
    "tcp.dstport",
    "tcp.len",
    "tcp.stream",
    "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission",
    "tcp.analysis.spurious_retransmission",
    "tcp.analysis.ack_rtt",
)


def percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


def format_optional_ms(value: object) -> str:
    return "N/A" if value is None else f"{float(value):.3f}"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_rows(
    text: str,
    local_ip: str,
    service_port: int | None = None,
) -> dict[str, object]:
    sent_segments = received_segments = 0
    sent_payload = received_payload = 0
    retransmissions = 0
    rtt_ms: list[float] = []
    streams: set[int] = set()
    payload_directions: dict[int, list[tuple[float, str]]] = defaultdict(list)
    for line_number, line in enumerate(text.splitlines(), 1):
        fields = line.split("\t")
        if len(fields) != len(FIELDS):
            raise ValueError(f"malformed tshark row {line_number}: {line!r}")
        (
            timestamp, source, source_port_text, destination,
            destination_port_text, tcp_length, stream_id,
            retransmission, fast_retransmission, spurious_retransmission,
            ack_rtt,
        ) = fields
        if source != local_ip and destination != local_ip:
            raise ValueError(f"packet outside local endpoint at row {line_number}")
        source_port = int(source_port_text)
        destination_port = int(destination_port_text)
        if service_port is not None and service_port not in (
            source_port, destination_port
        ):
            raise ValueError(
                f"packet outside campaign service port at row {line_number}"
            )
        direction = "sent" if source == local_ip else "received"
        length = int(tcp_length or 0)
        stream = int(stream_id)
        streams.add(stream)
        if direction == "sent":
            sent_segments += 1
            sent_payload += length
        else:
            received_segments += 1
            received_payload += length
        if any(value.strip() not in {"", "0"} for value in (
            retransmission, fast_retransmission, spurious_retransmission
        )):
            retransmissions += 1
        if ack_rtt.strip():
            value = float(ack_rtt) * 1000.0
            if not math.isfinite(value) or value < 0.0:
                raise ValueError(f"invalid ACK RTT at row {line_number}")
            rtt_ms.append(value)
        if length > 0:
            payload_directions[stream].append((float(timestamp), direction))

    direction_changes = 0
    payload_packets = 0
    for events in payload_directions.values():
        previous = None
        for _, direction in sorted(events):
            payload_packets += 1
            if previous is not None and direction != previous:
                direction_changes += 1
            previous = direction
    return {
        "tcp_connections": len(streams),
        "tcp_segments": sent_segments + received_segments,
        "sent_tcp_segments": sent_segments,
        "received_tcp_segments": received_segments,
        "tcp_payload_packets": payload_packets,
        "sent_tcp_payload_bytes": sent_payload,
        "received_tcp_payload_bytes": received_payload,
        "tcp_retransmission_packets": retransmissions,
        "payload_direction_changes": direction_changes,
        "tcp_ack_rtt_sample_count": len(rtt_ms),
        "tcp_ack_rtt_min_ms": min(rtt_ms) if rtt_ms else None,
        "tcp_ack_rtt_p50_ms": percentile(rtt_ms, 0.50),
        "tcp_ack_rtt_p95_ms": percentile(rtt_ms, 0.95),
        "tcp_ack_rtt_p99_ms": percentile(rtt_ms, 0.99),
        "tcp_ack_rtt_max_ms": max(rtt_ms) if rtt_ms else None,
        "tls_records": "not-applicable-zero-mq-curve",
    }


def render_markdown(report: dict[str, object]) -> str:
    return "\n".join([
        "# Native campaign packet profile",
        "",
        f"Campaign: `{report['campaign_id']}`. Route: `{report['route']}`. "
        f"Role: `{report['role']}`. Local IP: `{report['local_ip']}`. "
        f"TCP service port: `{report['service_port']}`.",
        "The capture filter is restricted to that single service port.",
        "",
        "| Connections | TCP segments (sent/received) | Payload packets | Payload bytes (sent/received) | Retransmissions | Payload direction changes | TLS records |",
        "|---:|---:|---:|---:|---:|---:|---|",
        f"| {report['metrics']['tcp_connections']} | "
        f"{report['metrics']['tcp_segments']} "
        f"({report['metrics']['sent_tcp_segments']}/{report['metrics']['received_tcp_segments']}) | "
        f"{report['metrics']['tcp_payload_packets']} | "
        f"{report['metrics']['sent_tcp_payload_bytes']}/"
        f"{report['metrics']['received_tcp_payload_bytes']} | "
        f"{report['metrics']['tcp_retransmission_packets']} | "
        f"{report['metrics']['payload_direction_changes']} | N/A (ZeroMQ CURVE) |",
        "",
        "## TCP ACK-derived RTT distribution",
        "",
        "RTT values come from `tcp.analysis.ack_rtt` in the campaign-scoped "
        "capture; they are not ICMP ping measurements.",
        "",
        "| Samples | Min (ms) | P50 (ms) | P95 (ms) | P99 (ms) | Max (ms) |",
        "|---:|---:|---:|---:|---:|---:|",
        f"| {report['metrics']['tcp_ack_rtt_sample_count']} | "
        f"{format_optional_ms(report['metrics']['tcp_ack_rtt_min_ms'])} | "
        f"{format_optional_ms(report['metrics']['tcp_ack_rtt_p50_ms'])} | "
        f"{format_optional_ms(report['metrics']['tcp_ack_rtt_p95_ms'])} | "
        f"{format_optional_ms(report['metrics']['tcp_ack_rtt_p99_ms'])} | "
        f"{format_optional_ms(report['metrics']['tcp_ack_rtt_max_ms'])} |",
        "",
        f"PCAP SHA-256: `{report['pcap_sha256']}`",
        f"tshark: `{report['tshark_version']}`",
        "",
    ])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--role", required=True, choices=("client", "server"))
    parser.add_argument("--local-ip", required=True)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--route", required=True, choices=("eu_to_us", "sg_to_us"))
    parser.add_argument("--service-port", type=int, required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--md-out", type=Path, required=True)
    args = parser.parse_args()
    if not args.pcap.is_file():
        parser.error(f"missing pcap: {args.pcap}")
    if not (1 <= args.service_port <= 65535):
        parser.error("invalid campaign TCP service port")
    command = ["tshark", "-r", str(args.pcap), "-Y", "tcp", "-T", "fields",
               "-E", "separator=/t", "-E", "occurrence=f"]
    for field in FIELDS:
        command.extend(("-e", field))
    try:
        process = subprocess.run(command, check=True, capture_output=True, text=True)
        version = subprocess.run(
            ["tshark", "--version"], check=True, capture_output=True, text=True
        ).stdout.splitlines()[0]
    except FileNotFoundError:
        parser.error("tshark is required")
    report = {
        "schema": "oasis-preswap-pcap-profile-v3",
        "role": args.role,
        "campaign_id": args.campaign_id,
        "route": args.route,
        "local_ip": args.local_ip,
        "service_port": args.service_port,
        "transport": "ZeroMQ CURVE over TCP",
        "tls_session_reuse": "not-applicable-native-transport-is-not-tls",
        "pcap_sha256": sha256(args.pcap),
        "tshark_version": version,
        "metrics": parse_rows(
            process.stdout,
            args.local_ip,
            args.service_port,
        ),
    }
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.md_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    args.md_out.write_text(render_markdown(report), encoding="utf-8")
    print(f"wrote={args.json_out}")
    print(f"wrote={args.md_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
