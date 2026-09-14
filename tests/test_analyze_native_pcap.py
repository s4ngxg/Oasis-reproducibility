import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import analyze_native_pcap  # noqa: E402


class NativePcapAnalysisTests(unittest.TestCase):
    def test_packet_directions_retransmission_and_turns(self):
        rows = "\n".join([
            "1.0\t10.0.0.1\t30000\t10.0.0.2\t50000\t20\t1\t\t\t\t0.100",
            "2.0\t10.0.0.2\t50000\t10.0.0.1\t30000\t30\t1\t1\t\t\t0.200",
            "3.0\t10.0.0.1\t30001\t10.0.0.2\t50001\t0\t2\t\t\t\t0.300",
        ])
        report = analyze_native_pcap.parse_rows(rows, "10.0.0.1")
        self.assertEqual(report["tcp_connections"], 2)
        self.assertEqual(report["tcp_segments"], 3)
        self.assertEqual(report["sent_tcp_payload_bytes"], 20)
        self.assertEqual(report["received_tcp_payload_bytes"], 30)
        self.assertEqual(report["tcp_retransmission_packets"], 1)
        self.assertEqual(report["payload_direction_changes"], 1)
        self.assertEqual(report["tcp_ack_rtt_sample_count"], 3)
        self.assertEqual(report["tcp_ack_rtt_p50_ms"], 200.0)
        self.assertAlmostEqual(report["tcp_ack_rtt_p95_ms"], 290.0)

    def test_packet_outside_local_endpoint_is_rejected(self):
        row = "1.0\t10.0.0.3\t1\t10.0.0.4\t2\t0\t1\t\t\t\t"
        with self.assertRaisesRegex(ValueError, "outside local endpoint"):
            analyze_native_pcap.parse_rows(row, "10.0.0.1")

    def test_packet_outside_campaign_service_port_is_rejected(self):
        row = "1.0\t10.0.0.1\t40000\t10.0.0.2\t50000\t20\t1\t\t\t\t"
        with self.assertRaisesRegex(ValueError, "campaign service port"):
            analyze_native_pcap.parse_rows(row, "10.0.0.1", 35000)

    def test_invalid_ack_rtt_is_rejected(self):
        row = (
            "1.0\t10.0.0.1\t35000\t10.0.0.2\t50000\t20\t1"
            "\t\t\t\t-0.1"
        )
        with self.assertRaisesRegex(ValueError, "invalid ACK RTT"):
            analyze_native_pcap.parse_rows(row, "10.0.0.1", 35000)


if __name__ == "__main__":
    unittest.main()
