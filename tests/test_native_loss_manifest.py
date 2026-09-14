import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "write_native_loss_manifest.py"


class NativeLossManifestTests(unittest.TestCase):
    def write_result(self, path, schema="oasis-preswap-cloud-v8"):
        path.write_text(json.dumps({
            "schema": schema,
            "role": "client",
            "route": "eu_to_us",
            "campaign_id": "eu-loss2",
            "authenticated_transport": True,
            "transport_security": {"mechanism": "ZeroMQ CURVE"},
            "environment": {"protocol_source_sha256": "source-hash"},
            "provenance": {"runner_sha256": "runner-hash"},
            "samples": [{"trial": 0}],
        }), encoding="utf-8")

    def command(self, result, evidence, output, loss="2"):
        return [
            sys.executable, str(SCRIPT),
            "--role", "client",
            "--route", "eu_to_us",
            "--campaign-id", "eu-loss2",
            "--loss-pct", loss,
            "--service-port", "9000",
            "--result", str(result),
            "--tc-evidence", str(evidence),
            "--out", str(output),
        ]

    def test_manifest_binds_result_and_impairment_evidence(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            result = directory / "client.json"
            evidence = directory / "tc.txt"
            output = directory / "manifest.json"
            self.write_result(result)
            evidence.write_text(
                "oasis_netem_action=apply device=ens5 loss_pct=2 "
                "service_port=9000\nqdisc netem loss 2%\n",
                encoding="utf-8",
            )
            process = subprocess.run(
                self.command(result, evidence, output),
                capture_output=True, text=True, check=False
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            manifest = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(manifest["protocol_source_sha256"], "source-hash")
            self.assertEqual(manifest["service_port"], 9000)
            self.assertEqual(
                manifest["result_sha256"],
                hashlib.sha256(result.read_bytes()).hexdigest(),
            )
            self.assertEqual(manifest["sample_count"], 1)

    def test_non_native_schema_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            result = directory / "client.json"
            evidence = directory / "tc.txt"
            output = directory / "manifest.json"
            self.write_result(result, schema="oasis-preswap-cloud-v7")
            evidence.write_text(
                "oasis_netem_action=apply device=ens5 loss_pct=2 "
                "service_port=9000\nqdisc netem loss 2%\n",
                encoding="utf-8",
            )
            process = subprocess.run(
                self.command(result, evidence, output),
                capture_output=True, text=True, check=False
            )
            self.assertNotEqual(process.returncode, 0)
            self.assertFalse(output.exists())

    def test_zero_loss_requires_observation_without_netem(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            result = directory / "client.json"
            evidence = directory / "tc.txt"
            output = directory / "manifest.json"
            self.write_result(result)
            evidence.write_text(
                "oasis_netem_action=observe device=ens5 loss_pct=0 "
                "service_port=9000\nqdisc fq_codel 0: root\n",
                encoding="utf-8",
            )
            process = subprocess.run(
                self.command(result, evidence, output, loss="0"),
                capture_output=True, text=True, check=False
            )
            self.assertEqual(process.returncode, 0, process.stderr)

            evidence.write_text(
                "oasis_netem_action=observe device=ens5 loss_pct=0 "
                "service_port=9000\nqdisc netem 30: root loss 2%\n",
                encoding="utf-8",
            )
            output.unlink()
            process = subprocess.run(
                self.command(result, evidence, output, loss="0"),
                capture_output=True, text=True, check=False
            )
            self.assertNotEqual(process.returncode, 0)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
