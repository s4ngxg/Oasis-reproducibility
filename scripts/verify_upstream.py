#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "vendor" / "paraswap-artifact.lock.json"


def main() -> int:
    manifest = json.loads(LOCK.read_text(encoding="utf-8"))
    failures = []
    for relative, expected in manifest["upstream_files"].items():
        path = ROOT / relative
        actual = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else "missing"
        if actual != expected:
            failures.append({
                "classification": "unchanged-upstream",
                "file": relative,
                "expected": expected,
                "actual": actual,
            })
    adapted = manifest.get("adapted_upstream_files", {})
    for relative, record in adapted.items():
        path = ROOT / relative
        actual = (
            hashlib.sha256(path.read_bytes()).hexdigest()
            if path.is_file()
            else "missing"
        )
        expected = record.get("integrated_sha256")
        upstream = record.get("upstream_sha256")
        purpose = record.get("purpose")
        if (
            actual != expected
            or not isinstance(upstream, str)
            or len(upstream) != 64
            or upstream == expected
            or not isinstance(purpose, str)
            or not purpose.strip()
        ):
            failures.append({
                "classification": "adapted-upstream",
                "file": relative,
                "upstream": upstream,
                "expected_integrated": expected,
                "actual": actual,
                "purpose": purpose,
            })
    if failures:
        print(json.dumps({"verified": False, "failures": failures}, indent=2))
        return 1
    print(json.dumps({
        "verified": True,
        "doi": manifest["doi"],
        "source_commit": manifest["source_commit"],
        "unchanged_upstream_files": len(manifest["upstream_files"]),
        "adapted_upstream_files": len(adapted),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
