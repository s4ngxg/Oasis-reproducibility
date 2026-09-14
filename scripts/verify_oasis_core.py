#!/usr/bin/env python3
"""Verify the pinned OASIS cryptographic core imported by this integration."""

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "vendor" / "oasis-linear.lock.json"


def main() -> int:
    manifest = json.loads(LOCK.read_text(encoding="utf-8"))
    failures = []
    tracked = {
        **manifest["files"],
        **manifest.get("integration_files", {}),
    }
    for relative, expected in tracked.items():
        path = ROOT / relative
        actual = (
            hashlib.sha256(path.read_bytes()).hexdigest()
            if path.is_file() else "missing"
        )
        if actual != expected:
            failures.append(
                {"file": relative, "expected": expected, "actual": actual}
            )
    if failures:
        print(json.dumps({"verified": False, "failures": failures}, indent=2))
        return 1
    print(
        json.dumps(
            {
                "verified": True,
                "component": manifest["component"],
                "source_commit": manifest["source_commit"],
                "upstream_files": len(manifest["files"]),
                "integration_files": len(
                    manifest.get("integration_files", {})
                ),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
