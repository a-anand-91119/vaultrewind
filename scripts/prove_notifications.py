#!/usr/bin/env python3
"""Repeat the notification integration assertions and save sanitized local evidence.

Requires the project's locked development environment (pytest supplies MonkeyPatch).
All receivers, credentials, certificates and SQLite files are disposable fixtures.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))


def _sanitized(value):
    """Evidence can contain only named counts, booleans and stable public codes."""
    if isinstance(value, dict):
        return all(isinstance(key, str) and _sanitized(item) for key, item in value.items())
    if isinstance(value, list):
        return all(_sanitized(item) for item in value)
    return isinstance(value, (bool, int)) or isinstance(value, str) and bool(re.fullmatch(r"[A-Z][A-Z0-9_]*", value))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=PROJECT / "docs/evidence/notifications.json")
    args = parser.parse_args()
    try:
        if not __debug__:
            raise RuntimeError("ASSERTIONS_REQUIRED")
        from pytest import MonkeyPatch

        from tests.unit.test_notifications_delivery import run_notification_proof

        with (tempfile.TemporaryDirectory(prefix="vaultrewind-notification-proof-") as directory,
              MonkeyPatch.context() as patch):
            evidence = run_notification_proof(Path(directory), patch)
        if not _sanitized(evidence):
            raise RuntimeError("EVIDENCE_NOT_SANITIZED")
        output = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output)
        print(output, end="")
    except Exception:  # noqa: BLE001 - privacy boundary emits only a stable public failure code
        # Do not dump exceptions, locals, SMTP envelopes, payloads or credential material.
        print(json.dumps({"result_code": "NOTIFICATION_PROOF_FAILED"}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
