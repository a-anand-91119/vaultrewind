#!/usr/bin/env python3
"""Scan repository artifacts and native fixture logs without printing any private value."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = ROOT / ".runtime"
SENSITIVE = {"private_key", "client_secret", "secret_access_key", "password", "access_token", "refresh_token"}


def values(value):
    found = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key in SENSITIVE and isinstance(child, str) and len(child) >= 12:
                found.extend([child.encode(), json.dumps(child)[1:-1].encode()])
            elif isinstance(child, (dict, list)):
                found.extend(values(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(values(child))
    return found


def main():
    private_files = [PRIVATE / "controller/admin-password", PRIVATE / "controller/database-url"]
    patterns = [p.read_bytes().strip() for p in private_files if p.is_file()]
    for path in (PRIVATE / "ssh/config.json", PRIVATE / "minio/credentials.json",
                 PRIVATE / "vm/controller-enrollment.json"):
        if path.is_file():
            patterns.extend(values(json.loads(path.read_text())))
    patterns = list({pattern for pattern in patterns if len(pattern) >= 12})
    assert patterns, "No private synthetic fixtures available for redaction scan"
    paths = []
    for directory in ("src", "frontend/src", "docs", "scripts", "tools", "tests", "migrations", "helper"):
        paths.extend(p for p in (ROOT / directory).rglob("*") if p.is_file()
                     and not any(part.startswith(".") or part == "__pycache__" for part in p.relative_to(ROOT).parts))
    paths += [p for p in (PRIVATE / "controller").glob("*.log") if p.is_file()]
    leaks = []
    for path in paths:
        content = path.read_bytes()
        if any(pattern in content for pattern in patterns):
            leaks.append(str(path.relative_to(ROOT)))
    report = {"result": "failed" if leaks else "passed", "synthetic_only": True,
              "private_pattern_count": len(patterns), "artifact_count": len(paths),
              "matching_paths": leaks,
              "scope": "Exact known private fixture values in repository artifacts and native API/worker logs.",
              "limits": ["Does not perform OCR on screenshots or prove absence of every possible derived secret.",
                         "HTTP response/event redaction and process-argument handling have separate automated tests."]}
    (ROOT / "docs/evidence/secret-scan.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return bool(leaks)


if __name__ == "__main__":
    raise SystemExit(main())
