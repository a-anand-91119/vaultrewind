#!/usr/bin/env python3
"""Build the pinned MinIO test fixture into private .runtime/bin; never installs system-wide."""
from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import subprocess
import tarfile
import urllib.request
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
LOCK = json.loads((ROOT / "tools/minio-fixture.lock.json").read_text())
RUNTIME = ROOT / ".runtime"
GO_ROOT = RUNTIME / "go-bootstrap"
BIN = RUNTIME / "bin"


def private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or not path.is_dir() or path.stat().st_mode & 0o077:
        raise SystemExit(f"Refusing non-private runtime directory: {path}")


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=180) as response:
        return response.read()


def safe_extract_go(archive: bytes) -> None:
    private_dir(RUNTIME)
    private_dir(GO_ROOT)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        for member in tar.getmembers():
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts or not name.parts or name.parts[0] != "go":
                raise SystemExit("Unexpected member in the checksum-verified Go archive")
        tar.extractall(GO_ROOT, filter="data")


def main() -> None:
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        raise SystemExit("The pinned MinIO fixture builder supports Linux amd64 only")
    spec = LOCK["go"]
    archive = fetch(spec["url"])
    actual = hashlib.sha256(archive).hexdigest()
    if actual != spec["sha256"]:
        raise SystemExit(f"Go archive SHA-256 mismatch: expected {spec['sha256']}, got {actual}")
    safe_extract_go(archive)
    go = GO_ROOT / "go" / "bin" / "go"
    env = os.environ.copy()
    env.update({"GOTOOLCHAIN": "local", "GOBIN": str(BIN), "GOPROXY": "https://proxy.golang.org,direct"})
    private_dir(BIN)
    module = f"{LOCK['module']}@{LOCK['module_version']}"
    info = subprocess.run([str(go), "mod", "download", "-json", module], check=True,
                          capture_output=True, text=True, env=env)
    metadata = json.loads(info.stdout)
    if metadata.get("Sum") != LOCK["module_sum"]:
        raise SystemExit(f"MinIO module checksum mismatch: expected {LOCK['module_sum']}, got {metadata.get('Sum')}")
    subprocess.run([str(go), "install", module], check=True, env=env)
    binary = BIN / "minio"
    if not binary.is_file():
        raise SystemExit("Go install completed without producing .runtime/bin/minio")
    binary.chmod(0o700)
    print(f"Built checksum-verified MinIO {LOCK['source_release']} at {binary}")


if __name__ == "__main__":
    main()
