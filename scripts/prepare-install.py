#!/usr/bin/env python3
"""Prepare private local installation files without deploying or printing secrets."""
import argparse
import os
import secrets
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--data-dir", type=Path, required=True)
parser.add_argument("--origin", default="https://localhost")
args = parser.parse_args()
if not args.data_dir.is_absolute() or len(args.data_dir.parts) < 3 or args.data_dir.is_symlink():
    raise SystemExit("Choose a dedicated absolute persistent directory, outside source data and staging.")
os.umask(0o077)
private = Path(".secrets")
private.mkdir(exist_ok=True, mode=0o700)
for name, data in {"master_key": secrets.token_bytes(32), "bootstrap": secrets.token_urlsafe(48).encode(),
                   "database_password": secrets.token_urlsafe(48).encode()}.items():
    path = private / name
    if not path.exists():
        with path.open("xb") as stream:
            stream.write(data)
        path.chmod(0o600)
        if os.geteuid() == 0:
            os.chown(path, 10001, 10001)
for role in ("backups", "staging", "cache", "metadata", "provider-credentials"):
    path = args.data_dir / role
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.geteuid() == 0:
        os.chown(path, 10001, 10001)
    path.chmod(0o700)
if not Path(".env").exists():
    Path(".env").write_text(f"VAULTREWIND_DATA_DIR={args.data_dir}\nVAULTREWIND_PUBLIC_ORIGIN={args.origin}\n")
print("Installation files prepared; no services were started.")
print("Read .secrets/bootstrap privately for first-run setup; do not paste it into chat or logs.")
if os.geteuid() != 0:
    print("Before Compose startup, give UID/GID 10001 ownership of the three .secrets files and the data subdirectories.")
