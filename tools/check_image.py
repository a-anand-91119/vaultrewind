"""Build-time target-wheel validation and secret-free runtime image smoke check."""
from __future__ import annotations

import argparse
import json
import platform
import sqlite3
from importlib.metadata import version
from pathlib import Path


def check_environment(environment: Path, architecture: str) -> int:
    machine = {"amd64": 62, "arm64": 183}[architecture]
    native_files = 0
    for path in environment.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open("rb") as stream:
            header = stream.read(20)
        if header[:4] != b"\x7fELF":
            continue
        if header[:6] != b"\x7fELF\x02\x01" or int.from_bytes(header[18:20], "little") != machine:
            raise ValueError(f"Wrong target architecture in {path.relative_to(environment)}")
        native_files += 1
    if not native_files:
        raise ValueError("The installed environment has no native dependency artifacts")
    return native_files


def smoke() -> dict:
    import psycopg.pq
    from argon2 import PasswordHasher
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    import vaultrewind.recovery.cli
    import vaultrewind.server.app
    import vaultrewind.server.worker

    # Do not construct an application, open a catalog, or load runtime secrets.
    assert callable(vaultrewind.server.app.create_app)
    assert vaultrewind.server.worker.Worker
    assert callable(vaultrewind.recovery.cli.main)
    assert callable(vaultrewind.recovery.cli.build_parser)
    key = AESGCM.generate_key(256)
    cipher = AESGCM(key)
    nonce = b"\x01" * 12
    assert cipher.decrypt(nonce, cipher.encrypt(nonce, b"synthetic-image-smoke", None), None) == b"synthetic-image-smoke"
    hasher = PasswordHasher(time_cost=1, memory_cost=1024, parallelism=1)
    assert hasher.verify(hasher.hash("synthetic-image-smoke"), "synthetic-image-smoke")
    with sqlite3.connect(":memory:") as database:
        database.execute("CREATE TABLE smoke (value TEXT)")
        database.execute("INSERT INTO smoke VALUES ('synthetic')")
        assert database.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert database.execute("SELECT value FROM smoke").fetchone()[0] == "synthetic"
    return {"architecture": platform.machine(), "vaultrewind": version("vaultrewind"),
            "application_imports": True, "sqlite": True, "aes_gcm": True, "argon2": True,
            "libpq_version": psycopg.pq.version()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", type=Path)
    parser.add_argument("--arch", choices=("amd64", "arm64"))
    args = parser.parse_args()
    if args.environment:
        if not args.arch:
            parser.error("--environment requires --arch")
        print(json.dumps({"native_files_verified": check_environment(args.environment, args.arch),
                          "target_architecture": args.arch}))
    else:
        print(json.dumps(smoke(), sort_keys=True))


if __name__ == "__main__":
    main()
