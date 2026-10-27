#!/usr/bin/env python3
"""Install checksum-pinned Linux tools for the selected image architecture."""
from __future__ import annotations

import argparse
import bz2
import hashlib
import io
import json
import os
import platform
import tempfile
import urllib.request
import zipfile
from pathlib import Path

MACHINES = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
ELF_MACHINES = {"amd64": 62, "arm64": 183}


def download(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=180) as response:
        content = response.read(128 * 1024**2 + 1)
    if len(content) > 128 * 1024**2:
        raise ValueError("Release archive exceeds the size limit")
    return content


def install(destination: Path, architecture: str | None = None, *, lock: Path | None = None) -> None:
    architecture = architecture or MACHINES.get(platform.machine().lower())
    if architecture not in ELF_MACHINES:
        raise ValueError("Only Linux amd64 and arm64 release tools are supported")
    entries = json.loads((lock or Path(__file__).with_name("binaries.lock.json")).read_text())
    for name, item in entries.items():
        asset = item["assets"][architecture]
        content = download(asset["url"])
        if hashlib.sha256(content).hexdigest() != asset["sha256"]:
            raise ValueError(f"Checksum verification failed for {name}")
        if name == "restic":
            executable = bz2.decompress(content)
        elif name == "rclone":
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                executable = archive.read(asset["asset"].removesuffix(".zip") + "/rclone")
        else:
            raise ValueError("Unknown release tool")
        if (len(executable) < 20 or executable[:6] != b"\x7fELF\x02\x01"
                or int.from_bytes(executable[18:20], "little") != ELF_MACHINES[architecture]):
            raise ValueError(f"Release binary architecture mismatch for {name}")
        destination.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=destination, delete=False) as temporary:
            temporary_path = Path(temporary.name)
            try:
                temporary.write(executable)
                temporary.flush()
                temporary_path.chmod(0o755)
                os.replace(temporary_path, destination / name)
            finally:
                temporary_path.unlink(missing_ok=True)
        print(f"Installed checksum-verified {name} {item['version']} linux/{architecture}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", nargs="?", type=Path, default=Path("/usr/local/bin"))
    parser.add_argument("--arch", choices=sorted(ELF_MACHINES))
    args = parser.parse_args()
    install(args.destination, args.arch)


if __name__ == "__main__":
    main()
