#!/usr/bin/env python3
"""Install only the checksum-pinned release tools selected for this build."""
import bz2
import hashlib
import io
import json
import platform
import sys
import urllib.request
import zipfile
from pathlib import Path

if platform.machine() != "x86_64":
    raise SystemExit("This locked binary bundle targets linux/amd64; add reviewed arm64 checksums before building there.")
destination = Path(sys.argv[1] if len(sys.argv) > 1 else "/usr/local/bin")
destination.mkdir(parents=True, exist_ok=True)
for name, item in json.loads(Path(__file__).with_name("binaries.lock.json").read_text()).items():
    content = urllib.request.urlopen(item["url"], timeout=180).read()
    if hashlib.sha256(content).hexdigest() != item["sha256"]:
        raise SystemExit(f"Checksum verification failed for {name}")
    if name == "restic":
        executable = bz2.decompress(content)
    else:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            executable = archive.read(f"rclone-v{item['version']}-linux-amd64/rclone")
    path = destination / name
    path.write_bytes(executable)
    path.chmod(0o755)
    print(f"Installed checksum-verified {name} {item['version']}")
