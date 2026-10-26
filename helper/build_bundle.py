#!/usr/bin/env python3
"""Build an auditable, self-contained helper zipapp; does not install or activate it."""
import argparse
import hashlib
import json
import shutil
import tempfile
import zipfile
from pathlib import Path

import yaml


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1]
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temp:
        tree = Path(temp)
        package = tree / "vaultrewind"
        package.mkdir()
        (package / "__init__.py").write_text('__version__ = "0.1.0"\n')
        shutil.copytree(Path(yaml.__file__).parent, tree / "yaml",
                        ignore=shutil.ignore_patterns("__pycache__", "*.so", "*.pyc"))
        for directory in ("core", "remote"):
            shutil.copytree(source / "src" / "vaultrewind" / directory, package / directory,
                            ignore=shutil.ignore_patterns("__pycache__", "ssh.py", "*.pyc"))
        units = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in (source / "helper" / "systemd").glob("*.service")}
        (tree / "bundle-units.json").write_text(json.dumps(units, sort_keys=True))
        (tree / "__main__.py").write_text("from vaultrewind.remote.helper import main\nraise SystemExit(main())\n")
        # Reviewed source must produce the same activation checksum on every build.
        # Temporary-file mtimes otherwise change zipapp's bytes without changing code.
        with zipfile.ZipFile(args.output / "helper.pyz", "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
            for path in sorted(tree.rglob("*")):
                if path.is_file():
                    info = zipfile.ZipInfo(path.relative_to(tree).as_posix(), date_time=(2020, 1, 1, 0, 0, 0))
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.external_attr = 0o100644 << 16
                    bundle.writestr(info, path.read_bytes(), compresslevel=9)
    for path in (source / "helper" / "systemd").glob("*.service"):
        shutil.copyfile(path, args.output / path.name)
    shutil.copyfile(source / "helper" / "install.py", args.output / "install.py")
    (args.output / "install.py").chmod(0o755)
    files = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
             for path in sorted(args.output.iterdir()) if path.is_file() and path.name != "checksums.json"}
    (args.output / "checksums.json").write_text(json.dumps(files, sort_keys=True, indent=2) + "\n")
    print("Helper bundle built; review policy and checksums before explicit host activation.")


if __name__ == "__main__":
    main()
