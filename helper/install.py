#!/usr/bin/env python3
"""Explicit local administrative activation. Never invoked by ordinary jobs."""
import argparse
import hashlib
import io
import json
import os
import pwd
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


def run(args):
    subprocess.run(args, check=True, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"})


def install_bytes(path, content, mode):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    for parent in (path.parent, *path.parent.parents):
        st = parent.lstat()
        if parent.is_symlink() or st.st_uid != 0 or st.st_mode & 0o022:
            raise SystemExit("Install directories must be root-owned, non-symlink and not writable by others")
    if path.is_symlink():
        raise SystemExit("Refusing symlink install destination")
    temporary = path.with_name(path.name + ".new")
    with temporary.open("xb") as out:
        out.write(content)
        out.flush()
        os.fsync(out.fileno())
    os.chmod(temporary, mode)
    os.chown(temporary, 0, 0)
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_DIRECTORY)
    os.fsync(fd)
    os.close(fd)


def main():
    parser = argparse.ArgumentParser(description="Install the explicitly reviewed VaultRewind host recovery bundle")
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--ssh-user", required=True)
    parser.add_argument("--bundle-sha256", required=True, help="Reviewed helper.pyz SHA-256 from the trusted build output")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Activation requires a local administrator/root")
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", args.ssh_user):
        raise SystemExit("Invalid SSH account")
    account = pwd.getpwnam(args.ssh_user)
    if account.pw_uid == 0:
        raise SystemExit("Use a dedicated non-root SSH account")
    base = Path(__file__).resolve().parent
    bundle_bytes = (base / "helper.pyz").read_bytes()
    actual = hashlib.sha256(bundle_bytes).hexdigest()
    if actual != args.bundle_sha256:
        raise SystemExit("Helper checksum differs from the explicitly reviewed build")
    checksums = json.loads((base / "checksums.json").read_bytes())
    bundle_members = {name: (base / name).read_bytes() for name in ("vaultrewind-watchdog@.service", "vaultrewind-reconcile.service")}
    bundle_members["helper.pyz"] = bundle_bytes
    with zipfile.ZipFile(io.BytesIO(bundle_bytes)) as archive:
        anchored_units = json.loads(archive.read("bundle-units.json"))
    for name in ("vaultrewind-watchdog@.service", "vaultrewind-reconcile.service"):
        if hashlib.sha256(bundle_members[name]).hexdigest() != anchored_units.get(name):
            raise SystemExit("Recovery unit differs from the reviewed executable bundle identity")
    for name, content in bundle_members.items():
        if hashlib.sha256(content).hexdigest() != checksums.get(name):
            raise SystemExit("Bundle member checksum mismatch")
    verified_temp = tempfile.TemporaryDirectory(prefix="vaultrewind-verified-")
    verified_path = Path(verified_temp.name) / "helper.pyz"
    verified_path.write_bytes(bundle_bytes)
    sys.path.insert(0, str(verified_path))
    from vaultrewind.remote.policy import Policy, no_symlink, root_trusted
    policy_bytes = args.policy.read_bytes()
    policy = Policy(json.loads(policy_bytes))
    if not Path("/run/systemd/system").is_dir():
        raise SystemExit("A running systemd host is required")
    run(["/usr/bin/systemctl", "is-active", "--quiet", "docker.service"])
    for value in policy.value["instances"].values():
        for mount in value["mounts"]:
            root_trusted(Path(mount["source"]).parent, directory=True)
            no_symlink(Path(mount["source"]), missing_leaf=True)
    state = Path("/var/lib/vaultrewind-helper")
    state.mkdir(mode=0o700, exist_ok=True)
    os.chown(state, 0, 0)
    os.chmod(state, 0o700)
    root_trusted(state, directory=True)
    # Upgrades never rewrite the running helper beneath an armed recovery transaction.
    for journal in (state / "journals").glob("*.json"):
        if json.loads(journal.read_bytes()).get("watchdog_armed"):
            raise SystemExit("An armed recovery transaction blocks upgrade/policy replacement")
    version = Path("/opt/vaultrewind-helper") / actual
    version.mkdir(parents=True, exist_ok=True)
    install_bytes(version / "helper.pyz", bundle_bytes, 0o644)
    wrapper = f"#!/bin/sh\nexec /usr/bin/python3 -I {version}/helper.pyz \"$@\"\n".encode()
    install_bytes(Path("/usr/local/libexec/vaultrewind-helper"), wrapper, 0o755)
    install_bytes(Path("/etc/vaultrewind/helper-policy.json"), policy_bytes, 0o600)
    for name in ("vaultrewind-watchdog@.service", "vaultrewind-reconcile.service"):
        install_bytes(Path("/etc/systemd/system") / name, bundle_members[name], 0o644)
        parents = sorted({str(Path(m["source"]).parent) for v in policy.value["instances"].values() for m in v["mounts"] if m["type"] == "bind"})
        # systemd unit paths are escaped; policy strings are never shell fragments.
        paths = [json.dumps(path).replace("%", "%%") for path in parents]
        install_bytes(Path("/etc/systemd/system") / (name + ".d") / "enrolled-paths.conf",
                      ("[Service]\nReadWritePaths=" + " ".join(paths) + "\n").encode(), 0o644)
    sudoers = (f"Defaults:{args.ssh_user} !requiretty\n"
               f"{args.ssh_user} ALL=(root) NOPASSWD: /usr/local/libexec/vaultrewind-helper \"\"\n").encode()
    check = Path("/etc/sudoers.d/.vaultrewind-check")
    install_bytes(check, sudoers, 0o440)
    try:
        run(["/usr/sbin/visudo", "-cf", str(check)])
        os.replace(check, "/etc/sudoers.d/vaultrewind-helper")
    finally:
        check.unlink(missing_ok=True)
    run(["/usr/bin/systemctl", "daemon-reload"])
    run(["/usr/bin/systemctl", "enable", "vaultrewind-reconcile.service"])
    from vaultrewind.remote.recovery import SystemdRecovery
    SystemdRecovery().verify()
    verified_temp.cleanup()
    print("Helper installed. No application was stopped or backed up. Restrict the SSH key as documented.")


if __name__ == "__main__":
    main()
