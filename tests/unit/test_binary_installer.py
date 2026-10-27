"""Release checksum and CPU selection checks without external downloads."""
from __future__ import annotations

import bz2
import hashlib
import io
import json
from pathlib import Path

import pytest

from tools import install_binaries as installer
from tools.check_image import check_environment, smoke


def elf(architecture):
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    header[18:20] = installer.ELF_MACHINES[architecture].to_bytes(2, "little")
    return bytes(header) + b"synthetic executable fixture"


def fixture_lock(tmp_path):
    lock = {}
    downloads = {}
    for name in ("restic", "rclone"):
        lock[name] = {"version": "1.0.0", "assets": {}}
        for arch in ("amd64", "arm64"):
            executable = elf(arch)
            if name == "restic":
                asset = f"restic_1.0.0_linux_{arch}.bz2"
                content = bz2.compress(executable)
            else:
                asset = f"rclone-v1.0.0-linux-{arch}.zip"
                output = io.BytesIO()
                with installer.zipfile.ZipFile(output, "w") as archive:
                    archive.writestr(asset.removesuffix(".zip") + "/rclone", executable)
                content = output.getvalue()
            url = "https://releases.example.invalid/" + asset
            lock[name]["assets"][arch] = {"asset": asset, "url": url,
                "sha256": hashlib.sha256(content).hexdigest()}
            downloads[url] = content
    filename = tmp_path / "lock.json"
    filename.write_text(json.dumps(lock))
    return filename, downloads


@pytest.mark.parametrize("architecture", ["amd64", "arm64"])
def test_installs_only_verified_executables_for_selected_target(tmp_path, monkeypatch, architecture):
    lock, downloads = fixture_lock(tmp_path)
    requested = []
    def download(url):
        requested.append(url)
        return downloads[url]
    monkeypatch.setattr(installer, "download", download)
    target = tmp_path / "bin"
    installer.install(target, architecture, lock=lock)
    assert all(architecture in url for url in requested)
    assert len(requested) == 2
    assert {p.name for p in target.iterdir()} == {"restic", "rclone"}
    for name in ("restic", "rclone"):
        assert (target / name).read_bytes() == elf(architecture)
        assert (target / name).stat().st_mode & 0o777 == 0o755


def test_checksum_rejection_preserves_existing_binary(tmp_path, monkeypatch):
    lock, downloads = fixture_lock(tmp_path)
    target = tmp_path / "bin"
    target.mkdir()
    previous = target / "restic"
    previous.write_bytes(b"previous verified release")
    monkeypatch.setattr(installer, "download", lambda url: downloads[url] + b"corruption")
    with pytest.raises(ValueError, match="Checksum verification failed"):
        installer.install(target, "arm64", lock=lock)
    assert previous.read_bytes() == b"previous verified release"
    assert not (target / "rclone").exists()


def test_wrong_cpu_is_rejected_even_with_matching_archive_checksum(tmp_path, monkeypatch):
    lock, downloads = fixture_lock(tmp_path)
    config = json.loads(lock.read_text())
    wrong = bz2.compress(elf("amd64"))
    item = config["restic"]["assets"]["arm64"]
    downloads[item["url"]] = wrong
    item["sha256"] = hashlib.sha256(wrong).hexdigest()
    lock.write_text(json.dumps(config))
    monkeypatch.setattr(installer, "download", downloads.__getitem__)
    with pytest.raises(ValueError, match="architecture mismatch"):
        installer.install(tmp_path / "bin", "arm64", lock=lock)
    assert not (tmp_path / "bin").exists()


def test_unsupported_cpu_fails_before_network_or_writes(tmp_path, monkeypatch):
    monkeypatch.setattr(installer, "download", lambda _: pytest.fail("unexpected download"))
    with pytest.raises(ValueError, match="Only Linux amd64 and arm64"):
        installer.install(tmp_path / "bin", "riscv64")
    assert not (tmp_path / "bin").exists()


@pytest.mark.parametrize("machine,expected", [("x86_64", "amd64"), ("aarch64", "arm64")])
def test_detects_native_architecture(tmp_path, monkeypatch, machine, expected):
    lock, downloads = fixture_lock(tmp_path)
    monkeypatch.setattr(installer.platform, "machine", lambda: machine)
    monkeypatch.setattr(installer, "download", downloads.__getitem__)
    installer.install(tmp_path / "bin", lock=lock)
    assert (tmp_path / "bin/restic").read_bytes() == elf(expected)


def test_real_lock_pins_both_official_platforms_without_unlocked_urls():
    lock = json.loads((Path(installer.__file__).parent / "binaries.lock.json").read_text())
    for tool, item in lock.items():
        assert set(item["assets"]) == {"amd64", "arm64"}
        for architecture, asset in item["assets"].items():
            assert len(asset["sha256"]) == 64
            assert asset["url"].startswith(f"https://github.com/{tool}/{tool}/releases/download/v")
            assert architecture in asset["asset"]
            assert asset["url"].endswith(asset["asset"])


def test_cross_environment_rejects_one_foreign_extension_among_target_wheels(tmp_path):
    (tmp_path / "correct.so").write_bytes(elf("arm64"))
    (tmp_path / "python.py").write_text("# architecture-independent module\n")
    assert check_environment(tmp_path, "arm64") == 1
    (tmp_path / "foreign.so").write_bytes(elf("amd64"))
    with pytest.raises(ValueError, match="Wrong target architecture in foreign.so"):
        check_environment(tmp_path, "arm64")


def test_runtime_smoke_checks_public_entrypoints_and_native_dependencies_without_services():
    result = smoke()
    assert all(result[key] for key in ("application_imports", "sqlite", "aes_gcm", "argon2"))
    assert result["vaultrewind"] == "0.1.0"
    assert result["libpq_version"] > 0
