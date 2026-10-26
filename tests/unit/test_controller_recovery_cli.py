from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from vaultrewind.core.errors import VaultRewindError
from vaultrewind.recovery import cli


def test_controller_commands_are_exposed_with_private_target_file() -> None:
    parser = cli.build_parser()
    args = parser.parse_args([
        "controller-restore", "--kit", "kit.vrkit", "--work-dir", "/tmp/work",
        "--snapshot", "a" * 64, "--destination", "destination-id", "--target", "/tmp/empty",
        "--target-database-url-file", "/tmp/target-url",
    ])
    assert args.command == "controller-restore"
    assert args.target_database_url_file == "/tmp/target-url"


def test_controller_restore_requires_full_restic_id_and_empty_target(tmp_path: Path) -> None:
    with pytest.raises(VaultRewindError, match="64-character"):
        cli._restic_snapshot_id("short")
    target = tmp_path / "target"
    target.mkdir()
    (target / "existing").write_text("keep")
    with pytest.raises(VaultRewindError, match="empty directory"):
        cli._empty_restore_target(str(target))


def test_database_confirmation_names_exact_target_and_requires_tty(monkeypatch) -> None:
    url = "postgresql://operator:private-password@db.example.test:5432/vr_recovery"
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda: "RESTORE db.example.test/vr_recovery")
    cli._confirm_database_target(url)

    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    with pytest.raises(VaultRewindError, match="interactive terminal"):
        cli._confirm_database_target(url)


def test_controller_restore_validates_exact_repository_snapshot_before_db_restore(tmp_path: Path, monkeypatch) -> None:
    import vaultrewind.server.controller_backup as backup

    snapshot_id = "a" * 64
    controller_id = "controller-uuid"
    destination_id = "destination-uuid"
    kit = {"controller_id": controller_id, "recovery_root_secret": "recovery-root"}
    destination = {"destination_id": destination_id, "backend": "local", "name": "Archive"}
    repository = object()
    row = {"id": snapshot_id, "snapshot_uuid": "snapshot-uuid", "manifest_hash": "b" * 64}
    from contextlib import nullcontext
    from types import SimpleNamespace
    monkeypatch.setattr(cli.offline, "OfflineSession", lambda *_args, **_kwargs: SimpleNamespace(open=lambda *_a: nullcontext(repository)))
    monkeypatch.setattr(
        cli, "_controller_snapshot_rows",
        lambda *_args, **_kwargs: iter([(destination, {"instance_id": controller_id}, repository, row)]),
    )
    seen = {}

    def validate(repo, exact_id, target, **kwargs):
        seen.update(repo=repo, exact_id=exact_id, target=target, **kwargs)
        return {
            "manifest": {
                "controller_uuid": controller_id,
                "destination_id": destination_id,
                "snapshot_uuid": "snapshot-uuid",
                "captured_at": "2026-10-25T12:00:00Z",
            },
            "catalog_verified": True,
            "pg_dump_verified": True,
            "tables": 6,
            "rows": 42,
        }

    monkeypatch.setattr(backup, "validate_controller_snapshot", validate)
    dump_calls = []
    monkeypatch.setattr(backup, "restore_dump_to_empty_database", lambda *args, **kwargs: dump_calls.append((args, kwargs)))
    target = tmp_path / "empty"
    urlfile = tmp_path / "target.url"
    urlfile.write_text("postgresql://operator:secret@db.example.test/vr_recovery\n")
    urlfile.chmod(0o600)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda: "RESTORE db.example.test/vr_recovery")
    args = argparse.Namespace(
        snapshot=snapshot_id,
        destination=destination_id,
        target=str(target),
        target_database_url_file=str(urlfile),
        work_dir=str(tmp_path / "work"),
    )

    result = cli._controller_restore(args, kit, {}, {})

    assert seen["repo"] is repository
    assert seen["exact_id"] == snapshot_id
    assert seen["expected_manifest_hash"] == row["manifest_hash"]
    assert result["catalog_verified"] and result["database_restored"]
    assert result["database_target"] == "db.example.test/vr_recovery"
    assert "secret" not in repr(result)
    assert dump_calls and dump_calls[0][1]["operator_authorized"] is True


def test_private_url_file_rejects_group_or_world_permissions(tmp_path: Path) -> None:
    path = tmp_path / "url"
    path.write_text("postgresql://db/recovery")
    path.chmod(0o640)
    with pytest.raises(VaultRewindError, match="chmod 600"):
        cli._private_file(str(path), "target database URL")
