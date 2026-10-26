"""Standalone offline recovery CLI: ``python -m vaultrewind.recovery <command>``.

Works without a running controller, its database or its master key.  Secrets
(passphrase, replacement credentials) are read from a prompt or owner-only
files, never from command-line arguments, and are never printed.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import stat
import sys
from pathlib import Path

from vaultrewind.core.errors import VaultRewindError
from vaultrewind.security.redaction import redact

from . import kit as kitmod
from . import offline


def _restic_snapshot_id(value: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise VaultRewindError("CONTROLLER_SNAPSHOT_INVALID", "Use the full 64-character restic snapshot ID.")
    return value


def _empty_restore_target(path: str) -> Path:
    target = Path(path)
    if target.is_symlink() or target.exists() and (not target.is_dir() or any(target.iterdir())):
        raise VaultRewindError("RESTORE_TARGET_NOT_EMPTY", "Controller recovery requires a new or empty directory.")
    return target


def _controller_snapshot_rows(kit: dict, session: offline.OfflineSession, destination_id: str | None = None):
    """Yield exact controller-tagged snapshots from kit repositories; never infer by a display label."""
    from vaultrewind.storage.controller import list_controller_snapshots

    controller_id = str(kit.get("controller_id") or "")
    if not controller_id:
        raise VaultRewindError("CONTROLLER_ID_MISSING", "This recovery kit has no controller identity.")
    for destination in session.destinations.values():
        dest_id = destination["destination_id"]
        if destination_id and dest_id != destination_id:
            continue
        candidates, _error = offline._candidates(session, destination)
        for candidate in candidates:
            identity = candidate.get("instance_id")
            if (candidate.get("purpose") != "controller" and identity != controller_id) or not candidate.get("password"):
                continue
            with session.open(destination, candidate) as repository:
                for item in list_controller_snapshots(
                    repository, controller_id=identity, destination_id=dest_id
                ):
                    yield destination, candidate, repository, {
                        "id": item["restic_snapshot_id"],
                        "time": item.get("captured_at"),
                        "manifest_hash": item["manifest_hash"],
                        "snapshot_uuid": item["snapshot_uuid"],
                    }


def _private_file(path: str, what: str) -> bytes:
    file = Path(path)
    fd = None
    try:
        fd = os.open(file, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(fd)
    except OSError as exc:
        raise VaultRewindError("RECOVERY_INPUT_UNAVAILABLE", f"The {what} file is unavailable.") from exc
    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise VaultRewindError("RECOVERY_INPUT_UNAVAILABLE", f"The {what} file must be a regular file.")
    if info.st_mode & 0o077:
        os.close(fd)
        raise VaultRewindError("RECOVERY_INPUT_UNSAFE", f"The {what} file must be readable only by you (chmod 600).")
    with os.fdopen(fd, "rb") as handle:
        return handle.read()


def _passphrase(args) -> str:
    if args.passphrase_file:
        return _private_file(args.passphrase_file, "passphrase").decode("utf-8").rstrip("\r\n")
    if not sys.stdin.isatty():
        raise VaultRewindError("RECOVERY_PASSPHRASE_REQUIRED", "Use --passphrase-file when no terminal is attached.")
    return getpass.getpass("Recovery kit passphrase: ")


def _load_kit(args) -> dict:
    try:
        blob = Path(args.kit).read_bytes()
    except OSError as exc:
        raise VaultRewindError("RECOVERY_KIT_INVALID", "The recovery kit file is unavailable.") from exc
    return kitmod.open_recovery_kit(blob, _passphrase(args))


def _overrides(args) -> tuple[dict, dict]:
    credentials = {}
    if getattr(args, "credentials_file", None):
        try:
            credentials = json.loads(_private_file(args.credentials_file, "credentials"))
        except ValueError as exc:
            raise VaultRewindError("RECOVERY_OVERRIDE_INVALID", "The credentials file is not valid JSON.") from exc
        if not isinstance(credentials, dict):
            raise VaultRewindError("RECOVERY_OVERRIDE_INVALID", "The credentials file must map destination IDs.")
    local_paths = {}
    for item in getattr(args, "local_path", None) or []:
        destination_id, sep, path = item.partition("=")
        if not sep or not os.path.isabs(path):
            raise VaultRewindError("RECOVERY_OVERRIDE_INVALID", "Use --local-path <destination_id>=<absolute path>.")
        local_paths[destination_id] = path
    return credentials, local_paths


def _emit(value, output: str | None = None) -> None:
    text = json.dumps(redact(value), indent=2, sort_keys=True) + "\n"
    if output:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(output, flags, 0o600), "w") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m vaultrewind.recovery",
                                     description="VaultRewind offline disaster recovery (no controller required).")
    sub = parser.add_subparsers(dest="command", required=True)

    def with_kit(p):
        p.add_argument("--kit", required=True, help="encrypted recovery kit file")
        p.add_argument("--passphrase-file", help="owner-only file containing the kit passphrase (else prompt)")

    def with_storage(p):
        p.add_argument("--work-dir", required=True, help="private working directory (caches, temporary credentials)")
        p.add_argument("--credentials-file", help="owner-only JSON {destination_id: replacement credential fields}")
        p.add_argument("--local-path", action="append", help="<destination_id>=<path> for a re-mounted local disk")

    inspect = sub.add_parser("inspect", help="show the kit's destinations and repositories (no secrets)")
    with_kit(inspect)
    discover = sub.add_parser("discover", help="list repositories and snapshots reachable with the kit")
    with_kit(discover)
    with_storage(discover)
    discover.add_argument("--skip-manifests", action="store_true", help="list tags only; do not read manifests")
    restore = sub.add_parser("restore", help="restore and verify one snapshot into an empty local directory")
    with_kit(restore)
    with_storage(restore)
    restore.add_argument("--snapshot", required=True, help="VaultRewind snapshot UUID")
    restore.add_argument("--target", required=True, help="new or empty directory")
    restore.add_argument("--destination", help="restrict to one destination ID")
    plan = sub.add_parser("plan", help="validate a restored snapshot and print the target deployment plan")
    plan.add_argument("--restored", required=True, help="directory produced by 'restore'")
    plan.add_argument("--target-profile", help="JSON file: public_url, network, port_bindings, target_name")
    plan.add_argument("--same-instance", action="store_true", help="recovering the original instance identity")
    plan.add_argument("--kit", help="optional kit for provider recovery instructions")
    plan.add_argument("--passphrase-file")
    importer = sub.add_parser("import-plan", help="write a protected-mode import plan for a fresh controller")
    with_kit(importer)
    with_storage(importer)
    importer.add_argument("--output", required=True, help="new file to create (0600)")
    controller_list = sub.add_parser("controller-snapshots", help="list exact controller metadata recovery snapshots")
    with_kit(controller_list)
    with_storage(controller_list)
    controller_list.add_argument("--destination", help="restrict to one destination UUID")
    controller_restore = sub.add_parser(
        "controller-restore", help="verify and restore one controller metadata snapshot offline"
    )
    with_kit(controller_restore)
    with_storage(controller_restore)
    controller_restore.add_argument("--snapshot", required=True, help="full restic snapshot ID from controller-snapshots")
    controller_restore.add_argument("--destination", required=True, help="destination UUID containing the snapshot")
    controller_restore.add_argument("--target", required=True, help="new or empty private restore directory")
    controller_restore.add_argument(
        "--target-database-url-file", help="optional mode-0600 file naming an explicitly prepared empty PostgreSQL database"
    )
    return parser


def _confirm_database_target(url: str) -> None:
    from sqlalchemy.engine import make_url

    try:
        parsed = make_url(url)
    except Exception as exc:
        raise VaultRewindError(
            "CONTROLLER_DATABASE_CONFIGURATION", "The target database URL is invalid."
        ) from exc
    if parsed.get_backend_name() != "postgresql" or not parsed.host or not parsed.database:
        raise VaultRewindError("CONTROLLER_DATABASE_CONFIGURATION", "The target URL must identify a PostgreSQL database.")
    identity = f"{parsed.host}/{parsed.database}"
    if not sys.stdin.isatty():
        raise VaultRewindError("CONTROLLER_RESTORE_CONFIRMATION_REQUIRED", "Database restore requires an interactive terminal.")
    sys.stderr.write(
        f"This restores controller metadata into the prepared empty database {identity}.\n"
        f"Type RESTORE {identity} to authorize this exact target: "
    )
    sys.stderr.flush()
    if input().strip() != f"RESTORE {identity}":
        raise VaultRewindError("CONTROLLER_RESTORE_CONFIRMATION_REQUIRED", "The target confirmation did not match.")


def _controller_restore(args, kit: dict, credentials: dict, local_paths: dict) -> dict:
    from sqlalchemy.engine import make_url

    from vaultrewind.server.controller_backup import (
        restore_dump_to_empty_database,
        validate_controller_snapshot,
    )

    restic_id = _restic_snapshot_id(args.snapshot)
    target = _empty_restore_target(args.target)
    destination_id = args.destination
    session = offline.OfflineSession(kit, Path(args.work_dir), credentials, local_paths)
    match = None
    for destination, candidate, repository, row in _controller_snapshot_rows(kit, session, destination_id):
        if row.get("id") == restic_id:
            match = (destination, candidate, repository, row)
            break
    if not match:
        raise VaultRewindError(
            "CONTROLLER_SNAPSHOT_NOT_FOUND", "That exact restic snapshot is not a controller backup in the selected destination."
        )
    destination, candidate, repository, row = match
    expected_controller = candidate["instance_id"]
    root_secret = (kit.get("controller_recovery_roots") or {}).get(expected_controller)
    if root_secret is None and expected_controller == kit.get("controller_id"):
        root_secret = kit.get("recovery_root_secret")
    if not root_secret:
        raise VaultRewindError("RECOVERY_ROOT_UNAVAILABLE", "The kit has no recovery root for this controller history; use its original independently encrypted kit.")
    # The listing generator's provider context closes after selection. Open the chosen
    # repository for the entire readback so Drive's private configuration remains live.
    with session.open(destination, candidate) as selected_repository:
        evidence = validate_controller_snapshot(
            selected_repository,
            restic_id,
            target,
            recovery_root_secret=root_secret,
            expected_manifest_hash=row["manifest_hash"],
        )
    manifest = evidence["manifest"]
    if (
        manifest.get("controller_uuid") != expected_controller
        or manifest.get("destination_id") != destination["destination_id"]
        or manifest.get("snapshot_uuid") != row["snapshot_uuid"]
    ):
        raise VaultRewindError(
            "CONTROLLER_SNAPSHOT_IDENTITY_MISMATCH", "The snapshot manifest does not match the kit and selected repository."
        )
    result = {
        "restic_snapshot_id": restic_id,
        "snapshot_uuid": manifest["snapshot_uuid"],
        "controller_id": manifest["controller_uuid"],
        "destination_id": destination["destination_id"],
        "captured_at": manifest.get("captured_at"),
        "restore_directory": str(target),
        "catalog_verified": evidence["catalog_verified"],
        "pg_dump_verified": evidence["pg_dump_verified"],
        "tables": evidence.get("tables"),
        "rows": evidence.get("rows"),
        "database_restored": False,
    }
    if args.target_database_url_file:
        try:
            target_url = _private_file(args.target_database_url_file, "target database URL").decode("utf-8").strip()
        except UnicodeDecodeError as exc:
            raise VaultRewindError(
                "CONTROLLER_DATABASE_CONFIGURATION", "The target database URL file is not valid UTF-8."
            ) from exc
        if not target_url:
            raise VaultRewindError("CONTROLLER_DATABASE_CONFIGURATION", "The target database URL file is empty.")
        _confirm_database_target(target_url)
        restore_dump_to_empty_database(target / "database.dump", target_url, operator_authorized=True)
        parsed = make_url(target_url)
        result.update(database_restored=True, database_target=f"{parsed.host}/{parsed.database}", workers_may_resume=False)
    return result


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "inspect":
            _emit(kitmod.kit_summary(_load_kit(args)))
        elif args.command == "discover":
            credentials, local_paths = _overrides(args)
            _emit(offline.discover(_load_kit(args), work_dir=Path(args.work_dir), credential_overrides=credentials,
                                   local_paths=local_paths, read_manifests=not args.skip_manifests))
        elif args.command == "restore":
            credentials, local_paths = _overrides(args)
            _emit(offline.restore_snapshot(_load_kit(args), args.snapshot, Path(args.target),
                                           work_dir=Path(args.work_dir), credential_overrides=credentials,
                                           local_paths=local_paths, destination_id=args.destination))
        elif args.command == "plan":
            profile = json.loads(Path(args.target_profile).read_text()) if args.target_profile else None
            kit = _load_kit(args) if args.kit else None
            _emit(offline.build_target_plan(Path(args.restored), target_profile=profile, kit=kit,
                                            same_instance=args.same_instance))
        elif args.command == "import-plan":
            credentials, local_paths = _overrides(args)
            kit = _load_kit(args)
            discovery = offline.discover(kit, work_dir=Path(args.work_dir), credential_overrides=credentials,
                                         local_paths=local_paths)
            _emit(offline.import_plan(discovery, kit), args.output)
        elif args.command == "controller-snapshots":
            credentials, local_paths = _overrides(args)
            kit = _load_kit(args)
            session = offline.OfflineSession(kit, Path(args.work_dir), credentials, local_paths)
            items = []
            for destination, _candidate, _repository, row in _controller_snapshot_rows(
                kit, session, args.destination
            ):
                items.append({
                    "restic_snapshot_id": row["id"],
                    "snapshot_uuid": row["snapshot_uuid"],
                    "manifest_hash": row["manifest_hash"],
                    "destination_id": destination["destination_id"],
                    "destination_name": destination.get("name"),
                    "backend": destination["backend"],
                    "captured_at": row.get("time"),
                })
            _emit({"controller_id": kit.get("controller_id"), "snapshots": items})
        elif args.command == "controller-restore":
            credentials, local_paths = _overrides(args)
            _emit(_controller_restore(args, _load_kit(args), credentials, local_paths))
        return 0
    except VaultRewindError as error:
        sys.stderr.write(json.dumps({"error": error.as_dict()}) + "\n")
        return 2
    except KeyboardInterrupt:
        return 130
