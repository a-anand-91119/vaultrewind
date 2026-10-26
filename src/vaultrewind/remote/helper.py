"""Privileged root helper. Administrative installation is deliberately separate."""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import math
import os
import shutil
import sys
import tarfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

from vaultrewind import core
from vaultrewind.core.errors import VaultRewindError

from . import HELPER_VERSION
from .cleanup import discard_candidate, isolated_candidate, remember_anonymous
from .docker import (
    Docker,
    create_config,
    discover,
    reject_other_writers,
    require_public_endpoint,
    target_network_profile,
    validate_descriptor,
    validate_public_network,
    verify_published_ports,
)
from .files import build_archive, copy_tree, extract_archive, file_hash, walk_checked
from .journal import (
    POST_ACTIVATION,
    TERMINAL,
    Journal,
    Locks,
    atomic_json,
    fsync_directory,
    read_json,
    resource_keys,
)
from .policy import Policy, clean_absolute, no_symlink, relative, root_trusted
from .protocol import (
    HEX,
    canonical,
    digest,
    fail,
    identifier,
    read_request,
    receive_frames,
    send_frames,
)
from .recovery import SystemdRecovery, expired, process_identity, same_process, watchdog_loop


def utc():
    return datetime.now(UTC).isoformat()


def durable_rename(source: Path, target: Path):
    os.rename(source, target)
    fsync_directory(source.parent)
    if target.parent != source.parent:
        fsync_directory(target.parent)


def persistent_bytes(manifest):
    return sum(item["size"] for item in manifest["inventory"]
               if item["type"] == "file" and (item["path"].startswith("data/") or item["path"].startswith("deployment/mounts/")))


def hash_required(value):
    if not isinstance(value, str) or not HEX.fullmatch(value):
        fail("PROTOCOL_INVALID", "An exact SHA-256 content identity is required.")
    return value


class Helper:
    def __init__(self, policy: Policy, docker=None, recovery=None):
        self.policy = policy
        self.root = policy.state_root
        self.docker = docker or Docker()
        self.recovery = recovery or SystemdRecovery()

    def active(self, instance_id):
        return read_json(self.root / "active" / (instance_id + ".json"))

    def inspect(self, enrolled):
        active = dict(self.active(enrolled.instance_id) or {})
        retained = set()
        for path in (self.root / "journals").glob("*.json"):
            value = read_json(path)
            if value["instance_id"] == enrolled.instance_id:
                if value.get("activation_started") and value.get("original", {}).get("container_id"):
                    retained.add(value["original"]["container_id"])
                if value.get("candidate_id"):
                    retained.add(value["candidate_id"])
        active["retained_container_ids"] = retained
        return discover(self.docker, self.policy, enrolled, active)

    def restore_readiness(self, enrolled, view, *, required=False, start_on_completion=False):
        try:
            network, ports = target_network_profile(enrolled, view)
            validate_public_network(self.docker, network, ports)
            if view["source_state"] == "running" or start_on_completion:
                require_public_endpoint(ports)
            return {"restore_ready": True, "restore_error_code": None}
        except VaultRewindError as error:
            if required or error.code not in {"PUBLIC_NETWORK_UNPUBLISHABLE", "PUBLIC_BIND_UNSUPPORTED", "PUBLIC_ENDPOINT_REQUIRED"}:
                raise
            return {"restore_ready": False, "restore_error_code": error.code}

    def current_public_readiness(self, view):
        if view["source_state"] != "running":
            return {"current_public_ports_ready": None, "current_public_error_code": None}
        try:
            verify_published_ports(self.docker.inspect(view["container_id"]), view["descriptor"]["host_config"].get("PortBindings") or {})
            return {"current_public_ports_ready": True, "current_public_error_code": None}
        except VaultRewindError as error:
            if error.code not in {"PUBLIC_PORTS_UNAVAILABLE", "PUBLIC_BIND_UNSUPPORTED", "DEPLOYMENT_UNSAFE"}:
                raise
            return {"current_public_ports_ready": False, "current_public_error_code": error.code}

    def check_payload(self, request):
        allowed = {
            "discover": set(), "preflight": {"controller_time", "expected_fingerprint"},
            "capture": {"snapshot_uuid", "controller_time", "expected_fingerprint"},
            "export": {"kind"},
            "stage_restore": {"manifest_hash", "expected_fingerprint", "start_on_completion", "archive_bytes", "archive_sha256", "controller_time"},
            "commit_restore": {"phase", "safety_ack"}, "status": set(), "cancel": set(),
            "rollback": set(), "cleanup": {"kind"},
        }
        if set(request.payload) - allowed[request.verb]:
            fail("PROTOCOL_INVALID", "Unsupported payload fields; caller paths and Docker arguments are prohibited.")
        if "start_on_completion" in request.payload and type(request.payload["start_on_completion"]) is not bool:
            fail("PROTOCOL_INVALID", "start_on_completion must be an explicit boolean.")

    def preflight(self, enrolled, payload, view=None):
        self.recovery.verify()
        view = view or self.inspect(enrolled)
        if payload.get("expected_fingerprint") and payload["expected_fingerprint"] != view["fingerprint"]:
            fail("TARGET_CHANGED", "Target configuration changed since confirmation.")
        clock = payload.get("controller_time")
        if not clock:
            fail("CLOCK_UNVERIFIED", "Send the controller UTC time for preflight clock verification.")
        try:
            timestamp = datetime.fromisoformat(clock)
            if timestamp.utcoffset() is None or abs(time.time() - timestamp.timestamp()) > 120:
                fail("CLOCK_SKEW", "Host/controller clock skew exceeds two minutes; correct time synchronization.")
        except (TypeError, ValueError, AttributeError):
            fail("CLOCK_UNVERIFIED", "A valid controller UTC timestamp is required.")
        size = 0
        for mount in view["mounts"]:
            source = Path(mount["source"])
            if view["empty_target"] and not source.exists():
                no_symlink(source.parent)
                continue
            entries = walk_checked(source)
            size += sum(s.st_size for _, s in entries)
            # Generation renames require root-controlled parent and no source mountpoint.
            if mount["type"] == "bind":
                root_trusted(source.parent, directory=True)
                if source.is_mount():
                    fail("UNSUPPORTED_FILESYSTEM", "Bind roots must be ordinary directories/files, not filesystem mountpoints.")
        for file in enrolled.value.get("additional_files", {}).values():
            path = no_symlink(clean_absolute(file))
            if not path.is_file():
                fail("UNENROLLED_DEPENDENCY", "Enrolled deployment documents must be regular files.")
            walk_checked(path)
            size += path.stat().st_size
        maximum = enrolled.limit("max_archive_bytes", 1024**4)
        if size > maximum:
            fail("INSUFFICIENT_SPACE", "Persistent content exceeds the per-operation staging quota.")
        reserve = enrolled.limit("free_space_reserve", 1024**3)
        image_size = 0 if view["empty_target"] else self.docker.image(view["descriptor"]["image_id"]).get("Size", 0)
        needed = size * 3 + image_size * 4
        usage_by_directory = {"operations": 0, "images": 0}
        for section in usage_by_directory:
            directory = self.root / section
            if directory.exists():
                for current, _, files in os.walk(directory, followlinks=False):
                    for name in files:
                        path = Path(current) / name
                        if not path.is_symlink():
                            usage_by_directory[section] += path.stat().st_size
        usage = sum(usage_by_directory.values())
        quota = self.policy.value.get("max_staging_bytes", 100 * 1024**3)
        if usage + needed > quota:
            fail("STAGING_QUOTA_EXCEEDED", "Protected staging and image caches exceed the configured host quota; clean completed staging explicitly.")
        if shutil.disk_usage(self.root).free < needed + reserve:
            fail("INSUFFICIENT_SPACE", "Remote staging lacks space for complete data/image copies and reserve.")
        return {"helper_version": HELPER_VERSION, "protocol_version": 1,
                **self.restore_readiness(enrolled, view), **self.current_public_readiness(view),
                "fingerprint": view["fingerprint"], "source_state": view["source_state"],
                "empty_target": view["empty_target"], "estimated_data_bytes": size,
                "resource_keys": resource_keys(self.policy.value["machine_id"], self.policy.value["daemon_id"], view["mounts"]),
                "clock_offset_seconds": time.time() - timestamp.timestamp(), "recovery_verified": True,
                "staging_bytes": usage, "source_staging_bytes": usage_by_directory["operations"],
                "image_cache_bytes": usage_by_directory["images"], "staging_quota_bytes": quota,
                "estimated_staging_bytes": needed}

    def check(self, journal):
        if (self.root / "cancel" / journal.value["operation_id"]).exists():
            fail("CANCEL_REQUESTED", "Operation cancellation requires safe recovery.")
        if journal.value.get("watchdog_armed") and expired(journal.value):
            fail("OUTAGE_BUDGET_EXCEEDED", "The host-local maintenance budget has expired.")
        # Each mutation proceeds under a process-held flock. Also verify the durable fence.
        for key in journal.value["resource_keys"]:
            record = read_json(self.root / "fences" / (key + ".json"))
            if record and (record["operation_id"] != journal.value["operation_id"] or record["token"] != journal.value["fencing_token"]):
                fail("STALE_FENCE", "Physical resource fencing changed; recovery is required.")

    def operation_root(self, journal):
        path = self.root / "operations" / journal.value["operation_id"]
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        return path

    def prepare_capture(self, enrolled, journal, view, kind):
        root = self.operation_root(journal) / kind
        root.mkdir(mode=0o700)
        (root / "deployment").mkdir(mode=0o700)
        (root / "images").mkdir(mode=0o700)
        atomic_json(root / "deployment" / "recovery.json", view["descriptor"])
        image = view["descriptor"]["image_id"]
        cache = self.root / "images"
        cache.mkdir(exist_ok=True, mode=0o700)
        cached = cache / (image[7:] + ".tar")
        cache_record = cache / (image[7:] + ".json")
        if cached.exists() and not cache_record.exists():
            # Rebuild pre-integrity-cache files before downtime; never reuse unverifiable bytes.
            cached.unlink()
        if not cached.exists():
            temporary = cache / (image[7:] + ".partial")
            temporary.unlink(missing_ok=True)
            self.docker.save_image(image, temporary, enrolled.limit("max_archive_bytes", 1024**4))
            self.verify_image_archive(temporary, image)
            os.replace(temporary, cached)
            fsync_directory(cache)
            atomic_json(cache_record, {"image_id": image, "sha256": file_hash(cached), "bytes": cached.stat().st_size})
        record = read_json(cache_record)
        if record != {"image_id": image, "sha256": file_hash(cached), "bytes": cached.stat().st_size}:
            fail("IMAGE_CACHE_CORRUPT", "The immutable image cache failed integrity verification; repair it before another capture.")
        self.verify_image_archive(cached, image)
        shutil.copyfile(cached, root / "images" / "vaultwarden.tar")
        with (root / "images" / "vaultwarden.tar").open("rb") as stream:
            os.fsync(stream.fileno())
        return root

    def verify_image_archive(self, path, image_id):
        try:
            with tarfile.open(path, "r:") as tar:
                members = {}
                for entry in tar:
                    name = relative(entry.name.rstrip("/"))
                    if name in members or not (entry.isfile() or entry.isdir()) or entry.size < 0 or len(members) > 100000:
                        fail("IMAGE_ARCHIVE_UNSAFE", "Saved-image archive contains unsupported members.")
                    members[name] = entry
                if "manifest.json" not in members or members["manifest.json"].size > 1024 * 1024:
                    fail("IMAGE_ARCHIVE_INVALID", "Saved Docker image manifest is missing or oversized.")
                manifest = json.loads(tar.extractfile(members["manifest.json"]).read())
                if not isinstance(manifest, list) or len(manifest) != 1:
                    fail("IMAGE_ARCHIVE_INVALID", "Exactly one saved image is required.")
                entry = manifest[0]
                if entry.get("RepoTags") not in (None, []):
                    fail("IMAGE_ARCHIVE_UNSAFE", "Saved images must be exported by immutable ID without mutable tag assignments.")
                if "repositories" in members:
                    repository_entry = members["repositories"]
                    if repository_entry.size > 1024 or json.loads(tar.extractfile(repository_entry).read()) != {}:
                        fail("IMAGE_ARCHIVE_UNSAFE", "Saved image archive may not rewrite unrelated repository tags.")
                config = relative(entry["Config"])
                if config not in members or members[config].size > 16 * 1024 * 1024:
                    fail("IMAGE_ARCHIVE_INVALID", "Saved image configuration is missing or oversized.")
                import hashlib
                content_id = "sha256:" + hashlib.sha256(tar.extractfile(members[config]).read()).hexdigest()
                if content_id != image_id:
                    fail("IMAGE_MISMATCH", "Saved image configuration does not match the recorded image ID.")
                for layer in entry["Layers"]:
                    if relative(layer) not in members or not members[layer].isfile():
                        fail("IMAGE_ARCHIVE_INVALID", "Saved image has a missing layer.")
        except (tarfile.TarError, OSError, ValueError, KeyError, TypeError):
            fail("IMAGE_ARCHIVE_INVALID", "Saved image archive cannot be validated.")

    def stop_original(self, journal):
        view = journal.value["original"]
        journal.transition("quiescing" if journal.value["kind"] == "capture" else "quiescing_target")
        if view["container_id"]:
            self.check(journal)
            # Persisted original policy precedes disabling daemon restart, including reboot.
            self.docker.restart_policy(view["container_id"], {"Name": "no", "MaximumRetryCount": 0})
            if self.docker.inspect(view["container_id"])["State"]["Running"]:
                self.docker.stop(view["container_id"], timeout=min(30, max(1, int(journal.value["deadline"] - time.time() - 5))))
            if self.docker.inspect(view["container_id"])["State"]["Running"]:
                fail("SOURCE_RESTART_CONFLICT", "Source restarted during quiescence.")
        self.check(journal)

    def raw_capture(self, enrolled, journal, view, root):
        journal.transition("capturing" if journal.value["kind"] == "capture" else "capturing_safety", capture_started_at=utc())
        for mount in view["mounts"]:
            copy_tree(Path(mount["source"]), root / mount["snapshot_path"], lambda: self.check(journal))
        for name, source in enrolled.value.get("additional_files", {}).items():
            copy_tree(Path(source), root / "deployment" / "files" / name, lambda: self.check(journal))
        self.check(journal)
        cid = view["container_id"]
        if cid and self.docker.inspect(cid)["State"]["Running"]:
            fail("SOURCE_RESTART_CONFLICT", "A writer restarted during the full-instance capture.")
        fresh = self.docker.inspect(cid) if cid else None
        if fresh:
            original = view["descriptor"]["config"]
            if any(fresh["Config"].get(k) != v for k, v in original.items()):
                fail("SOURCE_CHANGED", "Source configuration changed during capture.")
        current = self.inspect(enrolled)
        current["descriptor"]["host_config"]["RestartPolicy"] = view["descriptor"]["host_config"].get("RestartPolicy", {"Name": "no"})
        if digest(current["descriptor"]) != view["fingerprint"]:
            fail("SOURCE_CHANGED", "Source mounts or deployment changed during capture.")
        journal.value["captured_at"] = utc()
        journal.value["raw_capture_complete"] = True
        journal.save()

    def resume_original(self, enrolled, journal):
        view = journal.value["original"]
        cid = view["container_id"]
        if cid:
            if view["source_state"] == "running":
                self.docker.start(cid)
                self.docker.health(cid, min(enrolled.limit("validation_window", 180), 60))
            elif self.docker.inspect(cid)["State"]["Running"]:
                self.docker.stop(cid)
            self.docker.restart_policy(cid, view["restart_policy"])
        journal.value["source_service_outcome"] = view["source_state"]
        journal.save()

    def seal_capture(self, enrolled, journal, view, root, snapshot_uuid):
        evidence = core.normalize_sqlite(root / "data")
        descriptor = view["descriptor"]
        manifest = core.create_manifest(root, {
            "snapshot_uuid": snapshot_uuid, "instance_uuid": enrolled.instance_id,
            "capture_started_at": journal.value["capture_started_at"], "captured_at": journal.value["captured_at"],
            "remote_clock_offset_seconds": journal.value.get("clock_offset_seconds", 0),
            "source_state": view["source_state"], "consistency_mode": "controlled_stop", "helper_version": HELPER_VERSION,
            "image_id": descriptor["image_id"], "image_archive_hash": file_hash(root / "images" / "vaultwarden.tar"),
            "registry_digest": descriptor["registry_digest"], "platform": descriptor["platform"],
            "vaultwarden_version": descriptor["config"].get("Labels", {}).get("org.opencontainers.image.version", "unknown"),
            "deployment_fingerprint": digest(descriptor), "dependency_inventory": descriptor["dependencies"],
            "database_schema_evidence": evidence["database_schema_evidence"], "verification": evidence})
        verified = core.verify_snapshot(root, core.manifest_hash(manifest))
        archive = root.with_suffix(".tar")
        transfer = build_archive(root, archive, enrolled.limit("max_archive_bytes", 1024**4))
        return {"snapshot_uuid": snapshot_uuid, "manifest_hash": verified["manifest_hash"],
                "persistent_bytes": persistent_bytes(manifest), **transfer}

    def capture(self, enrolled, journal, payload):
        if journal.value["phase"] == "captured":
            return journal.public()
        if journal.value["phase"] != "preparing":
            fail("RECONCILIATION_REQUIRED", "Interrupted capture must be reconciled, never repeated destructively.")
        view = self.inspect(enrolled)
        if view["empty_target"]:
            fail("SOURCE_ABSENT", "An empty prepared target cannot be captured.")
        preflight = self.preflight(enrolled, payload, view)
        journal.value["clock_offset_seconds"] = preflight["clock_offset_seconds"]
        snapshot_uuid = identifier(payload.get("snapshot_uuid"))
        journal.value.update({"kind": "capture", "original": view, "source_state": view["source_state"], "snapshot_uuid": snapshot_uuid})
        journal.save()
        root = self.prepare_capture(enrolled, journal, view, "capture")
        self.recovery.arm(journal, enrolled.limit("capture_budget", 300))
        try:
            self.stop_original(journal)
            self.raw_capture(enrolled, journal, view, root)
            journal.transition("resuming_source")
            self.resume_original(enrolled, journal)
            self.recovery.disarm(journal)
            journal.transition("validating")
            result = self.seal_capture(enrolled, journal, view, root, snapshot_uuid)
            journal.transition("captured", **result)
            return journal.public()
        except BaseException:
            self._recover_locked(enrolled, journal, "capture_failed")
            raise

    def restore_metadata(self, root, manifest):
        # Only verified inventory paths below private staging are eligible. Never live host paths.
        for item in reversed(manifest["inventory"]):
            path = root / relative(item["path"])
            no_symlink(path.parent)
            mode = item["mode"]
            if type(mode) is not int or mode & ~0o777:
                fail("UNSUPPORTED_METADATA", "Restore file mode is unsupported.")
            for name in ("uid", "gid"):
                if type(item[name]) is not int or not 0 <= item[name] < 2**31:
                    fail("UNSUPPORTED_METADATA", "Restore numeric ownership is invalid.")
            os.chown(path, item["uid"], item["gid"], follow_symlinks=False)
            if not path.is_symlink():
                os.chmod(path, mode)
            for name, encoded in item.get("xattrs", {}).items():
                if name == "security.capability" or len(encoded) > 131072:
                    fail("UNSUPPORTED_METADATA", "Restore extended metadata is unsupported.")
                os.setxattr(path, name, base64.b64decode(encoded, validate=True), follow_symlinks=False)
            os.utime(path, ns=(item["mtime_ns"], item["mtime_ns"]), follow_symlinks=False)
        walk_checked(root)

    def stage_restore(self, enrolled, journal, payload, incoming):
        if journal.value["phase"] == "staged":
            return journal.public()
        if journal.value["phase"] != "preparing":
            fail("RECONCILIATION_REQUIRED", "Interrupted restore staging must be reconciled before reuse.")
        view = self.inspect(enrolled)
        self.preflight(enrolled, payload, view)
        self.restore_readiness(enrolled, view, required=True, start_on_completion=payload.get("start_on_completion", False))
        if not payload.get("expected_fingerprint") or payload["expected_fingerprint"] != view["fingerprint"]:
            fail("TARGET_CHANGED", "Restore requires the exact confirmed target fingerprint.")
        expected = hash_required(payload.get("manifest_hash"))
        hash_required(payload.get("archive_sha256"))
        if type(payload.get("archive_bytes")) is not int or payload["archive_bytes"] < 1:
            fail("PROTOCOL_INVALID", "Restore transfer requires an archive byte count.")
        archive_bytes = payload["archive_bytes"]
        reserve = enrolled.limit("free_space_reserve", 1024**3)
        if archive_bytes > enrolled.limit("max_archive_bytes", 1024**4) or shutil.disk_usage(self.root).free < archive_bytes * 3 + reserve:
            fail("INSUFFICIENT_SPACE", "Restore archive, verified staging and safety capture exceed available space or quota.")
        journal.value.update({"kind": "restore", "original": view, "source_state": view["source_state"],
                              "empty_target": view["empty_target"], "start_on_completion": payload.get("start_on_completion", False)})
        journal.save()
        work = self.operation_root(journal)
        archive = work / "incoming.tar"
        with archive.open("xb") as target:
            transfer = receive_frames(incoming, target, enrolled.limit("max_archive_bytes", 1024**4))
            target.flush()
            os.fsync(target.fileno())
        if transfer != {"bytes": payload["archive_bytes"], "sha256": payload["archive_sha256"]}:
            fail("TRANSFER_CHECKSUM", "Restore stream differs from its requested immutable archive.")
        if incoming.read(1):
            fail("PROTOCOL_INVALID", "Unexpected bytes after restore stream.")
        staged = work / "restore"
        extract_archive(archive, staged, enrolled.limit("max_archive_bytes", 1024**4), enrolled.limit("max_members", 1_000_000))
        result = core.verify_snapshot(staged, expected)
        self.restore_metadata(staged, result["manifest"])
        descriptor = read_json(staged / "deployment" / "recovery.json")
        if not descriptor or digest(descriptor) != result["manifest"]["deployment_fingerprint"]:
            fail("DEPLOYMENT_UNSAFE", "Recovery descriptor differs from its manifest identity.")
        # Target substitutions are only root-policy settings, never request-supplied values.
        descriptor = copy.deepcopy(descriptor)
        profile = enrolled.value.get("recovery_profile", {})
        if set(profile) - {"environment", "network", "port_bindings", "revision"}:
            fail("POLICY_INVALID", "Unsupported recovery profile substitution.")
        from .overlays import approved_environment
        overlays = approved_environment(profile)
        environment = dict(s.split("=", 1) for s in descriptor["config"].get("Env", []))
        environment.update(overlays)
        if result["manifest"]["instance_uuid"] != enrolled.instance_id and "DOMAIN" not in profile.get("environment", {}):
            fail("TARGET_PROFILE_REQUIRED", "Alternate-target recovery requires an explicit enrolled public URL overlay.")
        descriptor["config"]["Env"] = [f"{k}={v}" for k, v in environment.items()]
        descriptor["host_config"]["NetworkMode"] = profile.get("network", descriptor["host_config"]["NetworkMode"])
        descriptor["host_config"]["PortBindings"] = profile.get("port_bindings", descriptor["host_config"].get("PortBindings", {}))
        validate_descriptor(descriptor, enrolled, self.docker)
        image = staged / "images" / "vaultwarden.tar"
        if file_hash(image) != result["manifest"]["image_archive_hash"]:
            fail("IMAGE_MISMATCH", "Saved image archive checksum differs from the manifest.")
        self.verify_image_archive(image, descriptor["image_id"])
        # Check manifest platform before import and before target downtime.
        import platform
        arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine(), platform.machine())
        if descriptor["platform"] != "linux/" + arch:
            fail("UNSUPPORTED_ARCHITECTURE", "Recorded image architecture is incompatible with this target.")
        self.docker.load_image(image)
        validate_descriptor(descriptor, enrolled, self.docker, imported=True)
        self.check_ports(enrolled, view, descriptor)
        journal.value.update({"restore_descriptor": descriptor, "snapshot_uuid": result["snapshot_uuid"],
                              "target_environment": overlays,
                              "manifest_hash": expected, "profile_revision": profile.get("revision", 1),
                              "generation_logical_bytes": persistent_bytes(result["manifest"]), "generation_steps": []})
        journal.save()
        self.materialize(enrolled, journal, staged)
        from .overlays import apply_environment
        apply_environment(self.generation_mounts(journal, switched=False), overlays)
        journal.transition("staged", active_generation=journal.value["operation_id"])
        return journal.public()

    def check_ports(self, enrolled, view, descriptor):
        wanted = {(b["HostIp"], int(b["HostPort"])) for bindings in (descriptor["host_config"].get("PortBindings") or {}).values() for b in bindings}
        for peer in self.docker.containers():
            if peer["Id"] == view["container_id"]:
                continue
            for port in peer.get("Ports", []):
                if port.get("PublicPort") and any(port["PublicPort"] == p and (ip in ("", "0.0.0.0", "::") or port.get("IP") in (ip, "0.0.0.0", "::")) for ip, p in wanted):
                    fail("PORT_CONFLICT", "An enrolled application port is already in use by another container.")

    def materialize(self, enrolled, journal, staged):
        generation = journal.value["operation_id"]
        for index, mount in enumerate(journal.value["original"]["mounts"]):
            self.check(journal)
            source = staged / mount["snapshot_path"]
            step = {"mount": dict(mount), "phase": "planned", "index": index}
            if mount["type"] == "bind":
                live = Path(mount["source"])
                no_symlink(live.parent)
                root_trusted(live.parent, directory=True)
                private_parent = live.with_name(f".vrw-{generation}-{index}")
                if private_parent.exists():
                    fail("STAGING_CONFLICT", "An unowned private generation directory already exists.")
                private_parent.mkdir(mode=0o700)
                fsync_directory(private_parent.parent)
                new = private_parent / "new"
                old = private_parent / "old"
                if new.exists() or old.exists():
                    fail("STAGING_CONFLICT", "An unowned generation path already exists.")
                step.update({"new": str(new), "old": str(old), "had_original": live.exists(),
                             "original_identity": [live.stat().st_dev, live.stat().st_ino] if live.exists() else None})
            else:
                name = f"vrw-{generation}-{index}"
                step["volume_name"] = name
                prior = self.docker.volume(mount["volume_name"])
                step["original_volume"] = {key: prior.get(key) for key in ("Name", "Mountpoint", "Driver", "Scope", "Options", "CreatedAt", "Labels")}
                old_path = Path(mount["source"])
                step["original_volume_identity"] = [old_path.stat().st_dev, old_path.stat().st_ino]
            journal.value["generation_steps"].append(step)
            journal.save()
            if mount["type"] == "volume":
                vol = self.docker.create_volume(name, {"org.vaultrewind.instance": enrolled.instance_id,
                                                       "org.vaultrewind.operation": generation})
                if vol["Driver"] != "local" or vol.get("Options"):
                    fail("UNSUPPORTED_VOLUME_DRIVER", "Generation volume is not a plain local volume.")
                new = no_symlink(Path(vol["Mountpoint"]))
                if any(new.iterdir()):
                    fail("TARGET_CHANGED", "New generation volume is not empty.")
                step["new"] = str(new)
                journal.save()
            size = sum(s.st_size for _, s in walk_checked(source))
            if shutil.disk_usage(new.parent).free < size + enrolled.limit("free_space_reserve", 1024**3):
                fail("INSUFFICIENT_SPACE", "Target filesystem lacks space for an independent data generation.")
            copy_tree(source, new, lambda: self.check(journal))
            step["new_identity"] = [new.stat().st_dev, new.stat().st_ino]
            step["phase"] = "materialized"
            journal.save()

    def prepare_safety(self, enrolled, journal):
        if journal.value["phase"] == "safety_ready":
            return journal.public()
        if journal.value["phase"] != "staged":
            fail("RESTORE_PHASE_INVALID", "Restore safety preparation requires a verified staged generation.")
        view = self.inspect(enrolled)
        validate_descriptor(journal.value["restore_descriptor"], enrolled, self.docker)
        self.restore_readiness(enrolled, view, required=True, start_on_completion=journal.value.get("start_on_completion", False))
        if view["fingerprint"] != journal.value["original"]["fingerprint"]:
            fail("TARGET_CHANGED", "Target changed after restore staging; generate a new confirmation.")
        # Exact old image and deployment are exported before maintenance starts.
        safety_root = None
        if not view["empty_target"]:
            safety_root = self.prepare_capture(enrolled, journal, view, "safety")
            journal.value["safety_snapshot_uuid"] = str(uuid.uuid4())
            journal.save()
        self.recovery.arm(journal, enrolled.limit("restore_budget", 900))
        try:
            self.stop_original(journal)
            if safety_root:
                self.raw_capture(enrolled, journal, view, safety_root)
                result = self.seal_capture(enrolled, journal, view, safety_root, journal.value["safety_snapshot_uuid"])
                journal.value["safety_manifest_hash"] = result["manifest_hash"]
                journal.value["safety_archive_sha256"] = result["sha256"]
                journal.value["retained_generation_logical_bytes"] = result["persistent_bytes"]
            journal.transition("safety_ready")
            return journal.public()
        except BaseException:
            self._recover_locked(enrolled, journal, "safety_failed")
            raise

    def acknowledge_safety(self, journal, acknowledgment):
        if journal.value["empty_target"]:
            return
        if not isinstance(acknowledgment, dict):
            fail("SAFETY_ACK_REQUIRED", "Commit, verify and pin the encrypted local safety snapshot before switching.")
        required = {"snapshot_uuid", "manifest_hash", "restic_snapshot_id", "repository_id", "durable", "encrypted", "pinned", "stored_copy_verified"}
        if set(acknowledgment) != required:
            fail("SAFETY_ACK_REQUIRED", "Safety acknowledgment is incomplete.")
        if acknowledgment["snapshot_uuid"] != journal.value["safety_snapshot_uuid"] or acknowledgment["manifest_hash"] != journal.value["safety_manifest_hash"]:
            fail("SAFETY_ACK_MISMATCH", "Safety acknowledgment refers to a different immutable capture.")
        if any(acknowledgment[k] is not True for k in ("durable", "encrypted", "pinned", "stored_copy_verified")):
            fail("SAFETY_ACK_REQUIRED", "Safety content must be durably stored, encrypted, pinned and read back.")
        identifier(acknowledgment["repository_id"])
        hash_required(acknowledgment["restic_snapshot_id"])
        journal.value["safety_ack"] = acknowledgment
        journal.save()

    def generation_mounts(self, journal, *, switched):
        mounts = []
        for step in journal.value["generation_steps"]:
            mount = dict(step["mount"])
            if mount["type"] == "volume":
                mount.update({"source": step["new"], "volume_name": step["volume_name"]})
            elif not switched:
                mount["source"] = step["new"]
            mounts.append(mount)
        return mounts

    def switch_validate(self, enrolled, journal, payload):
        if journal.value["phase"] == "candidate_validated":
            return journal.public()
        if journal.value["phase"] != "safety_ready":
            fail("RESTORE_PHASE_INVALID", "Switching requires a complete safety capture.")
        self.acknowledge_safety(journal, payload.get("safety_ack"))
        self.check(journal)
        journal.transition("switching")
        try:
            for step in journal.value["generation_steps"]:
                self.check(journal)
                if step["mount"]["type"] == "bind":
                    live, new, old = map(Path, (step["mount"]["source"], step["new"], step["old"]))
                    if step["had_original"] and [live.stat().st_dev, live.stat().st_ino] != step["original_identity"]:
                        fail("TARGET_CHANGED", "The original data generation changed after staging.")
                    if [new.stat().st_dev, new.stat().st_ino] != step["new_identity"]:
                        fail("TARGET_CHANGED", "The staged data generation changed before switching.")
                    step["phase"] = "old_rename_started"
                    journal.save()
                    if step["had_original"]:
                        durable_rename(live, old)
                    step["phase"] = "old_preserved"
                    journal.save()
                    durable_rename(new, live)
                step["phase"] = "switched"
                journal.save()
            name = "vrw-candidate-" + journal.value["operation_id"]
            journal.value["candidate_name"] = name
            journal.transition("validating_candidate")
            config = create_config(journal.value["restore_descriptor"], self.generation_mounts(journal, switched=True),
                                   enrolled.instance_id, journal.value["operation_id"], isolated=True)
            candidate = self.docker.create(name, config)
            journal.value["candidate_id"] = candidate
            journal.save()
            self.docker.start(candidate)
            evidence = self.docker.health(candidate, enrolled.limit("validation_window", 180))
            self.check(journal)
            self.docker.stop(candidate)
            # Startup migrations/expiry cleanup only touched the isolated restored generation.
            data = next(Path(m["source"]) for m in self.generation_mounts(journal, switched=True) if m["snapshot_path"] == "data")
            evidence.update(core.validate_sqlite(data))
            from .overlays import verify_environment
            verify_environment(self.generation_mounts(journal, switched=True), journal.value.get("target_environment", {}))
            journal.transition("candidate_validated", candidate_validated=evidence)
            return journal.public()
        except BaseException:
            self._recover_locked(enrolled, journal, "candidate_failed")
            raise

    def managed_definition(self, enrolled, journal, final_id):
        mounts = self.generation_mounts(journal, switched=True)
        descriptor = journal.value["restore_descriptor"]
        # JSON is a valid Compose document; no captured Compose project is executed.
        service = {"image": descriptor["image_id"], "container_name": enrolled.value["container_name"],
                   "environment": dict(e.split("=", 1) for e in descriptor["config"].get("Env", [])),
                   "volumes": [{"type": m["type"], "source": m["volume_name"] if m["type"] == "volume" else m["source"],
                                "target": m["target"], "read_only": m["read_only"]} for m in mounts],
                   "network_mode": descriptor["host_config"]["NetworkMode"],
                   "restart": descriptor["host_config"].get("RestartPolicy", {}).get("Name", "no")}
        for key, compose in (("Entrypoint", "entrypoint"), ("Cmd", "command"), ("User", "user"), ("WorkingDir", "working_dir")):
            if descriptor["config"].get(key):
                service[compose] = descriptor["config"][key]
        service["ports"] = [{"target": int(port.split("/")[0]), "published": binding["HostPort"],
                             "host_ip": binding["HostIp"] or "0.0.0.0", "protocol": "tcp"}
                            for port, binds in (descriptor["host_config"].get("PortBindings") or {}).items() for binding in binds]
        host = descriptor["host_config"]
        for docker_key, compose_key in (("ReadonlyRootfs", "read_only"), ("CapDrop", "cap_drop"),
                                        ("SecurityOpt", "security_opt"), ("Memory", "mem_limit"),
                                        ("PidsLimit", "pids_limit"), ("ShmSize", "shm_size"), ("Init", "init")):
            if host.get(docker_key) is not None:
                service[compose_key] = host[docker_key]
        if host.get("NanoCpus"):
            service["cpus"] = host["NanoCpus"] / 1_000_000_000
        if descriptor["config"].get("StopSignal"):
            service["stop_signal"] = descriptor["config"]["StopSignal"]
        if descriptor["config"].get("Healthcheck"):
            health = descriptor["config"]["Healthcheck"]
            service["healthcheck"] = {"test": health["Test"]}
            for key, mapped in (("Interval", "interval"), ("Timeout", "timeout"), ("StartPeriod", "start_period")):
                if health.get(key):
                    service["healthcheck"][mapped] = str(health[key]) + "ns"
            if health.get("Retries"):
                service["healthcheck"]["retries"] = health["Retries"]
        retries = host.get("RestartPolicy", {}).get("MaximumRetryCount", 0)
        if service["restart"] == "on-failure" and retries:
            service["restart"] = f"on-failure:{retries}"
        definition = {"services": {"vaultwarden": service},
                      "volumes": {m["volume_name"]: {"external": True} for m in mounts if m["type"] == "volume"}}
        managed = self.root / "managed" / enrolled.instance_id
        atomic_json(managed / "compose.json", definition)
        atomic_json(managed / "docker-create.json", create_config(descriptor, mounts, enrolled.instance_id,
                                                                 journal.value["operation_id"], isolated=False))
        atomic_json(self.root / "active" / (enrolled.instance_id + ".json"), {
            "container_id": final_id, "mounts": mounts, "operation_id": journal.value["operation_id"],
            "image_id": descriptor["image_id"], "descriptor_fingerprint": digest(descriptor),
            "policy_revision": enrolled.value.get("revision", 1),
            "rollback_container_id": journal.value["original"]["container_id"]})

    def activate(self, enrolled, journal):
        if journal.value["phase"] in ("complete", "data_restored_service_stopped"):
            return self.completed_readiness(enrolled, journal)
        if journal.value["phase"] != "candidate_validated":
            fail("RESTORE_PHASE_INVALID", "Public activation requires successful isolated candidate validation.")
        self.check(journal)
        original = journal.value["original"]
        should_start = original["source_state"] == "running" or journal.value["start_on_completion"]
        if should_start:
            require_public_endpoint(journal.value["restore_descriptor"]["host_config"].get("PortBindings") or {})
        from .overlays import verify_environment
        verify_environment(self.generation_mounts(journal, switched=True), journal.value.get("target_environment", {}))
        # All actions that might expose ports or attach production networks follow this durable boundary.
        journal.transition("activation_started", activation_started=True)
        try:
            if original["container_id"]:
                self.docker.rename(original["container_id"], "vrw-old-" + journal.value["operation_id"])
            config = create_config(journal.value["restore_descriptor"], self.generation_mounts(journal, switched=True),
                                   enrolled.instance_id, journal.value["operation_id"], isolated=False)
            journal.value["final_name"] = enrolled.value["container_name"]
            journal.save()
            final_id = self.docker.create(enrolled.value["container_name"], config)
            journal.value["final_id"] = final_id
            journal.save()
            self.managed_definition(enrolled, journal, final_id)
            if should_start:
                self.ensure_restart_policy(final_id, journal.value["restore_descriptor"]["host_config"].get("RestartPolicy", {"Name": "no"}))
                self.docker.start(final_id)
                evidence = self.docker.health(final_id, enrolled.limit("validation_window", 180))
                evidence.update(self.docker.public_health(final_id, journal.value["restore_descriptor"]["host_config"].get("PortBindings") or {}, enrolled.limit("validation_window", 180)))
                self.retire_candidate(journal)
                journal.transition("complete", final_health=evidence, source_service_outcome="running",
                                   public_ports_verified=True, public_endpoint_verified=True,
                                   rollback_cleanup_after=time.time() + enrolled.limit("rollback_grace_seconds", 604800))
            else:
                # Keep restart=no for data-only restore so daemon reboot cannot start it.
                self.retire_candidate(journal)
                journal.transition("data_restored_service_stopped", source_service_outcome="stopped",
                                   rollback_cleanup_after=time.time() + enrolled.limit("rollback_grace_seconds", 604800))
            self.recovery.disarm(journal)
            return journal.public()
        except BaseException as error:
            code = error.code if isinstance(error, VaultRewindError) and error.code.startswith("PUBLIC_") else "RESTORE_ACTIVATION_UNCERTAIN"
            journal.transition("needs_attention", error_code=code, public_ports_verified=False, public_endpoint_verified=False)
            # The watchdog may attempt bounded non-destructive recovery; never old-generation rollback.
            raise

    def ensure_restart_policy(self, container, policy):
        expected = {"Name": policy.get("Name", "no"), "MaximumRetryCount": policy.get("MaximumRetryCount", 0)}
        self.docker.restart_policy(container, expected)
        actual = self.docker.inspect(container)["HostConfig"].get("RestartPolicy", {})
        if {"Name": actual.get("Name", "no"), "MaximumRetryCount": actual.get("MaximumRetryCount", 0)} != expected:
            fail("RESTART_POLICY_UNVERIFIED", "The active container restart policy could not be verified; preserve the generation and reconcile.")

    def retire_candidate(self, journal):
        candidate = self._owned_container(journal, "candidate_id", "candidate_name")
        if candidate:
            isolated_candidate(journal, candidate)
            if candidate["State"]["Running"]:
                fail("CLEANUP_UNSAFE", "Validated candidate is unexpectedly running; preserve it for review.")
            self.docker.remove(candidate["Id"])
            if self.docker.inspect(candidate["Id"], missing=True):
                fail("CLEANUP_UNSAFE", "Validated candidate removal could not be verified.")
        journal.value["candidate_container_retired"] = True
        journal.save()

    def completed_readiness(self, enrolled, journal):
        """Upgrade legacy internal-only results using read-only evidence, never restart."""
        value = journal.value
        if value["phase"] != "complete" or value.get("kind") != "restore":
            return journal.public()
        active = self.active(enrolled.instance_id)
        if active and active.get("operation_id") != value["operation_id"] and not value.get("watchdog_armed"):
            # A completed job is an audit record, not a claim that its retired
            # container still serves. Never probe/restart that old container.
            if value.get("historical_public_readiness") == "unverified":
                return journal.public()
            if value.get("final_health", {}).get("public_endpoint_verified") is True:
                try:
                    require_public_endpoint(value["restore_descriptor"]["host_config"].get("PortBindings") or {})
                    return journal.public()  # Retain actual past proof, without fabricating new proof.
                except VaultRewindError:
                    pass
            return journal.note_historical()
        try:
            require_public_endpoint(value["restore_descriptor"]["host_config"].get("PortBindings") or {})
            if value.get("final_health", {}).get("public_endpoint_verified") is True:
                return journal.public()
            if not active or active.get("operation_id") != value["operation_id"]:
                fail("PUBLIC_READINESS_UNVERIFIED", "Legacy restore has no durable public readiness proof for this active generation.")
            final = self._owned_container(journal, "final_id", "final_name")
            if final is None:
                fail("PUBLIC_READINESS_UNVERIFIED", "The legacy active container cannot be verified.")
            proof = self.docker.public_health(final["Id"], value["restore_descriptor"]["host_config"].get("PortBindings") or {}, 3)
            value.setdefault("final_health", {}).update(proof)
            value.update(public_ports_verified=True, public_endpoint_verified=True)
            journal.save()
        except VaultRewindError as error:
            journal.transition("needs_attention", error_code=error.code, public_ports_verified=False, public_endpoint_verified=False)
        return journal.public()

    @staticmethod
    def _historical_owner_inactive(owner):
        if owner is None:
            return True
        if (not isinstance(owner, dict) or set(owner) != {"pid", "start_ticks", "boot_id"}
                or type(owner["pid"]) is not int or owner["pid"] <= 0
                or not isinstance(owner["start_ticks"], str) or not owner["start_ticks"].isdigit()):
            return False
        identifier(owner["boot_id"])
        return not same_process(owner)

    def _historical_status_failure(self, journal):
        value = journal.value or {}
        try:
            return (value.get("phase") == "needs_attention" and value.get("error_code") == "PUBLIC_READINESS_UNVERIFIED"
                    and value.get("watchdog_armed") is False and self._historical_owner_inactive(value.get("owner"))
                    and value.get("final_health", {}).get("public_endpoint_verified") is not True
                    and journal.original_completion_at() is not None)
        except (VaultRewindError, KeyError, TypeError, ValueError, AttributeError):
            return False

    def _proven_historical_successor(self, enrolled, journal):
        """Read-only proof of a newer, completed and currently owned generation.

        No source health exec, restart, stop, rename, cleanup or registry rewrite.
        Any incomplete/changed/unreachable evidence fails closed.
        """
        try:
            old = journal.value
            completed_at = journal.original_completion_at()
            active = self.active(enrolled.instance_id)
            if completed_at is None or not active or active.get("operation_id") == old["operation_id"]:
                return None
            successor_id = identifier(active.get("operation_id"))
            successor = Journal(self.root, successor_id)
            current = successor.value
            if (not current or current.get("operation_id") != successor_id or current.get("instance_id") != enrolled.instance_id
                    or current.get("kind") != "restore" or current.get("phase") not in ("complete", "data_restored_service_stopped")
                    or current.get("watchdog_armed") is not False or not self._historical_owner_inactive(current.get("owner"))
                    or current.get("activation_started") is not True or current.get("active_generation") != successor_id
                    or type(current.get("created_at")) not in (int, float)
                    or not math.isfinite(current["created_at"]) or current["created_at"] <= completed_at):
                return None
            history = [item.get("phase") for item in current.get("history", [])]
            if (not history or history[-1] != current["phase"] or "candidate_validated" not in history
                    or "activation_started" not in history
                    or not history.index("candidate_validated") < history.index("activation_started") < len(history) - 1):
                return None
            candidate = current.get("candidate_validated") or {}
            if candidate.get("internal_http_alive") is not True or candidate.get("database_integrity") != "ok":
                return None
            descriptor = current["restore_descriptor"]
            mounts = self.generation_mounts(successor, switched=True)
            cid = current.get("final_id")
            if (not isinstance(cid, str) or not HEX.fullmatch(cid) or cid == old.get("final_id")
                    or active.get("container_id") != cid or active.get("mounts") != mounts or not mounts
                    or active.get("image_id") != descriptor["image_id"]
                    or active.get("descriptor_fingerprint") != digest(descriptor)):
                return None
            container = self.docker.inspect(cid, missing=True)
            if not container or container.get("Id") != cid or container.get("Image") != descriptor["image_id"]:
                return None
            labels = container["Config"].get("Labels") or {}
            if any(labels.get(key) != val for key, val in {"org.vaultrewind.instance": enrolled.instance_id,
                    "org.vaultrewind.operation": successor_id, "org.vaultrewind.role": "active"}.items()):
                return None
            if container.get("Name", "").lstrip("/") != current.get("final_name"):
                return None
            actual_mounts = container.get("Mounts", [])
            if len(actual_mounts) != len(mounts):
                return None
            for step, mount in zip(current["generation_steps"], mounts, strict=True):
                found = [m for m in actual_mounts if m.get("Destination") == mount["target"]]
                if len(found) != 1 or step.get("phase") != "switched":
                    return None
                actual = found[0]
                if (actual.get("Type") != mount["type"] or actual.get("Source") != mount["source"]
                        or actual.get("RW") != (not mount["read_only"])):
                    return None
                source = no_symlink(Path(mount["source"])).stat()
                if [source.st_dev, source.st_ino] != step.get("new_identity"):
                    return None
                if mount["type"] == "volume":
                    volume = self.docker.volume(mount["volume_name"], missing=True)
                    if (actual.get("Name") != mount["volume_name"] or not volume or volume.get("Driver") != "local"
                            or volume.get("Scope") != "local" or volume.get("Options") or volume.get("Mountpoint") != mount["source"]):
                        return None
            state, host = container["State"], container["HostConfig"]
            if (any(state.get(key) for key in ("Paused", "Restarting", "Dead", "OOMKilled"))
                    or state.get("Health", {}).get("Status") == "unhealthy"):
                return None
            if host.get("NetworkMode") != descriptor["host_config"]["NetworkMode"]:
                return None
            expected_restart = descriptor["host_config"].get("RestartPolicy") or {"Name": "no"}
            if current["phase"] == "complete":
                final = current.get("final_health") or {}
                if (current.get("source_service_outcome") != "running" or state.get("Running") is not True
                        or not (current.get("source_state") == "running" or current.get("start_on_completion") is True)
                        or any(final.get(key) is not True for key in ("application_started", "internal_http_alive", "public_ports_verified", "public_endpoint_verified"))
                        or type(final.get("public_endpoint_count")) is not int or final["public_endpoint_count"] < 1
                        or current.get("public_ports_verified") is not True or current.get("public_endpoint_verified") is not True):
                    return None
                ports = descriptor["host_config"].get("PortBindings") or {}
                if (host.get("PortBindings") or {}) != ports:
                    return None
                # Fixed approved loopback HTTP probe and Engine inspect only; no exec.
                proof = self.docker.public_health(cid, ports, 3)
                if proof.get("public_ports_verified") is not True or proof.get("public_endpoint_verified") is not True:
                    return None
            else:
                if (state.get("Running") is not False or current.get("source_state") not in ("stopped", "absent")
                        or current.get("start_on_completion") is not False or current.get("source_service_outcome") != "stopped"
                        or any((container.get("NetworkSettings", {}).get("Ports") or {}).values())):
                    return None
                expected_restart = {"Name": "no", "MaximumRetryCount": 0}
            restart = host.get("RestartPolicy") or {}
            if any(restart.get(key, default) != expected_restart.get(key, default) for key, default in (("Name", "no"), ("MaximumRetryCount", 0))):
                return None
            # Verify authority is still the same after the bounded endpoint probe.
            if self.active(enrolled.instance_id) != active or Journal(self.root, successor_id).value != current:
                return None
            return successor_id
        except (VaultRewindError, OSError, KeyError, TypeError, ValueError, AttributeError):
            return None

    def _repair_historical_status_locked(self, enrolled, journal):
        if not self._historical_status_failure(journal):
            return None
        successor = self._proven_historical_successor(enrolled, journal)
        if successor is None:
            return None
        before = hashlib.sha256(journal.path.read_bytes()).hexdigest()
        return journal.note_historical(successor=successor, reconcile=True, original_sha256=before)

    def historical_status_evidence_locked(self, operation_id):
        """Read-only admin validator; caller MUST already hold Locks(root, ...).

        The fixed bootstrap can keep that host lock across validation and install.
        Never expose this as an operational verb or call the locking wrapper while
        holding an outer lock. An eligible result authorizes only reviewed upgrade
        admission/metadata reconciliation, never a Docker or data mutation.
        """
        operation_id = identifier(operation_id)
        journal = Journal(self.root, operation_id)
        if not journal.value:
            return {"eligible": False, "reason": "operation_unknown"}
        enrolled = self.policy.instance(journal.value["instance_id"])
        current_hash = hashlib.sha256(journal.path.read_bytes()).hexdigest()
        successor = self._proven_historical_successor(enrolled, journal) if self._historical_status_failure(journal) else None
        result = {"eligible": successor is not None, "operation_id": operation_id, "journal_sha256": current_hash,
                  "superseded_by": successor, "changed": False}
        if successor is None:
            result["reason"] = "historical_repair_unproven"
        return result

    def reconcile_historical_status(self, operation_id, *, apply=False, expected_sha256=None):
        """Administrator migration API: dry-run by default; apply requires reviewed raw-file SHA256.

        This is deliberately not a new operational helper verb or an install bypass.
        """
        journal = Journal(self.root, identifier(operation_id))
        if not journal.value:
            return {"eligible": False, "reason": "operation_unknown"}
        with Locks(self.root, journal.value["resource_keys"]):
            journal = Journal(self.root, operation_id)
            result = self.historical_status_evidence_locked(operation_id)
            current_hash = result["journal_sha256"]
            if apply and (not expected_sha256 or hash_required(expected_sha256) != current_hash):
                fail("JOURNAL_CHANGED", "Review and back up the current journal hash before historical reconciliation.")
            if not result["eligible"]:
                return result
            if apply:
                result.update(changed=True, status=journal.note_historical(successor=result["superseded_by"], reconcile=True, original_sha256=current_hash))
            return result

    def commit_restore(self, enrolled, journal, payload):
        if not journal.value or journal.value.get("kind") != "restore":
            fail("OPERATION_UNKNOWN", "No staged restore transaction exists.")
        phase = payload.get("phase")
        if phase == "prepare_safety":
            return self.prepare_safety(enrolled, journal)
        if phase == "switch_validate":
            return self.switch_validate(enrolled, journal, payload)
        if phase == "activate":
            return self.activate(enrolled, journal)
        fail("PROTOCOL_INVALID", "Unknown restore commit phase.")

    def _owned_container(self, journal, key, namekey):
        cid = journal.value.get(key) or journal.value.get(namekey)
        if not cid:
            return None
        found = self.docker.inspect(cid, missing=True)
        if not found:
            return None
        if found["Config"].get("Labels", {}).get("org.vaultrewind.operation") != journal.value["operation_id"]:
            fail("TARGET_CHANGED", "Recovery found a container with a conflicting generation owner.")
        return found

    def _recover_locked(self, enrolled, journal, reason):
        if not journal.value:
            return {"exists": False}
        value = journal.value
        repaired = self._repair_historical_status_locked(enrolled, journal)
        if repaired is not None:
            return repaired
        if (value["phase"] in TERMINAL or value["phase"] in ("captured", "failed_safe")) and not value.get("watchdog_armed"):
            return self.completed_readiness(enrolled, journal)
        active = self.active(enrolled.instance_id)
        if active and active.get("operation_id") != value["operation_id"]:
            newer = Journal(self.root, identifier(active.get("operation_id"))).value
            if newer and newer.get("instance_id") == enrolled.instance_id and newer.get("created_at", 0) > value.get("created_at", 0):
                fail("RECONCILIATION_REQUIRED", "A newer active generation exists; preserve historical state for reviewed reconciliation.")
        if value.get("activation_started") or value["phase"] in POST_ACTIVATION:
            # After exposure is possible, preserve current writes and never switch to old data.
            try:
                final = self._owned_container(journal, "final_id", "final_name")
                if final is None:
                    journal.transition("needs_attention", error_code="RESTORE_ACTIVATION_UNCERTAIN")
                else:
                    journal.value["final_id"] = final["Id"]
                    self.managed_definition(enrolled, journal, final["Id"])
                    should_start = value["source_state"] == "running" or value.get("start_on_completion")
                    if should_start:
                        require_public_endpoint(value["restore_descriptor"]["host_config"].get("PortBindings") or {})
                        self.ensure_restart_policy(final["Id"], value["restore_descriptor"]["host_config"].get("RestartPolicy", {"Name": "no"}))
                        if not final["State"]["Running"]:
                            self.docker.start(final["Id"])
                        health = self.docker.health(final["Id"], min(enrolled.limit("validation_window", 180), 30))
                        health.update(self.docker.public_health(final["Id"], value["restore_descriptor"]["host_config"].get("PortBindings") or {}, min(enrolled.limit("validation_window", 180), 30)))
                        self.retire_candidate(journal)
                        journal.transition("complete", final_health=health, source_service_outcome="running",
                                           public_ports_verified=True, public_endpoint_verified=True,
                                           rollback_cleanup_after=value.get("rollback_cleanup_after", time.time() + enrolled.limit("rollback_grace_seconds", 604800)))
                    else:
                        self.ensure_restart_policy(final["Id"], {"Name": "no"})
                        if final["State"]["Running"]:
                            self.docker.stop(final["Id"])
                        self.retire_candidate(journal)
                        journal.transition("data_restored_service_stopped", source_service_outcome="stopped",
                                   rollback_cleanup_after=time.time() + enrolled.limit("rollback_grace_seconds", 604800))
                self.recovery.disarm(journal)
            except Exception as error:  # noqa: BLE001 -- preserve state and sanitize recovery failures.
                code = error.code if isinstance(error, VaultRewindError) and error.code.startswith("PUBLIC_") else "RESTORE_ACTIVATION_UNCERTAIN"
                if value["phase"] != "needs_attention" or value.get("error_code") != code:
                    journal.transition("needs_attention", error_code=code, public_ports_verified=False, public_endpoint_verified=False)
            return journal.public()
        try:
            candidate = self._owned_container(journal, "candidate_id", "candidate_name")
            if candidate:
                remember_anonymous(self.docker, journal, candidate)
                if candidate["State"]["Running"]:
                    self.docker.stop(candidate["Id"])
                self.docker.remove(candidate["Id"])
            # Inspect path existence to reconcile death between durable intent and rename completion.
            for step in reversed(value.get("generation_steps", [])):
                if step["mount"]["type"] != "bind" or step["phase"] in ("planned", "materialized"):
                    continue
                live, new, old = map(Path, (step["mount"]["source"], step["new"], step["old"]))
                if old.exists():
                    if live.exists():
                        if new.exists():
                            fail("ROLLBACK_AMBIGUOUS", "Both candidate generation paths exist; preserve for manual repair.")
                        durable_rename(live, new)
                    durable_rename(old, live)
                elif not step["had_original"] and live.exists():
                    if new.exists():
                        fail("ROLLBACK_AMBIGUOUS", "Alternate target contains two unexpected generations.")
                    durable_rename(live, new)
                elif step["had_original"] and (not live.exists() or [live.stat().st_dev, live.stat().st_ino] != step["original_identity"]):
                    fail("ROLLBACK_AMBIGUOUS", "Preserved old generation is missing.")
                step["phase"] = "recovered"
                journal.save()
            if "original" in value:
                self.resume_original(enrolled, journal)
            journal.transition("rolled_back" if value.get("kind") == "restore" else
                               "cancelled" if reason == "cancelled" else "failed_safe", recovery_reason=reason)
            self.recovery.disarm(journal)
        except Exception:  # noqa: BLE001 -- recovery/protocol boundaries must preserve state and sanitize every failure.
            phase = "rollback_failed" if value.get("kind") == "restore" else "source_recovery_failed"
            code = "ROLLBACK_FAILED" if value.get("kind") == "restore" else "SOURCE_RECOVERY_FAILED"
            # Prolonged daemon outages must not grow the bounded journal forever.
            if value["phase"] != phase or value.get("error_code") != code:
                journal.transition(phase, error_code=code)
        return journal.public()

    def recover(self, operation_id, reason="reconcile"):
        journal = Journal(self.root, identifier(operation_id))
        if not journal.value:
            return {"exists": False}
        enrolled = self.policy.instance(journal.value["instance_id"])
        with Locks(self.root, journal.value["resource_keys"]):
            journal = Journal(self.root, operation_id)
            return self._recover_locked(enrolled, journal, reason)

    def cleanup_generations(self, enrolled, journal):
        value = journal.value
        if value.get("kind") != "restore" or value["phase"] not in ("complete", "data_restored_service_stopped"):
            fail("CLEANUP_UNSAFE", "Only a completed activated restore can retire its preserved generation.")
        if value.get("generations_cleaned"):
            return journal.public()
        if not value.get("empty_target") and not value.get("safety_ack"):
            fail("CLEANUP_UNSAFE", "The preserved generation has no verified durable safety snapshot.")
        cleanup_after = value.get("rollback_cleanup_after", value.get("updated_at", time.time()) + enrolled.limit("rollback_grace_seconds", 604800))
        if time.time() < cleanup_after:
            fail("CLEANUP_GRACE_PERIOD", "The enrolled rollback preservation grace period has not elapsed.")
        active = self.active(enrolled.instance_id)
        if not active or active["operation_id"] != value["operation_id"]:
            fail("CLEANUP_UNSAFE", "Active generation changed; review older rollback generations locally.")
        original = value["original"]["container_id"]
        if original:
            found = self.docker.inspect(original, missing=True)
            if found:
                if found["State"]["Running"] or found["HostConfig"].get("RestartPolicy", {}).get("Name", "no") != "no":
                    fail("CLEANUP_UNSAFE", "Original container is still capable of writing; cleanup is blocked.")
                self.docker.remove(original)
        for step in value["generation_steps"]:
            if step["mount"]["type"] == "bind":
                path = no_symlink(Path(step["old"]), missing_leaf=True)
                if path.exists():
                    if [path.stat().st_dev, path.stat().st_ino] != step["original_identity"]:
                        fail("CLEANUP_UNSAFE", "Preserved generation identity changed; cleanup is blocked.")
                    if path.is_dir():
                        shutil.rmtree(path)
                    else:
                        path.unlink()
                    fsync_directory(path.parent)
            elif original:
                prior = next((m for m in value["original"]["mounts"] if m["target"] == step["mount"]["target"]), None)
                if prior != step["mount"] or any(m.get("volume_name") == prior.get("volume_name") for m in active["mounts"]):
                    fail("CLEANUP_UNSAFE", "Preserved volume provenance is inconsistent or still active; retain it for review.")
                volume = self.docker.volume(step["mount"]["volume_name"], missing=True)
                if volume:
                    recorded = step.get("original_volume")
                    identity = Path(volume["Mountpoint"]).stat()
                    if (not recorded or any(volume.get(key) != val for key, val in recorded.items())
                            or [identity.st_dev, identity.st_ino] != step.get("original_volume_identity")
                            or volume["Mountpoint"] != prior["source"] or volume.get("Driver") != "local" or volume.get("Options")):
                        fail("CLEANUP_UNSAFE", "Preserved volume identity changed; retain it for review.")
                    reject_other_writers(self.docker, [prior])
                    self.docker.remove_volume(volume["Name"])
                    if self.docker.volume(volume["Name"], missing=True):
                        fail("CLEANUP_UNSAFE", "Preserved volume removal could not be verified.")
        value["generations_cleaned"] = True
        journal.save()
        return journal.public()

    def dispatch(self, request, incoming=None, outgoing=None):
        self.check_payload(request)
        enrolled = self.policy.instance(request.instance_id)
        if request.verb not in enrolled.operations:
            fail("OPERATION_FORBIDDEN", "This SSH helper policy does not authorize the requested operation.")
        if request.verb == "discover":
            view = self.inspect(enrolled)
            readiness = self.restore_readiness(enrolled, view)
            members, size = 0, 0
            if not view["empty_target"]:
                for mount in view["mounts"]:
                    items = walk_checked(Path(mount["source"]))
                    members += len(items)
                    size += sum(s.st_size for _, s in items)
                for path in enrolled.value.get("additional_files", {}).values():
                    walk_checked(Path(path))
            return {"inventory_members": members, "estimated_data_bytes": size, "helper_version": HELPER_VERSION, "schema_version": 1, "fingerprint": view["fingerprint"],
                    "source_state": view["source_state"], "empty_target": view["empty_target"],
                    "mount_count": len(view["mounts"]), "database_engine": "sqlite",
                    **readiness, **self.current_public_readiness(view),
                    "restore_enabled": "commit_restore" in enrolled.operations and readiness["restore_ready"]}
        if request.verb == "preflight":
            return self.preflight(enrolled, request.payload)
        journal = Journal(self.root, request.operation_id)
        if journal.value and journal.value["instance_id"] != request.instance_id:
            fail("OPERATION_CONFLICT", "Operation identity belongs to another instance.")
        if journal.value is None and request.verb not in ("capture", "stage_restore"):
            if request.verb in ("status", "cancel", "rollback"):
                return {"exists": False}
            fail("OPERATION_UNKNOWN", "No durable operation with this identity exists.")
        if request.verb == "cancel" and journal.value and same_process(journal.value.get("owner")):
            if request.fencing_token < journal.value["fencing_token"]:
                fail("STALE_FENCE", "Stale worker cannot cancel a newer resource lease.")
            atomic_json(self.root / "cancel" / request.operation_id, {"requested_at": time.time()})
            return {**journal.public(), "cancel_requested": True}
        mounts = (self.active(enrolled.instance_id) or {}).get("mounts", enrolled.mounts)
        keys = journal.value["resource_keys"] if journal.value else resource_keys(self.policy.value["machine_id"], self.policy.value["daemon_id"], mounts)
        with Locks(self.root, keys) as locks:
            journal = Journal(self.root, request.operation_id)
            if request.verb == "status":
                # Only proven historical metadata repair bypasses live fencing.
                # Never adopt an old status request's fence or ignore other pending work.
                repaired = self._repair_historical_status_locked(enrolled, journal)
                if repaired is not None:
                    return repaired
            safe_phases = TERMINAL | {"captured", "failed_safe"}
            historical_status = request.verb == "status" and journal.value and journal.value["phase"] in safe_phases
            immutable_export = (request.verb == "export" and request.payload.get("kind", "capture") == "capture"
                                and journal.value and journal.value["phase"] == "captured")
            staging_cleanup = (request.verb == "cleanup" and request.payload.get("kind", "staging") == "staging"
                               and journal.value and journal.value["phase"] in safe_phases)
            if not (historical_status or immutable_export or staging_cleanup):
                locks.fence(request)
                if journal.value and request.fencing_token > journal.value["fencing_token"]:
                    journal.value["fencing_token"] = request.fencing_token
                    journal.save()
            elif not historical_status and request.fencing_token < journal.value["fencing_token"]:
                fail("STALE_FENCE", "This operation's staging lease has been superseded.")
            if request.verb == "status":
                if (journal.value and not journal.value.get("watchdog_armed")
                        and journal.value["phase"] in ("preparing", "validating")
                        and not same_process(journal.value.get("owner"))):
                    # No downtime has begun, or the source was already recovered.
                    # Preserve partial private staging; release the live-resource reservation.
                    journal.transition("failed_safe", error_code="PREPARATION_INTERRUPTED", owner=None)
                    return journal.public()
                if journal.value and journal.value.get("watchdog_armed") and (expired(journal.value) or not same_process(journal.value.get("owner")) and journal.value["phase"] not in ("safety_ready", "candidate_validated")):
                    return self._recover_locked(enrolled, journal, "reconcile")
                return self.completed_readiness(enrolled, journal)
            if request.verb in ("rollback", "cancel"):
                if not journal.value:
                    return {"exists": False}
                if request.verb == "rollback" and journal.value.get("activation_started"):
                    fail("ACTIVATION_BOUNDARY", "Activation may have exposed new writes; a new confirmed restore and safety capture is required.")
                return self._recover_locked(enrolled, journal, "cancelled" if request.verb == "cancel" else "requested")
            if request.verb == "export":
                if not journal.value:
                    fail("OPERATION_UNKNOWN", "No immutable captured stage exists.")
                kind = request.payload.get("kind", "capture")
                if kind not in ("capture", "safety"):
                    fail("PROTOCOL_INVALID", "Unknown snapshot export kind.")
                if kind == "capture" and journal.value["phase"] != "captured" or kind == "safety" and not journal.value.get("safety_manifest_hash"):
                    fail("SNAPSHOT_INCOMPLETE", "The requested capture has not been sealed and verified.")
                if kind == "safety":
                    self.check(journal)
                archive = self.operation_root(journal) / (kind + ".tar")
                expected = journal.value["sha256"] if kind == "capture" else journal.value["safety_archive_sha256"]
                if not archive.is_file():
                    fail("STAGING_EXPIRED", "Remote staging was cleaned; use a verified stored copy or a new capture.")
                if immutable_export:
                    # An open descriptor pins immutable content through concurrent staging
                    # cleanup. A stalled read-only transfer must never block a watchdog.
                    with archive.open("rb") as source:
                        locks.stack.close()
                        actual = hashlib.file_digest(source, "sha256").hexdigest()
                        if actual != expected:
                            fail("TRANSFER_CHECKSUM", "Immutable remote staging archive has changed.")
                        source.seek(0)
                        return send_frames(source, outgoing, enrolled.limit("max_archive_bytes", 1024**4))
                journal.value["owner"] = process_identity()
                journal.save()
                try:
                    if file_hash(archive) != expected:
                        fail("TRANSFER_CHECKSUM", "Immutable remote staging archive has changed.")
                    with archive.open("rb") as source:
                        return send_frames(source, outgoing, enrolled.limit("max_archive_bytes", 1024**4))
                finally:
                    journal.value["owner"] = None
                    journal.save()
            if request.verb == "cleanup":
                if not journal.value or journal.value["phase"] not in TERMINAL | {"captured", "failed_safe"}:
                    fail("CLEANUP_UNSAFE", "Only completed or safely recovered staging can be removed.")
                if request.payload.get("kind") == "generations":
                    return self.cleanup_generations(enrolled, journal)
                if request.payload.get("kind") == "discard_candidate":
                    return discard_candidate(self, enrolled, journal)
                if request.payload.get("kind", "staging") != "staging":
                    fail("PROTOCOL_INVALID", "Unknown cleanup kind.")
                path = self.root / "operations" / request.operation_id
                if path.exists():
                    shutil.rmtree(path)
                    fsync_directory(path.parent)
                journal.value["staging_cleaned"] = True
                journal.save()
                return journal.public()
            journal.create(request, keys)
            cached = journal.cached(request)
            if cached is not None:
                if journal.value.get("kind") == "restore" and journal.value["phase"] == "complete":
                    return self.completed_readiness(enrolled, journal)
                if journal.value["phase"] in ("rolled_back", "cancelled", "failed_safe", "needs_attention", "rollback_failed", "source_recovery_failed"):
                    return journal.public()
                if request.verb == "stage_restore" and incoming is not None:
                    # Drain/revalidate repeated upload so SSH senders never block on a full channel.
                    with open(os.devnull, "wb") as sink:
                        receive_frames(incoming, sink, enrolled.limit("max_archive_bytes", 1024**4))
                return cached
            journal.reserve(request)
            journal.value["fencing_token"] = request.fencing_token
            journal.value["owner"] = process_identity()
            journal.save()
            if request.verb == "capture":
                result = self.capture(enrolled, journal, request.payload)
            elif request.verb == "stage_restore":
                result = self.stage_restore(enrolled, journal, request.payload, incoming)
            else:
                result = self.commit_restore(enrolled, journal, request.payload)
            journal.remember(request, result)
            journal.value["owner"] = None
            journal.save()
            return result


def main():
    parser = argparse.ArgumentParser(description="VaultRewind constrained root helper")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--watchdog", metavar="OPERATION_UUID")
    mode.add_argument("--reconcile-all", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    if os.geteuid() != 0:
        print(canonical({"ok": False, "error": {"code": "ROOT_REQUIRED", "message": "Invoke the enrolled helper through its narrow sudo entrypoint."}}).decode())
        return 1
    streaming = False
    try:
        service = Helper(Policy.load())
        if args.watchdog:
            watchdog_loop(service, identifier(args.watchdog))
            return 0
        if args.reconcile_all:
            errors = []
            for path in sorted((service.root / "journals").glob("*.json")):
                try:
                    journal = Journal(service.root, identifier(path.stem))
                    if journal.value and journal.value.get("watchdog_armed"):
                        # A boot oneshot cannot own indefinite daemon recovery.
                        # Restore the per-operation watchdog before the first attempt.
                        service.recovery.resume(journal)
                        service.recover(path.stem, "boot")
                except VaultRewindError as exc:
                    errors.append(exc.code)
            return 1 if errors else 0
        request = read_request(sys.stdin.buffer)
        if request.verb == "export":
            # Once the stream starts, any failure is signaled by EOF/nonzero status.
            class Output:
                def write(self, value):
                    nonlocal streaming
                    streaming = True
                    return sys.stdout.buffer.write(value)
                def flush(self):
                    sys.stdout.buffer.flush()
            service.dispatch(request, incoming=sys.stdin.buffer, outgoing=Output())
        else:
            result = service.dispatch(request, incoming=sys.stdin.buffer)
            sys.stdout.buffer.write(canonical({"ok": True, "result": result}) + b"\n")
        return 0
    except VaultRewindError as exc:
        if not streaming:
            sys.stdout.buffer.write(canonical({"ok": False, "error": exc.as_dict()}) + b"\n")
        return 1
    except Exception:  # noqa: BLE001 -- recovery/protocol boundaries must preserve state and sanitize every failure.
        if not streaming:
            sys.stdout.buffer.write(canonical({"ok": False, "error": {"code": "HELPER_FAILED", "message": "Helper failed; reconcile the durable operation journal before retrying.", "retryable": False}}) + b"\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
