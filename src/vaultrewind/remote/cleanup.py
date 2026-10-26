"""Verified disposal of never-public restored generations, with durable retry progress."""
from __future__ import annotations

import shutil
import stat
import time
from pathlib import Path

from vaultrewind.core.errors import VaultRewindError

from .docker import reject_other_writers
from .files import walk_checked
from .journal import fsync_directory
from .policy import no_symlink, root_trusted
from .protocol import HEX, fail


def isolated_candidate(journal, container):
    labels = container["Config"].get("Labels") or {}
    expected = {"org.vaultrewind.operation": journal.value["operation_id"],
                "org.vaultrewind.instance": journal.value["instance_id"],
                "org.vaultrewind.role": "candidate"}
    host = container["HostConfig"]
    networks = container.get("NetworkSettings", {}).get("Networks", {})
    if (any(labels.get(k) != v for k, v in expected.items()) or host.get("NetworkMode") != "none"
            or host.get("PortBindings") or host.get("PublishAllPorts") or set(networks) - {"none"}
            or host.get("RestartPolicy", {}).get("Name", "no") != "no"):
        fail("CLEANUP_UNSAFE", "Candidate ownership or isolation changed; preserve it for local review.")


def remember_anonymous(docker, journal, container):
    """Persist anonymous-volume provenance before removing the only owning container."""
    isolated_candidate(journal, container)
    known = {s.get("volume_name") for s in journal.value.get("generation_steps", [])}
    known |= {s["mount"].get("volume_name") for s in journal.value.get("generation_steps", [])}
    records = journal.value.setdefault("candidate_anonymous_volumes", {})
    for mount in container.get("Mounts", []):
        name = mount.get("Name")
        if mount["Type"] != "volume" or name in known:
            continue
        if not isinstance(name, str) or not HEX.fullmatch(name):
            fail("CLEANUP_UNSAFE", "An unplanned named volume cannot be attributed to the disposable candidate.")
        volume = docker.volume(name)
        if (volume.get("Driver") != "local" or volume.get("Options") or volume.get("Scope") != "local"
                or volume["Mountpoint"] != mount["Source"] or not volume.get("CreatedAt")):
            fail("CLEANUP_UNSAFE", "Anonymous candidate volume provenance is incomplete.")
        from datetime import datetime
        try:
            created = datetime.fromisoformat(volume["CreatedAt"]).timestamp()
        except (TypeError, ValueError):
            fail("CLEANUP_UNSAFE", "Anonymous candidate volume creation time is unverifiable.")
        if created < journal.value["created_at"] - 1:
            fail("CLEANUP_UNSAFE", "Candidate references an anonymous volume predating this operation.")
        record = {"name": name, "path": volume["Mountpoint"], "created_at": volume["CreatedAt"]}
        if name in records and records[name] != record:
            fail("CLEANUP_UNSAFE", "Anonymous candidate volume identity changed.")
        records[name] = record
    journal.save()


def logical_bytes(path):
    return sum(s.st_size for _, s in walk_checked(path) if stat.S_ISREG(s.st_mode)) if path.exists() else 0


def delete_path(path):
    if path.exists():
        # Reject nested mounts/devices; shutil itself never follows internal symlinks.
        walk_checked(path)
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
        fsync_directory(path.parent)


def discard_candidate(helper, enrolled, journal):
    value = journal.value
    if (value.get("kind") != "restore" or value["phase"] not in ("rolled_back", "failed_safe", "cancelled")
            or value.get("activation_started") or value.get("watchdog_armed")):
        fail("CLEANUP_UNSAFE", "Candidate disposal requires a disarmed, safely recovered restore that never began activation.")
    active = helper.active(enrolled.instance_id)
    if active and active["operation_id"] == value["operation_id"]:
        fail("CLEANUP_UNSAFE", "The candidate is registered as active; preserve its data.")
    if value.get("candidate_cleanup_outcome") == "complete":
        return journal.public()
    candidate = helper._owned_container(journal, "candidate_id", "candidate_name")
    if candidate:
        isolated_candidate(journal, candidate)
        if candidate["State"]["Running"]:
            fail("CLEANUP_UNSAFE", "Candidate must already be stopped before disposal.")
        remember_anonymous(helper.docker, journal, candidate)
    if "candidate_cleanup_plan" not in value:
        plan = []
        if candidate:
            plan.append({"kind": "container", "id": candidate["Id"], "bytes": 0})
        for step in value.get("generation_steps", []):
            mount = step["mount"]
            if mount["type"] == "bind":
                live = Path(mount["source"])
                parent = live.parent / f'.vrw-{value["operation_id"]}-{step["index"]}'
                path = Path(step["new"])
                if path != parent / "new" or Path(step["old"]) != parent / "old" or (parent / "old").exists():
                    fail("CLEANUP_UNSAFE", "Original generation has not been safely restored.")
                if step["had_original"] and (not live.exists() or [live.stat().st_dev, live.stat().st_ino] != step["original_identity"]):
                    fail("CLEANUP_UNSAFE", "Original generation identity is not restored.")
                if parent.exists():
                    root_trusted(parent, directory=True)
                entry = {"kind": "bind", "path": str(path), "parent": str(parent), "identity": step.get("new_identity")}
            else:
                name = f'vrw-{value["operation_id"]}-{step["index"]}'
                if step.get("volume_name") != name or name == mount.get("volume_name"):
                    fail("CLEANUP_UNSAFE", "Generation volume identity is not disposable.")
                volume = helper.docker.volume(name, missing=True)
                path = Path(step.get("new") or (volume or {}).get("Mountpoint", "/nonexistent"))
                entry = {"kind": "volume", "name": name, "path": str(path), "identity": step.get("new_identity")}
            if path.exists():
                no_symlink(path)
                identity = [path.stat().st_dev, path.stat().st_ino]
                if entry["identity"] and entry["identity"] != identity:
                    fail("CLEANUP_UNSAFE", "Disposable generation identity changed.")
                entry["identity"] = identity
            entry["bytes"] = logical_bytes(path)
            plan.append(entry)
        for record in value.get("candidate_anonymous_volumes", {}).values():
            plan.append({"kind": "anonymous", **record, "bytes": logical_bytes(Path(record["path"]))})
        plan.append({"kind": "staging", "path": str(helper.root / "operations" / value["operation_id"]), "bytes": 0})
        value["candidate_cleanup_plan"] = plan
        value["candidate_cleanup_outcome"] = "pending"
        value["candidate_cleanup_remaining"] = len(plan)
        journal.save()
    plan = value["candidate_cleanup_plan"]
    for entry in plan:
        if entry.get("done"):
            continue
        for attempt in range(3):
            try:
                if entry["kind"] == "container":
                    found = helper.docker.inspect(entry["id"], missing=True)
                    if found:
                        isolated_candidate(journal, found)
                        if found["State"]["Running"]:
                            fail("CLEANUP_UNSAFE", "Candidate resumed during cleanup; preserve it.")
                        helper.docker.remove(found["Id"])
                    if helper.docker.inspect(entry["id"], missing=True):
                        raise OSError("Container deletion not confirmed")
                else:
                    path = Path(entry["path"])
                    if entry["kind"] != "staging":
                        reject_other_writers(helper.docker, [{"source": str(path), "type": "bind"}])
                        if path.exists():
                            no_symlink(path)
                            if entry.get("identity") and [path.stat().st_dev, path.stat().st_ino] != entry["identity"]:
                                fail("CLEANUP_UNSAFE", "Disposable resource was replaced; preserve it.")
                    if entry["kind"] in ("volume", "anonymous"):
                        volume = helper.docker.volume(entry["name"], missing=True)
                        if volume:
                            expected = {"org.vaultrewind.instance": enrolled.instance_id, "org.vaultrewind.operation": value["operation_id"]}
                            if (volume["Mountpoint"] != entry["path"] or volume.get("Driver") != "local" or volume.get("Options")
                                    or (entry["kind"] == "volume" and volume.get("Labels") != expected)
                                    or (entry["kind"] == "anonymous" and volume.get("CreatedAt") != entry["created_at"])):
                                fail("CLEANUP_UNSAFE", "Disposable volume provenance changed.")
                            helper.docker.remove_volume(entry["name"])
                        if helper.docker.volume(entry["name"], missing=True) or path.exists():
                            raise OSError("Volume deletion not confirmed")
                    else:
                        delete_path(path)
                        if path.exists():
                            raise OSError("Path deletion not confirmed")
                        if entry["kind"] == "bind" and Path(entry["parent"]).exists():
                            Path(entry["parent"]).rmdir()
                            fsync_directory(Path(entry["parent"]).parent)
                entry["done"] = True
                value["candidate_cleanup_remaining"] = sum(not item.get("done", False) for item in plan)
                value["discarded_candidate_bytes"] = sum(item["bytes"] for item in plan if item.get("done"))
                journal.save()
                break
            except (OSError, VaultRewindError) as error:
                if isinstance(error, VaultRewindError) and error.code not in ("DOCKER_OPERATION_FAILED", "DOCKER_UNAVAILABLE"):
                    raise
                if attempt < 2:
                    time.sleep(0.1 * (attempt + 1))
                else:
                    value["candidate_cleanup_outcome"] = "incomplete"
                    journal.save()
                    raise VaultRewindError("CANDIDATE_CLEANUP_INCOMPLETE", "Disposable cleanup remains incomplete; retry cleanup or inspect the privileged host.", retryable=True) from None
    value.update(candidate_cleanup_outcome="complete", candidate_cleanup_remaining=0, staging_cleaned=True)
    journal.save()
    return journal.public()
