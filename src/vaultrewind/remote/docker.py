"""Docker Engine API over its root-local Unix socket; no caller shell or CLI flags."""
from __future__ import annotations

import http.client
import ipaddress
import json
import os
import platform
import socket
import time
from pathlib import Path
from urllib.parse import quote, urlencode

from vaultrewind.core.errors import VaultRewindError

from .dependencies import validate_compose_dependencies
from .policy import no_symlink
from .protocol import HEX, canonical, decode, digest, fail


def operation_category(method, path):
    """Fixed diagnostic vocabulary; never return IDs, query strings or caller text."""
    route = path.split("?", 1)[0]
    direct = {("GET", "/info"): "daemon_info", ("GET", "/containers/json"): "containers_list",
              ("POST", "/containers/create"): "containers_create", ("GET", "/images/get"): "images_save",
              ("POST", "/images/load"): "images_load", ("POST", "/volumes/create"): "volumes_create"}
    if (method, route) in direct:
        return direct[method, route]
    parts = route.strip("/").split("/")
    if len(parts) == 3:
        return {("POST", "exec", "start"): "exec_start", ("GET", "exec", "json"): "exec_inspect",
                ("POST", "containers", "exec"): "exec_create", ("GET", "containers", "json"): "containers_inspect",
                ("POST", "containers", "stop"): "containers_stop", ("POST", "containers", "start"): "containers_start",
                ("POST", "containers", "update"): "containers_update", ("POST", "containers", "rename"): "containers_rename",
                ("GET", "images", "json"): "images_inspect"}.get((method, parts[0], parts[2]), "docker_request")
    if len(parts) == 2:
        return {("DELETE", "containers"): "containers_remove", ("GET", "volumes"): "volumes_inspect",
                ("DELETE", "volumes"): "volumes_remove", ("GET", "networks"): "networks_inspect"}.get((method, parts[0]), "docker_request")
    return "docker_request"


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class Docker:
    def __init__(self, socket_path="/var/run/docker.sock", timeout=60):
        self.socket_path = socket_path
        self.timeout = timeout

    def api(self, method, path, body=None, *, output=None, input_file=None, max_bytes=16 * 1024 * 1024,
            timeout=None, missing=False):
        conn = UnixConnection(self.socket_path, timeout or self.timeout)
        try:
            headers = {}
            data = None
            if input_file is not None:
                headers = {"Content-Type": "application/x-tar", "Content-Length": str(os.fstat(input_file.fileno()).st_size)}
                data = input_file
            elif body is not None:
                data = canonical(body)
                headers = {"Content-Type": "application/json"}
            conn.request(method, "/v1.41" + path, body=data, headers=headers)
            response = conn.getresponse()
            if response.status == 404 and missing:
                return None
            if response.status not in (200, 201, 204, 304):
                fail("DOCKER_OPERATION_FAILED", "Docker rejected the operation; inspect the privileged host diagnostics.")
            count = 0
            chunks = []
            while chunk := response.read(1024 * 1024):
                count += len(chunk)
                if count > max_bytes:
                    fail("DOCKER_OUTPUT_LIMIT", "Docker output exceeds the enrolled limit.")
                if output:
                    output.write(chunk)
                else:
                    chunks.append(chunk)
            if output:
                output.flush()
                os.fsync(output.fileno())
                return {"bytes": count}
            raw = b"".join(chunks)
            if not raw:
                return None
            if "application/json" in response.getheader("Content-Type", ""):
                # Image load returns JSON-lines progress, never include it in errors/logs.
                if input_file is not None:
                    for line in raw.splitlines():
                        if json.loads(line).get("error"):
                            fail("IMAGE_UNAVAILABLE", "Docker could not import the saved image.")
                    return None
                return json.loads(raw)
            return raw
        except (OSError, http.client.HTTPException, ValueError) as error:
            kind = ("timeout" if isinstance(error, TimeoutError) else
                    "http_protocol" if isinstance(error, http.client.HTTPException) else
                    "invalid_response" if isinstance(error, ValueError) else "os_error")
            raise VaultRewindError("DOCKER_UNAVAILABLE", "Docker transport failed; reconcile the operation before retrying.",
                                   operation_category=operation_category(method, path), transport_kind=kind) from None
        finally:
            conn.close()

    def info(self):
        return self.api("GET", "/info")

    def inspect(self, container, missing=False):
        return self.api("GET", "/containers/" + quote(container, safe="") + "/json", missing=missing)

    def image(self, image):
        return self.api("GET", "/images/" + quote(image, safe="") + "/json")

    def volume(self, name, missing=False):
        return self.api("GET", "/volumes/" + quote(name, safe=""), missing=missing)

    def remove_volume(self, name):
        self.api("DELETE", "/volumes/" + quote(name, safe=""), missing=True)

    def network(self, name):
        return self.api("GET", "/networks/" + quote(name, safe=""))

    def containers(self):
        return self.api("GET", "/containers/json?all=true")

    def stop(self, container, timeout=30):
        try:
            self.api("POST", f"/containers/{container}/stop?t={timeout}", timeout=timeout + 10)
        except VaultRewindError as error:
            if error.code != "DOCKER_UNAVAILABLE":
                raise
            # The engine may have stopped the exact container before its HTTP
            # acknowledgement was lost. Reconcile that state without repeating
            # the stop or accepting an ambiguous/running result.
            try:
                item = self.inspect(container)
            except VaultRewindError:
                raise error from None
            if item["State"]["Running"]:
                raise error from None
        else:
            item = self.inspect(container)
        if item["State"]["Running"] or item["State"].get("OOMKilled") or item["State"].get("ExitCode") == 137:
            fail("SOURCE_UNCLEAN_STOP", "Source did not stop gracefully; the capture is invalid.")

    def start(self, container):
        self.api("POST", f"/containers/{container}/start")

    def restart_policy(self, container, policy):
        self.api("POST", f"/containers/{container}/update", {"RestartPolicy": policy})

    def rename(self, container, name):
        self.api("POST", f"/containers/{container}/rename?" + urlencode({"name": name}))

    def remove(self, container):
        if self.inspect(container, missing=True):
            self.api("DELETE", f"/containers/{container}?v=false&force=false")

    def save_image(self, image, path, max_bytes):
        with path.open("xb") as stream:
            return self.api("GET", "/images/get?" + urlencode({"names": image}), output=stream,
                            max_bytes=max_bytes, timeout=600)

    def load_image(self, path):
        with path.open("rb") as stream:
            self.api("POST", "/images/load?quiet=true", input_file=stream, timeout=600)

    def create_volume(self, name, labels):
        old = self.volume(name, missing=True)
        if old is not None:
            if old.get("Labels") != labels:
                fail("TARGET_CHANGED", "A generation volume already exists with a different owner.")
            return old
        return self.api("POST", "/volumes/create", {"Name": name, "Driver": "local", "Labels": labels})

    def create(self, name, config):
        return self.api("POST", "/containers/create?" + urlencode({"name": name}), config)["Id"]

    def health(self, container, window=30):
        deadline = time.monotonic() + window
        while time.monotonic() < deadline:
            state = self.inspect(container)["State"]
            if not state["Running"]:
                fail("APPLICATION_START_FAILED", "Vaultwarden container exited before readiness.")
            # curl is included in the supported official Vaultwarden Debian image.
            # No shell, captured command, URL, or credential is executed here.
            exec_id = self.api("POST", f"/containers/{container}/exec", {
                "AttachStdout": False, "AttachStderr": False,
                "Cmd": ["curl", "--fail", "--silent", "--max-time", "3", "http://127.0.0.1:80/alive"]})["Id"]
            # No attached/hijacked stream is needed: inspect the detached process's
            # completion instead, including the fast-exit case.
            self.api("POST", f"/exec/{exec_id}/start", {"Detach": True, "Tty": False}, timeout=5)
            exec_deadline = min(deadline, time.monotonic() + 5)
            result = self.api("GET", f"/exec/{exec_id}/json")
            while result.get("Running") and time.monotonic() < exec_deadline:
                time.sleep(0.05)
                result = self.api("GET", f"/exec/{exec_id}/json")
            if result.get("ExitCode") == 0 and not result.get("Running"):
                state = self.inspect(container)["State"]
                if not state["Running"]:
                    fail("APPLICATION_START_FAILED", "Vaultwarden exited after its internal readiness probe.")
                health = state.get("Health", {}).get("Status")
                if health != "unhealthy":
                    return {"application_started": True, "internal_http_alive": True, "docker_health_status": health, "user_login_tested": False}
            time.sleep(min(1, max(0, deadline - time.monotonic())))
        fail("APPLICATION_NOT_READY", "Vaultwarden did not pass internal readiness within the policy window.")

    def public_health(self, container, expected, window=30):
        """Prove allocation AND host reachability; never follow DOMAIN or redirects."""
        bindings = normalized_ports(expected)
        require_public_endpoint(expected)
        deadline = time.monotonic() + window
        while True:
            item = self.inspect(container)
            if not item["State"]["Running"]:
                fail("APPLICATION_START_FAILED", "Vaultwarden exited before public readiness.")
            verify_published_ports(item, expected)
            ready = True
            for port, address, number in bindings:
                # Only literal loopback endpoints derived from root-approved bindings.
                host = "127.0.0.1" if address == "0.0.0.0" else "::1" if address == "::" else address
                timeout = min(3, max(0.01, deadline - time.monotonic()))
                try:
                    if port == "80/tcp":
                        conn = http.client.HTTPConnection(host, number, timeout=timeout)
                        try:
                            conn.request("GET", "/alive", headers={"Connection": "close"})
                            response = conn.getresponse()
                            ready = ready and response.status == 200
                        finally:
                            conn.close()
                    else:
                        with socket.create_connection((host, number), timeout=timeout):
                            pass
                except (OSError, http.client.HTTPException):
                    ready = False
                if not ready:
                    break
            if ready:
                # A disappearing allocation/container cannot satisfy the final postcondition.
                final = self.inspect(container)
                if not final["State"]["Running"] or final["State"].get("Health", {}).get("Status") == "unhealthy":
                    fail("APPLICATION_NOT_READY", "Vaultwarden lost readiness during its public probe.")
                verify_published_ports(final, expected)
                return {"public_ports_verified": True, "public_endpoint_verified": True,
                        "public_endpoint_count": len(bindings), "public_readiness_required": bool(bindings)}
            if time.monotonic() >= deadline:
                fail("PUBLIC_ENDPOINT_UNAVAILABLE", "The approved loopback host endpoint is unavailable; preserve the active generation and repair its networking.")
            time.sleep(min(0.25, max(0, deadline - time.monotonic())))


def normalized_ports(ports):
    """No DNS, URL, interface name, dynamic port, or remotely routed probe target."""
    if not isinstance(ports, dict):
        fail("DEPLOYMENT_UNSAFE", "Expected an explicit Docker port-binding map.")
    result = set()
    for port, bindings in ports.items():
        if port not in ("80/tcp", "3012/tcp") or not isinstance(bindings, list) or not bindings:
            fail("DEPLOYMENT_UNSAFE", "Only explicit Vaultwarden HTTP/WebSocket bindings are supported.")
        for binding in bindings:
            if not isinstance(binding, dict) or set(binding) != {"HostIp", "HostPort"}:
                fail("DEPLOYMENT_UNSAFE", "Invalid Docker host binding.")
            number, address = binding["HostPort"], binding["HostIp"]
            if not isinstance(number, str) or not number.isascii() or not number.isdigit() or not 1 <= int(number) <= 65535:
                fail("DEPLOYMENT_UNSAFE", "Dynamic/invalid host ports are unsupported.")
            try:
                if not isinstance(address, str) or "%" in address:
                    raise ValueError
                ip = ipaddress.ip_address(address or "0.0.0.0")
            except ValueError:
                fail("DEPLOYMENT_UNSAFE", "Host bindings must use literal IP addresses without scope identifiers.")
            if (not ip.is_loopback and not ip.is_unspecified) or (ip.version == 6 and ip.ipv4_mapped is not None):
                fail("PUBLIC_BIND_UNSUPPORTED", "Enroll a loopback or wildcard binding so the helper can verify the host endpoint locally.")
            result.add((port, str(ip), int(number)))
    return result


def require_public_endpoint(ports):
    if not any(port == "80/tcp" for port, _address, _number in normalized_ports(ports)):
        fail("PUBLIC_ENDPOINT_REQUIRED", "A running application restore requires an approved HTTP host endpoint; use an explicit stopped data-only restore or enroll a published HTTP port.")


def verify_published_ports(container, expected):
    wanted = normalized_ports(expected)
    raw = container.get("NetworkSettings", {}).get("Ports")
    if not isinstance(raw, dict):
        fail("PUBLIC_PORTS_UNAVAILABLE", "Docker did not report actual port allocations for the running container.")
    actual = normalized_ports({p: b for p, b in raw.items() if b})
    # Docker's empty HostIp may allocate both wildcard families. Explicit IPv4
    # and loopback policies never authorize an extra IPv6/wildcard exposure.
    optional = {(p, "::", int(b["HostPort"])) for p, bs in expected.items() for b in bs if b["HostIp"] == ""}
    if not wanted <= actual or actual - wanted - optional:
        fail("PUBLIC_PORTS_UNAVAILABLE", "Actual Docker host ports differ from the approved bindings; preserve the active generation and repair its networking.")


def validate_public_network(docker, network, ports):
    bindings = normalized_ports(ports)
    item = docker.network(network)
    if item.get("Driver") != "bridge" or item.get("Scope", "local") != "local":
        fail("DEPENDENCY_UNREADY", "Recovery requires a local Docker bridge network.")
    if bindings:
        options = item.get("Options") or {}
        if item.get("Internal") is not False or any(options.get("com.docker.network.bridge.gateway_mode_" + family, "nat") != "nat" for family in ("ipv4", "ipv6")):
            fail("PUBLIC_NETWORK_UNPUBLISHABLE", "Expected host ports require a non-internal bridge with NAT gateway mode; enroll a compatible recovery network before restore.")


def target_network_profile(policy, view):
    profile = policy.value.get("recovery_profile", {})
    if not isinstance(profile, dict) or set(profile) - {"environment", "network", "port_bindings", "revision"}:
        fail("POLICY_INVALID", "Unsupported recovery profile substitution.")
    allowed = policy.value.get("allowed_networks", ["bridge"])
    fallback = view.get("descriptor", {}).get("host_config", {}).get("NetworkMode")
    network = profile.get("network", fallback or (allowed[0] if len(allowed) == 1 else None))
    if network not in allowed or network in ("host", "none") or not isinstance(network, str) or network.startswith("container:"):
        fail("TARGET_PROFILE_REQUIRED", "Enroll one explicit approved recovery bridge network.")
    return network, profile.get("port_bindings", policy.value.get("port_bindings", {}))


def check_database(env: dict, config=None):
    values = [env.get("DATABASE_URL", ""), (config or {}).get("database_url", "")]
    if any(v and (not isinstance(v, str) or (":" in v and not v.startswith("sqlite:"))) for v in values):
        fail("UNSUPPORTED_DATABASE", "Release one supports only Vaultwarden SQLite.")
    for value in values:
        if value and value not in ("/data/db.sqlite3", "db.sqlite3", "sqlite:///data/db.sqlite3"):
            fail("UNSUPPORTED_DATABASE", "Enroll the supported SQLite location /data/db.sqlite3.")
    for key, expected in {"DATA_FOLDER": "/data", "ATTACHMENTS_FOLDER": "/data/attachments",
                          "SENDS_FOLDER": "/data/sends", "RSA_KEY_FILENAME": "/data/rsa_key",
                          "ICON_CACHE_FOLDER": "/data/icon_cache", "CONFIG_FILE": "/data/config.json"}.items():
        if env.get(key, expected) != expected or (config or {}).get(key.lower(), expected) != expected:
            fail("UNSUPPORTED_LAYOUT", "A custom persistent Vaultwarden path requires a supported explicit mapping.")


def validate_descriptor(descriptor: dict, policy, docker: Docker, *, imported=False, for_restore=True):
    if set(descriptor) != {"schema_version", "image_id", "registry_digest", "platform", "config", "host_config", "mounts", "dependencies"}:
        fail("DEPLOYMENT_UNSAFE", "Unknown recovery descriptor fields.")
    image_id = descriptor["image_id"]
    if descriptor["schema_version"] != 1 or not isinstance(image_id, str) or not image_id.startswith("sha256:") or not HEX.fullmatch(image_id[7:]):
        fail("DEPLOYMENT_UNSAFE", "Recovery must use an immutable image content ID.")
    if image_id not in policy.value.get("allowed_image_ids", []):
        fail("IMAGE_NOT_APPROVED", "Approve this exact Vaultwarden image ID in the root-owned target policy.")
    config, host = descriptor["config"], descriptor["host_config"]
    if set(config) - {"Env", "Entrypoint", "Cmd", "User", "WorkingDir", "Labels", "Healthcheck", "ExposedPorts", "StopSignal"}:
        fail("DEPLOYMENT_UNSAFE", "Unsupported container configuration.")
    if set(host) - {"PortBindings", "RestartPolicy", "NetworkMode", "ReadonlyRootfs", "CapDrop", "SecurityOpt", "Memory", "NanoCpus", "PidsLimit", "ShmSize", "Init"}:
        fail("DEPLOYMENT_UNSAFE", "Unsupported privileged Docker host configuration.")
    env = {}
    for entry in config.get("Env", []):
        if not isinstance(entry, str) or "=" not in entry or "\x00" in entry:
            fail("DEPLOYMENT_UNSAFE", "Invalid environment setting.")
        key, value = entry.split("=", 1)
        if key in env:
            fail("DEPLOYMENT_UNSAFE", "Duplicate environment setting.")
        env[key] = value
    check_database(env)
    if env.get("ROCKET_PORT", "80") != "80" or env.get("ROCKET_ADDRESS", "0.0.0.0") not in ("0.0.0.0", "::"):
        fail("DEPLOYMENT_UNSAFE", "The supported health profile requires Vaultwarden on container port 80.")
    if host.get("NetworkMode") not in policy.value.get("allowed_networks", ["bridge"]):
        fail("DEPENDENCY_UNREADY", "Recovery network is not approved on the target.")
    if host.get("NetworkMode") in ("host", "none") or host.get("NetworkMode", "").startswith("container:"):
        fail("DEPLOYMENT_UNSAFE", "Host/shared network namespaces are unsupported.")
    docker.network(host.get("NetworkMode", "bridge"))
    if host.get("SecurityOpt", []) not in ([], ["no-new-privileges"], ["no-new-privileges:true"]):
        fail("DEPLOYMENT_UNSAFE", "Custom security profiles and disabled isolation are unsupported.")
    if any(cap != "ALL" for cap in host.get("CapDrop", [])):
        fail("DEPLOYMENT_UNSAFE", "Only the supported drop-all capability profile is allowed.")
    restart = host.get("RestartPolicy", {})
    if set(restart) - {"Name", "MaximumRetryCount"} or restart.get("Name", "no") not in ("no", "always", "unless-stopped", "on-failure"):
        fail("DEPLOYMENT_UNSAFE", "Unsupported restart policy.")
    ports = host.get("PortBindings") or {}
    normalized_ports(ports)
    expected_ports = policy.value.get("recovery_profile", {}).get("port_bindings", policy.value.get("port_bindings", {}))
    if ports != expected_ports and (for_restore or ports != policy.value.get("port_bindings", {})):
        fail("TARGET_CHANGED", "Recovery port bindings must match the enrolled target profile.")
    if for_restore:
        validate_public_network(docker, host["NetworkMode"], ports)
    recorded = descriptor["mounts"]
    expected = [{k: m[k] for k in ("type", "target", "read_only", "snapshot_path")} for m in policy.mounts]
    if sorted(recorded, key=lambda m: m["target"]) != sorted(expected, key=lambda m: m["target"]):
        fail("UNSUPPORTED_MOUNT", "Every snapshot mount requires an exact enrolled target mapping.")
    blocked = ("/", "/proc", "/sys", "/dev", "/etc", "/run", "/var/run", "/usr", "/bin", "/sbin")
    for mount in recorded:
        if mount["target"] in blocked or "docker.sock" in mount["target"]:
            fail("DEPLOYMENT_UNSAFE", "A mount overrides a privileged container boundary.")
    if imported:
        image = docker.image(image_id)
        if image["Id"] != image_id:
            fail("IMAGE_MISMATCH", "Loaded image does not match its saved immutable identity.")
        for key in ("Entrypoint", "Cmd"):
            if (config.get(key) or []) != (image["Config"].get(key) or []):
                fail("DEPLOYMENT_UNSAFE", "Custom entrypoint/command overrides are unsupported by this recovery profile.")
        current = platform.machine()
        arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(current, current)
        if image.get("Os") != "linux" or image.get("Architecture") != arch:
            fail("UNSUPPORTED_ARCHITECTURE", "The recorded image cannot run on this Linux host architecture.")
        if descriptor["platform"] != "linux/" + image["Architecture"]:
            fail("IMAGE_MISMATCH", "Recorded and loaded image platforms differ.")
        if set(image["Config"].get("Volumes") or {}) - {m["target"] for m in recorded}:
            fail("UNENROLLED_MOUNT", "Image-declared anonymous volumes require explicit enrolled persistent mounts.")


def paths_overlap(left, right):
    """Compare canonical paths and root/ancestor inode identities, including bind aliases."""
    try:
        a, b = Path(left).resolve(), Path(right).resolve()
        if a == b or a in b.parents or b in a.parents:
            return True
        def identity(path):
            try:
                item = path.stat()
                return item.st_dev, item.st_ino
            except FileNotFoundError:
                return None
        ai, bi = identity(a), identity(b)
        return (ai is not None and ai in {identity(p) for p in (b, *b.parents)}
                or bi is not None and bi in {identity(p) for p in (a, *a.parents)})
    except (OSError, RuntimeError):
        fail("UNKNOWN_WRITER", "Persistent peer storage cannot be resolved; inspect mount ownership locally.")


def reject_other_writers(docker, mounts, current=None, retained=()):
    for peer in docker.containers():
        if peer["Id"] == current:
            continue
        # Labels alone are not authority. Only root-journal-proven retained IDs qualify.
        if peer["Id"] in retained:
            found = docker.inspect(peer["Id"])
            if found["State"]["Running"] or found["HostConfig"].get("RestartPolicy", {}).get("Name", "no") != "no":
                fail("UNKNOWN_WRITER", "A preserved generation can still restart or write to protected data.")
            continue
        for item in peer.get("Mounts", []):
            if item.get("Type") == "tmpfs":
                continue
            source = item.get("Source")
            if not source and item.get("Type") == "volume" and item.get("Name"):
                source = docker.volume(item["Name"])["Mountpoint"]
            if not source or not Path(source).is_absolute():
                fail("UNKNOWN_WRITER", "A peer persistent mount has no verifiable host source.")
            if any(paths_overlap(source, mount["source"]) or
                   (item.get("Type") == "volume" and mount["type"] == "volume"
                    and item.get("Name") == mount["volume_name"]) for mount in mounts):
                fail("UNKNOWN_WRITER", "Another container overlaps protected storage; remove its access, including stopped peers.")


def discover(docker: Docker, policy, enrolled, active=None):
    info = docker.info()
    if info.get("ID") != policy.value["daemon_id"] or info.get("OSType") != "linux":
        fail("HOST_CHANGED", "Docker daemon identity or operating system differs from enrollment.")
    if Path("/etc/machine-id").read_text().strip() != policy.value["machine_id"]:
        fail("HOST_CHANGED", "Linux machine identity differs from enrollment.")
    cid = (active or {}).get("container_id", enrolled.container_id)
    mounts = (active or {}).get("mounts", enrolled.mounts)
    reject_other_writers(docker, mounts, cid, (active or {}).get("retained_container_ids", ()))
    if cid is None:
        for mount in enrolled.mounts:
            path = enrolled.mount_source(mount)
            if path.exists() and (not path.is_dir() or any(path.iterdir())):
                fail("TARGET_NOT_EMPTY", "Prepared alternate target contains unowned application data.")
        if docker.inspect(enrolled.value["container_name"], missing=True):
            fail("TARGET_CHANGED", "Prepared alternate target container name is already occupied.")
        return {"empty_target": True, "container_id": None, "source_state": "absent",
                "fingerprint": digest({"policy": enrolled.value, "daemon_id": info["ID"]}), "mounts": enrolled.mounts}
    container = docker.inspect(cid)
    if container["Id"] != cid:
        fail("TARGET_CHANGED", "Container identity differs from enrollment.")
    if container["State"].get("Paused") or container["State"].get("Restarting") or container["State"].get("Dead"):
        fail("SOURCE_UNREADY", "Container is paused, restarting, or dead.")
    host = container["HostConfig"]
    for setting in ("OomKillDisable", "OomScoreAdj", "CpuShares", "CpuPeriod", "CpuQuota", "CpuRealtimePeriod", "CpuRealtimeRuntime", "CpusetCpus", "CpusetMems", "BlkioWeight", "BlkioWeightDevice", "BlkioDeviceReadBps", "BlkioDeviceWriteBps", "BlkioDeviceReadIOps", "BlkioDeviceWriteIOps", "StorageOpt", "MaskedPathsCustom", "MemoryReservation", "MemorySwappiness", "MemorySwap", "CgroupParent", "VolumeDriver", "ContainerIDFile", "Privileged", "PublishAllPorts", "AutoRemove", "Devices", "DeviceRequests", "CapAdd", "VolumesFrom", "Links", "ExtraHosts", "GroupAdd", "Tmpfs", "Sysctls", "Dns", "DnsOptions", "DnsSearch", "Ulimits"):
        if host.get(setting):
            fail("DEPLOYMENT_UNSAFE", "Container uses an unsupported Docker privilege or dependency setting.")
    for setting in ("PidMode", "IpcMode", "UTSMode", "UsernsMode", "CgroupnsMode"):
        if host.get(setting) not in (None, "", "private"):
            fail("DEPLOYMENT_UNSAFE", "Shared/custom Docker namespaces are unsupported.")
    logging = host.get("LogConfig", {})
    if logging and (logging.get("Type") not in ("json-file", "local") or logging.get("Config")):
        fail("DEPLOYMENT_UNSAFE", "Custom or external Docker logging configuration is unsupported.")
    if container["Config"].get("Hostname") not in (None, "", cid[:12]) or container["Config"].get("Domainname"):
        fail("DEPLOYMENT_UNSAFE", "Custom container hostname/domain settings require an explicit supported profile.")
    if host.get("Runtime") not in (None, "", "runc"):
        fail("DEPLOYMENT_UNSAFE", "Only the standard Docker runtime is supported.")
    networks = container.get("NetworkSettings", {}).get("Networks", {})
    if len(networks) > 1:
        fail("UNSUPPORTED_DEPENDENCY", "Multiple attached Docker networks require an explicit supported recovery adapter.")
    for endpoint in networks.values():
        if endpoint.get("IPAMConfig") or endpoint.get("Links") or endpoint.get("DriverOpts"):
            fail("UNSUPPORTED_DEPENDENCY", "Static addressing, network links and driver options are unsupported.")
        aliases = endpoint.get("Aliases") or []
        automatic = {cid, cid[:12], container["Name"].lstrip("/")}
        if any(alias not in automatic for alias in aliases):
            fail("UNSUPPORTED_DEPENDENCY", "Custom network aliases require an explicitly enrolled recovery profile.")
    mounts = (active or {}).get("mounts", enrolled.mounts)
    actual = container["Mounts"]
    if len(actual) != len(mounts):
        fail("UNENROLLED_MOUNT", "Container persistent mounts differ from enrolled dependencies.")
    for wanted in mounts:
        matches = [m for m in actual if m["Destination"] == wanted["target"]]
        if len(matches) != 1:
            fail("UNENROLLED_MOUNT", "An enrolled mount is missing from the container.")
        found = matches[0]
        if found["Type"] != wanted["type"] or found["RW"] == wanted["read_only"]:
            fail("TARGET_CHANGED", "Mount type or access mode changed.")
        if found.get("Propagation", "") not in ("", "rprivate"):
            fail("UNSUPPORTED_MOUNT", "Shared mount propagation is unsupported.")
        if wanted["type"] == "volume":
            vol = docker.volume(wanted["volume_name"])
            if vol.get("Driver") != "local" or vol.get("Options") or vol.get("Scope") != "local":
                fail("UNSUPPORTED_VOLUME_DRIVER", "Only local Docker volumes without driver options are supported.")
            if found.get("Name") != wanted["volume_name"] or vol["Mountpoint"] != wanted["source"]:
                fail("TARGET_CHANGED", "Named volume identity changed.")
        if found["Source"] != wanted["source"]:
            fail("TARGET_CHANGED", "Persistent mount source changed.")
        no_symlink(Path(wanted["source"]))
    image = docker.image(container["Image"])
    config_keys = ("Env", "Entrypoint", "Cmd", "User", "WorkingDir", "Labels", "Healthcheck", "ExposedPorts", "StopSignal")
    config = {k: container["Config"][k] for k in config_keys if container["Config"].get(k) is not None}
    # Compose/auto-healer labels are preserved in evidence, never applied to recovery containers.
    labels = config.get("Labels", {}) or {}
    if any("autoheal" in key.lower() or "watchtower" in key.lower() for key in labels):
        fail("SOURCE_RESTART_CONFLICT", "An external auto-healer must be explicitly disabled through enrollment ownership.")
    validate_compose_dependencies(labels, enrolled)
    enrolled_files = set(enrolled.value.get("additional_files", {}).values())
    for file in labels.get("com.docker.compose.project.config_files", "").split(","):
        if file and file not in enrolled_files:
            fail("UNENROLLED_DEPENDENCY", "Enroll every original Compose document and referenced deployment file.")
    environment = dict(s.split("=", 1) for s in config.get("Env", []) if "=" in s)
    data = Path(next(m["source"] for m in mounts if m["snapshot_path"] == "data"))
    db_config = {}
    if (data / "config.json").exists():
        no_symlink(data / "config.json")
        with (data / "config.json").open("rb") as stream:
            db_config = decode(stream.read(1024 * 1024 + 1))
    check_database(environment, db_config)
    for key, value in environment.items():
        if key.endswith("_FILE") and value and not any(value == m["target"] or value.startswith(m["target"] + "/") for m in mounts):
            fail("UNENROLLED_DEPENDENCY", "A referenced secret/configuration file is outside approved mounts.")
    descriptor = {"schema_version": 1, "image_id": container["Image"],
                  "registry_digest": next(iter(image.get("RepoDigests") or []), None),
                  "platform": image["Os"] + "/" + image["Architecture"], "config": config,
                  "host_config": {k: ("bridge" if k == "NetworkMode" and host[k] == "default" else host[k]) for k in ("PortBindings", "RestartPolicy", "NetworkMode", "ReadonlyRootfs", "CapDrop", "SecurityOpt", "Memory", "NanoCpus", "PidsLimit", "ShmSize", "Init") if host.get(k) is not None},
                  "mounts": [{k: m[k] for k in ("type", "target", "read_only", "snapshot_path")} for m in mounts],
                  "dependencies": enrolled.value.get("dependency_inventory", [])}
    validate_descriptor(descriptor, enrolled, docker, imported=True, for_restore=False)
    return {"empty_target": False, "container_id": cid,
            "source_state": "running" if container["State"]["Running"] else "stopped",
            "descriptor": descriptor, "fingerprint": digest(descriptor), "mounts": mounts,
            "restart_policy": host.get("RestartPolicy", {"Name": "no"}), "name": container["Name"].lstrip("/")}


def create_config(descriptor, mounts, instance_id, operation_id, *, isolated):
    config = {k: v for k, v in descriptor["config"].items() if k != "Labels"}
    config["Image"] = descriptor["image_id"]
    config["Labels"] = {"org.vaultrewind.instance": instance_id, "org.vaultrewind.operation": operation_id,
                        "org.vaultrewind.role": "candidate" if isolated else "active"}
    host = dict(descriptor["host_config"])
    host["RestartPolicy"] = {"Name": "no", "MaximumRetryCount": 0}
    host["Mounts"] = [{"Type": m["type"], "Source": m["volume_name"] if m["type"] == "volume" else m["source"],
                       "Target": m["target"], "ReadOnly": m["read_only"],
                       **({"VolumeOptions": {"NoCopy": True}} if m["type"] == "volume" else {})} for m in mounts]
    if isolated:
        host["NetworkMode"] = "none"
        host["PortBindings"] = {}
        host["PublishAllPorts"] = False
    config["HostConfig"] = host
    return config
