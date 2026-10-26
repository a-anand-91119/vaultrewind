"""Independent systemd recovery; armed before any stop or generation switch."""
from __future__ import annotations

import os
import signal
import subprocess
import time
from pathlib import Path

from vaultrewind.core.errors import VaultRewindError

from .journal import Journal
from .protocol import fail

BOOT_ID = Path("/proc/sys/kernel/random/boot_id")


def process_identity(pid=None):
    pid = pid or os.getpid()
    try:
        # comm may contain spaces and parentheses; fields after final ')' start at field 3.
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return {"pid": pid, "start_ticks": fields[19], "boot_id": BOOT_ID.read_text().strip()}
    except (OSError, IndexError):
        return None


def same_process(owner):
    return bool(owner and process_identity(owner["pid"]) == owner)


class SystemdRecovery:
    @staticmethod
    def _run(args, *, check=True):
        try:
            result = subprocess.run(["/usr/bin/systemctl", *args], capture_output=True,
                                    timeout=15, check=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"})
        except (OSError, subprocess.TimeoutExpired):
            fail("WATCHDOG_UNAVAILABLE", "systemd recovery could not be contacted; no downtime is permitted.")
        if check and result.returncode:
            fail("WATCHDOG_UNAVAILABLE", "Install and enable the VaultRewind recovery units before any downtime.")
        return result

    def verify(self):
        if not Path("/run/systemd/system").is_dir():
            fail("WATCHDOG_UNAVAILABLE", "Release one requires a systemd-capable Linux recovery host.")
        self._run(["is-enabled", "vaultrewind-reconcile.service"])
        for name in ("vaultrewind-watchdog@00000000-0000-4000-8000-000000000000.service",
                     "vaultrewind-reconcile.service"):
            result = self._run(["show", name, "--property=LoadState", "--value"])
            if result.stdout.strip() != b"loaded":
                fail("WATCHDOG_UNAVAILABLE", "The installed recovery unit cannot be loaded.")
        result = self._run(["show", "vaultrewind-watchdog@00000000-0000-4000-8000-000000000000.service",
                            "--property=Requires", "--property=Requisite", "--property=BindsTo", "--property=PartOf", "--value"])
        if {b"docker.service", b"docker.socket"} & set(result.stdout.split()):
            fail("WATCHDOG_UNAVAILABLE", "The watchdog must remain active when Docker stops; install the independent recovery unit.")

    def arm(self, journal: Journal, seconds: int):
        self.verify()
        journal.value.update({"deadline": time.time() + seconds,
                              "monotonic_deadline": time.monotonic() + seconds,
                              "boot_id": BOOT_ID.read_text().strip(), "watchdog_armed": True,
                              "owner": process_identity()})
        journal.save()
        self.resume(journal)

    def resume(self, journal: Journal):
        """Reactivate durable recovery after boot without resetting deadlines/owner."""
        unit = f"vaultrewind-watchdog@{journal.value['operation_id']}.service"
        self._run(["start", unit])
        self._run(["is-active", "--quiet", unit])

    def disarm(self, journal: Journal):
        journal.value["watchdog_armed"] = False
        journal.save()
        self._run(["stop", "--no-block", f"vaultrewind-watchdog@{journal.value['operation_id']}.service"], check=False)


def expired(value):
    return (value.get("boot_id") != BOOT_ID.read_text().strip()
            or time.time() >= value.get("deadline", 0)
            or time.monotonic() >= value.get("monotonic_deadline", 0))


def watchdog_loop(service, operation_id):
    retry_delay = 2
    while True:
        journal = Journal(service.root, operation_id)
        if not journal.value or not journal.value.get("watchdog_armed"):
            return
        cancelled = (service.root / "cancel" / operation_id).exists()
        if expired(journal.value) or cancelled:
            owner = journal.value.get("owner")
            if same_process(owner) and owner["pid"] != os.getpid():
                os.kill(owner["pid"], signal.SIGTERM)
                for _ in range(30):
                    if not same_process(owner):
                        break
                    time.sleep(0.1)
                if same_process(owner):
                    os.kill(owner["pid"], signal.SIGKILL)
            try:
                service.recover(operation_id, reason="cancelled" if cancelled else "deadline")
            except VaultRewindError:
                # Busy locks and unavailable infrastructure are unresolved recovery,
                # not permission to exit successfully with an armed journal.
                pass
            journal = Journal(service.root, operation_id)
            if not journal.value or not journal.value.get("watchdog_armed"):
                return
            # Keep the original expired deadline and truthful failure state. Docker
            # may remain down arbitrarily long; retry until recovery actually disarms.
            time.sleep(retry_delay)
            retry_delay = min(30, retry_delay * 2)
            continue
        time.sleep(0.5)
