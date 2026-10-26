"""Authenticated operator CLI; long work uses the same durable API as the browser."""
from __future__ import annotations

import getpass
import json
import os
import stat
from pathlib import Path
from typing import Annotated
from urllib.parse import urlparse

import httpx
import typer

app = typer.Typer(no_args_is_help=True, help="VaultRewind — one-click backup, one-click restore.")


def write_private(path: Path, value: bytes):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def read_private(path: Path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
            raise typer.BadParameter("Private session/plan files must be owned by you with mode 0600.")
        return stream.read()


def show(value):
    typer.echo(json.dumps(value, indent=2, default=str))


@app.callback()
def configure(ctx: typer.Context, url: Annotated[str, typer.Option(envvar="VAULTREWIND_URL")] = "https://localhost",
              session_file: Annotated[Path, typer.Option(envvar="VAULTREWIND_SESSION_FILE")] = Path("~/.config/vaultrewind/session.json")):
    parsed = urlparse(url)
    if (parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"})) or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise typer.BadParameter("Use an HTTPS controller origin, or loopback HTTP for development.")
    ctx.obj = {"url": url.rstrip("/"), "session_file": session_file.expanduser()}


def client(ctx):
    options = ctx.find_root().obj
    cookies = {}
    if options["session_file"].exists():
        cookies = json.loads(read_private(options["session_file"]))
    return httpx.Client(base_url=options["url"] + "/api/v1", cookies=cookies,
                        headers={"Origin": options["url"], "X-CSRF-Token": cookies.get("vr_csrf", "")},
                        timeout=30, follow_redirects=False)


def request(ctx, method, path, body=None, **headers):
    from uuid import uuid4
    try:
        with client(ctx) as connection:
            response = connection.request(method, path, json=body,
                headers={"Idempotency-Key": str(uuid4()), **headers})
        data = response.json() if response.content else {}
        if response.is_error:
            error = data.get("error", {})
            typer.echo(f"{error.get('code', 'REQUEST_FAILED')}: {error.get('message', 'Controller request failed.')}", err=True)
            raise typer.Exit(1)
        return data
    except httpx.HTTPError:
        typer.echo("CONTROLLER_UNAVAILABLE: Check the controller URL and its TLS/network readiness.", err=True)
        raise typer.Exit(1) from None


@app.command()
def login(ctx: typer.Context, username: str):
    """Sign in privately; no password is accepted as a process argument."""
    password = getpass.getpass("Controller password: ")
    with client(ctx) as connection:
        response = connection.post("/sessions", json={"username": username, "password": password})
        if response.is_error:
            typer.echo("LOGIN_FAILED: Check credentials and controller origin.", err=True)
            raise typer.Exit(1)
        write_private(ctx.obj["session_file"], json.dumps(dict(connection.cookies)).encode())
    typer.echo("Signed in. Session stored in your private configuration directory.")


@app.command()
def logout(ctx: typer.Context):
    request(ctx, "DELETE", "/sessions/current")
    ctx.obj["session_file"].unlink(missing_ok=True)
    typer.echo("Session revoked.")


@app.command()
def backup(ctx: typer.Context, instance_id: str):
    """Queue a complete backup; source recovery and storage commit run in the worker."""
    show(request(ctx, "POST", f"/instances/{instance_id}/backups", {}))


@app.command()
def snapshots(ctx: typer.Context, instance_id: str, limit: int = 50, offset: int = 0):
    show(request(ctx, "GET", f"/instances/{instance_id}/snapshots?limit={limit}&offset={offset}"))


@app.command("restore-plan")
def restore_plan(ctx: typer.Context, snapshot_id: str, target_id: str | None = None,
                 output: Path = Path("restore-plan.private.json"), start_on_completion: bool = False):
    plan = request(ctx, "POST", f"/snapshots/{snapshot_id}/restore-plans",
                   {"target_id": target_id, "start_on_completion": start_on_completion})
    write_private(output, json.dumps(plan).encode())
    show({k: v for k, v in plan.items() if k != "confirmation_token"})
    typer.echo(f"Single-use confirmation saved privately in {output}.")


@app.command()
def restore(ctx: typer.Context, plan_file: Path = Path("restore-plan.private.json"), yes: bool = False):
    plan = json.loads(read_private(plan_file))
    if not yes and not typer.confirm(f"Restore snapshot {plan['snapshot_id']} to target {plan['target_id']}? Later target changes will be replaced"):
        raise typer.Abort()
    result = request(ctx, "POST", f"/restore-plans/{plan['id']}/execute", {"confirmation_token": plan["confirmation_token"]})
    plan_file.unlink()
    show(result)


@app.command()
def verify(ctx: typer.Context, snapshot_id: str, level: str = "full_data", runner_id: str | None = None):
    if level not in {"full_data", "restore", "application"}:
        raise typer.BadParameter("Choose full_data, restore or application.")
    show(request(ctx, "POST", f"/snapshots/{snapshot_id}/verify", {"level": level, "runner_id": runner_id}))


@app.command()
def jobs(ctx: typer.Context, job_id: str | None = None, after: int = 0, events: bool = False):
    path = f"/jobs/{job_id}/events?after={after}" if events and job_id else f"/jobs/{job_id}" if job_id else "/jobs"
    show(request(ctx, "GET", path))


@app.command("retention-preview")
def retention_preview(ctx: typer.Context, instance_id: str):
    show(request(ctx, "POST", f"/instances/{instance_id}/retention-preview", {}))


@app.command("recovery-export")
def recovery_export(ctx: typer.Context):
    phrase = getpass.getpass("Independent recovery passphrase (16+ characters): ")
    if phrase != getpass.getpass("Confirm recovery passphrase: "):
        raise typer.BadParameter("Passphrases differ.")
    show(request(ctx, "POST", "/recovery-kits/export", {"passphrase": phrase}))
    typer.echo("When the job completes, download its administrator-only artifact. Keep the kit and passphrase outside both applications.")


@app.command("recovery-import")
def recovery_import(ctx: typer.Context, kit: Path):
    phrase = getpass.getpass("Independent recovery passphrase: ")
    show(request(ctx, "POST", "/recovery/import-plans", {"kit": kit.read_text(), "passphrase": phrase}))


@app.command()
def doctor(ctx: typer.Context, probe: bool = False):
    """Read catalog diagnostics; --probe explicitly permits repository writes/credential refresh."""
    show(request(ctx, "POST" if probe else "GET", "/doctor", {} if probe else None))


@app.command("artifact")
def artifact(ctx: typer.Context, job_id: str, output: Path):
    with client(ctx) as connection:
        response = connection.get(f"/jobs/{job_id}/artifact")
        if response.is_error:
            raise typer.BadParameter("Artifact unavailable, expired, or not authorized.")
        write_private(output, response.content)
    typer.echo(f"Encrypted artifact saved privately to {output}.")


@app.command("offline", context_settings={"allow_extra_args": True, "ignore_unknown_options": True,
                                          "help_option_names": []})
def offline_recovery(ctx: typer.Context):
    """Independent recovery; invoke with --help for discover/restore/plan/import-plan."""
    from .recovery.cli import main
    raise typer.Exit(main(ctx.args))


if __name__ == "__main__":
    app()
