"""Explicit operator maintenance commands that run against the controller database.

Usage (inside the controller environment, with the normal VAULTREWIND_* settings):

    python -m vaultrewind.server.maintenance secret-bindings            # report only
    python -m vaultrewind.server.maintenance secret-bindings --apply    # upgrade legacy envelopes
    python -m vaultrewind.server.maintenance controller-id              # print/create the controller identity

Nothing here prints secrets, envelopes or connection strings.
"""
from __future__ import annotations

import argparse
import json
import sys

from .db import make_engine, sessions
from .secrets import Secrets
from .settings import Settings


def _report(value: dict) -> None:
    sys.stdout.write(json.dumps(value, sort_keys=True) + "\n")


def secret_bindings(settings: Settings, apply: bool) -> dict:
    engine = make_engine(settings.database_url)
    try:
        factory = sessions(engine)
        store = Secrets(settings)
        with factory.begin() as db:
            result = store.migrate_bindings(db, apply=apply)
            if apply:
                from .queue import audit
                audit(db, None, "secret.binding_migration", "controller", "succeeded",
                      changes={k: v for k, v in result.items() if k != "undecryptable_ids"})
        return result
    finally:
        engine.dispose()


def controller_identity(settings: Settings) -> dict:
    from .services import controller_id
    engine = make_engine(settings.database_url)
    try:
        with sessions(engine).begin() as db:
            return {"controller_id": controller_id(db)}
    finally:
        engine.dispose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vaultrewind-maintenance", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    bindings = sub.add_parser("secret-bindings", help="Verify or upgrade stored secret envelope bindings.")
    bindings.add_argument("--apply", action="store_true", help="Upgrade legacy envelopes; default reports only.")
    sub.add_parser("controller-id", help="Print the stable controller identity, creating it if absent.")
    args = parser.parse_args(argv)
    settings = Settings()
    if args.command == "secret-bindings":
        result = secret_bindings(settings, args.apply)
        _report(result)
        return 0 if not result["undecryptable"] and not result["key_unavailable"] else 2
    _report(controller_identity(settings))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
