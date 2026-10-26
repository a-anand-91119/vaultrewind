"""Encrypted controller secrets with a versioned row binding.

Every envelope is produced by ``vaultrewind.security.secrets.SecretBox`` (AES-256-GCM, versioned ``vr1``
text format). The server additionally binds each envelope to its own row through the authenticated
``context`` ``"<kind>:<owner_scope>:<id>"`` so a ciphertext copied to another row fails authentication.

``Secret.binding`` records which binding a row was written with:

* ``row`` — written by this code; decrypted only with the row context. No fallback exists.
* ``unverified`` — the database default. It marks rows that were inserted before row binding existed or
  by an older process during a rolling upgrade. Such a row is read with the row context first; only when
  that fails authentication and ``Settings.accept_legacy_secret_envelopes`` is enabled is the historical
  context-less decryption tried. A legacy row that decrypts is upgraded in place to ``row`` (re-encrypted
  with the row context, revision incremented). ``migrate_bindings`` performs that upgrade explicitly for
  the whole table and reports exact counts; ``doctor`` reports rows that still await it.
"""
from sqlalchemy import func, select

from vaultrewind.core.errors import VaultRewindError

from .db import now, uid
from .models import Secret
from .settings import read_private_file

ROW = "row"
UNVERIFIED = "unverified"


def row_context(kind: str, owner_scope: str, ident: str) -> str:
    return f"{kind}:{owner_scope}:{ident}"


class Secrets:
    def __init__(self, settings):
        self.settings = settings
        self._box = None
        self._key_mtime = None

    def box(self):
        import os

        from vaultrewind.security.secrets import SecretBox
        try:
            mtime = os.stat(self.settings.master_key_file).st_mtime_ns
        except OSError:
            mtime = None
        if self._box is None or mtime != self._key_mtime:
            self._box = SecretBox(read_private_file(self.settings.master_key_file, length=32))
            self._key_mtime = mtime
        return self._box

    def put(self, db, kind, scope, value):
        ident = uid()
        row = Secret(id=ident, kind=kind, owner_scope=scope, binding=ROW,
                     envelope=self.box().encrypt(value, context=row_context(kind, scope, ident)))
        db.add(row)
        db.flush()
        return row.id

    def _decrypt(self, row):
        """Return (value, legacy) following the row's recorded binding version."""
        box = self.box()
        context = row_context(row.kind, row.owner_scope, row.id)
        try:
            return box.decrypt(row.envelope, context=context), False
        except VaultRewindError as exc:
            if exc.code != "SECRET_DECRYPT_FAILED" or row.binding != UNVERIFIED:
                raise
            if not getattr(self.settings, "accept_legacy_secret_envelopes", True):
                raise VaultRewindError("SECRET_BINDING_UNVERIFIED",
                                       "A stored secret predates row binding; run the secret binding migration.") from None
            # Historical envelopes (no binding context). Only reachable for rows explicitly marked unverified.
            return box.decrypt(row.envelope, context=None), True

    def get(self, db, secret_id, *, upgrade=True):
        row = db.get(Secret, secret_id)
        if row is None:
            raise VaultRewindError("SECRET_UNAVAILABLE", "A required private credential is unavailable.")
        value, legacy = self._decrypt(row)
        if legacy and upgrade:
            # Converge to row binding; the write is committed only if the caller's transaction commits.
            row.envelope = self.box().encrypt(value, context=row_context(row.kind, row.owner_scope, row.id))
            row.binding, row.revision, row.rotated_at = ROW, row.revision + 1, now()
        elif row.binding == UNVERIFIED and upgrade:
            # Proven row-bound: record the verified binding version without touching the ciphertext.
            row.binding = ROW
        return value

    def replace(self, db, secret_id, value):
        row = db.scalar(select(Secret).where(Secret.id == secret_id).with_for_update())
        if row is None:
            raise VaultRewindError("SECRET_UNAVAILABLE", "A required private credential is unavailable.")
        row.envelope = self.box().encrypt(value, context=row_context(row.kind, row.owner_scope, row.id))
        row.binding = ROW
        row.revision += 1
        row.rotated_at = now()

    def unverified_count(self, db) -> int:
        return int(db.scalar(select(func.count()).select_from(Secret).where(Secret.binding == UNVERIFIED)) or 0)

    def migrate_bindings(self, db, *, apply: bool, limit: int = 10000) -> dict:
        """Explicit binding migration. Never changes rows already recorded as row-bound.

        Returns exact counts: ``row_bound`` (unverified rows proven row-bound), ``legacy_upgraded`` (rows that
        only decrypted without a context and were re-encrypted with row binding), ``undecryptable`` (rows this
        master key cannot open with either binding; left untouched and listed by ID for review).
        """
        from vaultrewind.security.secrets import SecretBox
        counts = {"examined": 0, "row_bound": 0, "legacy_upgraded": 0, "undecryptable": 0, "applied": bool(apply),
                  "undecryptable_ids": [], "key_unavailable": 0}
        box: SecretBox = self.box()
        query = select(Secret).where(Secret.binding == UNVERIFIED).order_by(Secret.created_at).limit(limit)
        if apply:
            query = query.with_for_update(skip_locked=True)
        for row in db.scalars(query):
            counts["examined"] += 1
            context = row_context(row.kind, row.owner_scope, row.id)
            try:
                box.decrypt(row.envelope, context=context)
                counts["row_bound"] += 1
                if apply:
                    row.binding = ROW
                continue
            except VaultRewindError as exc:
                if exc.code == "SECRET_KEY_UNAVAILABLE":
                    counts["key_unavailable"] += 1
                    continue
                if exc.code != "SECRET_DECRYPT_FAILED":
                    raise
            try:
                value = box.decrypt(row.envelope, context=None)
            except VaultRewindError:
                counts["undecryptable"] += 1
                counts["undecryptable_ids"].append(row.id)
                continue
            counts["legacy_upgraded"] += 1
            if apply:
                row.envelope = box.encrypt(value, context=context)
                row.binding, row.revision, row.rotated_at = ROW, row.revision + 1, now()
        counts["remaining_unverified"] = (self.unverified_count(db) - (counts["row_bound"] + counts["legacy_upgraded"]
                                          if not apply else 0))
        if apply:
            db.flush()
            counts["remaining_unverified"] = self.unverified_count(db)
        return counts
