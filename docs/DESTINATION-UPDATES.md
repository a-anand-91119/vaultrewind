# Edit storage access without losing recovery points

An administrator can open **Edit destination** in Storage to rename a destination,
edit its supported configuration, or replace private provider credentials. Saving
updates encrypted controller state without contacting the provider. **Test saved
connection** queues the existing scoped write/read/delete probe; Google Drive may
refresh and persist its token during that job.

For an expired or incorrect S3 key pair, select **Replace private S3 key pair**,
enter both the new access key ID and secret access key, and save. A session token
is optional; leaving it blank with a new pair removes the previous session token.
Leaving both replacement fields blank keeps the current pair. A partial pair or
session-token-only update is rejected. Stored keys and tokens are never populated
back into the form. Credentials stay in component memory only and clear after
saving, reloading, or closing the editor.

For Google Drive, replace both OAuth client values together. Saving creates a new
encrypted credential generation with a new grant identifier, an empty token, and
local revocation markers. The destination reports `reauthorization_required`.
Reconnect using **Reconnect saved Google Drive client**, complete consent, and
then test the saved connection. Existing browser authorization states are consumed
when the client changes. The existing OAuth worker later finalizes a fresh grant.
No Google revocation call is made by an edit. A client rotation can require
provider-side access to the existing folder; it never silently switches folders.

After repairing access, retry the failed copy from the snapshot. The worker reads
credentials through the unchanged destination ID, and the retry uses the same
logical snapshot and repository. Available immutable staging or an equivalent
complete copy is required by the existing retry service. No additional source
pause is needed. Saving or testing credentials alone does not retry a copy.

Export a current encrypted recovery kit after changing storage access, especially
after reconnecting Drive. Keep the kit and its passphrase outside Vaultwarden and
VaultRewind. An older kit can contain expired provider credentials even though its
repository encryption keys still unlock historical snapshots.

## Configuration and identity

The editor exposes local directory/displayed host directory, free-space reserve,
mount/filesystem policy; S3 endpoint, bucket, prefix, region, addressing, local
development HTTP and custom CA replacement; or Drive folder ID/display name and
the fixed `drive.file` scope. Custom CA contents are private: inspection returns
only `custom_ca: true/false`. A replacement PEM bundle is validated as certificates
without private keys. Keeping the existing CA requires no PEM round trip.

Once any repository exists, its local path, S3 endpoint/bucket/prefix, or Drive
folder/scope cannot change. Every existing repository is checked against both
`providers.repository_location` and `providers.physical_identity`, including
controller repositories with a nullable instance ID. The controller identity
comes from repository-private metadata or the current `ControllerState`.
Repository IDs, physical identities, locations, encryption-key references and
snapshot history remain unchanged. To change physical storage, create a new
destination and retain the old one for existing copies. Migration is a separate
operation.

No operational update accepts `recovery_mode`, tokens, arbitrary JSON settings,
backend changes or unknown fields. Local path changes before repository creation
must stay within the configured persistent backup root. Runtime filesystem and
provider checks remain in queued connection tests and worker preflight.

## Integration contract

ROOT owns route/schema wiring in `app.py` and `schemas.py`, and the administrator
insertion in `main.tsx`. The implementation module exports:

```python
destination_view(db, store, ident) -> dict
update_destination(db, store, settings, ident, changes, revision, actor_id) -> dict
```

Both use the caller's transaction. Apply administrator authorization to both
routes, the existing CSRF dependency to PATCH, and the existing safe error handler.

* `GET /api/v1/storage-destinations/{id}` returns safe detail. Set
  `ETag: "<revision>"` from its integer `revision`.
* `PATCH /api/v1/storage-destinations/{id}` requires `If-Match: "<revision>"`
  and an object with optional `name`, `configuration` and `credentials` objects.
  Configuration is a partial merge; credentials require a complete replacement
  pair when any nonblank replacement is supplied. Pass a dictionary containing
  only explicitly supplied fields (for Pydantic, `model_dump(exclude_unset=True)`).
  Return the safe detail and its new ETag.

The response includes `id`, `name`, `backend`, `revision`, `health`, `last_test_at`,
`quota_bytes`, the provider-specific `configuration`, `credentials_configured`,
`credential_flags`, `repository_count`, `physical_identity_locked`, and
`recovery_kit_reminder`. Credential flags are booleans only. S3 uses
`access_key_id`, `secret_access_key`, `session_token`; Drive uses `client_id`,
`client_secret`, `authorized`. No access key, secret, client ID, client secret,
OAuth token, grant identifier, secret-row ID or CA contents appear in a response.
GET uses `Secrets.get(..., upgrade=False)` to avoid legacy-envelope writes.

PATCH locks `credential:<id>` before the destination row. Any owned resource
lease, including an expired lease awaiting reconciliation, produces
`RESOURCE_BUSY`. Queued jobs may subsequently use the new generation. A stale
revision produces `REVISION_CONFLICT`. An attempted physical move produces
`DESTINATION_IDENTITY_CHANGED`; an unverifiable controller owner produces
`REPOSITORY_IDENTITY_MISMATCH`. Configure safe user-facing messages for these
identity errors in ROOT's API error mapping. Schema validation must not echo
private request values.

Credential replacement uses `Secrets.put` and switches `credential_id` to a new
row. It never resets a revision on the same row. Existing generation-aware SQL
CAS and durable pending-refresh reconciliation reject the previous generation.
No provider calls or filesystem writes occur in the update service. Audit changes
contain field names and the new revision only. Credential/configuration changes
clear prior test evidence and set health to `untested`; a Drive client replacement
sets `reauthorization_required`.

Render `<DestinationEditor destination={row} onSaved={reloadStorage} />` for
administrators only. The component loads safe detail when opened and provides
visible fields, masked credential inputs, revision-protected save, explicit CA
keep/replace/remove, queued testing and Drive reconnect actions.

## Verification

`pytest -q tests/unit/test_destination_updates.py` uses disposable in-memory
SQLite, synthetic credentials, and the real encrypted SQL credential store. It
covers credential generations, stale CAS rejection, safe reads, blank-field
retention, partial-pair rejection, revision conflicts, owned/expired leases,
operational-setting rejection, configuration edits and repository identity
protection for instance and controller repositories. `npm run build` in
`frontend` typechecks and builds the component.

The AC18 MinIO/real-worker proof belongs to ROOT: use a valid endpoint and bad
synthetic keys, capture once with a valid local copy plus failed S3 copy, PATCH
only the keys on the existing destination, test, and retry that failed copy.
Verify the same snapshot/repository IDs and no second source pause. This module's
unit tests do not claim that live-provider or source lifecycle evidence.
