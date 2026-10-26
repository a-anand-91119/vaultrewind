# VaultRewind UI flow map

The frontend is a same-origin React 19 and TypeScript application. It calls the persisted `/api/v1` API in `src/api.ts`; it does not fabricate operation success or use API mocks. Mutating requests carry the CSRF token and a stable in-memory idempotency key. Secrets are submitted in request bodies, not URLs or browser storage.

## Flow map

| User flow | UI path | API evidence |
| --- | --- | --- |
| Sign in and fleet health | Sign in → Instances | `GET /sessions/current`, `POST /sessions`, `GET /instances`; source health and backup health remain separate. Fleet loading and API errors are shown as received. |
| Host onboarding | Hosts → Connect host → Discover → select instance → approve explicit dependency files, target URL overlay and budgets → review activation plan → activate/enroll | `POST /hosts`, `POST /hosts/{id}/discover`, `GET /jobs/{id}/enrollment`, `POST /hosts/{id}/activation-plans`, `POST /hosts/{id}/activate`, followed by evidence-based discovery and `POST /instances`. Discovery is read-only. Additional Compose, environment and secret files are only captured when named as `NAME=/absolute/path`; the form does not crawl unrelated directories. |
| One-click backup | Instance → Backup now → inspect persisted job and reload/reopen | `POST /instances/{id}/backups`, `GET /jobs/{id}`, `GET /jobs/{id}/events`. Job status is durable and survives browser reload. |
| Reconcile an uncertain operation | Activity → open a `needs_attention` or `rollback_failed` operation → Reconcile operation | `POST /jobs/{id}/reconcile` with `{}` requeues the same operation. The UI explains that the worker reads the durable remote journal, preserves leases until remote proof, and performs no automatic rollback after possible activation. The control appears only for administrators and those two states. |
| Snapshot trust and copies | Instance → Dated snapshots | `GET /instances/{id}/snapshots`; show capture time, logical/stored bytes, copy states/errors, copy verification/data-read timestamps, pinned/safety state and immutable saved image ID. The snapshot endpoint currently returns restore evidence as booleans without its run timestamp, so the UI says the timestamp is not returned instead of inventing one. |
| Original or alternate restore | Snapshot → Restore → choose exact complete storage copy and ready target → inspect exact point/maintenance plan → confirm once | `POST /snapshots/{id}/restore-plans` with `copy_id`, `target_id`, and `start_on_completion`; then `POST /restore-plans/{id}/execute` with the bound confirmation token. Existing target is preselected for the default restore. Only ready enrolled instances are selectable. The API owns safety capture, switching, rollback boundary and activation. |
| Pin and deletion | Snapshot → More actions → Pin/Unpin, or Preview deletion → review exact eligible copy IDs → confirm | `POST`/`DELETE /snapshots/{id}/pin`; `POST /snapshots/{id}/deletion-plans`; `POST /deletion-plans/{id}/execute`. Deletion is a server-calculated exact-ID plan, with protections rechecked by the API. A protected snapshot returns its real API error. |
| Schedule and retention | Instance → Manage policy → schedule, timezone, retention, destinations and runner → preview → save with revision guard | `GET/PATCH /instances/{id}/policy`, `POST /instances/{id}/retention-preview`, `POST /instances/{id}/schedule-preview`. Preview rows show cutoff, planned expiry, eligibility and protections. Current UI sends the unsaved proposed `retention_days`/forever value for the dry run; the server contract must accept that hypothetical input before this can be used as a confirmed pre-apply preview. |
| Storage | Storage → add local, S3-compatible, or Drive destination → explicit connection test | `POST /storage-destinations`, `POST /storage-destinations/{id}/test`. Local mount path/free space, S3 endpoint/bucket/prefix/CA state, and Drive folder identity/authorization expiry display only sanitized API details. S3 prefix defaults empty because the adapter adds `vaultrewind/`; addressing offers auto/path/DNS, and custom CA is an explicit PEM field. |
| Google Drive | Storage → Authorize/reconnect, or Headless token import | Browser authorization uses `POST /storage-destinations/{id}/authorize` and the clean `authorization_job` callback to reopen persisted job progress. Headless import sends parsed token JSON only in the POST body. The form masks pasted JSON visually, does not write it to local/session storage, and drops it when closed. |
| Alerts and notifications | Storage → Alerts & delivery; Settings → configure SMTP or webhook | `GET /notifications`, `POST /notification-channels`. SMTP controller host/from come from controller environment; recipients and optional credentials are encrypted channel input. Alert state and each delivery state/error display separately from backup validity. |
| Access | Settings → create viewer/admin or revoke sessions for an explicit user ID | `POST /users`, `POST /sessions/revoke`. Viewer access remains read-only in the UI and the API remains the authorization authority. |
| Recovery and diagnosis | Recovery kit, Integrity & readiness, Audit trail | Recovery-kit/import jobs, `GET /doctor`, `POST /doctor`, and `GET /audit-events`. Diagnostics disclose that the explicit run may write scoped probes or refresh credentials. |

## Honest status and safety behavior

- Loading and API failures are rendered from the real request state; a stale or unavailable API response is not replaced with synthetic healthy data.
- Job progress uses persisted named phases and states. Unknown-duration work does not receive a guessed percentage.
- Partial/failed copies remain distinct from a valid complete copy. Copy errors show the API error code and a useful destination-access/retry next step.
- Source recovery, content commit, required-copy outcome and target activation are not collapsed into one green state.
- Restore confirmation is bound by the server to the selected capture, copy, target and policy revision. UI confirmation cannot override a backend safety refusal.
- The callback query contains only the opaque job ID; it is removed from the visible URL after the page reads it. Authorization codes/tokens are not retained in the UI.
- Dialogs use native modal focus handling, labels, keyboard dismissal and mobile layouts. Status includes text in addition to color.

## Browser evidence

`frontend/e2e/workflows.spec.ts` uses the local native API and the private synthetic SSH fixture at `.runtime/controller/integration.json`; it has no mocked API routes. Coverage includes the first post-login fleet `GET` response, host-enrollment dialog labels and focus return, narrow-screen navigation, a real backup with reload/reconnect, original-target confirmation and safety snapshot, real pin/unpin and retention preview, protected-deletion errors, and prepared alternate restore when the integration fixture includes its target ID/name.

Tests skip only when the explicit disposable host fixture is absent, or when the fixture has not enrolled the separately prepared alternate target. These are external integration prerequisites, not passing assertions. The parent integration owner runs the complete workflow suite after the native server/runtime fix; this frontend task has not represented an unrun browser suite as passed.

`npm run build --prefix frontend` passes after the UI changes. This compiles TypeScript and produces Vite output in `frontend/dist`; it does not verify live API or SSH workflows.

## Server integration items

1. `POST /instances/{id}/retention-preview` currently documents/implements an empty request. To preview an unsaved policy safely, accept `retention_days: 1..3650 | null` as a hypothetical input and calculate exact cutoff/copy IDs/protections without mutating policy or queueing deletion. Keep the saved policy revision in the response so the preview can be invalidated if it changes.
2. Copy retry without another source pause needs a dedicated API/job contract. Until that exists, the UI reports a failed copy and preserves other complete copies; it does not pretend a backup retry is a copy retry.
3. External Drive authorization and refresh still require the dedicated real Google account workflow. The UI supports both authorization entry paths but does not claim the live provider integration is release-verified.
4. Delivery failures are displayed from notification delivery rows. SMTP configuration must include `recipients` and may include `username`/`password`; host and sender remain controller environment settings.
5. The server now exposes `POST /jobs/{id}/reconcile` for recoverable operations (`backup`, `restore`, `verify`) in `needs_attention`, `rollback_failed`, or `waiting_retry`. Keep `docs/API-CONTRACT.md` synchronized with its request/response and state semantics; the frontend exposes the action only for administrator-visible `needs_attention` and `rollback_failed` states.

