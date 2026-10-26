# Remote storage accounting and administrator cleanup

VaultRewind shows source-host temporary storage separately from encrypted snapshot repositories. Open an instance's **Remote storage and cleanup** panel and select **Refresh remote usage** as an administrator. Refresh creates a durable queued inspection job; closing the page does not cancel it. Viewers can read cached inventory and job progress but cannot request refresh or cleanup.

The panel reports the following measurements:

- Source staging and saved-image cache bytes, their combined usage, and the enrolled host staging quota. These are **shared host totals**, including other enrolled instances using that helper staging root.
- Each historical restore's restored-generation and preserved rollback-generation logical bytes, rollback cleanup deadline, staging cleanup state, and unused-candidate disposal outcome. Logical bytes describe content size rather than allocated filesystem blocks; historical counts remain visible after cleanup, alongside their retired/removed state.
- Persisted maintenance job state, phase, error code and job ID. Inventory has a UTC sampling timestamp and remains explicitly cached until a refresh completes.

The newest 500 historical backup/restore operations are inspected per inventory. The panel flags a truncated list; shared host staging counters still include older operations. Missing journals or accounting fields produce an explicit accounting error and unknown values, never invented zero-byte measurements. Protocol 1 helpers must support `source_staging_bytes` and `image_cache_bytes`; a protocol number alone does not prove that capability.

If helper preflight reports full staging or insufficient space before returning counters, the job records a partial inventory with `accounting_error` and unknown counters. Journal-verified cleanup actions remain available, so low space does not hide the controls needed to recover. Refresh again after reclamation. Other inspection failures remain visible as failed jobs; an earlier successful cache keeps its original timestamp.

## Deliberate cleanup

An administrator selects an eligible action on a historical operation, reviews the inline explanation and confirms cleanup. Cleanup is queued and takes the same physical host/data leases as normal source work. It waits while another job owns those resources. It never acquires a repository deletion capability or invokes restic deletion.

- **Remove staging** deletes only a terminal or safely recovered operation's helper staging. Active operations, unresolved activation and failed rollback are blocked. Do not remove staging needed for a failed-copy retry unless an equivalent complete copy is available; the normal retry API reports when its immutable input is unavailable.
- **Retire rollback generation** applies only to a successful completed restore after its root-owned grace deadline. The proposed/default grace is seven days, configurable in the reviewed helper policy. The helper verifies durable safety evidence, current active-generation ownership, and that the old container cannot write before deleting the preserved original generation. The active generation and new client writes are preserved.
- **Discard unused candidate** applies only to a restore recovered as `rolled_back`, `failed_safe` or `cancelled` before activation. The helper verifies positive resource ownership, isolation, restored-original identity and disposal progress. A changed or ambiguous candidate is preserved for repair. Historical protocol 1 journals may omit `activation_started` in these verified pre-activation phases; explicit null, true or any other unknown value is rejected.

Safety snapshots remain separately pinned in encrypted repositories and follow snapshot protection controls. They are not rollback generations. Saved image caches remain visible and retained for exact-image recovery; these endpoints do not expose image deletion, host path selection, arbitrary operation IDs, shell commands, volume names or repository IDs.

After cleanup, the worker resamples usage; it never estimates reclaimed bytes by subtracting historical logical counts. The helper journals partial disposal, allowing an explicit retry to verify and continue the same operation safely. If final accounting fails, the job retains any confirmed cleanup result independently from the error.

## API and worker wiring contract

All routes live under `/api/v1`. The API owns authorization, CSRF, the existing idempotency dependency and strict request schemas. Long actions return the standard `JobAccepted` response with HTTP 202.

```python
from . import remote_maintenance

# GET /instances/{ident}/remote-storage; viewer dependency
return remote_maintenance.storage_view(db, ident)

# POST /instances/{ident}/remote-storage/refresh; administrator; body Empty
return domain.accepted(remote_maintenance.queue_inventory(
    db, ident, key=key, actor_id=user.id))

# POST /jobs/{ident}/remote-cleanup; administrator
# strict body: kind: Literal["generations", "discard_candidate", "staging"]
return domain.accepted(remote_maintenance.queue_cleanup(
    db, ident, body.kind, key=key, actor_id=user.id))

# Worker methods (existing Context owns heartbeat and fencing):
def handle_remote_inventory(self, ctx):
    remote_maintenance.run_inventory(self, ctx)

def handle_remote_cleanup(self, ctx):
    remote_maintenance.run_cleanup(self, ctx)
```

`queue_cleanup` derives the instance from the historical Job row; the HTTP caller cannot supply it. Restore requests must bind `target_id` to that instance. Historical host ownership and at least one surviving physical mount key must match the current enrollment. Cleanup leases include the union of historical/current host and physical data keys, accommodating inode/generation changes while preserving the active lease boundary. They exclude repository and storage credential leases.

The worker independently revalidates the historical binding, owned resources, terminal state and remote journal identity. Remote `status` and `cleanup` use the **historical job UUID** as operation ID and the **new maintenance job's fence** (`ctx.token`). Read-only preflight uses `ctx.id`; it never issues capture. The helper owns final resource, grace, isolation and active-generation verification. Every remote call has a controller fence check before proceeding.

Inventory is assembled from nested primitive allowlists and saved only in `Job.result["remote_storage"]`; no tables or migrations are required. `storage_view` reads the most recent succeeded/partial maintenance cache without SSH, credential refresh, probe writes or vault access. The job view may allow `remote_storage`, `historical_job_id` and `cleanup_kind` for inspection; the UI reads inventory through the dedicated GET endpoint.

Stable maintenance errors include `CLEANUP_UNSAFE`, `CLEANUP_GRACE_PERIOD`, `REMOTE_ACCOUNTING_UNAVAILABLE`, `REMOTE_ACCOUNTING_INVALID`, `REMOTE_CLEANUP_UNCONFIRMED`, `TARGET_CHANGED`, and helper-provided safe error codes. The central API error dictionary should provide operator-facing messages for the new codes.

Frontend integration:

```tsx
import { RemoteMaintenance, CopyRetryButton } from "./RemoteMaintenance";

<RemoteMaintenance instanceId={instance.id} admin={admin} />
<CopyRetryButton copyId={copy.id} state={copy.state} admin={admin}
  onQueued={(job) => { /* optional navigation to the persisted job */ }}
  onComplete={(job) => { /* optional refresh of snapshot detail */ }} />
```

The copy retry button calls the existing `POST /snapshot-copies/{id}/retry` endpoint and polls its real persisted job state. It reuses the selected immutable recovery point without another source pause; no extra modal or JSON input is needed. Accepted jobs appear in the normal Jobs view after page reload. Normal Backup now and Restore remain unchanged.

## Verification

Run the disposable tests and frontend compilation:

```sh
uv run pytest tests/unit/test_remote_maintenance.py -q
cd frontend
npm run build
```

The unit suite uses a real disposable SQLite catalog, actual enqueue/claim/fence machinery and a recorded synthetic remote wire. It proves active/uncertain rejection, historical host/target binding, new-fence/old-operation addressing, wrong remote journal rejection, grace handling, legacy pre-activation journal compatibility, full-disk unknown accounting, nested redaction, old-helper accounting errors and serialization behind an active physical owner. It does not establish live SSH, Docker disposal or systemd recovery evidence; those remain the constrained helper's disposable integration boundary.

This feature supports specification sections 12.6 and 26, with relevant safety boundaries from AC20, AC21, AC25, AC26, AC31 and AC32. Browser verification should refresh actual synthetic usage, inspect the persisted job through reload, reject viewer mutations directly, observe a grace-blocked generation, and confirm eligible cleanup changes the helper journal while preserving active data. Production sources are not authorized test targets.
