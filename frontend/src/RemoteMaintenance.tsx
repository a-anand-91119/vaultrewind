import { useCallback, useEffect, useState } from "react";
import { api, APIError, bytes, date, rows } from "./api";

type CleanupKind = "generations" | "discard_candidate" | "staging";
type Job = {
  id: string; instance_id?: string; kind: string; state: string; phase: string;
  error_code?: string; error?: { message?: string };
};
type Operation = {
  job_id: string; kind: string; state: string; remote_phase: string;
  generation_bytes: number | null; retained_generation_bytes: number | null;
  cleanup_after: string | null; staging_cleaned: boolean; generations_cleaned: boolean;
  candidate_cleanup_outcome: string; accounting_error?: string;
  eligible_cleanup: CleanupKind[]; cleanup_blocked: Partial<Record<CleanupKind, string>>;
};
type Inventory = {
  as_of: string | null; source_staging_bytes: number | null; image_cache_bytes: number | null;
  staging_bytes: number | null; quota_bytes: number | null; operations: Operation[];
  operations_truncated?: boolean;
  accounting_error?: string;
};
const terminal = new Set(["succeeded", "partial", "failed", "cancelled", "rolled_back", "rollback_failed", "needs_attention"]);
const labels: Record<CleanupKind, string> = {
  staging: "Remove staging", generations: "Retire rollback generation", discard_candidate: "Discard unused candidate",
};
const friendly = (value: string) => value.replaceAll("_", " ");
const errorText = (error: unknown) => error instanceof APIError
  ? `${error.code}: ${error.message}` : "Connection interrupted. Reload status or retry the same action.";

function JobStatus({ job }: { job: Job }) {
  return <p role="status">{friendly(job.kind)}: <strong>{friendly(job.state)}</strong> — {friendly(job.phase)}
    {job.error_code && <span className="error"> {job.error_code}: {job.error?.message || "Inspect the job and retry when its prerequisites are resolved."}</span>}
    <small> Job {job.id}</small>
  </p>;
}

export function RemoteMaintenance({ instanceId, admin }: { instanceId: string; admin: boolean }) {
  const [inventory, setInventory] = useState<Inventory | null>(null);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [confirmation, setConfirmation] = useState<{ operation: Operation; kind: CleanupKind } | null>(null);
  const load = useCallback(async () => {
    const [storage, listing] = await Promise.all([
      api(`/instances/${encodeURIComponent(instanceId)}/remote-storage`), api("/jobs?limit=100"),
    ]);
    setInventory(storage);
    setJobs(rows(listing).filter((job: Job) => job.instance_id === instanceId &&
      ["remote_inventory", "remote_cleanup"].includes(job.kind)).slice(0, 8));
  }, [instanceId]);
  useEffect(() => {
    let disposed = false;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try { await load(); if (!disposed) setError(""); }
      catch (failure) { if (!disposed) setError(errorText(failure)); }
      if (!disposed) timer = setTimeout(poll, 3000);
    };
    setInventory(null); setJobs([]); setConfirmation(null); void poll();
    return () => { disposed = true; clearTimeout(timer); };
  }, [load]);
  const active = jobs.some((job) => !terminal.has(job.state));
  const submit = async (path: string, body: object) => {
    setBusy(true); setError("");
    try {
      const accepted = await api(path, "POST", body);
      setConfirmation(null);
      const job: Job = await api(`/jobs/${encodeURIComponent(accepted.job_id)}`);
      setJobs((previous) => [job, ...previous.filter((value) => value.id !== job.id)].slice(0, 8));
      await load();
    } catch (failure) { setError(errorText(failure)); }
    finally { setBusy(false); }
  };
  return <section className="panel" aria-label="Remote storage and cleanup">
    <div className="section-head"><h3>Remote storage and cleanup</h3>
      {admin && <button className="btn" disabled={busy || active} onClick={() => void submit(
        `/instances/${encodeURIComponent(instanceId)}/remote-storage/refresh`, {},
      )}>{busy ? "Submitting…" : active ? "Maintenance queued or running" : "Refresh remote usage"}</button>}
    </div>
    <p>Staging and saved image cache usage cover the shared enrolled host. Rollback generations below belong to this instance.
      Refresh runs a queued read-only inspection. Closing this page leaves accepted jobs running.</p>
    {error && <p role="alert" className="error">{error}</p>}
    {!inventory ? <p role="status">Loading remote storage…</p> : <>
      <p>Last measured: {date(inventory.as_of)} UTC</p>
      {inventory.accounting_error && <p role="alert">{inventory.accounting_error}: remote usage could not be measured.
        Verified cleanup actions remain available below. Refresh after freeing space.</p>}
      {!inventory.as_of && <p>No remote inventory yet. {admin ? "Refresh remote usage to measure storage and cleanup eligibility." : "Ask an administrator to refresh remote usage."}</p>}
      <dl className="facts">
        <dt>Source staging</dt><dd>{bytes(inventory.source_staging_bytes)}</dd>
        <dt>Saved image cache</dt><dd>{bytes(inventory.image_cache_bytes)}</dd>
        <dt>Combined staging</dt><dd>{bytes(inventory.staging_bytes)}</dd>
        <dt>Host staging quota</dt><dd>{bytes(inventory.quota_bytes)}</dd>
      </dl>
      <p>Rollback generations are preserved for the root-owned grace period (default seven days).
        Retiring an eligible old generation preserves the active deployment and its new writes.
        Safety snapshots remain separately pinned in encrypted storage. Saved images remain cached for exact-image recovery.</p>
      {inventory.operations.length === 0 && inventory.as_of && <p>No historical backup or restore jobs for this instance.</p>}
      {inventory.operations_truncated && <p role="status">Showing the newest 500 operations. Shared host staging totals include older operations.</p>}
      {inventory.operations.map((operation) => <article key={operation.job_id} className="panel">
        <h4>{friendly(operation.kind)} · {friendly(operation.state)}</h4>
        <p><small>Job {operation.job_id}</small> · Remote: {friendly(operation.remote_phase)}</p>
        {operation.accounting_error && <p role="alert">{operation.accounting_error}: accounting is unavailable; review helper compatibility and refresh.</p>}
        {operation.kind === "restore" && <dl className="facts">
          <dt>Restored generation (logical)</dt><dd>{bytes(operation.generation_bytes)}</dd>
          <dt>Preserved rollback generation (logical)</dt><dd>{bytes(operation.retained_generation_bytes)}{operation.generations_cleaned ? " · retired" : " · retained"}</dd>
          <dt>Rollback cleanup eligible after</dt><dd>{date(operation.cleanup_after)} UTC</dd>
          <dt>Unused candidate cleanup</dt><dd>{friendly(operation.candidate_cleanup_outcome)}</dd>
        </dl>}
        <p>Staging: {operation.staging_cleaned ? "removed" : "retained or awaiting verification"}</p>
        {admin && <div className="actions">{operation.eligible_cleanup.map((kind) => <button
          key={kind} className="btn" disabled={busy || active}
          onClick={() => setConfirmation({ operation, kind })}>{labels[kind]}</button>)}</div>}
        {operation.cleanup_blocked.generations === "CLEANUP_GRACE_PERIOD" && <p>The rollback grace period is still active.</p>}
        {operation.state === "needs_attention" || operation.state === "rollback_failed"
          ? <p>Reconcile the original job before requesting cleanup.</p> : null}
      </article>)}
    </>}
    {confirmation && <div className="panel" role="group" aria-label="Confirm remote cleanup">
      <h4>{labels[confirmation.kind]}?</h4>
      <p>This removes only verified {confirmation.kind === "generations" ? "old rollback data after its grace period"
        : confirmation.kind === "discard_candidate" ? "never-activated candidate resources" : "terminal operation staging"} for job {confirmation.operation.job_id}.
        The helper verifies ownership and preserves the active instance. Encrypted snapshots are retained.</p>
      <button className="btn danger" disabled={busy || active} onClick={() => void submit(
        `/jobs/${encodeURIComponent(confirmation.operation.job_id)}/remote-cleanup`, { kind: confirmation.kind },
      )}>Confirm cleanup</button>
      <button className="btn" disabled={busy} onClick={() => setConfirmation(null)}>Cancel</button>
    </div>}
    <div aria-label="Persisted maintenance jobs">{jobs.map((job) => <JobStatus key={job.id} job={job} />)}</div>
  </section>;
}

export function CopyRetryButton({ copyId, state, admin, onQueued, onComplete }: {
  copyId: string; state: string; admin: boolean;
  onQueued?: (job: Job) => void; onComplete?: (job: Job) => void;
}) {
  const [job, setJob] = useState<Job | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => { setJob(null); setError(""); }, [copyId]);
  useEffect(() => {
    if (!job || terminal.has(job.state)) return;
    let disposed = false;
    let polling = false;
    const timer = setInterval(async () => {
      if (polling) return;
      polling = true;
      try {
        const current: Job = await api(`/jobs/${encodeURIComponent(job.id)}`);
        if (disposed) return;
        setJob(current); setError("");
        if (terminal.has(current.state)) onComplete?.(current);
      } catch (failure) { if (!disposed) setError(errorText(failure)); }
      finally { polling = false; }
    }, 2000);
    return () => { disposed = true; clearInterval(timer); };
  }, [job, onComplete]);
  if (!admin || state === "complete") return null;
  const retry = async () => {
    setBusy(true); setError("");
    try {
      const accepted = await api(`/snapshot-copies/${encodeURIComponent(copyId)}/retry`, "POST", {});
      const current: Job = await api(`/jobs/${encodeURIComponent(accepted.job_id)}`);
      setJob(current); onQueued?.(current);
    } catch (failure) { setError(errorText(failure)); }
    finally { setBusy(false); }
  };
  return <div>
    <button className="btn" disabled={busy || (!!job && !terminal.has(job.state))} onClick={() => void retry()}>
      {busy ? "Submitting…" : job && !terminal.has(job.state) ? "Copy retry in progress" : "Retry failed copy"}
    </button>
    <small> Reuses this recovery point without another source pause.</small>
    {error && <p role="alert" className="error">{error}</p>}
    {job && <JobStatus job={job} />}
  </div>;
}
