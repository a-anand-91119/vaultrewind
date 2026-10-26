import { useEffect, useState } from "react";
import { ArrowRight, Check, RefreshCw, ShieldCheck } from "lucide-react";
import { api, rows, date } from "./api";
type Row = Record<string, any>;
const done = new Set([
  "succeeded",
  "failed",
  "partial",
  "cancelled",
  "rolled_back",
  "rollback_failed",
  "needs_attention",
]);
export function HostOnboarding({
  host,
  saved,
}: {
  host: Row;
  saved: () => void;
}) {
  const [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [phase, setPhase] = useState(""),
    [discovery, setDiscovery] = useState<Row | null>(null),
    [chosen, setChosen] = useState<string[]>([]),
    [plan, setPlan] = useState<Row | null>(null),
    [ownership, setOwnership] = useState(false),
    [dependencies, setDependencies] = useState(false),
    [budget, setBudget] = useState(300),
    [names, setNames] = useState<Record<string, string>>({}),
    [additionalFiles, setAdditionalFiles] = useState<Record<string, string>>({}),
    [targetUrls, setTargetUrls] = useState<Record<string, string>>({}),
    [targetNetworks, setTargetNetworks] = useState<Record<string, string>>({}),
    [targetPorts, setTargetPorts] = useState<Record<string, string>>({}),
    [complete, setComplete] = useState(false);
  async function wait(id: string) {
    for (let i = 0; i < 200; i++) {
      const job = await api("/jobs/" + id);
      setPhase(job.phase.replaceAll("_", " "));
      if (done.has(job.state)) {
        if (job.state !== "succeeded")
          throw new Error(
            (job.error_code || "Setup operation failed").replaceAll("_", " "),
          );
        return job;
      }
      await new Promise((r) => setTimeout(r, 1500));
    }
    throw new Error(
      "Setup is still running. Inspect its persisted job in Activity before continuing.",
    );
  }
  async function act(fn: () => Promise<void>) {
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      await fn();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const inspect = () =>
    act(async () => {
      const accepted = await api("/hosts/" + host.id + "/discover", "POST", {});
      const job = await wait(accepted.job_id);
      const evidence = await api("/jobs/" + job.id + "/enrollment");
      if (evidence.host_id !== host.id)
        throw new Error("Discovery belongs to a different host.");
      setDiscovery(evidence);
      setChosen([]);
      setPlan(null);
    });
  const prepare = () =>
    act(async () => {
      const proposals = discovery!.proposals.filter((p: Row) =>
        chosen.includes(p.remote_instance_id),
      );
      const fileMaps = Object.fromEntries(proposals.map((p: Row) => {
        const parsed: Record<string, string> = { ...(p.policy.additional_files || {}) };
        for (const line of (additionalFiles[p.remote_instance_id] || "").split("\n")) {
          if (!line.trim()) continue;
          const split = line.indexOf("=");
          if (split <= 0) throw new Error("Use one NAME=/absolute/path entry per line.");
          const name = line.slice(0, split).trim(), path = line.slice(split + 1).trim();
          if (!/^[A-Za-z0-9_.-]{1,128}$/.test(name) || !path.startsWith("/")) throw new Error("Each approved file needs a simple name and an absolute path.");
          parsed[name] = path;
        }
        return [p.remote_instance_id, parsed];
      }));
      const profileMaps = Object.fromEntries(proposals.map((p: Row) => {
        const previous = p.policy.recovery_profile || {};
        let port_bindings = previous.port_bindings;
        if (targetPorts[p.remote_instance_id]?.trim()) {
          try { port_bindings = JSON.parse(targetPorts[p.remote_instance_id]); }
          catch { throw new Error("Target port bindings must be a JSON object."); }
          if (!port_bindings || Array.isArray(port_bindings) || typeof port_bindings !== "object") throw new Error("Target port bindings must be a JSON object.");
        }
        return [p.remote_instance_id, {
          ...previous,
          revision: (previous.revision || 1) + 1,
          ...(targetNetworks[p.remote_instance_id]?.trim() ? { network: targetNetworks[p.remote_instance_id].trim() } : {}),
          ...(port_bindings ? { port_bindings } : {}),
          environment: {
            ...(previous.environment || {}),
            ...(targetUrls[p.remote_instance_id]?.trim() ? { DOMAIN: targetUrls[p.remote_instance_id].trim() } : {}),
          },
        }];
      }));
      const policy = {
        schema_version: 1,
        machine_id: discovery!.machine_id,
        daemon_id: discovery!.daemon_id,
        instances: Object.fromEntries(
          proposals.map((p: Row) => [
            p.remote_instance_id,
            {
              ...p.policy,
              additional_files: fileMaps[p.remote_instance_id],
              recovery_profile: profileMaps[p.remote_instance_id],
              external_dependencies_ready: dependencies,
              ownership: ownership ? "exclusive" : "unconfirmed",
              capture_budget: budget,
            },
          ]),
        ),
      };
      const accepted = await api(
        "/hosts/" + host.id + "/activation-plans",
        "POST",
        { policy },
      );
      setPlan(await wait(accepted.job_id));
    });
  const activate = () =>
    act(async () => {
      const accepted = await api("/hosts/" + host.id + "/activate", "POST", {
        plan_id: plan!.result.plan_id,
        plan_hash: plan!.result.plan_hash,
      });
      await wait(accepted.job_id);
      for (const proposal of discovery!.proposals.filter((p: Row) =>
        chosen.includes(p.remote_instance_id),
      )) {
        setPhase("verifying enrolled recovery boundary");
        const check = await api("/hosts/" + host.id + "/discover", "POST", {
          instance_id: proposal.remote_instance_id,
        });
        const evidence = await wait(check.job_id);
        await api("/instances", "POST", {
          host_id: host.id,
          name: names[proposal.remote_instance_id] || proposal.name,
          container_id: proposal.container_id,
          configuration: {
            discovery_job_id: evidence.id,
            remote_instance_id: proposal.remote_instance_id,
          },
        });
      }
      setComplete(true);
      saved();
    });
  return (
    <div>
      {complete ? (
        <div className="notice">
          <Check size={20} />
          <p>
            Helper activation and instance enrollment completed. Choose required
            storage and a schedule from the instance policy, then take your
            first backup.
          </p>
        </div>
      ) : (
        <>
          <p className="muted small">
            {host.name}: discover the deployment, review the exact host changes,
            then activate and enroll. Discovery does not write to the host.
          </p>
          {!discovery ? (
            <>
              <div className="notice">
                <ShieldCheck size={19} />
                <p>
                  A separate administrative setup credential is needed for
                  discovery and activation. Routine jobs use only the
                  constrained helper credential.
                </p>
              </div>
              <SetupCredential host={host} />
              <button className="primary" disabled={busy} onClick={inspect}>
                {busy ? <RefreshCw className="spin" size={15} /> : null}Discover
                supported instances
                <ArrowRight size={15} />
              </button>
            </>
          ) : (
            <>
              <h3 className="wizard-subtitle">
                Discovered recovery boundaries
              </h3>
              {discovery.proposals?.length ? (
                discovery.proposals.map((p: Row) => (
                  <div key={p.remote_instance_id} className="enrollment-choice">
                    <label className="check">
                      <input
                        type="checkbox"
                        disabled={!!plan}
                        checked={chosen.includes(p.remote_instance_id)}
                        onChange={(e) =>
                          setChosen(
                            e.target.checked
                              ? [...chosen, p.remote_instance_id]
                              : chosen.filter(
                                  (x) => x !== p.remote_instance_id,
                                ),
                          )
                        }
                      />
                      <strong>{p.name}</strong>
                    </label>
                    <p className="muted small">
                      Docker / SQLite · {p.container_id.slice(0, 12)}
                    </p>
                    {chosen.includes(p.remote_instance_id) && (
                      <>
                        <label className="field">
                          <span>Instance display name</span>
                          <input
                            value={names[p.remote_instance_id] ?? p.name}
                            onChange={(e) =>
                              setNames({
                                ...names,
                                [p.remote_instance_id]: e.target.value,
                              })
                            }
                          />
                        </label>
                        <dl className="mount-list">
                          {p.policy.mounts.map((m: Row) => (
                            <div key={m.target}>
                              <dt>{m.target}</dt>
                              <dd>
                                {m.type === "volume"
                                  ? "Local volume " + m.volume_name
                                  : m.source}
                              </dd>
                            </div>
                          ))}
                        </dl>
                        <label className="field">
                          <span>Explicit deployment files to capture</span>
                          <textarea rows={4} spellCheck={false} placeholder="compose.yml=/srv/vaultwarden/compose.yml\nproduction.env=/srv/vaultwarden/production.env\nsmtp.secret=/etc/vaultwarden/smtp.secret" value={additionalFiles[p.remote_instance_id] ?? Object.entries(p.policy.additional_files || {}).map(([k, v]) => `${k}=${v}`).join("\n")} onChange={(e) => setAdditionalFiles({ ...additionalFiles, [p.remote_instance_id]: e.target.value })} />
                          <small>Optional. One NAME=absolute-path per line. Each file must be readable and inside an approved host boundary. VaultRewind captures only these listed files; it does not crawl unrelated paths.</small>
                        </label>
                        <label className="field">
                          <span>Prepared alternate target public URL overlay (DOMAIN)</span>
                          <input type="url" placeholder="https://vault.example.net" value={targetUrls[p.remote_instance_id] ?? p.policy.recovery_profile?.environment?.DOMAIN ?? ""} onChange={(e) => setTargetUrls({ ...targetUrls, [p.remote_instance_id]: e.target.value })} />
                          <small>Set the target's public URL here when this enrollment is a prepared recovery destination. Other deployment settings are resolved by its approved network and port profile.</small>
                        </label>
                        <div className="form-grid">
                          <label className="field">
                            <span>Target Docker network overlay (optional)</span>
                            <input value={targetNetworks[p.remote_instance_id] ?? p.policy.recovery_profile?.network ?? ""} onChange={(e) => setTargetNetworks({ ...targetNetworks, [p.remote_instance_id]: e.target.value })} placeholder="bridge" />
                            <small>Must be an allowed network present on this enrolled target.</small>
                          </label>
                          <label className="field">
                            <span>Target port bindings JSON (optional)</span>
                            <input value={targetPorts[p.remote_instance_id] ?? (p.policy.recovery_profile?.port_bindings ? JSON.stringify(p.policy.recovery_profile.port_bindings) : "")} onChange={(e) => setTargetPorts({ ...targetPorts, [p.remote_instance_id]: e.target.value })} placeholder='{"80/tcp":[{"HostIp":"127.0.0.1","HostPort":"8081"}]}' />
                            <small>Use a profile approved for this target. The backend rejects conflicts or unsupported bindings.</small>
                          </label>
                        </div>
                      </>
                    )}
                  </div>
                ))
              ) : (
                <p className="notice">
                  No supported running or stopped Vaultwarden deployment was
                  discovered. Prepare a compatible target and resolve
                  unsupported mounts/database engines before continuing.
                </p>
              )}
              {chosen.length > 0 && !plan && (
                <>
                  <label className="check">
                    <input
                      type="checkbox"
                      checked={ownership}
                      onChange={(e) => setOwnership(e.target.checked)}
                    />
                    This instance has exclusive writers and a supported
                    maintenance agreement with any external deployment
                    controller.
                  </label>
                  <label className="check">
                    <input
                      type="checkbox"
                      checked={dependencies}
                      onChange={(e) => setDependencies(e.target.checked)}
                    />
                    Required proxy, network, configuration, secret-file and
                    external authentication dependencies are enrolled and ready.
                  </label>
                  <label className="field">
                    <span>Maximum capture pause budget (seconds)</span>
                    <input
                      type="number"
                      min={10}
                      max={3600}
                      value={budget}
                      onChange={(e) => setBudget(Number(e.target.value))}
                    />
                  </label>
                  <button
                    className="primary"
                    disabled={busy || !ownership || !dependencies}
                    onClick={prepare}
                  >
                    Prepare host-change preview
                    <ArrowRight size={15} />
                  </button>
                </>
              )}
              {plan && (
                <section className="activation-preview">
                  <h3>Proposed host changes</h3>
                  <ul>
                    {(plan.result.changes || []).map((c: any, i: number) => (
                      <li key={i}>
                        {typeof c === "string"
                          ? c
                          : c.description || c.action || JSON.stringify(c)}
                      </li>
                    ))}
                  </ul>
                  {(plan.result.prerequisites || []).map(
                    (p: any, i: number) => (
                      <p key={i} className="muted small">
                        {typeof p === "string" ? p : JSON.stringify(p)}
                      </p>
                    ),
                  )}
                  <div className="notice">
                    <ShieldCheck size={18} />
                    <p>
                      Installs the root-owned helper and policy, constrained
                      sudo entrypoint, watchdog and boot recovery unit. No
                      backup is run during activation. Normal captures briefly
                      pause the selected service.
                    </p>
                  </div>
                  <button
                    className="primary"
                    disabled={busy}
                    onClick={activate}
                  >
                    Activate approved helper & enroll
                    <Check size={15} />
                  </button>
                </section>
              )}
            </>
          )}
          {busy && (
            <p className="loading" role="status">
              <RefreshCw className="spin" size={15} />
              {phase || "Preparing…"}
            </p>
          )}
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
        </>
      )}
    </div>
  );
}
function SetupCredential({ host }: { host: Row }) {
  const [open, setOpen] = useState(false),
    [busy, setBusy] = useState(false),
    [status, setStatus] = useState("");
  return (
    <details
      open={open}
      onToggle={(e) => setOpen(e.currentTarget.open)}
      className="setup-credential"
    >
      <summary>Configure or remove administrative setup access</summary>
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setStatus("");
          const d = new FormData(e.currentTarget);
          try {
            const file = d.get("key") as File;
            await api("/hosts/" + host.id + "/activation-credential", "PUT", {
              username: d.get("username"),
              private_key: await file.text(),
              passphrase: d.get("passphrase") || null,
            });
            setStatus(
              "Setup credential saved encrypted. Remove it after activation.",
            );
          } catch (err) {
            setStatus((err as Error).message);
          } finally {
            setBusy(false);
          }
        }}
      >
        <label className="field">
          <span>Administrative SSH account</span>
          <input name="username" required autoComplete="off" />
        </label>
        <label className="field">
          <span>Administrative SSH private key file</span>
          <input type="file" name="key" required />
        </label>
        <label className="field">
          <span>Key passphrase (optional)</span>
          <input name="passphrase" type="password" autoComplete="off" />
        </label>
        <button className="secondary" disabled={busy}>
          Save private setup credential
        </button>
        <button
          type="button"
          className="text-button"
          onClick={async () => {
            try {
              await api(
                "/hosts/" + host.id + "/activation-credential",
                "DELETE",
              );
              setStatus("Administrative setup credential removed.");
            } catch (e) {
              setStatus((e as Error).message);
            }
          }}
        >
          Remove setup credential
        </button>
        {status && (
          <p className="muted small" role="status">
            {status}
          </p>
        )}
      </form>
    </details>
  );
}
