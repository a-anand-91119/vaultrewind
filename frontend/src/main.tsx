import React, { useState, useEffect, useCallback, useRef } from "react";
import { createRoot } from "react-dom/client";
import {
  ShieldCheck,
  Layers,
  Activity,
  HardDrive,
  Server,
  KeyRound,
  Stethoscope,
  ScrollText,
  Settings,
  Plus,
  ArrowUpRight,
  ArrowLeft,
  ArrowRight,
  RotateCcw,
  Download,
  Play,
  Pin,
  Check,
  Clock,
  AlertTriangle,
  X,
  LogOut,
  RefreshCw,
  Menu,
  Cloud,
  Lock,
  Search,
  Bell,
  Trash2,
} from "lucide-react";
import { api, APIError, rows, bytes, date, age } from "./api";
import "./style.css";
import { HostOnboarding } from "./Onboarding";
import { RemoteMaintenance, CopyRetryButton } from "./RemoteMaintenance";
import { DestinationEditor } from "./DestinationEditor";
type Row = Record<string, any>;
type Modal = { title: string; content: React.ReactNode };
const terminal = new Set([
  "succeeded",
  "partial",
  "failed",
  "cancelled",
  "rolled_back",
  "rollback_failed",
  "needs_attention",
]);
const friendly = (s: string) => s.replaceAll("_", " ");
function Badge({ value }: { value: string }) {
  return (
    <span
      className={
        "badge " +
        (value === "succeeded" ||
        value === "healthy" ||
        value === "complete" ||
        value === "ready"
          ? "good"
          : value === "failed" ||
              value === "needs_attention" ||
              value === "rollback_failed"
            ? "bad"
            : "neutral")
      }
    >
      <i />
      {friendly(value || "unknown")}
    </span>
  );
}
function Empty({
  title,
  children,
}: {
  title: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="empty">
      <Layers size={28} />
      <h3>{title}</h3>
      {children && <p>{children}</p>}
    </div>
  );
}
function Field({
  label,
  name,
  type = "text",
  required = true,
  value,
  help,
  ...rest
}: any) {
  return (
    <label className="field">
      <span>{label}</span>
      <input
        name={name}
        type={type}
        required={required}
        defaultValue={value}
        {...rest}
      />
      {help && <small>{help}</small>}
    </label>
  );
}
function Select({ label, name, children, ...rest }: any) {
  return (
    <label className="field">
      <span>{label}</span>
      <select name={name} {...rest}>
        {children}
      </select>
    </label>
  );
}
function Textarea({ label, name, help, ...rest }: any) {
  return (
    <label className="field">
      <span>{label}</span>
      <textarea name={name} {...rest} />
      {help && <small>{help}</small>}
    </label>
  );
}
function Form({
  submit,
  label = "Save",
  children,
}: {
  submit: (data: FormData) => Promise<void>;
  label?: string;
  children: React.ReactNode;
}) {
  const [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault();
        if (busy) return;
        setBusy(true);
        setError("");
        try {
          await submit(new FormData(e.currentTarget));
        } catch (err) {
          setError(err instanceof Error ? err.message : "Request failed");
        } finally {
          setBusy(false);
        }
      }}
    >
      {children}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <button className="primary" disabled={busy}>
        {busy ? (
          <>
            <RefreshCw size={16} className="spin" />
            Working…
          </>
        ) : (
          label
        )}
        <ArrowRight size={16} />
      </button>
    </form>
  );
}
function Dialog({ modal, close }: { modal: Modal; close: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const previous = document.activeElement as HTMLElement;
    ref.current?.showModal();
    return () => {
      previous?.focus();
    };
  }, []);
  return (
    <dialog
      ref={ref}
      onCancel={(e) => {
        e.preventDefault();
        close();
      }}
      onClick={(e) => {
        if (e.target === ref.current) close();
      }}
    >
      <div className="dialog-head">
        <h2>{modal.title}</h2>
        <button className="icon" aria-label="Close dialog" onClick={close}>
          <X />
        </button>
      </div>
      {modal.content}
    </dialog>
  );
}
function useLoad(path: string | null, refresh = 0, interval = 0) {
  const [data, setData] = useState<any>(null),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(true);
  useEffect(() => {
    let active = true;
    const load = () => {
      if (!path) {
        setLoading(false);
        return;
      }
      api(path)
        .then((v) => {
          if (active) {
            setData(v);
            setError("");
            setLoading(false);
          }
        })
        .catch((e) => {
          if (active) {
            setError(e.message);
            setLoading(false);
          }
        });
    };
    setLoading(true);
    load();
    const timer = interval ? setInterval(load, interval) : undefined;
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [path, refresh, interval]);
  return { data, error, loading };
}
function LoadState({
  state,
  children,
}: {
  state: ReturnType<typeof useLoad>;
  children: React.ReactNode;
}) {
  return state.loading && !state.data ? (
    <div className="loading" role="status">
      <RefreshCw className="spin" size={18} />
      Loading current state…
    </div>
  ) : state.error ? (
    <div className="error" role="alert">
      <AlertTriangle size={18} />
      {state.error}
    </div>
  ) : (
    <>{children}</>
  );
}
function Auth({ onAuth }: { onAuth: (v: Row) => void }) {
  const [setup, setSetup] = useState(false);
  return (
    <div className="auth">
      <div className="auth-brand">
        <ShieldCheck size={34} />
        <strong>VaultRewind</strong>
        <span>YOUR VAULT. YOUR WAY BACK.</span>
      </div>
      <section className="auth-card">
        <span className="eyebrow">PRIVATE BY DESIGN</span>
        <h1>{setup ? "Make recovery part of the plan." : "Welcome back."}</h1>
        <p className="muted">
          {setup
            ? "Create the first administrator using the installation’s private bootstrap secret."
            : "Sign in to manage your Vaultwarden recovery points."}
        </p>
        <Form
          label={setup ? "Create administrator" : "Sign in"}
          submit={async (d) => {
            const body: any = {
              username: d.get("username"),
              password: d.get("password"),
            };
            if (setup) {
              body.bootstrap_secret = d.get("bootstrap");
              body.timezone = d.get("timezone");
            }
            const v = await api(setup ? "/setup" : "/sessions", "POST", body);
            onAuth(v.user);
          }}
        >
          {setup && (
            <Field
              label="Bootstrap secret"
              name="bootstrap"
              type="password"
              autoComplete="off"
              help="Read this from the protected installation file. It is accepted once."
            />
          )}
          <Field label="Username" name="username" autoComplete="username" />
          <Field
            label="Password"
            name="password"
            type="password"
            minLength={setup ? 12 : 1}
            autoComplete={setup ? "new-password" : "current-password"}
          />
          {setup && (
            <Field
              label="Timezone"
              name="timezone"
              value={Intl.DateTimeFormat().resolvedOptions().timeZone}
            />
          )}
        </Form>
        <button className="text-button" onClick={() => setSetup(!setup)}>
          {setup
            ? "Already configured? Sign in"
            : "First installation? Set up VaultRewind"}
          <ArrowUpRight size={14} />
        </button>
      </section>
      <p className="auth-footer">
        <Lock size={13} />
        Self-hosted. Encrypted. In your control.
      </p>
    </div>
  );
}
function App() {
  const [user, setUser] = useState<Row | null | undefined>(undefined),
    [page, setPage] = useState("fleet"),
    [selected, setSelected] = useState<string | null>(null),
    [modal, setModal] = useState<Modal | null>(null),
    [revision, setRevision] = useState(0),
    [toast, setToast] = useState(""),
    [menu, setMenu] = useState(false);
  useEffect(() => {
    const authorizationJob = new URLSearchParams(window.location.search).get("authorization_job");
    if (authorizationJob) {
      window.history.replaceState({}, "", window.location.pathname);
      setPage("storage");
      setModal({ title: "Google Drive authorization", content: <JobPanel id={authorizationJob} onChange={() => setRevision((x) => x + 1)} admin={true} /> });
    }
  }, []);
  useEffect(() => {
    api("/sessions/current")
      .then((v) => setUser(v.user || v))
      .catch(() => setUser(null));
  }, []);
  const reload = () => setRevision((x) => x + 1);
  const close = () => setModal(null);
  const notify = (m: string) => {
    setToast(m);
    setTimeout(() => setToast(""), 7000);
  };
  const execute = async (path: string, body: unknown = {}) => {
    const job = await api(path, "POST", body);
    reload();
    if (job.job_id) {
      showJob(job.job_id);
      notify("Job queued. It continues when you close this page.");
    }
    return job;
  };
  const showJob = (id: string) =>
    setModal({
      title: "Operation progress",
      content: <JobPanel id={id} onChange={reload} admin={admin} />,
    });
  const fleet = useLoad(user ? "/instances" : null, revision, 10000),
    runnerProfiles = useLoad(user ? "/instances?include_runners=true&limit=200" : null, revision),
    hosts = useLoad(user ? "/hosts" : null, revision),
    storage = useLoad(user ? "/storage-destinations" : null, revision),
    jobs = useLoad(user ? "/jobs?limit=50" : null, revision, 5000);
  const instances = rows(fleet.data),
    destinations = rows(storage.data),
    hostRows = rows(hosts.data);
  const admin = user?.role === "administrator";
  function hostForm() {
    setModal({
      title: "Connect a host",
      content: (
        <>
          <p className="muted">
            Read-only discovery comes first. Verify the SSH host key using a
            trusted channel before enrolling it.
          </p>
          <Form
            label="Save connection"
            submit={async (d) => {
              await api("/hosts", "POST", {
                name: d.get("name"),
                endpoint: d.get("endpoint"),
                port: Number(d.get("port")),
                username: d.get("username"),
                host_public_key: d.get("host_public_key"),
                private_key: await (d.get("private_key") as File).text(),
                passphrase: d.get("passphrase") || null,
              });
              close();
              reload();
              notify(
                "Host connection saved. Run discovery to inspect supported instances.",
              );
            }}
          >
            <Field
              label="Display name"
              name="name"
              placeholder="Recovery host"
            />
            <div className="form-grid">
              <Field label="SSH hostname or IP" name="endpoint" />
              <Field
                label="Port"
                name="port"
                type="number"
                value="22"
                min="1"
                max="65535"
              />
            </div>
            <Field label="SSH account" name="username" />
            <Textarea
              label="Verified host public key"
              name="host_public_key"
              required
              placeholder="ssh-ed25519 …"
            />
            <Field
              label="SSH private key"
              name="private_key"
              type="file"
              required
              help="Choose the private key file. Its contents are encrypted and never displayed."
            />
            <Field
              label="Private key passphrase (optional)"
              name="passphrase"
              type="password"
              required={false}
            />
          </Form>
        </>
      ),
    });
  }
  function storageForm() {
    setModal({
      title: "Add storage destination",
      content: (
        <StorageForm
          saved={() => {
            close();
            reload();
            notify(
              "Destination saved. Test the connection before assigning a policy.",
            );
          }}
        />
      ),
    });
  }
  function enrollForm(host: Row) {
    setModal({
      title: "Connect and protect instances",
      content: <HostOnboarding host={host} saved={reload} />,
    });
  }
  function activation(host: Row) {
    enrollForm(host);
  }
  function policyForm(instance: Row) {
    setModal({
      title: "Schedule & retention",
      content: (
        <PolicyForm
          instance={instance}
          destinations={destinations}
          instances={[...instances, ...rows(runnerProfiles.data).filter((x: Row) => x.is_runner)]}
          saved={() => {
            close();
            reload();
          }}
        />
      ),
    });
  }
  function restore(snapshot: Row, target?: string) {
    setModal({
      title: target ? "Restore to another server" : "Restore snapshot",
      content: (
        <RestoreDialog
          snapshot={snapshot}
          instances={instances}
          target={target}
          confirm={async (plan: Row) => {
            await execute("/restore-plans/" + plan.id + "/execute", {
              confirmation_token: plan.confirmation_token,
            });
          }}
        />
      ),
    });
  }
  async function deletePreview(snapshot: Row) {
    try {
      const plan = await api(`/snapshots/${snapshot.id}/deletion-plans`, "POST", {});
      setModal({ title: "Confirm snapshot deletion", content: <DeletionConfirmation snapshot={snapshot} plan={plan} confirm={async () => {
        const job = await api(`/deletion-plans/${plan.id}/execute`, "POST", { confirmation_token: plan.confirmation_token });
        close(); reload(); if (job.job_id) showJob(job.job_id);
      }} /> });
    } catch (e) { notify((e as Error).message); }
  }
  if (user === undefined)
    return (
      <div className="loading">
        <RefreshCw className="spin" />
        Connecting to VaultRewind…
      </div>
    );
  if (!user)
    return (
      <Auth
        onAuth={(u) => {
          setUser(u);
          reload();
        }}
      />
    );
  const nav = [
    ["fleet", "Instances", Layers],
    ["activity", "Activity", Activity],
    ["storage", "Storage", HardDrive],
    ["hosts", "Hosts", Server],
    ["recovery", "Recovery kit", KeyRound],
    ["doctor", "Integrity", Stethoscope],
    ["audit", "Audit trail", ScrollText],
    ["settings", "Settings", Settings],
  ] as const;
  const activeTitle = selected
    ? "Instance details"
    : nav.find((n) => n[0] === page)?.[1];
  return (
    <div className="app">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <aside className={menu ? "sidebar open" : "sidebar"}>
        <a
          className="brand"
          href="#"
          onClick={(e) => {
            e.preventDefault();
            setPage("fleet");
            setSelected(null);
          }}
        >
          <span className="brand-mark">
            <ShieldCheck size={23} />
          </span>
          <span>
            VaultRewind<small>RECOVERY, SIMPLIFIED</small>
          </span>
        </a>
        <div className="workspace">
          <span className="workspace-dot" />
          Personal workspace<small>SELF-HOSTED</small>
        </div>
        <nav aria-label="Main navigation">
          {nav.map(([id, label, Icon]) => (
            <button
              key={id}
              className={page === id ? "nav active" : "nav"}
              onClick={() => {
                setPage(id);
                setSelected(null);
                setMenu(false);
              }}
            >
              <Icon size={18} />
              {label}
              {id === "activity" &&
                rows(jobs.data).some((j) => !terminal.has(j.state)) && (
                  <i className="activity-dot" />
                )}
            </button>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div className="encryption">
            <Lock size={15} />
            <span>
              Encrypted at rest<small>Standard restic repositories</small>
            </span>
          </div>
          <div className="account">
            <span className="avatar">
              {user.username?.slice(0, 1).toUpperCase()}
            </span>
            <span>
              {user.username}
              <small>{friendly(user.role)}</small>
            </span>
            <button
              className="icon"
              aria-label="Sign out"
              onClick={async () => {
                await api("/sessions/current", "DELETE");
                setUser(null);
              }}
            >
              <LogOut size={16} />
            </button>
          </div>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div>
            <button
              className="icon mobile-menu"
              aria-label="Open navigation"
              onClick={() => setMenu(!menu)}
            >
              <Menu />
            </button>
            <span className="breadcrumb">
              Workspace <span>/</span> <strong>{activeTitle}</strong>
            </span>
          </div>
          <span className="private-label">
            <Lock size={12} />
            Private controller
          </span>
        </header>
        <main id="main">
          {selected ? (
            <InstanceDetail
              key={selected}
              id={selected}
              instances={instances}
              revision={revision}
              admin={admin}
              timezone={user.timezone}
              back={() => setSelected(null)}
              backup={async (id: string) =>
                execute("/instances/" + id + "/backups")
              }
              onJob={showJob}
              policy={policyForm}
              restore={restore}
              reload={reload}
              notify={notify}
              deletePreview={deletePreview}
            />
          ) : page === "fleet" ? (
            <>
              <div className="page-heading">
                <div>
                  <span className="eyebrow">YOUR RECOVERY WORKSPACE</span>
                  <h1>Every vault. A way back.</h1>
                  <p className="muted">
                    Complete recovery points for your Vaultwarden instances.
                  </p>
                </div>
                {admin && (
                  <button className="primary" onClick={hostForm}>
                    <Plus size={17} />
                    Connect instance
                  </button>
                )}
              </div>
              <div className="stats">
                <Stat
                  label="Enrolled instances"
                  value={instances.length}
                  icon={<Layers />}
                />
                <Stat
                  label="Healthy backups"
                  value={
                    instances.filter((i) =>
                      ["healthy", "complete", "protected"].includes(
                        i.backup_health,
                      ),
                    ).length
                  }
                  icon={<ShieldCheck />}
                />
                <Stat
                  label="Needs attention"
                  value={
                    instances.filter(
                      (i) =>
                        (i.protection_issues?.length > 0) || !["healthy", "complete", "protected"].includes(
                          i.backup_health,
                        ),
                    ).length
                  }
                  icon={<AlertTriangle />}
                />
                <Stat
                  label="Active operations"
                  value={
                    rows(jobs.data).filter((j) => !terminal.has(j.state)).length
                  }
                  icon={<Activity />}
                />
              </div>
              <div className="section-heading">
                <h2>
                  Instances <span className="count">{instances.length}</span>
                </h2>
                <button className="text-button" onClick={reload}>
                  <RefreshCw size={14} />
                  Refresh
                </button>
              </div>
              <LoadState state={fleet}>
                {instances.length ? (
                  <div className="instance-grid">
                    {instances.map((instance) => (
                      <article className="instance-card" key={instance.id}>
                        <div className="card-top">
                          <span className="instance-icon">
                            <Server size={22} />
                          </span>
                          <Badge value={instance.backup_health} />
                        </div>
                        <button
                          className="instance-title"
                          onClick={() => setSelected(instance.id)}
                        >
                          {instance.name}
                          <ArrowUpRight size={17} />
                        </button>
                        <p className="muted small">
                          {hostRows.find((h) => h.id === instance.host_id)
                            ?.name || "Enrolled SSH host"}{" "}
                          · Vaultwarden / SQLite
                        </p>
                        <div className="instance-meta">
                          <div>
                            <span>Source</span>
                            <Badge value={instance.source_health} />
                            {instance.source_public_ports_ready === false && <span className="error small">Published endpoint unready</span>}
                          </div>
                          <div>
                            <span>Last complete capture</span>
                            <strong title={instance.last_complete_at || ""}>
                              {date(instance.last_complete_at, user.timezone)}
                              <small className="capture-age">
                                {age(instance.capture_age_seconds)}
                              </small>
                            </strong>
                          </div>
                          <div>
                            <span>Last restore test</span>
                            <strong>
                              {date(instance.last_test_at, user.timezone)}
                              {instance.protection_issues?.includes("restore_testing_not_configured") &&
                                <small className="capture-age">Restore testing not configured</small>}
                            </strong>
                          </div>
                        </div>
                        <div className="card-actions">
                          <button
                            className="secondary"
                            onClick={() => setSelected(instance.id)}
                          >
                            View snapshots
                            <ArrowRight size={15} />
                          </button>
                          {admin && (
                            <ActionButton
                              action={() =>
                                execute(
                                  "/instances/" + instance.id + "/backups",
                                )
                              }
                              disabled={instance.readiness !== "ready"}
                              title={
                                instance.readiness !== "ready"
                                  ? "Complete enrollment and policy setup first"
                                  : undefined
                              }
                            >
                              <Download size={15} />
                              Backup now
                            </ActionButton>
                          )}
                        </div>
                      </article>
                    ))}
                  </div>
                ) : (
                  <section className="panel">
                    <Empty title="Give your first vault a way back.">
                      Connect an SSH host, review read-only discovery and choose
                      encrypted storage. Your recovery points will appear here.
                    </Empty>
                    {admin && (
                      <div className="empty-action">
                        <button className="secondary" onClick={hostForm}>
                          <Plus size={16} />
                          Connect a host
                        </button>
                      </div>
                    )}
                  </section>
                )}
              </LoadState>
              <div className="info-strip">
                <ShieldCheck size={20} />
                <div>
                  <strong>One-click backup. One-click restore.</strong>
                  <p>
                    Every capture includes your database, files, deployment
                    configuration and exact application image.
                  </p>
                </div>
                <span>COMPLETE INSTANCE RECOVERY</span>
              </div>
              <div className="section-heading">
                <h2>Recent activity</h2>
                <button
                  className="text-button"
                  onClick={() => setPage("activity")}
                >
                  View all
                  <ArrowRight size={14} />
                </button>
              </div>
              <Jobs jobs={rows(jobs.data).slice(0, 5)} open={showJob} />
            </>
          ) : page === "activity" ? (
            <>
              <PageHeading
                title="Activity"
                description="Durable operations continue independently of this browser."
              />
              <LoadState state={jobs}>
                <Jobs jobs={rows(jobs.data)} open={showJob} />
              </LoadState>
            </>
          ) : page === "storage" ? (
            <>
              <PageHeading
                title="Encrypted storage"
                description="Capture once. Track every required and best-effort copy independently."
                action={
                  admin ? (
                    <button className="primary" onClick={storageForm}>
                      <Plus size={16} />
                      Add destination
                    </button>
                  ) : null
                }
              />
              <LoadState state={storage}>
                {destinations.length ? (
                  <div className="instance-grid">
                    {destinations.map((d) => (
                      <article className="panel storage-card" key={d.id}>
                        <div className="card-top">
                          {d.backend === "local" ? <HardDrive /> : <Cloud />}
                          <Badge value={d.health} />
                        </div>
                        <h2>{d.name}</h2>
                        <p className="muted">
                          {d.backend === "s3"
                            ? "S3-compatible"
                            : d.backend === "drive"
                              ? "Google Drive"
                              : "Persistent local disk"}
                        </p>
                        <p className="small">
                          Last connection test:{" "}
                          {date(d.last_test_at, user.timezone)}
                        </p>
                        {d.backend === "drive" && <p className="small muted">{d.details?.authorized ? `Drive folder ${d.details.folder_name || "VaultRewind"} · ${d.details.folder_id || "folder identity unavailable"} · token expires ${date(d.details.token_expiry)}` : "Authorization required. Use the guided browser grant or private headless import."}</p>}
                        {d.backend === "local" && <p className="small muted">{d.details?.host_path || d.details?.mount_path || "Controller storage path unavailable"} · {d.details?.free_bytes != null ? `${bytes(d.details.free_bytes)} free` : "Free space unavailable"}</p>}
                        {d.backend === "s3" && <p className="small muted">{d.details?.endpoint_host || "Endpoint unavailable"} / {d.details?.bucket || "bucket unavailable"}{d.details?.prefix ? ` / ${d.details.prefix}` : ""} · {d.details?.custom_ca ? "Custom CA configured" : "System CA"}</p>}
                        {admin && (
                          <div className="button-row">
                            <ActionButton
                              action={() =>
                                execute(
                                  "/storage-destinations/" + d.id + "/test",
                                )
                              }
                            >
                              Test connection
                            </ActionButton>
                            {d.backend === "drive" && (
                              <DriveActions destination={d} onJob={showJob} notify={notify} />
                            )}
                            <DestinationEditor destination={d} onSaved={reload} />
                          </div>
                        )}
                      </article>
                    ))}
                  </div>
                ) : (
                  <div className="panel">
                    <Empty title="Choose where recovery lives.">
                      Local disk, S3-compatible storage and Google Drive use
                      standard encrypted restic repositories.
                    </Empty>
                  </div>
                )}
              </LoadState>
              <p className="muted footnote">
                A connection test may write and remove a scoped probe, or
                refresh provider credentials. Local copies survive container
                recreation; keep an independent copy for disk-loss recovery.
              </p>
              <Notifications revision={revision} />
            </>
          ) : page === "hosts" ? (
            <>
              <PageHeading
                title="SSH hosts"
                description="Pinned host identities. Explicit enrollment. Constrained remote access."
                action={
                  admin ? (
                    <button className="primary" onClick={hostForm}>
                      <Plus size={16} />
                      Connect host
                    </button>
                  ) : null
                }
              />
              <LoadState state={hosts}>
                {hostRows.length ? (
                  hostRows.map((h) => (
                    <section className="panel host-row" key={h.id}>
                      <Server size={22} />
                      <div className="grow">
                        <h3>{h.name}</h3>
                        <p className="muted small">
                          {h.endpoint}:{h.port} · {h.username}
                        </p>
                      </div>
                      <Badge value={h.readiness} />
                      {admin && (
                        <div className="button-row">
                          <ActionButton
                            action={() =>
                              execute("/hosts/" + h.id + "/discover")
                            }
                          >
                            Discover
                          </ActionButton>
                          <button
                            className="secondary"
                            onClick={() => activation(h)}
                          >
                            Review activation
                          </button>
                          <button
                            className="secondary"
                            onClick={() => enrollForm(h)}
                          >
                            Enroll instance
                          </button>
                        </div>
                      )}
                    </section>
                  ))
                ) : (
                  <div className="panel">
                    <Empty title="No hosts connected">
                      Read-only discovery checks the deployment before proposing
                      any host changes.
                    </Empty>
                  </div>
                )}
              </LoadState>
            </>
          ) : page === "recovery" ? (
            <Recovery admin={admin} execute={execute} />
          ) : page === "doctor" ? (
            <Doctor revision={revision} execute={execute} admin={admin} />
          ) : page === "audit" ? (
            <Audit revision={revision} admin={admin} />
          ) : (
            <SettingsPage admin={admin} saved={notify} />
          )}
        </main>
        <footer className="main-footer">
          <span>
            VaultRewind <span> / </span> One click away from a way back.
          </span>
          <span>Controller v0.1.0</span>
        </footer>
      </div>
      {modal && <Dialog key={modal.title} modal={modal} close={close} />}{" "}
      {toast && (
        <div className="toast" role="status">
          <Check size={18} />
          {toast}
          <button
            className="icon"
            aria-label="Dismiss notification"
            onClick={() => setToast("")}
          >
            <X size={15} />
          </button>
        </div>
      )}
    </div>
  );
}
function PageHeading({ title, description, action }: any) {
  return (
    <div className="page-heading">
      <div>
        <span className="eyebrow">VAULTREWIND</span>
        <h1>{title}</h1>
        <p className="muted">{description}</p>
      </div>
      {action}
    </div>
  );
}
function Stat({ label, value, icon }: any) {
  return (
    <div className="stat">
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
      <span className="stat-icon">{icon}</span>
    </div>
  );
}
function ActionButton({ action, children, disabled, title }: any) {
  const [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  return (
    <span className="action-wrapper">
      <button
        className="secondary"
        disabled={busy || disabled}
        title={title}
        onClick={async () => {
          if (busy) return;
          setBusy(true);
          setError("");
          try {
            await action();
          } catch (e) {
            setError((e as Error).message);
          } finally {
            setBusy(false);
          }
        }}
      >
        {busy ? <RefreshCw size={14} className="spin" /> : null}
        {children}
      </button>
      {error && (
        <small className="error" role="alert">
          {error}
        </small>
      )}
    </span>
  );
}
function Jobs({ jobs, open }: any) {
  return jobs.length ? (
    <div className="panel table-wrap">
      <table>
        <thead>
          <tr>
            <th>Operation</th>
            <th>Phase</th>
            <th>Result</th>
            <th>Started</th>
            <th>
              <span className="sr-only">Inspect</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {jobs.map((j: Row) => (
            <tr key={j.id}>
              <td>
                <strong>{friendly(j.kind)}</strong>
                <small className="mono">{j.id.slice(0, 8)}</small>
              </td>
              <td>{friendly(j.phase)}</td>
              <td>
                <Badge value={j.state} />
              </td>
              <td>{date(j.created_at)}</td>
              <td>
                <button className="text-button" onClick={() => open(j.id)}>
                  Inspect
                  <ArrowUpRight size={14} />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  ) : (
    <section className="panel">
      <Empty title="No operations yet">
        Backup, restore and verification results appear here.
      </Empty>
    </section>
  );
}
function JobPanel({ id, onChange, admin }: any) {
  const [revision, setRevision] = useState(0), [reconciling, setReconciling] = useState(false), [reconcileError, setReconcileError] = useState("");
  const job = useLoad("/jobs/" + id, revision, 1500),
    events = useLoad("/jobs/" + id + "/events", revision, 1500);
  const importReview = useLoad(
      job.data?.kind === "recovery_import" && job.data?.state === "succeeded"
        ? "/recovery/import-plans/" + id
        : null,
      revision,
    ),
    [applyBusy, setApplyBusy] = useState(false),
    [applyError, setApplyError] = useState(""),
    [applyJobId, setApplyJobId] = useState("");
  useEffect(() => {
    if (job.data && terminal.has(job.data.state)) onChange();
  }, [job.data?.state]);
  return (
    <LoadState state={job}>
      {job.data && (
        <>
          <div className="job-status">
            <Badge value={job.data.state} />
            <span className="mono">{id.slice(0, 8)}</span>
          </div>
          <h3>{friendly(job.data.phase)}</h3>
          <p className="muted">
            You can close this dialog. Progress and recovery decisions are
            persisted by the controller.
          </p>
          <ol className="steps">
            {rows(events.data).map((e: Row) => (
              <li key={e.sequence}>
                <span className="step-dot" />
                <div>
                  <strong>{friendly(e.phase)}</strong>
                  <p>
                    {friendly(e.code || "Phase recorded")}
                    {e.progress?.bytes != null &&
                      " · " + bytes(e.progress.bytes)}
                  </p>
                  <small>{date(e.created_at)}</small>
                </div>
              </li>
            ))}
          </ol>
          {job.data.error_code && (
            <p className="error" role="alert">
              {friendly(job.data.error_code)}. Inspect Integrity for the next
              recovery action.
            </p>
          )}
          {admin && job.data.kind === "recovery_import" && job.data.state === "succeeded" && (
            <LoadState state={importReview}>
              {importReview.data && !applyJobId && (
                <section className="reconcile-panel" aria-label="Review protected recovery import">
                  <h4>Review discovered recovery points</h4>
                  <p className="muted small">
                    {importReview.data.summary?.snapshots ?? 0} snapshots across {importReview.data.summary?.instances?.length ?? 0} instances and {importReview.data.summary?.repositories ?? 0} repositories.
                    {" "}{importReview.data.summary?.verified_copies ?? 0} verified copies; {importReview.data.summary?.unverified_copies ?? 0} unverified copies.
                  </p>
                  <p className="notice">
                    This import stays in protected review mode. Automatic deletion is disabled; each imported snapshot receives review protection, with additional protection for safety and future-dated snapshots.
                  </p>
                  {importReview.data.summary?.future_dated > 0 && <p className="notice">{importReview.data.summary.future_dated} future-dated recovery points are protected for review.</p>}
                  {importReview.data.summary?.conflicts > 0 && <p className="error">{importReview.data.summary.conflicts} identity conflicts need review.</p>}
                  {importReview.data.summary?.errors?.map((item: Row, index: number) => (
                    <p className="error" key={item.destination_id + item.error_code + index}>
                      {friendly(item.error_code)} · {item.destination_id}
                    </p>
                  ))}
                  <div className="table-wrap">
                    <table>
                      <thead><tr><th>Snapshot</th><th>Instance</th><th>Captured</th><th>Kind</th><th>Protection</th></tr></thead>
                      <tbody>{(importReview.data.snapshots || []).map((snapshot: Row) => (
                        <tr key={snapshot.snapshot_uuid}>
                          <td className="mono">{snapshot.snapshot_uuid}</td>
                          <td>{snapshot.instance_id}</td>
                          <td>{date(snapshot.captured_at)}</td>
                          <td>{friendly(snapshot.kind || "backup")}</td>
                          <td>{snapshot.future_dated ? "Import review · future dated" : snapshot.kind === "safety" ? "Import review · safety" : "Import review"}</td>
                        </tr>
                      ))}</tbody>
                    </table>
                  </div>
                  {applyError && <p role="alert" className="error">{applyError}</p>}
                  <button className="primary" disabled={applyBusy || importReview.data.summary?.conflicts > 0} onClick={async () => {
                    if (applyBusy) return;
                    setApplyBusy(true); setApplyError("");
                    try {
                      const accepted = await api(`/recovery/import-plans/${id}/apply`, "POST", { plan_hash: importReview.data.plan_hash });
                      if (!accepted.job_id) throw new Error("The protected import was not queued.");
                      setApplyJobId(accepted.job_id); onChange();
                    } catch (error) { setApplyError((error as Error).message); }
                    finally { setApplyBusy(false); }
                  }}>{applyBusy ? "Applying protected import…" : "Apply protected import"}<ArrowRight size={16} /></button>
                </section>
              )}
            </LoadState>
          )}
          {applyJobId && <JobPanel id={applyJobId} onChange={onChange} admin={admin} />}
          {admin && ["needs_attention", "rollback_failed"].includes(job.data.state) && <section className="reconcile-panel" aria-label="Operation reconciliation">
            <h4>Reconcile this operation</h4>
            <p className="muted small">VaultRewind will read the helper’s durable operation journal and resume only non-destructive recovery that the journal proves is safe. This keeps the same operation and leases until remote state is verified. It will not automatically roll back an activated restore.</p>
            {reconcileError && <p className="error" role="alert">{reconcileError}</p>}
            <button className="secondary" disabled={reconciling} onClick={async () => {
              if (reconciling) return; setReconciling(true); setReconcileError("");
              try { await api(`/jobs/${id}/reconcile`, "POST", {}); setRevision((v) => v + 1); onChange(); }
              catch (e) { setReconcileError((e as Error).message); }
              finally { setReconciling(false); }
            }}>{reconciling ? "Requesting journal reconciliation…" : "Reconcile operation"}</button>
          </section>}
          <div className="outcomes">
            {[
              "content_commit",
              "required_copy_outcome",
              "source_service_outcome",
              "target_activation_outcome",
            ].map(
              (k) =>
                job.data[k] && (
                  <div key={k}>
                    <span>{friendly(k)}</span>
                    <strong>{friendly(String(job.data[k]))}</strong>
                  </div>
                ),
            )}
          </div>
          {(job.data.result?.download_url ||
            job.data.result?.artifact_ready) && (
            <a
              className="primary"
              href={
                job.data.result.download_url ||
                "/api/v1/jobs/" + id + "/artifact"
              }
            >
              Download encrypted artifact
              <Download size={16} />
            </a>
          )}
          {!terminal.has(job.data.state) && (
            <ActionButton
              action={() => api("/jobs/" + id + "/cancel", "POST", {})}
            >
              Request safe cancellation
            </ActionButton>
          )}
        </>
      )}
    </LoadState>
  );
}
function InstanceDetail({
  id,
  instances,
  revision,
  admin,
  timezone,
  back,
  backup,
  policy,
  restore,
  reload,
  notify,
  deletePreview,
}: any) {
  const [snapshotCursor, setSnapshotCursor] = useState<Row | null>(null),
    [snapshotHistory, setSnapshotHistory] = useState<(Row | null)[]>([]);
  const snapshotQuery = snapshotCursor ? `&before=${encodeURIComponent(snapshotCursor.captured_at)}&before_id=${snapshotCursor.id}` : "";
  const info = useLoad("/instances/" + id, revision, 10000),
    snapshots = useLoad(
      "/instances/" + id + "/snapshots?limit=100" + snapshotQuery,
      revision,
      5000,
    );
  const item = info.data || instances.find((x: Row) => x.id === id);
  return (
    <>
      <button className="text-button back" onClick={back}>
        <ArrowLeft size={15} />
        All instances
      </button>
      <LoadState state={info}>
        {item && (
          <>
            <div className="page-heading">
              <div>
                <span className="eyebrow">VAULTWARDEN · SQLITE</span>
                <h1>{item.name}</h1>
                <div className="button-row">
                  <span className="small muted">Source</span>
                  <Badge value={item.source_health} />
                  {item.source_public_ports_ready === false && <span className="error small">Published endpoint unready</span>}
                  <span className="small muted">Backup</span>
                  <Badge value={item.backup_health} />
                </div>
              </div>
              {admin && (
                <ActionButton
                  action={() => backup(id)}
                  disabled={item.readiness !== "ready"}
                >
                  <Download size={16} />
                  Backup now
                </ActionButton>
              )}
            </div>
            <div className="panel policy-summary">
              <div>
                <Clock size={20} />
                <span>
                  Capture schedule
                  <strong>
                    {item.policy?.enabled === false
                      ? "Paused"
                      : item.policy?.schedule_kind === "hourly"
                        ? `Every ${item.policy.interval_hours} hour(s)`
                        : `Daily at ${item.policy?.daily_time || "02:00"}`}
                  </strong>
                </span>
              </div>
              <div>
                <Layers size={20} />
                <span>
                  Retention
                  <strong>
                    {item.policy?.retention_days === null
                      ? "Keep forever"
                      : `Every snapshot within ${item.policy?.retention_days || 30} rolling days`}
                  </strong>
                </span>
              </div>
              {admin && (
                <button className="secondary" onClick={() => policy(item)}>
                  Manage policy
                </button>
              )}
            </div>
            <div className="section-heading">
              <h2>Dated snapshots</h2>
              <span className="muted small">
                Capture time · {timezone || "UTC"}
              </span>
            </div>
            <LoadState state={snapshots}>
              {rows(snapshots.data).length ? (
                <div className="snapshot-list">
                  {rows(snapshots.data).map((s: Row) => (
                    <article className="panel snapshot" key={s.id} data-snapshot-id={s.id}>
                      <div className="snapshot-symbol">
                        <RotateCcw size={20} />
                      </div>
                      <div className="grow">
                        <h3 title={s.captured_at + " UTC"}>
                          {date(s.captured_at, timezone)}{" "}
                          {s.pinned && <Pin size={13} aria-label="Pinned" />}
                        </h3>
                        <p className="muted small">
                          {friendly(s.trigger)} · {bytes(s.logical_bytes)} ·
                          Vaultwarden {s.vaultwarden_version}
                        </p>
                        <div className="button-row">
                          <Badge value={s.completeness} />
                          {s.safety && (
                            <span className="badge neutral">
                              Safety snapshot
                            </span>
                          )}
                          <span className="small muted">
                            {
                              s.copies.filter(
                                (c: Row) => c.state === "complete",
                              ).length
                            }{" "}
                            complete copies
                          </span>
                        </div>
                        <div className="copy-list" aria-label="Storage copy status">
                          {s.copies.map((copy: Row) => <div key={copy.id}>
                            <Badge value={copy.state} />
                            <span>{copy.destination_name || copy.destination_id?.slice(0, 8) || "Storage copy"}</span>
                            <span className="muted">Logical {bytes(s.logical_bytes)} · Stored {bytes(copy.stored_bytes)}</span>
                            <span className="muted">Copy verified {date(copy.verified_at)} · Data verified {date(copy.data_verified_at)}</span>
                            {copy.error_code && <span className="error small">{friendly(copy.error_code)} — retry the storage operation or check destination access.</span>}
                            <CopyRetryButton copyId={copy.id} state={copy.state} admin={admin} onComplete={reload} />
                          </div>)}
                        </div>
                        <div className="trust small">
                          {s.verification?.application_started
                            ? "Application started"
                            : s.verification?.restored_bytes_verified
                              ? "Restored bytes verified"
                              : s.verification?.database_integrity
                                ? "Integrity checked"
                                : "Capture validation recorded"}{" "}
                          ·{" "}
                          {s.verification?.user_login_tested
                            ? "Synthetic user login tested"
                            : "User login not tested"}
                        </div>
                        <div className="trust small">Capture time {date(s.captured_at)} · Capture validation {s.verification?.capture_validated ? "recorded" : "not reported"} · Restore bytes {s.verification?.restored_bytes_verified ? "verified" : "not verified"} (restore-test timestamp not returned by this API)</div>
                        <p className="small muted">Saved image identity: <code>{s.image_id || "Not recorded"}</code></p>
                        {s.copies.some((c: Row) => c.state === "failed") && (
                          <p className="error small">
                            A destination copy failed. Complete copies remain
                            available.
                          </p>
                        )}
                      </div>
                      {admin && (
                        <div className="snapshot-actions">
                          <button
                            className="primary"
                            disabled={
                              !s.copies.some((c: Row) => c.state === "complete")
                            }
                            onClick={() => restore(s)}
                          >
                            Restore
                            <RotateCcw size={15} />
                          </button>
                          <details>
                            <summary>More actions</summary>
                            <div className="dropdown">
                              <button
                                onClick={() =>
                                  restore(
                                    s,
                                    instances.find((x: Row) => x.id !== id)
                                      ?.id || "alternate",
                                  )
                                }
                              >
                                Restore to another server
                              </button>
                              <button
                                onClick={async () => {
                                  try {
                                    await api(
                                      "/snapshots/" + s.id + "/pin",
                                      s.pinned ? "DELETE" : "POST",
                                      {},
                                    );
                                    reload();
                                  } catch (e) {
                                    notify((e as Error).message);
                                  }
                                }}
                              >
                                {s.pinned ? "Unpin" : "Pin"} snapshot
                              </button>
                              <ActionButton
                                action={() =>
                                  api(
                                    "/snapshots/" + s.id + "/verify",
                                    "POST",
                                    { level: "full_data" },
                                  ).then(() =>
                                    notify(
                                      "Full repository data check queued.",
                                    ),
                                  )
                                }
                              >
                                Verify stored data
                              </ActionButton>
                              <ActionButton
                                action={() =>
                                  api(
                                    "/snapshots/" + s.id + "/verify",
                                    "POST",
                                    { level: "application" },
                                  ).then(() =>
                                    notify("Isolated restore test queued."),
                                  )
                                }
                              >
                                Test restore
                              </ActionButton>
                              <button className="danger-text" onClick={() => deletePreview(s)}>Preview deletion…</button>
                            </div>
                          </details>
                        </div>
                      )}
                    </article>
                  ))}
                </div>
              ) : (
                <div className="panel">
                  <Empty title="Your recovery timeline starts here.">
                    Choose Backup now after configuring a destination. Every
                    capture creates a distinct dated snapshot.
                  </Empty>
                </div>
              )}
            </LoadState>
            <nav aria-label="Snapshot pages" className="button-row">
              <button className="secondary" disabled={snapshots.loading || snapshotHistory.length === 0}
                onClick={() => { setSnapshotCursor(snapshotHistory[snapshotHistory.length - 1]); setSnapshotHistory((previous) => previous.slice(0, -1)); }}>
                Newer snapshots
              </button>
              <button className="secondary" disabled={snapshots.loading || rows(snapshots.data).length < 100}
                onClick={() => { setSnapshotHistory((previous) => [...previous, snapshotCursor]); setSnapshotCursor(rows(snapshots.data).at(-1)); }}>
                Older snapshots
              </button>
              {snapshotCursor && <button className="text-button" onClick={() => { setSnapshotCursor(null); setSnapshotHistory([]); }}>Latest recovery points</button>}
            </nav>
            <RemoteMaintenance instanceId={item.id} admin={admin} />
          </>
        )}
      </LoadState>
    </>
  );
}
function RestoreDialog({ snapshot, instances, target, confirm }: any) {
  const [selected, setSelected] = useState(target || snapshot.instance_id),
    [copyId, setCopyId] = useState(snapshot.copies.find((c: Row) => c.state === "complete")?.id || ""),
    [start, setStart] = useState(false),
    [receivedPlan, setPlan] = useState<Row | null>(null),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  const requestBinding = JSON.stringify([snapshot.id, selected, copyId, start]);
  const plan = receivedPlan?.requestBinding === requestBinding ? receivedPlan : null;
  useEffect(() => {
    let valid = true;
    setPlan(null);
    setError("");
    if (selected === "alternate") {
      setError("Enroll a prepared alternate target in Hosts before restoring.");
      return;
    }
    api("/snapshots/" + snapshot.id + "/restore-plans", "POST", {
      target_id: selected,
      copy_id: copyId || undefined,
      start_on_completion: start,
    })
      .then((v) => {
        if (valid) setPlan({ ...v, requestBinding });
      })
      .catch((e) => {
        if (valid) setError(e.message);
      });
    return () => {
      valid = false;
    };
  }, [snapshot.id, selected, start, copyId]);
  return (
    <>
      <p className="muted">
        Restore the complete instance to this exact capture point. Changes after
        it will be replaced on the selected target.
      </p>
      <div className="restore-point">
        <RotateCcw size={22} />
        <div>
          <strong>{date(snapshot.captured_at)}</strong>
          <small>{snapshot.captured_at} · UTC</small>
          <small>Vaultwarden {snapshot.vaultwarden_version}</small>
        </div>
      </div>
      <label className="field">
        <span>Verified storage copy</span>
        <select value={copyId} onChange={(e) => { setPlan(null); setCopyId(e.target.value); }}>
          {snapshot.copies.filter((c: Row) => c.state === "complete").map((c: Row) => <option key={c.id} value={c.id}>{c.destination_name || c.destination_id?.slice(0, 8) || "Storage destination"} · stored {bytes(c.stored_bytes)}</option>)}
        </select>
      </label>
      <label className="field">
        <span>Destination</span>
        <select value={selected} onChange={(e) => { setPlan(null); setSelected(e.target.value); }}>
          {instances.map((i: Row) => (
            <option key={i.id} value={i.id} disabled={i.readiness !== "ready"}>
              {i.name}
              {i.id === snapshot.instance_id ? " (original instance)" : ""}
              {i.readiness !== "ready" ? " — target not ready" : ""}
            </option>
          ))}
          {selected === "alternate" && (
            <option value="alternate">
              Prepared alternate target required
            </option>
          )}
        </select>
      </label>
      <label className="check">
        <input
          type="checkbox"
          checked={start}
          onChange={(e) => { setPlan(null); setStart(e.target.checked); }}
        />
        Start on completion if the target is stopped or empty
      </label>
      <div className="notice">
        <ShieldCheck size={18} />
        <p>
          Replacing an existing instance creates a pinned encrypted safety
          snapshot and preserves its previous generation. Expect a maintenance
          pause during switching and validation.
        </p>
      </div>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {plan && (
        <div className="plan-summary">
          <p>
            Target:{" "}
            <strong>
              {instances.find((i: Row) => i.id === selected)?.name}
            </strong>
          </p>
          <p>
            Validation: <strong>{friendly(snapshot.completeness)}</strong>
          </p>
          <p>
            Maintenance budget:{" "}
            <strong>
              {plan.maintenance_budget_seconds ||
                plan.maintenance_seconds ||
                900}{" "}
              seconds
            </strong>
          </p>
          {plan.substitutions &&
            Object.entries(plan.substitutions).map(([k, v]) => (
              <p key={k}>
                {friendly(k)}: {String(v)}
              </p>
            ))}
        </div>
      )}
      <button
        className="primary"
        disabled={!plan || busy}
        onClick={async () => {
          if (!plan || busy) return;
          setBusy(true);
          try {
            await confirm(plan);
          } catch (e) {
            setError((e as Error).message);
            setBusy(false);
          }
        }}
      >
        {busy
          ? "Queuing restore…"
          : plan
            ? "Confirm restore"
            : "Checking exact snapshot and target…"}
        <RotateCcw size={15} />
      </button>
    </>
  );
}
function DeletionConfirmation({ snapshot, plan, confirm }: any) {
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  return <>
    <p className="error">This action permanently forgets the eligible stored copies of this snapshot. Other protected snapshots and copies are not included.</p>
    <div className="plan-summary"><p>Snapshot captured: <strong>{date(snapshot.captured_at)} · UTC</strong></p><p>Eligible copy IDs: <strong>{plan.copy_ids?.length || 0}</strong></p><p>Confirmation expires: {date(plan.expires_at)} · UTC</p><ul>{(plan.copy_ids || []).map((id: string) => <li key={id}><code>{id}</code></li>)}</ul></div>
    {error && <p role="alert" className="error">{error}</p>}
    <button className="danger" disabled={busy || !plan.copy_ids?.length} onClick={async () => { setBusy(true); try { await confirm(); } catch (e) { setError((e as Error).message); setBusy(false); } }}>{busy ? "Submitting deletion…" : "Confirm deletion"}<Trash2 size={15} /></button>
  </>;
}
function PolicyForm({ instance, destinations, instances, saved }: any) {
  const state = useLoad("/instances/" + instance.id + "/policy"),
    [preview, setPreview] = useState<any>(null), [previewError, setPreviewError] = useState(""), [previewBusy, setPreviewBusy] = useState(false);
  return (
    <LoadState state={state}>
      {state.data && (
        <Form
          label="Save policy"
          submit={async (d) => {
            const destinationList = destinations
              .filter((x: Row) => d.get("destination-" + x.id) === "on")
              .map((x: Row) => ({
                destination_id: x.id,
                required: d.get("required-" + x.id) === "on",
              }));
            await api(
              "/instances/" + instance.id + "/policy",
              "PATCH",
              {
                enabled: d.get("enabled") === "on",
                schedule_kind: d.get("schedule"),
                timezone: d.get("timezone"),
                daily_time: d.get("time"),
                interval_hours: Number(d.get("interval")),
                retention_days:
                  d.get("forever") === "on" ? null : Number(d.get("retention")),
                destinations: destinationList,
                runner_id: d.get("runner") || null,
              },
              { "If-Match": '"' + state.data.revision + '"' },
            );
            saved();
          }}
        >
          <label className="check">
            <input
              type="checkbox"
              name="enabled"
              defaultChecked={state.data.enabled}
            />
            Scheduled backups enabled
          </label>
          <div className="form-grid">
            <Select
              label="Schedule"
              name="schedule"
              defaultValue={state.data.schedule_kind}
            >
              <option value="daily">Daily</option>
              <option value="hourly">Hourly interval</option>
            </Select>
            <Field
              label="Timezone"
              name="timezone"
              value={state.data.timezone}
            />
            <Field
              label="Daily time"
              name="time"
              type="time"
              value={state.data.daily_time}
            />
            <Field
              label="Hourly interval"
              name="interval"
              type="number"
              min="1"
              max="24"
              value={state.data.interval_hours}
            />
          </div>
          <Field
            label="Keep every snapshot for this many rolling UTC days"
            name="retention"
            type="number"
            min="1"
            max="3650"
            value={state.data.retention_days || 30}
          />
          <label className="check">
            <input
              type="checkbox"
              name="forever"
              defaultChecked={state.data.retention_days === null}
            />
            Keep forever
          </label>
          <fieldset>
            <legend>Storage copies</legend>
            {destinations.length ? (
              destinations.map((x: Row) => (
                <div className="destination-choice" key={x.id}>
                  <label className="check">
                    <input
                      type="checkbox"
                      name={"destination-" + x.id}
                      defaultChecked={state.data.destinations?.some(
                        (v: Row) => v.destination_id === x.id,
                      )}
                    />
                    {x.name}
                  </label>
                  <label className="check small">
                    <input
                      type="checkbox"
                      name={"required-" + x.id}
                      defaultChecked={
                        state.data.destinations?.find(
                          (v: Row) => v.destination_id === x.id,
                        )?.required ?? true
                      }
                    />
                    Required
                  </label>
                </div>
              ))
            ) : (
              <p className="muted">Add and test a storage destination first.</p>
            )}
          </fieldset>
          <Select
            label="Isolated restore-test runner"
            name="runner"
            defaultValue={state.data.runner_id || ""}
          >
            <option value="">Restore testing not configured</option>
            {instances
              .filter((x: Row) => x.is_runner)
              .map((x: Row) => (
                <option key={x.id} value={x.id}>
                  {x.name}
                </option>
              ))}
          </Select>
          <p className="muted small">
            Pins, safety snapshots, active restore inputs and the latest
            complete/tested recovery points remain protected. Deletion freezes
            when protection is degraded or overdue.
          </p>
          <button
            type="button"
            className="secondary"
            disabled={previewBusy}
            onClick={async (e: any) => {
              const form = e.currentTarget.closest("form");
              const values = new FormData(form);
              setPreviewBusy(true); setPreviewError("");
              try {
                const retention_days = values.get("forever") === "on" ? null : Number(values.get("retention"));
                setPreview(await api("/instances/" + instance.id + "/retention-preview", "POST", { retention_days }));
              } catch (err) { setPreviewError((err as Error).message); }
              finally { setPreviewBusy(false); }
            }}
          >
            {previewBusy ? "Calculating exact eligible copies…" : "Preview this retention policy"}
          </button>
          {previewError && <p className="error" role="alert">{previewError}</p>}
          {preview && <RetentionReadout preview={preview} />}
        </Form>
      )}
    </LoadState>
  );
}
function DriveActions({ destination, onJob, notify }: any) {
  const [headless, setHeadless] = useState(false), [busy, setBusy] = useState(false), [error, setError] = useState("");
  return (
    <>
      <button className="secondary" onClick={async () => {
        try {
          const v = await api(`/storage-destinations/${destination.id}/authorize`, "POST", { mode: "browser" });
          const url = v.authorization_url || v.url;
          if (!url) throw new Error("Authorization URL unavailable. Check the destination setup and retry.");
          window.location.assign(url);
        } catch (e) { notify((e as Error).message); }
      }}>Authorize / reconnect <ArrowUpRight size={14} /></button>
      <button className="secondary" type="button" onClick={() => { setHeadless((v) => !v); setError(""); }}>Headless token import</button>
      {headless && <form className="drive-import" onSubmit={async (e) => {
        e.preventDefault(); if (busy) return; setBusy(true); setError("");
        const data = new FormData(e.currentTarget);
        try {
          const tokenFile = data.get("token_file") as File;
          const rawToken = tokenFile?.size ? await tokenFile.text() : String(data.get("token") || "");
          const token = JSON.parse(rawToken);
          const accepted = await api(`/storage-destinations/${destination.id}/authorize`, "POST", { mode: "headless", token });
          if (!accepted.job_id) throw new Error("Token import was not accepted as a background job.");
          onJob(accepted.job_id); setHeadless(false);
        } catch (err) { setError(err instanceof SyntaxError ? "Paste the complete token JSON returned by rclone authorize." : (err as Error).message); }
        finally { setBusy(false); }
      }}>
        <label className="field"><span>Token JSON file (recommended)</span><input type="file" name="token_file" accept=".json,application/json" /></label>
        <label className="field"><span>Or paste private token JSON</span><textarea name="token" autoComplete="off" spellCheck={false} style={{ WebkitTextSecurity: "disc" } as any} /></label>
        <p className="muted small">Choose the token object returned by the one-time rclone authorization or paste it. The content is sent in the request body and is not saved in browser storage or shown in the URL.</p>
        {error && <p role="alert" className="error">{error}</p>}
        <button className="primary" disabled={busy}>{busy ? "Submitting privately…" : "Validate and import token"}</button>
      </form>}
    </>
  );
}
function Notifications({ revision }: { revision: number }) {
  const state = useLoad("/notifications?limit=50", revision, 15000);
  return <section className="panel padded notification-panel">
    <div className="section-heading"><div><h2><Bell size={18} /> Alerts & delivery</h2><p className="muted small">Alert state and message delivery are tracked independently from backups.</p></div></div>
    <LoadState state={state}>
      {rows(state.data).length ? <div className="notification-list">{rows(state.data).map((alert: Row) => <article key={alert.id} className="notification-row">
        <div><Badge value={alert.active ? "active" : "recovered"} /><strong>{friendly(alert.code)}</strong><small>{date(alert.created_at)}</small></div>
        <div className="delivery-list">{alert.deliveries?.length ? alert.deliveries.map((delivery: Row, i: number) => <span key={delivery.channel_id + i}>Delivery {friendly(delivery.state)}{delivery.error_code ? ` · ${friendly(delivery.error_code)}` : ""}</span>) : <span>In-app alert recorded; no external delivery attempted.</span>}</div>
      </article>)}</div> : <p className="notice">No active or recovered alerts are recorded.</p>}
    </LoadState>
  </section>;
}
function StorageForm({ saved }: any) {
  const [backend, setBackend] = useState("local");
  return (
    <Form
      label="Save encrypted destination"
      submit={async (d) => {
        let configuration: Row = {},
          credentials: Row | undefined;
        if (backend === "local")
          configuration = { root: d.get("root"), path: d.get("root") };
        if (backend === "s3") {
          configuration = {
            endpoint: d.get("endpoint"),
            bucket: d.get("bucket"),
            prefix: d.get("prefix") || "",
            region: d.get("region"),
            addressing_mode: d.get("addressing"),
            allow_insecure_local: d.get("development") === "on",
            ca_cert_pem: d.get("ca_cert_pem") || null,
          };
          credentials = {
            access_key_id: d.get("access_key"),
            secret_access_key: d.get("secret_key"),
          };
        }
        if (backend === "drive") {
          configuration = {
            folder_id: d.get("folder_id"),
            root_folder_id: d.get("folder_id"),
            client_id: d.get("client_id"),
            scope: "drive.file",
          };
          credentials = {
            client_id: d.get("client_id"),
            client_secret: d.get("client_secret"),
          };
        }
        await api("/storage-destinations", "POST", {
          name: d.get("name"),
          backend,
          configuration,
          credentials,
        });
        saved();
      }}
    >
      <Field label="Destination name" name="name" />
      <label className="field">
        <span>Storage provider</span>
        <select value={backend} onChange={(e) => setBackend(e.target.value)}>
          <option value="local">Local persistent disk</option>
          <option value="s3">S3-compatible storage</option>
          <option value="drive">Google Drive</option>
        </select>
      </label>
      {backend === "local" ? (
        <>
          <Field
            label="Mounted repository root"
            name="root"
            value="/var/lib/vaultrewind/backups"
          />
          <p className="muted small">
            This must be the persistent host directory configured during
            installation. Missing mounts fail instead of writing to the
            container layer.
          </p>
        </>
      ) : backend === "s3" ? (
        <>
          <Field
            label="HTTPS endpoint"
            name="endpoint"
            type="url"
            placeholder="https://s3.example.com"
          />
          <div className="form-grid">
            <Field label="Bucket" name="bucket" />
            <Field label="Prefix" name="prefix" value="" help="Optional bucket subdirectory. Leave empty for the standard vaultrewind/ layout." />
            <Field label="Region" name="region" value="us-east-1" />
            <Select label="Addressing" name="addressing" defaultValue="auto">
              <option value="auto">Automatic</option>
              <option value="path">Path</option>
              <option value="dns">DNS / virtual host</option>
            </Select>
          </div>
          <Field label="Access key ID" name="access_key" type="password" />
          <Field label="Secret access key" name="secret_key" type="password" autoComplete="new-password" />
          <Textarea label="Custom CA certificate (PEM, optional)" name="ca_cert_pem" required={false} rows={5} spellCheck={false} />
          <label className="check">
            <input type="checkbox" name="development" />
            Explicit loopback HTTP development fixture
          </label>
          <p className="muted small">
            Grant list/read/write permissions for backup and delete permissions
            for retention. Lifecycle rules must preserve retained repository
            chunks.
          </p>
        </>
      ) : (
        <>
          <Field
            label="Your OAuth client ID"
            name="client_id"
            autoComplete="off"
          />
          <Field
            label="OAuth client secret"
            name="client_secret"
            type="password"
            autoComplete="off"
          />
          <Field
            label="Dedicated folder ID (optional)"
            name="folder_id"
            required={false}
          />
          <p className="muted small">
            Save, then choose Authorize / reconnect to grant access in Google’s
            browser flow. The drive.file scope limits access to app-created
            files. Personal Drive support; shared drives require separate
            validation.
          </p>
        </>
      )}
    </Form>
  );
}
function Recovery({ admin, execute }: any) {
  return (
    <>
      <PageHeading
        title="A recovery plan beyond this controller."
        description="An independently encrypted kit unlocks your repositories after total controller loss."
      />
      <div className="two-columns">
        <section className="panel padded">
          <KeyRound className="feature-icon" />
          <h2>Export your recovery kit</h2>
          <p className="muted">
            Keep the kit and passphrase outside both Vaultwarden and
            VaultRewind. It works without this database or master key.
          </p>
          {admin ? (
            <RecoveryExportForm execute={execute} />
          ) : (
            <p>Administrator access required.</p>
          )}
        </section>
        <section className="panel padded">
          <RotateCcw className="feature-icon" />
          <h2>Recover existing repositories</h2>
          <p className="muted">
            Import a kit into protected mode. Automatic retention remains
            disabled until policies are reviewed.
          </p>
          {admin && (
            <RecoveryImportForm execute={execute} />
          )}
        </section>
      </div>
      <section className="notice">
        <ShieldCheck size={20} />
        <p>
          The offline CLI can discover, verify and recover repository content
          when the controller is unavailable. A prepared target still uses the
          same safety and activation protocol. Back up the controller’s
          PostgreSQL metadata separately.
        </p>
      </section>
    </>
  );
}

function RecoveryImportForm({ execute }: any) {
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  return <form onSubmit={async (event) => {
    event.preventDefault();
    if (busy) return;
    const form = event.currentTarget;
    const data = new FormData(form);
    setBusy(true); setError("");
    try {
      const file = data.get("kit") as File;
      await execute("/recovery/import-plans", {
        kit: await file.text(),
        passphrase: data.get("passphrase"),
      });
    } catch (failure) {
      setError((failure as Error).message);
    } finally {
      form.reset();
      setBusy(false);
    }
  }}>
    <Field label="Encrypted kit file" name="kit" type="file" accept=".json,.vrkit,.txt" />
    <Field label="Kit passphrase" name="passphrase" type="password" minLength={16} autoComplete="off" />
    {error && <p role="alert" className="error">{error}</p>}
    <button className="primary" disabled={busy}>{busy ? "Discovering recovery points…" : "Discover recovery points"}<ArrowRight size={16} /></button>
  </form>;
}

function RecoveryExportForm({ execute }: any) {
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  return <form onSubmit={async (event) => {
    event.preventDefault();
    if (busy) return;
    const form = event.currentTarget, data = new FormData(form);
    setBusy(true); setError("");
    try { await execute("/recovery-kits/export", { passphrase: data.get("passphrase") }); }
    catch (failure) { setError((failure as Error).message); }
    finally { form.reset(); setBusy(false); }
  }}>
    <Field label="User-held recovery passphrase" name="passphrase" type="password" minLength={16} autoComplete="new-password" help="Use at least 16 characters. Keep it in an independent safe location." />
    {error && <p role="alert" className="error">{error}</p>}
    <button className="primary" disabled={busy}>{busy ? "Creating encrypted kit…" : "Create encrypted kit"}<ArrowRight size={16} /></button>
  </form>;
}
function Doctor({ revision, execute, admin }: any) {
  const state = useLoad("/doctor", revision, 15000);
  return (
    <>
      <PageHeading
        title="Integrity & readiness"
        description="Read-only checks expose incomplete protection and unresolved recovery state."
        action={
          admin ? (
            <ActionButton action={() => execute("/doctor")}>
              Run connection diagnostics
            </ActionButton>
          ) : null
        }
      />
      <LoadState state={state}>
        <section className="panel padded">
          <h2>Controller checks</h2>
          <div className="diagnostic-list">
            {(state.data?.checks || []).map((check: Row) => (
              <div key={check.code + check.object_id} className="diagnostic">
                <AlertTriangle size={17} />
                <div>
                  <strong>{friendly(check.code).toLowerCase()}</strong>
                  <p>{diagnosticAction(check.code)}</p>
                  <small className="mono">{check.object_id}</small>
                </div>
              </div>
            ))}
            {state.data?.checks?.length === 0 && (
              <p className="notice">
                All configured catalog readiness checks pass. Repository data
                verification is recorded separately.
              </p>
            )}
          </div>
        </section>
      </LoadState>
      <p className="muted footnote">
        Connection diagnostics may write scoped probe objects and refresh
        provider credentials. Read-only status above does neither.
      </p>
    </>
  );
}
function Audit({ revision, admin }: any) {
  const state = useLoad(admin ? "/audit-events?limit=100" : null, revision);
  return (
    <>
      <PageHeading
        title="Audit trail"
        description="Actors, object IDs and outcomes. Vault payloads and secret values stay out of history."
      />
      {!admin ? (
        <div className="notice">
          Audit history requires administrator access.
        </div>
      ) : (
        <LoadState state={state}>
          <div className="panel table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Action</th>
                  <th>Outcome</th>
                  <th>Actor</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {rows(state.data).map((r: Row) => (
                  <tr key={r.id}>
                    <td>{r.action}</td>
                    <td>
                      <Badge value={r.outcome} />
                    </td>
                    <td className="mono">
                      {r.actor_id?.slice(0, 8) || "System"}
                    </td>
                    <td>{date(r.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!rows(state.data).length && <Empty title="No audit events" />}
          </div>
        </LoadState>
      )}
    </>
  );
}
function ControllerProtection({ admin }: { admin: boolean }) {
  const [revision, setRevision] = useState(0),
    [notice, setNotice] = useState(""),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [selectedDestination, setSelectedDestination] = useState(""),
    [jobId, setJobId] = useState("");
  const policy = useLoad("/controller-backup-policy", revision, 10000),
    backupData = useLoad("/controller-backups", revision, 10000),
    destinations = useLoad("/storage-destinations", revision, 30000),
    job = useLoad(jobId ? "/jobs/" + jobId : null, revision, 2000);
  useEffect(() => {
    if (!selectedDestination && policy.data?.destination_id) setSelectedDestination(policy.data.destination_id);
  }, [policy.data?.destination_id]);
  useEffect(() => {
    if (job.data && terminal.has(job.data.state)) setRevision((v) => v + 1);
  }, [job.data?.state]);
  const status = backupData.data?.status || {};
  const items = rows(backupData.data?.items).filter((item: Row) => item.state === "complete");
  const configuredDestinations = rows(destinations.data);
  return <section className="panel padded controller-protection">
    <div className="panel-heading">
      <ShieldCheck className="feature-icon" />
      <div><h2>Controller metadata protection</h2>
        <p className="muted">Encrypted PostgreSQL recovery snapshots. The controller master key is separate and is not included in these backups.</p>
      </div>
    </div>
    <div className="diagnostic-list">
      <div className="diagnostic"><Clock size={17} /><div><strong>{status.stale ? "Stale or not yet backed up" : "Recent controller backup"}</strong><p>Last success: {date(status.last_captured_at)}{status.max_age_days ? ` · stale after ${status.max_age_days} days` : ""}</p></div></div>
      <div className="diagnostic"><HardDrive size={17} /><div><strong>Scheduled protection: {status.enabled ? "enabled" : "disabled"}</strong><p>{status.configured ? `${status.daily_time || ""} ${status.timezone || "UTC"} · next ${date(status.next_run_at)}` : "Choose a destination and save a daily schedule."}</p></div></div>
      {status.last_state && status.last_state !== "complete" && <div className="diagnostic"><AlertTriangle size={17} /><div><strong>Latest attempt: {friendly(status.last_state)}</strong><p>{status.last_error_code ? friendly(status.last_error_code) : "Check the persisted job for details."}</p></div></div>}
      {job.data && <div className="diagnostic"><Activity size={17} /><div><strong>Manual backup: {friendly(job.data.state)} · {friendly(job.data.phase || "queued")}</strong><p>{job.data.error_code ? friendly(job.data.error_code) : "This job continues if you leave Settings."}</p></div></div>}
    </div>
    {error && <p role="alert" className="error">{error}</p>}
    {notice && <p role="status" className="notice">{notice}</p>}
    {admin && <>
      <h3>Daily backup policy</h3>
      <form key={`${policy.data?.revision ?? "loading"}-${policy.data?.destination_id ?? "none"}`} onSubmit={async (event) => {
        event.preventDefault();
        if (busy) return;
        const form = event.currentTarget, data = new FormData(form);
        setBusy(true); setError(""); setNotice("");
        try {
          const next = await api("/controller-backup-policy", "PUT", {
            destination_id: data.get("destination_id"),
            enabled: data.get("enabled") === "on",
            timezone: String(data.get("timezone") || "UTC").trim(),
            daily_time: data.get("daily_time"),
          }, { "If-Match": String(policy.data?.revision ?? 0) });
          setRevision((v) => v + 1);
          setNotice(`Controller backup policy saved (revision ${next.revision}).`);
        } catch (failure) { setError((failure as Error).message); }
        finally { setBusy(false); }
      }}>
        <label className="field"><span>Backup destination</span><select name="destination_id" required value={selectedDestination} onChange={(event) => setSelectedDestination(event.target.value)}>
          <option value="" disabled>Choose a configured destination</option>
          {configuredDestinations.map((destination: Row) => <option key={destination.id} value={destination.id}>{destination.name} · {destination.backend} · {friendly(destination.health)}</option>)}
        </select><small>Supports configured local disk, S3-compatible storage, and Google Drive destinations.</small></label>
        <div className="form-grid">
          <label className="field"><span>Daily time</span><input name="daily_time" type="time" required defaultValue={policy.data?.daily_time || "02:00"} /></label>
          <label className="field"><span>IANA timezone</span><input name="timezone" required defaultValue={policy.data?.timezone || "UTC"} placeholder="America/New_York" /></label>
        </div>
        <label className="check"><input name="enabled" type="checkbox" defaultChecked={policy.data?.enabled ?? true} />Enable daily controller backups</label>
        <button className="secondary" disabled={busy || !configuredDestinations.length}>{busy ? "Saving policy…" : "Save daily policy"}</button>
      </form>
      <button className="primary" disabled={busy || !selectedDestination} onClick={async () => {
        if (busy) return;
        setBusy(true); setError(""); setNotice("");
        try {
          const accepted = await api("/controller-backups", "POST", { destination_id: selectedDestination });
          if (!accepted.job_id) throw new Error("The controller backup was not queued.");
          setJobId(accepted.job_id); setRevision((v) => v + 1); setNotice("Controller backup queued. Its status remains available in this card.");
        } catch (failure) { setError((failure as Error).message); }
        finally { setBusy(false); }
      }}>{busy ? "Queueing backup…" : "Back up controller now"}<ArrowRight size={16} /></button>
    </>}
    {items.length > 0 && <>
      <h3>Recent controller recovery points</h3>
      <div className="table-wrap"><table><thead><tr><th>Captured</th><th>Destination</th><th>PostgreSQL dump</th><th>Size</th><th>Restic snapshot</th></tr></thead>
        <tbody>{items.slice(0, 8).map((item: Row) => {
          const destination = configuredDestinations.find((d: Row) => d.id === item.destination_id);
          return <tr key={item.id}><td>{date(item.captured_at)}</td><td>{destination?.name || item.destination_id}</td><td>{item.pg_dump_included ? "Verified" : "Missing"}</td><td>{bytes(item.bytes)}</td><td className="mono">{item.restic_snapshot_id || "Pending"}</td></tr>;
        })}</tbody>
      </table></div>
    </>}
    <p className="muted small">Keep a separate copy of the independently encrypted recovery kit and keep the controller master key outside the database, repositories, and kit. Losing the master key prevents decrypting database secret envelopes.</p>
  </section>;
}

function SettingsPage({ admin, saved }: any) {
  const [channel, setChannel] = useState("smtp");
  return (
    <>
      <PageHeading
        title="Workspace settings"
        description="Manage access and sanitized operational notifications."
      />
      <ControllerProtection admin={admin} />
      {!admin ? (
        <div className="notice">
          Administrator access is required to change settings.
        </div>
      ) : (
        <div className="two-columns">
          <section className="panel padded">
            <h2>Create workspace account</h2>
            <Form
              label="Create account"
              submit={async (d) => {
                await api("/users", "POST", {
                  username: d.get("username"),
                  password: d.get("password"),
                  role: d.get("role"),
                  timezone: "UTC",
                });
                saved("Workspace account created.");
              }}
            >
              <Field label="Username" name="username" autoComplete="off" />
              <Field
                label="Temporary password"
                name="password"
                type="password"
                minLength={12}
                autoComplete="new-password"
              />
              <Select label="Role" name="role">
                <option value="viewer">Viewer — read-only status</option>
                <option value="administrator">
                  Administrator — manage recovery
                </option>
              </Select>
            </Form>
            <h3>Revoke user sessions</h3>
            <p className="muted small">Use the exact user ID from the audit or account record. This revokes every active session for that user, including their current session.</p>
            <Form label="Revoke all sessions" submit={async (d) => {
              await api("/sessions/revoke", "POST", { user_id: d.get("user_id") });
              saved("All sessions for the selected user were revoked. They will need to sign in again.");
            }}>
              <Field label="User ID" name="user_id" autoComplete="off" />
            </Form>
          </section>
          <section className="panel padded">
            <h2>External notifications</h2>
            <p className="muted">The controller SMTP host and sender address come from its environment. Recipients and optional SMTP credentials are encrypted as channel configuration. Delivery failures remain visible separately.</p>
            <Select label="Channel type" name="channel-type" value={channel} onChange={(e: any) => setChannel(e.target.value)}>
              <option value="smtp">SMTP email</option><option value="webhook">HTTPS webhook</option>
            </Select>
            {channel === "smtp" ? <Form label="Save SMTP recipients" submit={async (d) => {
              const recipients = String(d.get("recipients") || "").split(/[;,\\n]/).map((x) => x.trim()).filter(Boolean);
              await api("/notification-channels", "POST", { kind: "smtp", configuration: { recipients, username: d.get("username") || undefined, password: d.get("password") || undefined } });
              saved("SMTP notification channel saved encrypted.");
            }}>
              <Textarea label="Recipients (one per line)" name="recipients" required rows={3} />
              <Field label="SMTP username (optional)" name="username" required={false} autoComplete="off" />
              <Field label="SMTP password (optional)" name="password" type="password" required={false} autoComplete="new-password" />
              <p className="muted small">Configure VAULTREWIND_SMTP_HOST and VAULTREWIND_SMTP_FROM on the controller. Email uses STARTTLS with certificate validation.</p>
            </Form> : <Form label="Save webhook channel" submit={async (d) => {
              await api("/notification-channels", "POST", { kind: "webhook", configuration: { url: d.get("url"), signing_secret: d.get("secret") || undefined } });
              saved("Webhook notification channel saved encrypted.");
            }}>
              <Field label="HTTPS webhook URL" name="url" type="url" />
              <Field label="Signing secret (optional)" name="secret" type="password" required={false} autoComplete="new-password" />
              <p className="muted small">The host must be on the controller allowlist. TLS is verified and payloads contain sanitized status only.</p>
            </Form>}
          </section>
        </div>
      )}
    </>
  );
}
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);

function RetentionReadout({ preview }: { preview: Row }) {
  return (
    <section className="retention-readout">
      <h3>
        {preview.frozen
          ? "Automatic deletion is frozen"
          : `${preview.copy_ids?.length || 0} copies eligible for expiration`}
      </h3>
      <p className="muted small">
        {preview.cutoff
          ? `Keep every capture at or after ${date(preview.cutoff)} UTC.`
          : "Keep forever — no automatic expiration."}
      </p>
      {preview.freeze_reasons?.map((r: string) => (
        <p className="notice" key={r}>
          {friendly(r)}
        </p>
      ))}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Captured</th>
              <th>Planned expiry</th>
              <th>Protection</th>
            </tr>
          </thead>
          <tbody>
            {preview.entries?.map((e: Row) => (
              <tr key={e.copy_id}>
                <td>{date(e.captured_at)}</td>
                <td>{date(e.expires_at)}</td>
                <td>
                  {e.protections?.length
                    ? e.protections.map(friendly).join(", ")
                    : e.eligible
                      ? "Eligible for deletion"
                      : "Retained"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
function diagnosticAction(code: string) {
  const messages: Record<string, string> = {
    HELPER_NOT_READY:
      "Review host activation and verify the compatible watchdog and boot recovery units.",
    STALE_JOB_RECONCILIATION_REQUIRED:
      "Let the worker reconcile the remote journal before starting overlapping operations.",
    MANUAL_RECOVERY_REQUIRED:
      "Preserve both generations and review the job’s activation/rollback evidence before a new confirmed recovery.",
    CLEANUP_FAILED:
      "Inspect staging capacity and retry cleanup after confirming no active recovery uses it.",
    REPOSITORY_REVIEW_REQUIRED:
      "Test repository access and review imported content. Automatic deletion remains protected.",
    RESTORE_TESTING_NOT_CONFIGURED:
      "Enroll a dedicated isolated verification runner and select it in the instance policy.",
    RECOVERY_KIT_NOT_EXPORTED:
      "Export an independently encrypted recovery kit and keep its passphrase outside both applications.",
  };
  return (
    messages[code] ||
    "Inspect the related persisted operation and resolve its stated prerequisite."
  );
}
