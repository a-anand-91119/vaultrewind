import { useState } from "react";
import type { FormEvent } from "react";
import { api, APIError } from "./api";

type DestinationRow = { id: string; name: string; backend: string };
type Detail = DestinationRow & {
  revision: number; health: string; configuration: Record<string, any>;
  credential_flags: Record<string, boolean>; physical_identity_locked: boolean;
};
const failureText = (error: unknown) => error instanceof APIError
  ? `${error.code}: ${error.message}` : "Could not save the destination. Reload its current settings and retry.";

/** Render only for administrators. The detail and mutation endpoints enforce that role too. */
export function DestinationEditor({ destination, onSaved }: {
  destination: DestinationRow; onSaved: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [detail, setDetail] = useState<Detail | null>(null);
  const [config, setConfig] = useState<Record<string, any>>({});
  const [name, setName] = useState(destination.name);
  const [replace, setReplace] = useState(false);
  const [first, setFirst] = useState("");
  const [second, setSecond] = useState("");
  const [token, setToken] = useState("");
  const [ca, setCa] = useState("");
  const [caAction, setCaAction] = useState("keep");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const path = `/storage-destinations/${encodeURIComponent(destination.id)}`;
  const clearPrivate = () => { setFirst(""); setSecond(""); setToken(""); setCa(""); setReplace(false); setCaAction("keep"); };
  const load = async () => {
    setBusy(true); setError(""); clearPrivate();
    try {
      const current: Detail = await api(path);
      setDetail(current); setConfig(current.configuration); setName(current.name); setOpen(true);
    } catch (error) { setError(failureText(error)); }
    finally { setBusy(false); }
  };
  const change = (key: string, value: unknown) => setConfig((previous) => ({ ...previous, [key]: value }));
  const input = (key: string, label: string, identity = false, type = "text") => <label className="field" key={key}>
    <span>{label}{identity && detail?.physical_identity_locked ? " (existing repository identity)" : ""}</span>
    <input type={type} value={config[key] ?? ""} disabled={busy || (identity && detail?.physical_identity_locked)}
      onChange={(event) => change(key, type === "number" ? Number(event.target.value) : event.target.value)}
      min={type === "number" ? 0 : undefined} step={type === "number" ? 1 : undefined} />
  </label>;
  const checkbox = (key: string, label: string) => <label className="check" key={key}>
    <input type="checkbox" checked={!!config[key]} disabled={busy}
      onChange={(event) => change(key, event.target.checked)} /> {label}
  </label>;
  const save = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); if (!detail) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const delta: Record<string, any> = {};
      for (const [key, value] of Object.entries(config))
        if (key !== "custom_ca" && value !== detail.configuration[key]) delta[key] = value;
      if (caAction === "replace") delta.ca_cert_pem = ca;
      if (caAction === "remove") delta.ca_cert_pem = null;
      const body: Record<string, any> = { name };
      if (Object.keys(delta).length) body.configuration = delta;
      if (replace && (first || second || token)) {
        if (!first || !second) throw new APIError("STORAGE_CREDENTIALS_INVALID", "Enter both replacement values, or leave both blank to retain the current credentials.");
        body.credentials = destination.backend === "s3"
          ? { access_key_id: first, secret_access_key: second, ...(token ? { session_token: token } : {}) }
          : { client_id: first, client_secret: second };
      }
      const saved: Detail = await api(path, "PATCH", body, { "If-Match": `"${detail.revision}"` });
      setDetail(saved); setName(saved.name); setConfig(saved.configuration); clearPrivate();
      setNotice(saved.health === "reauthorization_required"
        ? "Saved. Reconnect Google Drive with the new client before testing or retrying a copy. Export a current encrypted recovery kit after reconnecting."
        : "Saved. Test the connection, then retry the failed copy from its snapshot to reuse the same recovery point without another source pause. Export a current encrypted recovery kit after changing storage access.");
      onSaved();
    } catch (error) { setError(failureText(error)); }
    finally { setBusy(false); }
  };
  const test = async () => {
    setBusy(true); setError("");
    try {
      const accepted = await api(`${path}/test`, "POST", {});
      setNotice(`Connection test queued (${accepted.job_id}). It writes, reads and deletes a scoped probe; Drive may refresh its token. Inspect the job before retrying the failed copy.`);
      onSaved();
    } catch (error) { setError(failureText(error)); }
    finally { setBusy(false); }
  };
  const reconnect = async () => {
    setBusy(true); setError("");
    try {
      const result = await api(`${path}/authorize`, "POST", { mode: "browser" });
      clearPrivate(); window.location.assign(result.authorization_url);
    } catch (error) { setError(failureText(error)); setBusy(false); }
  };
  return <div>
    {!open && <button className="secondary" disabled={busy} onClick={() => void load()}>
      {busy ? "Loading settings…" : "Edit destination"}
    </button>}
    {error && <p role="alert" className="error">{error}</p>}
    {open && detail && <section className="panel" aria-label={`Edit ${destination.name}`}>
      <h3>Edit {destination.name}</h3>
      <p>Physical repository changes require a new destination. Keep this destination to retain access to older copies.
        Saving updates private controller settings; use Test connection to check provider access.</p>
      <form onSubmit={(event) => void save(event)} autoComplete="off">
        <fieldset disabled={busy}>
          <legend>Destination settings</legend>
          <label className="field"><span>Destination name</span><input required maxLength={120} value={name}
            onChange={(event) => setName(event.target.value)} /></label>
          {destination.backend === "local" && <>
            {input("path", "Controller mount directory", true)}
            {input("host_path", "Displayed host directory")}
            {input("min_free_bytes", "Minimum free space (bytes)", false, "number")}
            {checkbox("require_dedicated_mount", "Require dedicated persistent mount")}
            {checkbox("allow_unlisted_filesystems", "Allow an unlisted filesystem after administrator review")}
          </>}
          {destination.backend === "s3" && <>
            {input("endpoint", "S3 endpoint", true)}{input("bucket", "Bucket", true)}{input("prefix", "Prefix", true)}
            {input("region", "Region")}
            <label className="field"><span>Bucket addressing</span><select value={config.bucket_lookup || "auto"}
              onChange={(event) => change("bucket_lookup", event.target.value)}>
              <option value="auto">Automatic</option><option value="path">Path</option><option value="dns">DNS</option>
            </select></label>
            {checkbox("development_http", "Allow HTTP for a local development fixture")}
            <label className="field"><span>Custom CA: {config.custom_ca ? "configured" : "not configured"}</span>
              <select value={caAction} onChange={(event) => setCaAction(event.target.value)}>
                <option value="keep">Keep current CA setting</option><option value="replace">Replace certificate bundle</option>
                <option value="remove">Remove custom CA (use system trust)</option>
              </select>
            </label>
            {caAction === "replace" && <label className="field"><span>New CA certificate bundle (PEM certificates only)</span>
              <textarea required value={ca} onChange={(event) => setCa(event.target.value)} spellCheck={false} />
            </label>}
          </>}
          {destination.backend === "drive" && <>
            {input("folder_id", "Drive folder ID", true)}{input("folder_name", "Folder display name")}
            <p>Scope: drive.file. Authorization: {detail.credential_flags.authorized ? "configured" : "reconnect required"}.</p>
          </>}
        </fieldset>
        {destination.backend !== "local" && <fieldset disabled={busy}>
          <legend>Private credentials</legend>
          <p>{destination.backend === "s3"
            ? `Access key pair: ${detail.credential_flags.access_key_id && detail.credential_flags.secret_access_key ? "configured" : "not configured"}.`
            : `Google client pair: ${detail.credential_flags.client_id && detail.credential_flags.client_secret ? "configured" : "not configured"}.`}
            {" "}Stored values are never returned. Blank replacement fields keep the current pair.</p>
          <label className="check"><input type="checkbox" checked={replace}
            onChange={(event) => { setReplace(event.target.checked); setFirst(""); setSecond(""); setToken(""); }} />
            Replace private {destination.backend === "s3" ? "S3 key pair" : "Google OAuth client pair"}</label>
          {replace && <>
            {destination.backend === "drive" && <p>Replacing the client immediately disables the old local grant and token.
              Save, then reconnect Google Drive. No external Google revocation request is sent.</p>}
            <label className="field"><span>New {destination.backend === "s3" ? "access key ID" : "client ID"}</span>
              <input type="password" autoComplete="new-password" value={first} spellCheck={false}
                onChange={(event) => setFirst(event.target.value)} /></label>
            <label className="field"><span>New {destination.backend === "s3" ? "secret access key" : "client secret"}</span>
              <input type="password" autoComplete="new-password" value={second} spellCheck={false}
                onChange={(event) => setSecond(event.target.value)} /></label>
            {destination.backend === "s3" && <label className="field"><span>New session token (optional; blank clears old token with replacement pair)</span>
              <input type="password" autoComplete="new-password" value={token} spellCheck={false}
                onChange={(event) => setToken(event.target.value)} /></label>}
          </>}
        </fieldset>}
        <div className="actions"><button className="primary" disabled={busy}>{busy ? "Saving…" : "Save changes"}</button>
          <button type="button" className="secondary" disabled={busy} onClick={() => void load()}>Reload current settings</button>
          <button type="button" className="secondary" disabled={busy}
            onClick={() => { clearPrivate(); setOpen(false); setError(""); setNotice(""); }}>Close editor</button>
        </div>
      </form>
      <div className="actions">
        <button className="secondary" disabled={busy} onClick={() => void test()}>Test saved connection</button>
        {destination.backend === "drive" && <button className="secondary" disabled={busy}
          onClick={() => void reconnect()}>Reconnect saved Google Drive client</button>}
      </div>
      {notice && <p role="status">{notice}</p>}
    </section>}
  </div>;
}
