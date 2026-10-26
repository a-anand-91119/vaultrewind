import { test, expect } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
const privateRoot = path.resolve("../.runtime/controller");
function sourceReadback() {
  return JSON.parse(execFileSync(path.resolve("../.venv/bin/python"), ["-c", `
import hashlib,json,sqlite3,subprocess
from pathlib import Path
v=json.loads(subprocess.check_output(['docker','inspect','vr-ssh-source']))[0]
assert v['State']['Running']
root=Path(next(m['Source'] for m in v['Mounts'] if m['Destination']=='/data'))
assert str(root).startswith('/srv/vaultrewind-fixtures/')
with sqlite3.connect('file:'+str(root/'db.sqlite3')+'?mode=ro',uri=True) as db:
    dump='\\n'.join(db.iterdump()).encode()
files={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob('*')) if p.is_file() and p.name not in {'db.sqlite3','db.sqlite3-wal','db.sqlite3-shm'} and not p.is_symlink()}
print(json.dumps({'started_at':v['State']['StartedAt'],'image_id':v['Image'],'sqlite_dump_sha256':hashlib.sha256(dump).hexdigest(),'files':files}))
`], { encoding: "utf8", timeout: 30000 }));
}
async function login(page: any) {
  await page.goto("/");
  await page.getByLabel("Username", { exact: true }).fill("synthetic-admin");
  await page
    .getByLabel("Password", { exact: true })
    .fill(fs.readFileSync(path.join(privateRoot, "admin-password"), "utf8"));
  const fleetResponse = page.waitForResponse(
    (r: any) => new URL(r.url()).pathname === "/api/v1/instances",
  );
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  expect((await fleetResponse).status()).toBe(200);
  await expect(
    page.getByRole("heading", { name: "Every vault. A way back." }),
  ).toBeVisible();
  await expect(
    page.getByText("Sign in to continue.", { exact: true }),
  ).not.toBeVisible();
  await expect(
    page
      .getByText("Give your first vault a way back.", { exact: true })
      .or(page.locator("article.instance-card").first()),
  ).toBeVisible();
}
test("real session, private enrollment dialog, keyboard focus and narrow layout", async ({
  page,
}) => {
  await login(page);
  const connect = page.getByRole("button", {
    name: "Connect instance",
    exact: true,
  });
  await connect.click();
  const dialog = page.getByRole("dialog");
  await expect(
    dialog.getByRole("heading", { name: "Connect a host" }),
  ).toBeVisible();
  await expect(dialog.getByLabel("SSH private key")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(dialog).not.toBeVisible();
  await expect(connect).toBeFocused();
  await page.screenshot({
    path: "../docs/evidence/dashboard-desktop.png",
    fullPage: true,
  });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("button", { name: "Open navigation" }).click();
  await page.getByRole("button", { name: "Storage", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Encrypted storage" }),
  ).toBeVisible();
  await expect
    .poll(() =>
      page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
    )
    .toBeTruthy();
  await page.screenshot({
    path: "../docs/evidence/storage-mobile.png",
    fullPage: true,
  });
});
test("Backup now survives reload and records a real complete recovery point", async ({
  page,
}) => {
  test.setTimeout(420000);
  const file = path.join(privateRoot, "integration.json");
  test.skip(
    !fs.existsSync(file),
    "Requires explicit disposable SSH/systemd fixture enrollment",
  );
  const fixture = JSON.parse(fs.readFileSync(file, "utf8"));
  await login(page);
  const card = page.locator("article.instance-card").filter({
    has: page.getByRole("button", { name: fixture.source_name, exact: true }),
  });
  const acceptedResponse = page.waitForResponse((r) => r.request().method() === "POST" && new URL(r.url()).pathname === `/api/v1/instances/${fixture.source_id}/backups`);
  await card.getByRole("button", { name: "Backup now", exact: true }).click();
  const response = await acceptedResponse;
  expect(response.status()).toBe(202);
  const accepted = await response.json();
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.reload();
  await expect(
    page.getByRole("heading", { name: "Every vault. A way back." }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: fixture.source_name, exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Dated snapshots" }),
  ).toBeVisible();
  let finalJob: any;
  await expect.poll(async () => {
    finalJob = await (await page.request.get(accepted.status_url)).json();
    return finalJob.state;
  }, { timeout: 360000, intervals: [1500, 3000] }).toBe("succeeded");
  expect(finalJob.content_commit).toBe("complete");
  expect(finalJob.source_service_outcome).toBe("running");
  await expect(page.locator(`[data-snapshot-id="${finalJob.result.snapshot_id}"]`).getByRole("button", { name: "Restore", exact: true })).toBeEnabled();
  await page.screenshot({
    path: "../docs/evidence/snapshots-real.png",
    fullPage: true,
  });
});
test("original-target restore has one exact confirmation and creates a pinned safety point", async ({
  page,
}) => {
  test.setTimeout(600000);
  const file = path.join(privateRoot, "integration.json");
  test.skip(!fs.existsSync(file), "Requires disposable SSH fixture");
  const fixture = JSON.parse(fs.readFileSync(file, "utf8"));
  await login(page);
  await page
    .getByRole("button", { name: fixture.source_name, exact: true })
    .click();
  await page
    .locator(".snapshot")
    .first()
    .getByRole("button", { name: "Restore", exact: true })
    .click();
  const dialog = page.getByRole("dialog");
  await expect(
    dialog.getByRole("heading", { name: "Restore snapshot", exact: true }),
  ).toBeVisible();
  await expect(dialog.getByLabel("Destination")).toHaveValue(fixture.source_id);
  const acceptedResponse = page.waitForResponse((r) => r.request().method() === "POST" && /\/restore-plans\/[^/]+\/execute$/.test(new URL(r.url()).pathname));
  await dialog
    .getByRole("button", { name: "Confirm restore", exact: true })
    .click();
  const accepted = await (await acceptedResponse).json();
  let result: any;
  await expect.poll(async () => {
    result = await (await page.request.get(accepted.status_url)).json();
    return ["succeeded", "failed", "partial", "needs_attention", "rollback_failed", "rolled_back", "cancelled"].includes(result.state);
  }, { timeout: 540000, intervals: [1500, 3000] }).toBeTruthy();
  expect(result.error_code).toBeNull();
  expect(result.state).toBe("succeeded");
  expect(result.result.public_ports_verified).toBe(true);
  expect(result.result.public_endpoint_verified).toBe(true);
  await expect(page.getByRole("dialog").getByText("succeeded", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Close dialog" }).click();
  await expect(
    page.getByText("Safety snapshot", { exact: true }).first(),
  ).toBeVisible({ timeout: 15000 });
  await page.screenshot({
    path: "../docs/evidence/restore-real.png",
    fullPage: true,
  });
});

test("real snapshot pinning protects it, retention preview shows exact expirations, and protected deletion fails clearly", async ({ page }) => {
  const file = path.join(privateRoot, "integration.json");
  test.skip(!fs.existsSync(file), "Requires the disposable SSH/systemd integration fixture");
  const fixture = JSON.parse(fs.readFileSync(file, "utf8"));
  await login(page);
  await page.getByRole("button", { name: fixture.source_name, exact: true }).click();
  const points = await (await page.request.get(`/api/v1/instances/${fixture.source_id}/snapshots`)).json();
  const selected = points.items.find((point: any) => !point.safety && point.completeness === "complete");
  expect(selected).toBeTruthy();
  const selectedId = selected.id;
  const snapshot = page.locator(`[data-snapshot-id="${selectedId}"]`);
  if (!(await snapshot.locator("details").evaluate((el: HTMLDetailsElement) => el.open))) {
    await snapshot.getByText("More actions").click();
  }
  if (selected.pinned) {
    const unpin = page.waitForResponse((r) => new URL(r.url()).pathname === `/api/v1/snapshots/${selectedId}/pin` && r.request().method() === "DELETE");
    await snapshot.getByRole("button", { name: "Unpin snapshot", exact: true }).click();
    expect((await unpin).status()).toBe(200);
    await expect(snapshot.locator('[aria-label="Pinned"]')).not.toBeVisible();
    if (!(await snapshot.locator("details").evaluate((el: HTMLDetailsElement) => el.open))) {
      await snapshot.getByText("More actions").click();
    }
  }
  const pinResponse = page.waitForResponse((r) => new URL(r.url()).pathname === `/api/v1/snapshots/${selectedId}/pin` && r.request().method() === "POST", { timeout: 15000 });
  await snapshot.getByRole("button", { name: /Pin snapshot/ }).click();
  expect((await pinResponse).status()).toBe(200);
  await expect(snapshot.locator('[aria-label="Pinned"]')).toBeVisible();
  if (!(await snapshot.locator("details").evaluate((el: HTMLDetailsElement) => el.open))) {
    await snapshot.getByText("More actions").click();
  }
  await expect(snapshot.getByRole("button", { name: "Unpin snapshot", exact: true })).toBeVisible();
  const deletionResponse = page.waitForResponse((r) => new URL(r.url()).pathname === `/api/v1/snapshots/${selectedId}/deletion-plans`);
  await snapshot.getByRole("button", { name: "Preview deletion…", exact: true }).click();
  const deletion = await deletionResponse;
  expect(deletion.status()).toBe(409);
  expect((await deletion.json()).error.code).toBe("RETENTION_PROTECTED");
  await expect(page.locator(".toast")).toContainText(/protection|protected|retention/i);
  await page.getByRole("button", { name: "Manage policy", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByRole("heading", { name: "Schedule & retention" })).toBeVisible();
  await dialog.getByRole("button", { name: "Preview this retention policy", exact: true }).click();
  await expect(dialog.getByRole("heading", { name: /copies eligible for expiration|deletion is frozen/i })).toBeVisible();
  await expect(dialog.getByRole("columnheader", { name: "Planned expiry" })).toBeVisible();
  await page.keyboard.press("Escape");
  if (!(await snapshot.locator("details").evaluate((el: HTMLDetailsElement) => el.open))) {
    await snapshot.getByText("More actions").click();
  }
  await snapshot.getByRole("button", { name: "Unpin snapshot", exact: true }).click();
});

test("prepared alternate restore binds the selected target and exact capture point", async ({ page }) => {
  test.setTimeout(1200000);
  const file = path.join(privateRoot, "integration.json");
  test.skip(!fs.existsSync(file), "Requires the disposable SSH/systemd integration fixture");
  const fixture = JSON.parse(fs.readFileSync(file, "utf8"));
  test.skip(!fixture.alternate_id || !fixture.alternate_name, "Requires ROOT to enroll the prepared empty alternate target in the shared fixture");
  const original = sourceReadback();
  await login(page);
  await page.getByRole("button", { name: fixture.source_name, exact: true }).click();
  await page.locator(".snapshot").first().getByRole("button", { name: "Restore", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Destination").selectOption(fixture.alternate_id);
  await expect(dialog.locator("strong").filter({ hasText: fixture.alternate_name })).toBeVisible();
  let releasePlan!: () => void;
  let planReceived!: () => void;
  const planGate = new Promise<void>((resolve) => { releasePlan = resolve; });
  const pendingPlan = new Promise<void>((resolve) => { planReceived = resolve; });
  await page.route("**/api/v1/snapshots/*/restore-plans", async (route) => {
    const body = route.request().postDataJSON();
    if (body.target_id !== fixture.alternate_id || body.start_on_completion !== true) {
      await route.continue();
      return;
    }
    // Delay the real API response to prove an old confirmation cannot remain
    // usable while the newly selected start mode is awaiting its own plan.
    const response = await route.fetch();
    expect(response.status()).toBe(201);
    planReceived();
    await planGate;
    await route.fulfill({ response });
  });
  await dialog.getByRole("checkbox", { name: /Start on completion/ }).check();
  try {
    await pendingPlan;
    await expect(dialog.getByRole("button", { name: "Checking exact snapshot and target…", exact: true })).toBeDisabled();
  } finally {
    releasePlan();
  }
  await expect(dialog.getByRole("button", { name: "Confirm restore", exact: true })).toBeEnabled({ timeout: 30000 });
  const acceptedResponse = page.waitForResponse((response) => response.request().method() === "POST" && /\/restore-plans\/[^/]+\/execute$/.test(new URL(response.url()).pathname));
  await dialog.getByRole("button", { name: "Confirm restore", exact: true }).click();
  const response = await acceptedResponse;
  expect(response.status()).toBe(202);
  const accepted = await response.json();
  let job: any;
  await expect.poll(async () => {
    job = await (await page.request.get(accepted.status_url)).json();
    return ["succeeded", "failed", "partial", "needs_attention", "rollback_failed", "rolled_back", "cancelled"].includes(job.state);
  }, { timeout: 1080000, intervals: [2000, 5000] }).toBeTruthy();
  expect(job.error_code).toBeNull();
  expect(job.state).toBe("succeeded");
  expect(job.instance_id).toBe(fixture.alternate_id);
  expect(job.result.public_ports_verified).toBe(true);
  expect(job.result.public_endpoint_verified).toBe(true);
  const after = sourceReadback();
  expect(after).toEqual(original);
  fs.writeFileSync(path.resolve("../docs/evidence/alternate-browser.json"), JSON.stringify({ result: "passed", synthetic_only: true,
    restore_job_id: job.id, target_id: fixture.alternate_id, original_unchanged: true, source_before: original, source_after: after,
    public_ports_verified: true, public_endpoint_verified: true, limits: ["Public target HTTP and configuration receive separate independent SSH readback.", "No authenticated client login claim."] }, null, 2) + "\n");
});
