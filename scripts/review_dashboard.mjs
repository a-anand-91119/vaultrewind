#!/usr/bin/env node
/** Read-only private-fixture dashboard review. Default preparation performs no I/O. */
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';

const project = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const origin = 'http://127.0.0.1:8098';
const sourceId = '46ac8eb9-1854-4fc6-924f-af14c6b7d0c2';
const execute = process.argv.slice(2).includes('--execute');
const screenshots = process.argv.slice(2).includes('--screenshots');
if (process.argv.slice(2).some((arg) => !['--execute', '--screenshots'].includes(arg))) {
  process.stdout.write('DASHBOARD_REVIEW_INVALID_ARGUMENT\n');
  process.exit(1);
}
if (!execute) {
  process.stdout.write(JSON.stringify({ result: 'prepared', external_calls: 0, private_reads: 0 }) + '\n');
  process.exit(0);
}
process.umask(0o077);

function requireCondition(value, code) {
  if (!value) throw new Error(code);
}
function privateText(filename) {
  const filenamePath = path.resolve(project, '.runtime/controller', filename);
  const info = fs.lstatSync(filenamePath);
  requireCondition(info.isFile() && !info.isSymbolicLink()
    && info.uid === process.getuid() && (info.mode & 0o077) === 0, 'PRIVATE_FIXTURE_REQUIRED');
  return fs.readFileSync(filenamePath, 'utf8').trim();
}
const runId = randomUUID();
const workspace = path.join(project, '.runtime/dashboard-review', runId);
fs.mkdirSync(workspace, { recursive: true, mode: 0o700 });
const review = {
  result: 'running', run_id: runId, synthetic_only: true,
  origin, page_checks: [], api_errors: [], blocked_mutations: [], blocked_external_requests: 0,
  page_exception_count: 0, console_error_count: 0, expected_login_401_count: 0, screenshots_private: screenshots,
  screenshots_contain_login_credentials: false, trace: false, video: false,
  browser: 'repository Playwright; T3 preview explicitly unavailable under root sandbox',
  limits: [
    'Read-only navigation/layout/status review; session creation is the only permitted POST.',
    'No backup, restore, policy, provider, host, account or deletion mutation is submitted.',
    'Existing operational alerts and historical failed jobs are displayed as recorded, not cleared.',
    'Fleet-only screenshots stay in the private runtime tree; storage/account detail screenshots are disabled.',
  ],
};
let browser;
let context;
let sessionCreated = false;
let stage = 'login';
try {
  const require = createRequire(path.join(project, 'frontend/package.json'));
  const { chromium } = require('playwright');
  browser = await chromium.launch({ headless: true, chromiumSandbox: false });
  context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, locale: 'en-US' });
  await context.route('**/*', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (['http:', 'https:'].includes(url.protocol) && url.origin !== origin) {
      review.blocked_external_requests += 1;
      return route.abort('blockedbyclient');
    }
    if (url.pathname.startsWith('/api/v1/') && !['GET', 'HEAD', 'OPTIONS'].includes(request.method())) {
      review.blocked_mutations.push({ method: request.method(), path: url.pathname });
      return route.abort('blockedbyclient');
    }
    return route.continue();
  });
  const page = await context.newPage();
  page.on('pageerror', () => { review.page_exception_count += 1; });
  page.on('console', (message) => {
    if (sessionCreated && message.type() === 'error') review.console_error_count += 1;
  });
  page.on('response', (response) => {
    const url = new URL(response.url());
    if (url.origin === origin && url.pathname.startsWith('/api/v1/') && response.status() >= 400) {
      if (!sessionCreated && url.pathname === '/api/v1/sessions/current' && response.status() === 401) {
        review.expected_login_401_count += 1;
        return;
      }
      review.api_errors.push({ method: response.request().method(), path: url.pathname, status: response.status() });
    }
  });
  await page.goto(origin, { waitUntil: 'domcontentloaded' });
  await page.getByRole('heading', { name: 'Welcome back.', exact: true }).waitFor();
  requireCondition(await page.getByLabel('Username', { exact: true }).isVisible(), 'LOGIN_LABEL_MISSING');
  requireCondition(await page.getByLabel('Password', { exact: true }).getAttribute('type') === 'password', 'PASSWORD_NOT_MASKED');
  // APIRequestContext is deliberately separate from browser routing: only this explicit session POST is issued.
  const login = await context.request.post(origin + '/api/v1/sessions', {
    headers: { Origin: origin }, data: { username: 'synthetic-admin', password: privateText('admin-password') },
  });
  requireCondition(login.status() === 200, 'PRIVATE_SESSION_CREATION_FAILED');
  const identity = await login.json();
  requireCondition(identity.user?.username === 'synthetic-admin' && identity.user?.role === 'administrator', 'SYNTHETIC_ADMIN_REQUIRED');
  sessionCreated = true;
  await page.goto(origin, { waitUntil: 'domcontentloaded' });
  await page.getByRole('heading', { name: 'Every vault. A way back.', exact: true }).waitFor();
  await page.keyboard.press('Tab');
  review.keyboard_skip_link_focused = await page.evaluate(() => document.activeElement?.textContent?.trim() === 'Skip to content');
  requireCondition(review.keyboard_skip_link_focused, 'KEYBOARD_SKIP_LINK_MISSING');
  await page.keyboard.press('Enter');
  review.keyboard_skip_link_target_resolves = await page.evaluate(() => location.hash === '#main' && Boolean(document.querySelector('#main')));
  requireCondition(review.keyboard_skip_link_target_resolves, 'KEYBOARD_SKIP_TARGET_MISSING');
  const pages = [
    ['Instances', 'Every vault. A way back.'], ['Activity', 'Activity'], ['Storage', 'Encrypted storage'],
    ['Hosts', 'SSH hosts'], ['Recovery kit', 'A recovery plan beyond this controller.'],
    ['Integrity', 'Integrity & readiness'], ['Audit trail', 'Audit trail'], ['Settings', 'Workspace settings'],
  ];
  const source = await context.request.get(origin + '/api/v1/instances/' + sourceId);
  requireCondition(source.status() === 200, 'EXISTING_SYNTHETIC_SOURCE_REQUIRED');
  const sourceView = await source.json();
  for (const viewport of [{ width: 1440, height: 1000 }, { width: 768, height: 1024 }, { width: 390, height: 844 }]) {
    await page.setViewportSize(viewport);
    for (const [label, heading] of pages) {
      stage = `${viewport.width}:${label}`;
      const toggle = page.getByRole('button', { name: 'Open navigation', exact: true });
      if (await toggle.isVisible()) await toggle.click();
      await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: label, exact: true }).click();
      await page.getByRole('main').getByRole('heading', { name: heading, exact: true }).waitFor();
      await page.waitForFunction(() => !document.querySelector('main .loading'), null, { timeout: 20000 });
      const measured = await page.evaluate(() => ({ document_width: document.documentElement.scrollWidth, viewport_width: innerWidth }));
      if (measured.document_width > measured.viewport_width + 1) {
        review.overflow_elements = await page.evaluate(() => Array.from(document.querySelectorAll('main, main *'))
          .map((el) => ({ tag: el.tagName, classes: el.className?.toString().slice(0, 100),
            right: Math.round(el.getBoundingClientRect().right), width: Math.round(el.getBoundingClientRect().width) }))
          .filter((el) => el.right > innerWidth + 1).slice(0, 30));
        review.table_containment_diagnostic = await page.evaluate(() => {
          const panels = Array.from(document.querySelectorAll('.table-wrap'));
          const previous = panels.map((el) => el.style.position);
          panels.forEach((el) => { el.style.position = 'relative'; });
          const width = document.documentElement.scrollWidth;
          panels.forEach((el, i) => { el.style.position = previous[i]; });
          return { width_with_positioned_table_wrap: width, viewport_width: innerWidth };
        });
      }
      requireCondition(measured.document_width <= measured.viewport_width + 1, 'HORIZONTAL_PAGE_OVERFLOW');
      review.page_checks.push({ page: label, width: viewport.width, heading_visible: true, loaded: true, ...measured });
      if (label === 'Instances' && screenshots) {
        await page.screenshot({ path: path.join(workspace, 'fleet-' + viewport.width + '.png'), fullPage: true });
      }
    }
    stage = `${viewport.width}:snapshot-detail`;
    const toggle = page.getByRole('button', { name: 'Open navigation', exact: true });
    if (await toggle.isVisible()) await toggle.click();
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Instances', exact: true }).click();
    const card = page.locator('article.instance-card').filter({ has: page.getByRole('button', { name: sourceView.name, exact: true }) });
    await card.getByRole('button', { name: 'View snapshots', exact: true }).click();
    await page.getByRole('main').getByRole('heading', { name: sourceView.name, exact: true }).waitFor();
    await page.waitForFunction(() => !document.querySelector('main .loading'), null, { timeout: 20000 });
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1);
    if (overflow) {
      review.overflow_elements = await page.evaluate(() => Array.from(document.querySelectorAll('main, main *'))
        .map((el) => ({ tag: el.tagName, classes: el.className?.toString().slice(0, 100),
          right: Math.round(el.getBoundingClientRect().right), width: Math.round(el.getBoundingClientRect().width) }))
        .filter((el) => el.right > innerWidth + 1).slice(0, 35));
    }
    requireCondition(!overflow, 'SNAPSHOT_DETAIL_OVERFLOW');
    review.page_checks.push({ page: 'Instance snapshot detail', width: viewport.width, heading_visible: true, loaded: true, horizontal_overflow: false });
  }
  requireCondition(review.page_exception_count === 0 && review.api_errors.length === 0
    && review.console_error_count === 0 && review.blocked_mutations.length === 0
    && review.blocked_external_requests === 0, 'DASHBOARD_RUNTIME_ERROR');
  review.result = 'passed';
} catch (error) {
  review.result = 'failed';
  review.error_stage = stage;
  const location = error instanceof Error ? error.stack?.match(/review_dashboard\.mjs:(\d+):(\d+)/) : null;
  if (location) review.error_location = `${location[1]}:${location[2]}`;
  const code = error instanceof Error ? error.message : '';
  review.error_code = /^[A-Z_]{1,80}$/.test(code) ? code : 'DASHBOARD_REVIEW_FAILED_PRIVATE_DETAILS_WITHHELD';
} finally {
  review.session_created = sessionCreated;
  review.recorded_at = new Date().toISOString();
  if (context) await context.close().catch(() => {});
  if (browser) await browser.close().catch(() => {});
  fs.writeFileSync(path.join(workspace, 'review.json'), JSON.stringify(review, null, 2) + '\n', { mode: 0o600 });
}
if (review.result === 'passed') {
  const filename = path.join(project, 'docs/evidence/dashboard-review.json');
  if (fs.existsSync(filename)) {
    const old = JSON.parse(fs.readFileSync(filename, 'utf8'));
    review.previous_review = { result: old.result, run_id: old.run_id, recorded_at: old.recorded_at };
  }
  fs.writeFileSync(filename, JSON.stringify(review, null, 2) + '\n');
}
process.stdout.write(JSON.stringify({ result: review.result, run_id: runId, page_checks: review.page_checks.length,
  api_errors: review.api_errors.length, page_exceptions: review.page_exception_count,
  console_errors: review.console_error_count, blocked_mutations: review.blocked_mutations.length,
  error_code: review.error_code }) + '\n');
process.exitCode = review.result === 'passed' ? 0 : 1;
