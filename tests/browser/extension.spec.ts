// 拡張機能を本物のブラウザ（Playwright の Chromium）で読み込んで動かす（npm run test:browser）。
// 通常の Chrome は --load-extension が効かないので、Playwright の Chromium を使う。
// API には通信しない（ログイン前の状態だけを見る）。manifest の key は、テストのたびに作る使い捨ての公開鍵。

import { test, expect, chromium, type BrowserContext, type Worker } from '@playwright/test';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildExtension } from '../../scripts/build-extension.ts';

const OUT = new URL('../../dist/browser-extension/', import.meta.url);
let context: BrowserContext;
let worker: Worker;
let extensionId: string;
let server: Server;
let pageOrigin: string;
let profile: string;

test.beforeAll(async () => {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'der' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
  await buildExtension({
    outDir: OUT,
    config: { apiOrigin: 'https://pw-api.example.com', discordClientId: '100000000000000001', manifestKey: Buffer.from(publicKey).toString('base64') },
  });
  const dir = fileURLToPath(OUT);
  profile = mkdtempSync(join(tmpdir(), 'teampw-browser-'));
  context = await chromium.launchPersistentContext(profile, {
    channel: 'chromium',
    headless: true,
    args: [`--disable-extensions-except=${dir}`, `--load-extension=${dir}`],
  });
  worker = context.serviceWorkers()[0] ?? (await context.waitForEvent('serviceworker'));
  extensionId = new URL(worker.url()).host;
  // ふつうの Web ページ（拡張機能から見て、知らないページ）
  server = createServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end('<!doctype html><title>ふつうのページ</title><p>page</p>');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const address = server.address();
  pageOrigin = `http://127.0.0.1:${typeof address === 'object' && address ? address.port : 0}`;
});

test.afterAll(async () => {
  await context?.close();
  server?.close();
  rmSync(profile, { recursive: true, force: true });
});

test('拡張機能を読み込むと Service Worker が動き、ポップアップがログインの画面を出す', async () => {
  expect(extensionId).toMatch(/^[a-p]{32}$/);
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/extension/popup/popup.html`);
  await expect(page.getByRole('button', { name: 'Discord でログイン' })).toBeVisible();
  await page.close();
});

test('E-08 本物の入口：自分の拡張機能のページからでも、表にない種類や余分な項目は処理しない。status は答える', async () => {
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/extension/page/app.html`);
  const replies = await page.evaluate(async () => {
    const runtime = (globalThis as unknown as { chrome: { runtime: { sendMessage(m: unknown): Promise<unknown> } } }).chrome.runtime;
    return {
      unknown: await runtime.sendMessage({ type: 'readSecrets' }),
      extra: await runtime.sendMessage({ type: 'status', extra: 1 }),
      status: await runtime.sendMessage({ type: 'status' }),
    };
  });
  expect(replies.unknown).toEqual({ ok: false, error: 'BAD_REQUEST' });
  expect(replies.extra).toEqual({ ok: false, error: 'BAD_REQUEST' });
  expect(replies.status).toMatchObject({ ok: true, loggedIn: false, locked: true });
  await page.close();
});

test('E-08 E-16 ふつうの Web ページからは、拡張機能にメッセージを送れず、chrome.storage も見えない', async () => {
  const page = await context.newPage();
  await page.goto(`${pageOrigin}/`);
  const seen = await page.evaluate(() => {
    const c = (globalThis as unknown as { chrome?: { runtime?: { sendMessage?: unknown }; storage?: unknown } }).chrome;
    return { sendMessage: typeof c?.runtime?.sendMessage, storage: typeof c?.storage };
  });
  expect(seen).toEqual({ sendMessage: 'undefined', storage: 'undefined' });
  await page.close();
});

// 鍵を持たせてから止めるには API が要るので、ここでは「本当に止まり、次のメッセージで起き直した」ことまでを、
// CDP の Service Worker の状態（stopped → running）で見る。解除した状態から止めると鍵が消えることは、
// Node の E-14（tests/extension/quick-unlock.test.ts）で確かめている（2b Codex #5）
test('E-14 Service Worker を止めても、次のメッセージで起き直し、ロック状態から答える', async () => {
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/extension/popup/popup.html`);
  const cdp = await context.newCDPSession(page);
  const states: string[] = [];
  cdp.on('ServiceWorker.workerVersionUpdated', (e: { versions: { scriptURL: string; runningStatus: string }[] }) => {
    for (const v of e.versions) if (v.scriptURL.startsWith(`chrome-extension://${extensionId}/`)) states.push(v.runningStatus);
  });
  await cdp.send('ServiceWorker.enable');
  await cdp.send('ServiceWorker.stopAllWorkers');
  await expect.poll(() => states.at(-1), { timeout: 10_000 }).toBe('stopped');
  const stoppedAt = states.length;
  const status = await page.evaluate(async () => {
    const runtime = (globalThis as unknown as { chrome: { runtime: { sendMessage(m: unknown): Promise<unknown> } } }).chrome.runtime;
    return runtime.sendMessage({ type: 'status' });
  });
  expect(status).toMatchObject({ ok: true, locked: true, vault: 'locked' });
  expect(states.slice(stoppedAt), '止まった後に起き直している').toContain('running');
  await page.close();
});
