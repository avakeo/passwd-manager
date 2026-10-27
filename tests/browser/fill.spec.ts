// 入力のスクリプト（src/extension/background/inject.ts の fillLogin）を、test-sites のページで本物のブラウザに動かす（E-01・E-06）。
// ポップアップの操作による activeTab は Playwright から作れないので、関数を page.evaluate で直接動かす。
// test-sites の CSP は外のスクリプトを許さないので、このテストのブラウザだけ CSP を外す（bypassCSP）。

import { test, expect, chromium, type Browser, type Page } from '@playwright/test';
import { createServer, type Server } from 'node:http';
import site from '../../test-sites/worker.ts';
import { fillLogin } from '../../src/extension/background/inject.ts';

let server: Server;
let origin: string;
let browser: Browser;

test.beforeAll(async () => {
  server = createServer(async (req, res) => {
    const r = await site.fetch(new Request(`http://127.0.0.1${req.url ?? '/'}`), {});
    res.writeHead(r.status, Object.fromEntries(r.headers));
    res.end(await r.text());
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const address = server.address();
  origin = `http://127.0.0.1:${typeof address === 'object' && address ? address.port : 0}`;
  browser = await chromium.launch({ channel: 'chromium', headless: true });
});

test.afterAll(async () => {
  await browser?.close();
  server?.close();
});

async function open(path: string): Promise<Page> {
  const context = await browser.newContext({ bypassCSP: true });
  const page = await context.newPage();
  await page.goto(`${origin}${path}`);
  return page;
}

function fill(page: Page, expectedOrigin: string, username = 'team@example.com', password = 'correct-horse') {
  return page.evaluate(([src, o, u, p]) => (0, eval)(`(${src})`)(o, u, p), [fillLogin.toString(), expectedOrigin, username, password] as const);
}

test('E-01 ふつうのフォームに、ユーザー名とパスワードを入れる。input のイベントも届く', async () => {
  const page = await open('/simple');
  const events = page.evaluate(() => new Promise<number>((r) => { let n = 0; document.getElementById('password')!.addEventListener('input', () => r(++n)); }));
  expect(await fill(page, origin)).toEqual({ filled: 2 });
  expect(await page.inputValue('#username')).toBe('team@example.com');
  expect(await page.inputValue('#password')).toBe('correct-horse');
  expect(await events).toBe(1);
  await page.context().close();
});

test('E-06 見えない4つの欄（display:none、visibility:hidden、大きさ0、画面の外）には入れない', async () => {
  const page = await open('/hidden');
  expect(await fill(page, origin)).toEqual({ filled: 2 });
  expect(await page.inputValue('#password')).toBe('correct-horse');
  for (const id of ['password_display_none', 'password_visibility_hidden', 'password_zero_size', 'password_offscreen']) {
    expect(await page.inputValue(`#${id}`), id).toBe('');
  }
  await page.click('button[type="submit"]');
  await expect(page.locator('#hidden-result')).toHaveText('見えない欄：4つとも空');
  await page.context().close();
});

test('2段階のログイン：最初はユーザー名だけ入れる。パスワードの画面で、もう一度入れるとパスワードも入る', async () => {
  const page = await open('/two-step');
  expect(await fill(page, origin)).toEqual({ filled: 1 });
  expect(await page.inputValue('#username')).toBe('team@example.com');
  expect(await page.inputValue('#password')).toBe('');
  await page.click('#next');
  expect(await fill(page, origin)).toEqual({ filled: 2 });
  expect(await page.inputValue('#password')).toBe('correct-horse');
  await page.context().close();
});

test('後から描くフォーム：描かれる前は何も入れず、描かれた後なら入れる', async () => {
  const page = await open('/spa');
  expect(await fill(page, origin)).toEqual({ filled: 0, reason: 'no-field' });
  await page.waitForSelector('#password');
  expect(await fill(page, origin)).toEqual({ filled: 2 });
  await page.context().close();
});

test('E-13 入れる直前にページのオリジンが照合したものと違えば、何も入れない', async () => {
  const page = await open('/simple');
  expect(await fill(page, 'https://wiki.example.com')).toEqual({ filled: 0, reason: 'origin' });
  expect(await page.inputValue('#password')).toBe('');
  await page.context().close();
});
