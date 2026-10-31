// Web ページを配る Worker（2026-11-01 追記、判断待ち10）。仕様書「Webページの配信」。
// 静的アセットの応答すべてにセキュリティのヘッダーを付け（W-03）、http なら https へ転送する（W-04）。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../../src/web/worker.ts';

const API_ORIGIN = 'https://pw-api.example.com';

function env(files: Record<string, string> = { '/index.html': '<!doctype html><title>teampw</title>' }, apiOrigin: string = API_ORIGIN) {
  const seen: string[] = [];
  return {
    seen,
    env: {
      API_ORIGIN: apiOrigin,
      ASSETS: {
        async fetch(req: Request): Promise<Response> {
          const path = new URL(req.url).pathname;
          seen.push(path);
          const body = files[path] ?? files['/index.html'];
          return new Response(body, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8', 'X-From-Assets': '1' } });
        },
      },
    },
  };
}

test('W-03 どの応答にも、CSP・HSTS・フレームの禁止などのヘッダーを付ける', async () => {
  for (const path of ['/', '/callback?code=abc&state=xyz', '/app.js', '/style.css']) {
    const { env: e } = env();
    const res = await worker.fetch(new Request(`https://pw.example.com${path}`), e);
    assert.equal(res.status, 200, path);
    const csp = res.headers.get('content-security-policy')!;
    for (const part of ["default-src 'none'", "script-src 'self'", "style-src 'self'", `connect-src ${API_ORIGIN}`, "img-src 'self'", "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'"]) {
      assert.ok(csp.split('; ').includes(part), `${path}: ${part}`);
    }
    assert.ok(!csp.includes("'unsafe-inline'") && !csp.includes("'unsafe-eval'") && !csp.includes('*'), path);
    assert.equal(res.headers.get('strict-transport-security'), 'max-age=31536000; includeSubDomains');
    assert.equal(res.headers.get('x-frame-options'), 'DENY');
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
    assert.equal(res.headers.get('cross-origin-opener-policy'), 'same-origin');
    assert.match(res.headers.get('permissions-policy')!, /camera=\(\)/);
    // アセットの中身と、ほかのヘッダーはそのまま
    assert.equal(res.headers.get('x-from-assets'), '1');
  }
});

test('W-04 http で来たら、アセットを返さずに同じパスの https へ転送する', async () => {
  const { env: e, seen } = env();
  const res = await worker.fetch(new Request('http://pw.example.com/callback?code=abc'), e);
  assert.equal(res.status, 301);
  assert.equal(res.headers.get('location'), 'https://pw.example.com/callback?code=abc');
  assert.deepEqual(seen, []);
});

test('W-03 API のオリジンの設定がおかしければ、ページを返さない（CSP を緩めて返さない）', async () => {
  for (const bad of ['', 'http://pw-api.example.com', 'https://pw-api.example.com/v1', '*', "https://a.example.com 'unsafe-inline'"]) {
    const { env: e, seen } = env(undefined, bad);
    const res = await worker.fetch(new Request('https://pw.example.com/'), e);
    assert.equal(res.status, 500, bad);
    assert.deepEqual(seen, [], bad);
  }
});
