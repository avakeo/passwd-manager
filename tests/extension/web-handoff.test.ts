// 拡張機能から Web ページを開く（2026-11-05 追記、W-09）。仕様書「Webページの配信」。
// 全画面ページの「Web ページを開く」で、Service Worker が使い捨てのコードを作り、拡張機能の設定の Web ページのオリジンに付けて返す。
// 開く先はサーバーの値を使わず、拡張機能の設定（ビルドで入れる）だけで決める。

import { after, beforeEach, mock, test } from 'node:test';
import assert from 'node:assert/strict';
import { WEB_ORIGIN } from '../helpers/api.ts';
import { POPUP, adminReady, newDiscord, restart, send, world } from '../helpers/extension-world.ts';

const T0 = 1_800_000_000_000;
mock.timers.enable({ apis: ['Date'], now: T0 });
after(() => mock.timers.reset());
beforeEach(() => mock.timers.setTime(T0));

const discord = newDiscord();
after(discord.install());

test('W-09 「Web ページを開く」：コードを作り、設定の Web ページのオリジンの #handoff= に付けた URL を返す。そのコードで Web 用のセッションになる', async () => {
  const w = world(discord);
  await adminReady(w, discord);
  const r = await send(w, { type: 'openWebPage' });
  assert.equal(r.ok, true, JSON.stringify(r));
  const url = new URL(String(r.url));
  assert.equal(url.origin, WEB_ORIGIN);
  assert.equal(url.pathname, '/');
  assert.equal(url.search, '', 'コードはサーバーに送られない # の後ろにだけ置く');
  const code = /^#handoff=([A-Za-z0-9_-]{43})$/.exec(url.hash)?.[1];
  assert.ok(code);
  const res = await w.t.request('POST', '/v1/auth/web-handoff', undefined, { code });
  assert.equal(res.status, 200);
});

test('W-09 サーバーが別のオリジンを返しても、開く先は拡張機能の設定のまま', async () => {
  const w = world(discord);
  await adminReady(w, discord);
  w.rewrite = async (call, res) =>
    call === 'POST /v1/me/web-handoff' ? new Response(JSON.stringify({ ...((await res.json()) as object), url: 'https://evil.example.com/' }), { status: 201, headers: { 'Content-Type': 'application/json' } }) : null;
  const r = await send(w, { type: 'openWebPage' });
  assert.equal(new URL(String(r.url)).origin, WEB_ORIGIN);
});

test('W-09 サーバーの返したコードの形が違えば、URL を作らない', async () => {
  const w = world(discord);
  await adminReady(w, discord);
  w.rewrite = async (call) => (call === 'POST /v1/me/web-handoff' ? new Response(JSON.stringify({ code: 'x#y' }), { status: 201, headers: { 'Content-Type': 'application/json' } }) : null);
  const r = await send(w, { type: 'openWebPage' });
  assert.equal(r.ok, false);
  assert.equal(r.url, undefined);
});

test('W-09 Web ページのオリジンを設定していなければ、API を呼ばずに NO_WEB_PAGE', async () => {
  const w = world(discord);
  await adminReady(w, discord);
  w.webOrigin = null;
  restart(w);
  w.calls.length = 0;
  assert.equal((await send(w, { type: 'openWebPage' })).error, 'NO_WEB_PAGE');
  assert.deepEqual(w.calls, []);
});

test('W-09 ポップアップからは受けない（全画面ページだけ）。ログインしていなければ NOT_LOGGED_IN', async () => {
  const w = world(discord);
  assert.equal((await send(w, { type: 'openWebPage' })).error, 'NOT_LOGGED_IN');
  await adminReady(w, discord);
  assert.equal((await send(w, { type: 'openWebPage' }, POPUP)).ok, false);
});
