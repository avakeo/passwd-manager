// この端末を覚える（2026-10-29 追記。仕様書「この端末を覚える」）。偽の chrome と本物の API をつなぐ。
// ブラウザを閉じると storage.session（ログインのトークン）は消えるが、storage.local の端末のトークンは残る。
// 4桁のパスコードで同じセッションに戻り、マスターパスワードで鍵を開く。Discord と TOTP は要らない。

import { after, beforeEach, mock, test } from 'node:test';
import assert from 'node:assert/strict';
import { ADMIN_PASSWORD, POPUP, adminReady, newDiscord, restart, send, world, type World } from '../helpers/extension-world.ts';

const T0 = 1_800_000_000_000;
mock.timers.enable({ apis: ['Date'], now: T0 });
after(() => mock.timers.reset());
beforeEach(() => mock.timers.setTime(T0));

const discord = newDiscord();
after(discord.install());

const PIN = '1357';

function deviceRecord(w: World): Record<string, unknown> | undefined {
  const entry = [...w.chrome.storage.local.values.entries()].find(([k]) => k.startsWith('teampw/v1/device|'));
  return entry?.[1] as Record<string, unknown> | undefined;
}

// ブラウザを閉じて開き直す：storage.session が消え、Service Worker も起き直す
async function reopenBrowser(w: World): Promise<void> {
  w.chrome.storage.session.clear();
  restart(w);
  await w.bg.onStartup();
}

async function remembered(): Promise<World> {
  const w = world(discord);
  await adminReady(w, discord);
  assert.deepEqual(await send(w, { type: 'rememberDevice', pin: PIN }), { ok: true });
  return w;
}

test('A-16 ログインの直後に端末を覚える。storage.local には端末のトークンと期限だけ。パスコードは置かない', async () => {
  const w = await remembered();
  const rec = deviceRecord(w)!;
  assert.deepEqual(Object.keys(rec).sort(), ['expiresAt', 'memberId', 'token']);
  assert.ok(!w.chrome.storage.local.dump().includes(PIN));
  assert.equal(rec.expiresAt, T0 + 7 * 24 * 60 * 60 * 1000);
});

test('A-17 ブラウザを開き直したら、パスコードで戻り、マスターパスワードで鍵を開く。Discord の画面は出さない', async () => {
  const w = await remembered();
  const firstToken = deviceRecord(w)!.token;
  await reopenBrowser(w);
  const before = await send(w, { type: 'status' }, POPUP);
  assert.deepEqual([before.loggedIn, before.deviceResumeAvailable], [false, true]);
  const callsBefore = w.calls.length;
  const r = await send(w, { type: 'resumeDevice', pin: PIN }, POPUP);
  assert.deepEqual(r, { ok: true });
  assert.deepEqual(w.calls.slice(callsBefore), ['POST /v1/auth/resume'], 'Discord と TOTP の入口は使わない');
  const after = await send(w, { type: 'status' }, POPUP);
  assert.deepEqual([after.loggedIn, after.locked], [true, true], 'ログインは戻るが、鍵は開いていない');
  assert.equal((await send(w, { type: 'unlock', masterPassword: ADMIN_PASSWORD }, POPUP)).vault, 'ready');
  // 端末のトークンは戻るたびに替わる（前のトークンを盗まれても、使えなくする）
  assert.notEqual(deviceRecord(w)!.token, firstToken);
});

test('A-18 パスコードを間違えると残りの回数を返し、3回目で端末のトークンを消す。その後はログインからやり直す', async () => {
  const w = await remembered();
  await reopenBrowser(w);
  assert.deepEqual(await send(w, { type: 'resumeDevice', pin: '0000' }, POPUP), { ok: false, error: 'BAD_PASSCODE', attemptsLeft: 2 });
  assert.deepEqual(await send(w, { type: 'resumeDevice', pin: '0000' }, POPUP), { ok: false, error: 'BAD_PASSCODE', attemptsLeft: 1 });
  assert.deepEqual(await send(w, { type: 'resumeDevice', pin: '0000' }, POPUP), { ok: false, error: 'DEVICE_FORGOTTEN' });
  assert.equal(deviceRecord(w), undefined);
  assert.equal((await send(w, { type: 'status' }, POPUP)).deviceResumeAvailable, false);
  assert.deepEqual(await send(w, { type: 'resumeDevice', pin: PIN }, POPUP), { ok: false, error: 'NO_DEVICE' });
});

test('A-19 ログアウトすると、端末のトークンを消し、サーバーでも無効にする', async () => {
  const w = await remembered();
  const token = String(deviceRecord(w)!.token);
  await send(w, { type: 'logout' }, POPUP);
  assert.equal(deviceRecord(w), undefined);
  // 手元に残っていたとしても、サーバーで無効
  const res = await w.t.request('POST', '/v1/auth/resume', undefined, { device_token: token, pin_proof: 'A'.repeat(43) });
  assert.equal(res.status, 403);
});

test('A-16 ログインから5分を過ぎたら、認証アプリのコードで再確認してからでないと覚えられない', async () => {
  const w = world(discord);
  await adminReady(w, discord);
  mock.timers.setTime(T0 + 6 * 60 * 1000);
  assert.deepEqual(await send(w, { type: 'rememberDevice', pin: PIN }), { ok: false, error: 'STEP_UP_REQUIRED' });
  assert.equal(deviceRecord(w), undefined);
});

test('忘れる：手元の端末のトークンを消す。パスコードは4桁の数字だけ', async () => {
  const w = await remembered();
  assert.deepEqual(await send(w, { type: 'forgetDevice' }), { ok: true });
  assert.equal(deviceRecord(w), undefined);
  for (const pin of ['123', '12345', 'abcd']) assert.deepEqual(await send(w, { type: 'rememberDevice', pin }), { ok: false, error: 'BAD_REQUEST' });
});

test('期限（7日）を過ぎた端末のトークンでは戻らず、消す', async () => {
  const w = await remembered();
  await reopenBrowser(w);
  mock.timers.setTime(T0 + 7 * 24 * 60 * 60 * 1000 + 1);
  assert.equal((await send(w, { type: 'status' }, POPUP)).deviceResumeAvailable, false);
  assert.deepEqual(await send(w, { type: 'resumeDevice', pin: PIN }, POPUP), { ok: false, error: 'NO_DEVICE' });
  assert.equal(deviceRecord(w), undefined);
});
