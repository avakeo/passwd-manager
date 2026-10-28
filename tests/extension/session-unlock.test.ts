// ロック解除を保つ（2026-10-29 追記。仕様書「ロックと鍵の置き場所」）。
// 利用者が選んだときだけ、Vault 鍵を storage.session（メモリ。ディスクに書かない）に置き、
// Service Worker が止まった後も、ブラウザを閉じる・ロックする・45分放置するまでは、何も入れずに戻る。秘密鍵は置かない。

import { after, beforeEach, mock, test } from 'node:test';
import assert from 'node:assert/strict';
import { IDLE_LOCK_MS } from '../../src/extension/background/background.ts';
import { ADMIN_PASSWORD, POPUP, adminReady, newDiscord, restart, send, world, type World } from '../helpers/extension-world.ts';
import { referenceTotp, stepAt } from '../helpers/totp-reference.ts';
import { fromBase64Url } from '../../src/crypto/bytes.ts';

const T0 = 1_800_000_000_000;
mock.timers.enable({ apis: ['Date'], now: T0 });
after(() => mock.timers.reset());
beforeEach(() => mock.timers.setTime(T0));

const discord = newDiscord();
after(discord.install());

const SESSION_PREFIX = 'teampw/v1/unlock|session|';

function sessionRecord(w: World): Record<string, unknown> | undefined {
  const entry = [...w.chrome.storage.session.values.entries()].find(([k]) => k.startsWith(SESSION_PREFIX));
  return entry?.[1] as Record<string, unknown> | undefined;
}

async function stop(w: World): Promise<void> {
  restart(w);
  await w.bg.onStartup();
}

// 管理者でロック解除し、メモを1件作り、「ロック解除を保つ」をオンにする
let admin: { userId: string; secret: Uint8Array } = { userId: '', secret: new Uint8Array() };

async function kept(): Promise<World> {
  const w = world(discord);
  admin = await adminReady(w, discord);
  assert.equal((await send(w, { type: 'saveItem', item: { type: 'note', title: 'メモ', body: '中身' } })).ok, true);
  const r = await send(w, { type: 'setKeepUnlocked', enabled: true });
  assert.deepEqual(r, { ok: true, keepUnlocked: true });
  return w;
}

test('E-14 初めはオフ：Service Worker が止まるとロックされる（今までどおり）', async () => {
  const w = world(discord);
  await adminReady(w, discord);
  assert.equal((await send(w, { type: 'status' }, POPUP)).keepUnlocked, false);
  await stop(w);
  assert.equal((await send(w, { type: 'status' }, POPUP)).locked, true);
  assert.equal(sessionRecord(w), undefined);
});

test('E-19 オンにすると、Service Worker が止まった後も、何も入れずに Vault 鍵だけが戻る。秘密鍵は戻らない', async () => {
  const w = await kept();
  await stop(w);
  assert.deepEqual(w.bg.memoryState(), { unlocked: false, vaultKey: false }, '起きた直後はメモリに鍵がない');
  const status = await send(w, { type: 'status' }, POPUP);
  assert.deepEqual([status.locked, status.unlockedBy, status.vault, status.keepUnlocked], [false, 'session', 'ready', true]);
  assert.deepEqual(w.bg.memoryState(), { unlocked: false, vaultKey: true }, '秘密鍵は持たない');
  assert.equal((await send(w, { type: 'sync' })).ok, true);
  const items = (await send(w, { type: 'listItems' })).items as { id: string; title: string }[];
  assert.deepEqual(items.map((i) => i.title), ['メモ']);
  assert.equal((await send(w, { type: 'getItem', id: items[0]!.id })).ok, true);
});

test('E-19 保存は storage.session にだけ置き、中身は Vault 鍵（32バイト）と世代だけ。storage.local には設定（オンかオフか）だけ', async () => {
  const w = await kept();
  const rec = sessionRecord(w)!;
  assert.deepEqual(Object.keys(rec).sort(), ['vaultKey', 'vaultKeyVersion']);
  assert.equal(fromBase64Url(String(rec.vaultKey)).length, 32);
  assert.equal(rec.vaultKeyVersion, 1);
  const local = w.chrome.storage.local.dump();
  assert.ok(!local.includes(String(rec.vaultKey)), 'storage.local には鍵を置かない');
  assert.ok(local.includes('keep-unlocked'));
});

test('E-17 E-19 保った状態から戻ったときは、管理操作とパスコードの設定にマスターパスワードを求める', async () => {
  const w = await kept();
  await stop(w);
  assert.equal((await send(w, { type: 'initVault' })).error, 'PASSWORD_REQUIRED');
  assert.equal((await send(w, { type: 'setupQuickUnlock', passcode: '2580' })).error, 'PASSWORD_REQUIRED');
  assert.equal((await send(w, { type: 'createKey', masterPassword: 'x'.repeat(14), replace: true })).error, 'PASSWORD_REQUIRED');
  // オンにするのも、マスターパスワードで解除した状態からだけ（オフにはいつでもできる）
  assert.equal((await send(w, { type: 'setKeepUnlocked', enabled: true })).error, 'PASSWORD_REQUIRED');
  assert.deepEqual(await send(w, { type: 'setKeepUnlocked', enabled: false }), { ok: true, keepUnlocked: false });
});

test('E-20 ロックを押すと保存が消え、止まった後は戻らない', async () => {
  const w = await kept();
  await send(w, { type: 'lock' }, POPUP);
  assert.equal(sessionRecord(w), undefined);
  await stop(w);
  assert.equal((await send(w, { type: 'status' }, POPUP)).locked, true);
});

test('E-20 45分放置すると、起きたときに保存を消してロックする', async () => {
  const w = await kept();
  mock.timers.setTime(T0 + IDLE_LOCK_MS + 60_000);
  await stop(w);
  assert.equal(sessionRecord(w), undefined);
  assert.equal((await send(w, { type: 'status' }, POPUP)).locked, true);
});

test('E-20 ブラウザを閉じると（storage.session が消える）戻らない。設定はオンのまま、次にマスターパスワードで解除したときに保存し直す', async () => {
  const w = await kept();
  w.chrome.storage.session.clear();
  await stop(w);
  // ブラウザを閉じるとログインのトークン（storage.session）も消えるので、同じ人でログインからやり直す
  w.chrome.loginAs = admin.userId;
  assert.equal((await send(w, { type: 'login', deviceLabel: 'テスト端末' }, POPUP)).status, 'totp_required');
  assert.equal((await send(w, { type: 'loginTotp', code: referenceTotp(admin.secret, stepAt(Date.now()) + 1) }, POPUP)).ok, true);
  assert.equal((await send(w, { type: 'status' }, POPUP)).locked, true, 'ログインしただけでは戻らない');
  assert.equal((await send(w, { type: 'unlock', masterPassword: ADMIN_PASSWORD }, POPUP)).vault, 'ready');
  assert.equal((await send(w, { type: 'status' }, POPUP)).keepUnlocked, true);
  assert.ok(sessionRecord(w), 'マスターパスワードで解除したら保存し直す');
  await stop(w);
  assert.equal((await send(w, { type: 'status' }, POPUP)).locked, false);
});

test('オフにすると保存が消え、止まった後は戻らない。ログアウトでも消える', async () => {
  const w = await kept();
  assert.deepEqual(await send(w, { type: 'setKeepUnlocked', enabled: false }), { ok: true, keepUnlocked: false });
  assert.equal(sessionRecord(w), undefined);
  await stop(w);
  assert.equal((await send(w, { type: 'status' }, POPUP)).locked, true);

  const v = await kept();
  await send(v, { type: 'logout' }, POPUP);
  assert.equal(sessionRecord(v), undefined);
});

test('端末が最後に見た世代より古い世代の保存では戻らない（ローテーションの後）。保存は消す', async () => {
  const w = await kept();
  const key = [...w.chrome.storage.session.values.keys()].find((k) => k.startsWith(SESSION_PREFIX))!;
  w.chrome.storage.session.values.set(key, { ...sessionRecord(w)!, vaultKeyVersion: 0 });
  await stop(w);
  assert.equal((await send(w, { type: 'status' }, POPUP)).locked, true);
  assert.equal(sessionRecord(w), undefined);
});

test('形の違う保存では戻らず、消す', async () => {
  const w = await kept();
  const key = [...w.chrome.storage.session.values.keys()].find((k) => k.startsWith(SESSION_PREFIX))!;
  w.chrome.storage.session.values.set(key, { vaultKey: 'AAAA', vaultKeyVersion: 1 });
  await stop(w);
  assert.equal((await send(w, { type: 'status' }, POPUP)).locked, true);
  assert.equal(sessionRecord(w), undefined);
});
