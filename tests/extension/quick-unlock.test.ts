// フェーズ2b：クイックロック解除（4桁のパスコード。仕様書「クイックロック解除」、A-5）。
// E-14（Service Worker の停止）、E-15（5回の失敗）、E-17（戻った状態での管理操作）、E-18（ブラウザの再起動）。

import { after, beforeEach, mock, test } from 'node:test';
import assert from 'node:assert/strict';
import { POPUP, adminReady, newDiscord, restart, send, world, type World } from '../helpers/extension-world.ts';
import { fromBase64Url } from '../../src/crypto/bytes.ts';

const T0 = 1_800_000_000_000;
mock.timers.enable({ apis: ['Date'], now: T0 });
after(() => mock.timers.reset());
beforeEach(() => mock.timers.setTime(T0));

const discord = newDiscord();
after(discord.install());

const PASSCODE = '2580';

function quickRecord(w: World): Record<string, unknown> | undefined {
  const entry = [...w.chrome.storage.session.values.entries()].find(([k]) => k.startsWith('teampw/v1/unlock|'));
  return entry?.[1] as Record<string, unknown> | undefined;
}

// 管理者でロック解除し、パスコードを決め、Service Worker を止める（起動し直す）
async function stoppedWithPasscode() {
  const w = world(discord);
  await adminReady(w, discord);
  assert.equal((await send(w, { type: 'saveItem', item: { type: 'note', title: 'メモ', body: '中身' } })).ok, true);
  const set = await send(w, { type: 'setupQuickUnlock', passcode: PASSCODE });
  assert.equal(set.ok, true, JSON.stringify(set));
  restart(w);
  await w.bg.onStartup();
  return w;
}

test('E-14 Service Worker が止まった後、パスコードで Vault 鍵だけが戻る。秘密鍵は戻らない', async () => {
  const w = await stoppedWithPasscode();
  const status = await send(w, { type: 'status' }, POPUP);
  assert.deepEqual([status.locked, status.quickUnlockAvailable], [true, true]);
  assert.deepEqual(w.bg.memoryState(), { unlocked: false, vaultKey: false });
  const r = await send(w, { type: 'quickUnlock', passcode: PASSCODE }, POPUP);
  assert.deepEqual([r.ok, r.vault], [true, 'ready'], JSON.stringify(r));
  assert.deepEqual(w.bg.memoryState(), { unlocked: false, vaultKey: true }, '秘密鍵は持たない');
  assert.equal((await send(w, { type: 'status' }, POPUP)).unlockedBy, 'passcode');
  assert.equal((await send(w, { type: 'sync' })).ok, true);
  const items = (await send(w, { type: 'listItems' })).items as { title: string }[];
  assert.deepEqual(items.map((i) => i.title), ['メモ']);
});

test('クイックロック解除の保存：storage.session にだけ置き、中身はソルト・反復回数・世代・包んだ Vault 鍵・失敗の回数。60万回、形式とアルゴリズム ID 付き', async () => {
  const w = await stoppedWithPasscode();
  const rec = quickRecord(w)!;
  assert.deepEqual(Object.keys(rec).sort(), ['failures', 'iterations', 'salt', 'vaultKeyVersion', 'wrapped']);
  assert.equal(rec.iterations, 600_000);
  assert.equal(rec.failures, 0);
  assert.equal(fromBase64Url(String(rec.salt)).length, 16);
  const wrapped = fromBase64Url(String(rec.wrapped));
  assert.deepEqual([wrapped[0], wrapped[1]], [0x01, 0x01]);
  assert.equal(wrapped.length, 2 + 12 + 32 + 16, 'Vault 鍵（32バイト）だけ。秘密鍵は入らない');
  assert.ok(!w.chrome.storage.local.dump().includes(String(rec.wrapped)), 'storage.local には置かない');
});

test('E-15 4回間違えても戻れるが、5回目の失敗で保存を消し、正しいパスコードでも戻れずマスターパスワードを求める', async () => {
  const w = await stoppedWithPasscode();
  for (let i = 1; i <= 4; i++) {
    assert.equal((await send(w, { type: 'quickUnlock', passcode: '0000' }, POPUP)).error, 'BAD_PASSCODE', `${i}回目`);
    assert.equal(quickRecord(w)!.failures, i, '試す前に数えて書いてある');
  }
  assert.equal((await send(w, { type: 'quickUnlock', passcode: '0000' }, POPUP)).error, 'QUICK_UNLOCK_CLEARED');
  assert.equal(quickRecord(w), undefined, '5回目で保存を消す');
  assert.equal((await send(w, { type: 'quickUnlock', passcode: PASSCODE }, POPUP)).error, 'NO_QUICK_UNLOCK');
  assert.equal((await send(w, { type: 'status' }, POPUP)).quickUnlockAvailable, false);
});

test('E-15 間違ったパスコードを同時に10個送っても、試せるのは5回までで、保存は消える', async () => {
  const w = await stoppedWithPasscode();
  const replies = await Promise.all(Array.from({ length: 10 }, () => send(w, { type: 'quickUnlock', passcode: '1111' }, POPUP)));
  const errors = replies.map((r) => r.error);
  assert.equal(errors.filter((e) => e === 'BAD_PASSCODE' || e === 'QUICK_UNLOCK_CLEARED').length, 5, JSON.stringify(errors));
  assert.equal(errors.filter((e) => e === 'NO_QUICK_UNLOCK').length, 5);
  assert.equal(quickRecord(w), undefined);
});

test('E-15 戻れたら失敗の回数を0に戻す', async () => {
  const w = await stoppedWithPasscode();
  for (let i = 0; i < 4; i++) await send(w, { type: 'quickUnlock', passcode: '0000' }, POPUP);
  assert.equal((await send(w, { type: 'quickUnlock', passcode: PASSCODE }, POPUP)).ok, true);
  assert.equal(quickRecord(w)!.failures, 0);
});

test('E-17 パスコードで戻った状態では、鍵の作り直し・最初の Vault・パスコードの設定にマスターパスワードを求める', async () => {
  const w = await stoppedWithPasscode();
  await send(w, { type: 'quickUnlock', passcode: PASSCODE }, POPUP);
  assert.equal((await send(w, { type: 'createKey', masterPassword: 'another-master-pass-77', replace: true })).error, 'PASSWORD_REQUIRED');
  assert.equal((await send(w, { type: 'initVault' })).error, 'PASSWORD_REQUIRED');
  assert.equal((await send(w, { type: 'setupQuickUnlock', passcode: '1357' })).error, 'PASSWORD_REQUIRED');
});

test('E-17 パスコードで戻った状態で、新しい世代（ローテーションの後）のアイテムが来たら、ロックしてマスターパスワードを求める', async () => {
  const w = await stoppedWithPasscode();
  await send(w, { type: 'quickUnlock', passcode: PASSCODE }, POPUP);
  // サーバーでローテーションがあった（世代2のアイテムが届く）
  w.t.db.db.exec(`UPDATE vault_meta SET current_vault_key_version = 2, vault_revision = vault_revision + 1`);
  w.t.db.db
    .prepare(`INSERT INTO items (id, revision, vault_key_version, ciphertext, created_by, created_at, updated_by, updated_at, change_seq)
              VALUES ('item_RRRRRRRRRRRRRRRRRRRRRR', 1, 2, ?, 'x', 0, 'x', 0, 1000)`)
    .run('AQE' + 'A'.repeat(720));
  const r = await send(w, { type: 'sync' });
  assert.deepEqual([r.ok, r.error], [false, 'PASSWORD_REQUIRED']);
  assert.deepEqual(w.bg.memoryState(), { unlocked: false, vaultKey: false });
});

test('E-18 ブラウザを閉じると（storage.session が消える）、パスコードは使えない。ロックと15分の放置でも消える', async () => {
  const w = await stoppedWithPasscode();
  w.chrome.storage.session.clear();
  restart(w);
  await w.bg.onStartup();
  assert.equal((await send(w, { type: 'quickUnlock', passcode: PASSCODE }, POPUP)).error, 'NOT_LOGGED_IN');
  // 明示的なロック
  const v = await stoppedWithPasscode();
  await send(v, { type: 'lock' }, POPUP);
  assert.equal(quickRecord(v), undefined);
  // 15分の放置
  const x = await stoppedWithPasscode();
  mock.timers.setTime(T0 + 16 * 60 * 1000);
  restart(x);
  await x.bg.onStartup();
  assert.equal(quickRecord(x), undefined);
});

test('パスコードの設定は、マスターパスワードで解除した後だけ。4桁の数字だけを受け付ける', async () => {
  const w = world(discord);
  await adminReady(w, discord);
  for (const passcode of ['123', '12345', 'abcd', '１２３４']) assert.equal((await send(w, { type: 'setupQuickUnlock', passcode })).error, 'BAD_REQUEST', passcode);
  await send(w, { type: 'lock' }, POPUP);
  assert.equal((await send(w, { type: 'setupQuickUnlock', passcode: PASSCODE })).error, 'LOCKED');
});
