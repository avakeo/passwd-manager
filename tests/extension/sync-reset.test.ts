// 同期の状態を作り直す（2026-10-30 追記、判断待ち1。DeepSeek #6 の残り、#7）。
// サーバーが一度でも大きな Vault リビジョンを返すと、以後の正直な応答もすべて巻き戻し（S-09）になる。
// 管理者と対面で Vault リビジョンを見比べた後に、マスターパスワードを確かめて、端末の同期の状態を消して全件を取り直す。

import { after, beforeEach, mock, test } from 'node:test';
import assert from 'node:assert/strict';
import { ADMIN_PASSWORD, POPUP, adminReady, newDiscord, restart, send, world, type World } from '../helpers/extension-world.ts';
import { fakeCiphertext } from '../helpers/api.ts';

const T0 = 1_800_000_000_000;
mock.timers.enable({ apis: ['Date'], now: T0 });
after(() => mock.timers.reset());
beforeEach(() => mock.timers.setTime(T0));

const discord = newDiscord();
after(discord.install());

async function titles(w: World): Promise<string[]> {
  return ((await send(w, { type: 'listItems' })).items as { title: string }[]).map((i) => i.title).sort();
}

function serverRevision(w: World): number {
  return Number(w.t.db.db.prepare('SELECT vault_revision AS r FROM vault_meta').get()!.r);
}

// 2件を作ってから、サーバーが1回だけ大きな Vault リビジョンと、1件の偽の削除と、サーバーにない偽のアイテムを返す。以後の正直な応答は巻き戻しになる
async function stuck(): Promise<{ w: World; ids: string[] }> {
  const w = world(discord);
  await adminReady(w, discord);
  for (const title of ['A', 'B']) assert.equal((await send(w, { type: 'saveItem', item: { type: 'note', title, body: `${title} の中身` } })).ok, true);
  assert.equal((await send(w, { type: 'sync' })).ok, true);
  const ids = ((await send(w, { type: 'listItems' })).items as { id: string; title: string }[]).sort((a, b) => a.title.localeCompare(b.title)).map((i) => i.id);
  w.rewrite = async (call) => {
    if (call !== 'GET /v1/items') return null;
    w.rewrite = null;
    return Response.json({
      vault_revision: 999,
      items: [
        { id: ids[1], revision: 99, vault_key_version: 1, deleted: true, change_seq: 999 },
        { id: 'item_ZZZZZZZZZZZZZZZZZZZZZZ', revision: 1, vault_key_version: 1, ciphertext: fakeCiphertext(), change_seq: 999 },
      ],
    });
  };
  assert.equal((await send(w, { type: 'sync' })).ok, true);
  assert.deepEqual(await titles(w), ['', 'A'], '偽の削除で B が消え、読めない偽のアイテムが入った');
  assert.equal((await send(w, { type: 'sync' })).error, 'ROLLBACK_DETECTED');
  return { w, ids };
}

test('S-12 同期の状態：この端末が最後に見た Vault リビジョンと、サーバーの今の値を出す（見比べる値）', async () => {
  const { w } = await stuck();
  const r = await send(w, { type: 'syncStatus' });
  assert.deepEqual(r, { ok: true, deviceRevision: 999, serverRevision: serverRevision(w) });
});

test('S-12 マスターパスワードを確かめて作り直すと、全件を取り直し、偽の削除で消えたアイテムも戻り、同期が続けられる', async () => {
  const { w } = await stuck();
  const now = serverRevision(w);
  assert.deepEqual(await send(w, { type: 'resetSync', masterPassword: ADMIN_PASSWORD, vaultRevision: now }), { ok: true, items: 2 });
  assert.deepEqual(await titles(w), ['A', 'B'], 'B が戻り、偽のアイテムは消えた');
  assert.equal((await send(w, { type: 'sync' })).ok, true);
  assert.deepEqual(await send(w, { type: 'syncStatus' }), { ok: true, deviceRevision: now, serverRevision: now });
  // 作り直した後も、巻き戻しの検知は続く（見比べた値より古い応答は止める）
  w.rewrite = async (call, res) => {
    if (call !== 'GET /v1/items') return null;
    return Response.json({ ...((await res.json()) as Record<string, unknown>), vault_revision: now - 1, items: [] });
  };
  assert.equal((await send(w, { type: 'sync' })).error, 'ROLLBACK_DETECTED');
  w.rewrite = null;
  // 起動し直しても、保存した同期の状態から続く
  assert.equal((await send(w, { type: 'saveItem', item: { type: 'note', title: 'C', body: '' } })).ok, true);
  restart(w);
  assert.equal((await send(w, { type: 'unlock', masterPassword: ADMIN_PASSWORD }, POPUP)).ok, true);
  assert.equal((await send(w, { type: 'sync' })).ok, true);
  assert.deepEqual(await titles(w), ['A', 'B', 'C']);
});

test('S-12 マスターパスワードが違えば、何も消さない', async () => {
  const { w } = await stuck();
  const before = w.chrome.storage.local.dump();
  assert.deepEqual(await send(w, { type: 'resetSync', masterPassword: 'wrong-password-123456', vaultRevision: serverRevision(w) }), { ok: false, error: 'BAD_PASSWORD' });
  assert.equal(w.chrome.storage.local.dump(), before);
  assert.equal((await send(w, { type: 'sync' })).error, 'ROLLBACK_DETECTED');
});

test('S-12 見比べた値と、押したときのサーバーの値が違えば、何も消さない', async () => {
  const { w } = await stuck();
  const shown = serverRevision(w);
  const before = w.chrome.storage.local.dump();
  w.t.db.db.prepare('UPDATE vault_meta SET vault_revision = vault_revision + 1').run();
  assert.deepEqual(await send(w, { type: 'resetSync', masterPassword: ADMIN_PASSWORD, vaultRevision: shown }), { ok: false, error: 'REVISION_CHANGED' });
  assert.equal(w.chrome.storage.local.dump(), before);
});

test('S-12 パスコードで戻った状態でも、マスターパスワードを確かめれば作り直せる。ロック中はできない', async () => {
  const { w } = await stuck();
  assert.equal((await send(w, { type: 'setupQuickUnlock', passcode: '2580' })).ok, true);
  restart(w);
  assert.deepEqual(await send(w, { type: 'resetSync', masterPassword: ADMIN_PASSWORD, vaultRevision: serverRevision(w) }), { ok: false, error: 'LOCKED' });
  assert.equal((await send(w, { type: 'quickUnlock', passcode: '2580' }, POPUP)).ok, true);
  assert.deepEqual(await send(w, { type: 'resetSync', masterPassword: ADMIN_PASSWORD, vaultRevision: serverRevision(w) }), { ok: true, items: 2 });
});

test('S-12 作り直して全件を取るときも、見比べた値より古い Vault リビジョンが返れば止める。作り直した記録は残る', async () => {
  const { w } = await stuck();
  const now = serverRevision(w);
  w.rewrite = async (call, res) => {
    if (call !== 'GET /v1/items') return null;
    return Response.json({ ...((await res.json()) as Record<string, unknown>), vault_revision: now - 1 });
  };
  assert.deepEqual(await send(w, { type: 'resetSync', masterPassword: ADMIN_PASSWORD, vaultRevision: now }), { ok: false, error: 'ROLLBACK_DETECTED' });
  // 作り直した分（見比べた値から始める記録）は、起動し直しても残る。正直な応答に戻れば、そのまま同期できる
  w.rewrite = null;
  restart(w);
  assert.equal((await send(w, { type: 'unlock', masterPassword: ADMIN_PASSWORD }, POPUP)).ok, true);
  assert.deepEqual(await send(w, { type: 'syncStatus' }), { ok: true, deviceRevision: now, serverRevision: now });
  assert.equal((await send(w, { type: 'sync' })).ok, true);
  assert.deepEqual(await titles(w), ['A', 'B']);
});
