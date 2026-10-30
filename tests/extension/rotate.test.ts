// フェーズ4b：ローテーションを、拡張機能の Service Worker で通しで確かめる（docs/実装状況.md の12.4）。
// 管理者とメンバーは、同じサーバーにつないだ2つの偽の chrome。照合と承認は admin.test.ts と同じ流れで済ませる。

import { after, beforeEach, mock, test } from 'node:test';
import assert from 'node:assert/strict';
import { POPUP, adminReady, hold, newDiscord, newDiscordUser, restart, send, world, type World } from '../helpers/extension-world.ts';
import { base32ToBytes, referenceTotp, stepAt } from '../helpers/totp-reference.ts';
import { fakeCiphertext } from '../helpers/api.ts';

const T0 = 1_800_000_000_000;
mock.timers.enable({ apis: ['Date'], now: T0 });
after(() => mock.timers.reset());
beforeEach(() => mock.timers.setTime(T0));

const discord = newDiscord();
after(discord.install());

const MEMBER_PASSWORD = 'member-umi-yama-kawa-31';

async function approvedMember(admin: World): Promise<{ m: World; memberId: string }> {
  const m = world(discord, admin.t);
  m.chrome.loginAs = newDiscordUser(discord);
  await send(m, { type: 'login', deviceLabel: 'メンバーの端末' }, POPUP);
  const start = await send(m, { type: 'totpSetupStart' });
  await send(m, { type: 'totpSetupConfirm', code: referenceTotp(base32ToBytes(String(start.secret).replace(/ /g, '')), stepAt(Date.now())) });
  await send(m, { type: 'createKey', masterPassword: MEMBER_PASSWORD, replace: false });
  const memberId = String(admin.t.db.db.prepare('SELECT id FROM members WHERE discord_user_id = ?').get(m.chrome.loginAs)!.id);
  const shown = await send(m, { type: 'adminSigner' });
  assert.equal((await send(m, { type: 'confirmAdminSigner', keyId: shown.keyId, fingerprint: shown.fingerprint, vaultKeyVersion: shown.vaultKeyVersion })).ok, true);
  const row = ((await send(admin, { type: 'listMembers' })).members as { id: string; keyId: string; fingerprint: string }[]).find((x) => x.id === memberId)!;
  assert.equal((await send(admin, { type: 'pinMember', memberId, keyId: row.keyId, fingerprint: row.fingerprint })).ok, true);
  assert.deepEqual(await send(admin, { type: 'approveMember', memberId }), { ok: true });
  assert.equal((await send(m, { type: 'reopenVault' })).vault, 'ready');
  return { m, memberId };
}

async function team() {
  const w = world(discord);
  await adminReady(w, discord);
  const { m, memberId } = await approvedMember(w);
  for (const title of ['A', 'B']) assert.equal((await send(w, { type: 'saveItem', item: { type: 'note', title, body: `${title} の中身` } })).ok, true);
  assert.equal((await send(m, { type: 'saveItem', item: { type: 'note', title: 'M', body: 'メンバーの中身' } })).ok, true);
  await send(w, { type: 'sync' });
  return { w, m, memberId };
}

async function titles(w: World): Promise<string[]> {
  await send(w, { type: 'sync' });
  return ((await send(w, { type: 'listItems' })).items as { title: string }[]).map((i) => i.title).sort();
}

test('ローテーション：新しい世代の鍵で全アイテムを暗号化し直し、管理者もメンバーも続けて読み書きできる', async () => {
  const { w, m } = await team();
  const r = await send(w, { type: 'rotateVault' });
  assert.deepEqual(r, { ok: true, vaultKeyVersion: 2, items: 3 });
  assert.equal(Number(w.t.db.db.prepare('SELECT current_vault_key_version AS v FROM vault_meta').get()!.v), 2);
  assert.equal((await send(w, { type: 'listMembers' })).lastSeenGeneration, 2, '管理者の端末の最後に見た世代も上げる');
  assert.deepEqual(await titles(w), ['A', 'B', 'M']);
  // メンバーは、次の同期で新しい世代のグラントを開き直す（マスターパスワードで解除した状態なので、入力なしで）
  assert.deepEqual(await titles(m), ['A', 'B', 'M']);
  const items = (await send(m, { type: 'listItems' })).items as { id: string; title: string }[];
  assert.equal(((await send(m, { type: 'getItem', id: items.find((i) => i.title === 'A')!.id })).item as { body: string }).body, 'A の中身');
  assert.equal((await send(m, { type: 'saveItem', item: { type: 'note', title: 'N', body: '新しい世代で' } })).ok, true);
  assert.deepEqual(await titles(w), ['A', 'B', 'M', 'N']);
  // サーバーには平文を送っていない
  const stored = JSON.stringify(w.t.db.db.prepare('SELECT * FROM items').all());
  for (const plain of ['A の中身', 'メンバーの中身']) assert.ok(!stored.includes(plain));
});

test('S-06 削除したメンバーは、ローテーションの後に新しい世代のグラントを受け取らない', async () => {
  const { w, m, memberId } = await team();
  assert.equal((await send(w, { type: 'removeMember', memberId })).ok, true);
  assert.deepEqual(await send(w, { type: 'rotateVault' }), { ok: true, vaultKeyVersion: 2, items: 3 });
  const keys = w.t.db.db.prepare('SELECT recipient_key_id FROM vault_key_grants').all().map((r) => r.recipient_key_id);
  const memberKeys = w.t.db.db.prepare('SELECT id FROM member_keys WHERE member_id = ?').all(memberId).map((r) => r.id);
  assert.equal(keys.length, 1, '管理者の分だけ');
  assert.ok(!keys.some((k) => memberKeys.includes(k)));
  assert.equal((await send(m, { type: 'sync' })).ok, false);
});

test('S-07 管理者が取得した後に、メンバーがアイテムを書き換えたら 409。何も変わらず、やり直せば通る', async () => {
  const { w, m } = await team();
  const gate = hold(w, 'POST /v1/vault/rotate');
  const pending = send(w, { type: 'rotateVault' });
  await gate.arrived;
  await send(m, { type: 'sync' });
  const items = (await send(m, { type: 'listItems' })).items as { id: string; title: string; revision: number }[];
  const a = items.find((i) => i.title === 'A')!;
  assert.equal((await send(m, { type: 'saveItem', id: a.id, revision: a.revision, item: { type: 'note', title: 'A', body: '書き換えた' } })).ok, true);
  gate.release();
  assert.deepEqual(await pending, { ok: false, error: 'ROTATION_CONFLICT' });
  assert.equal(Number(w.t.db.db.prepare('SELECT current_vault_key_version AS v FROM vault_meta').get()!.v), 1);
  assert.deepEqual(await titles(w), ['A', 'B', 'M'], '管理者の手元も前の世代のまま読める');
  assert.deepEqual(await send(w, { type: 'rotateVault' }), { ok: true, vaultKeyVersion: 2, items: 3 });
});

test('P-01 有効なメンバーの公開鍵がサーバーで差し替えられていたら、ローテーションのグラントを作らずに止める', async () => {
  const { w, memberId } = await team();
  const adminKey = String(w.t.db.db.prepare(`SELECT ecdh_public_key FROM member_keys WHERE ecdsa_public_key IS NOT NULL`).get()!.ecdh_public_key);
  w.t.db.db.prepare('UPDATE member_keys SET ecdh_public_key = ? WHERE member_id = ?').run(adminKey, memberId);
  assert.deepEqual(await send(w, { type: 'rotateVault' }), { ok: false, error: 'KEY_MISMATCH' });
  assert.equal(w.calls.filter((c) => c === 'POST /v1/vault/rotate').length, 0);
});

test('A-10 E-17 ローテーションは、5分以内に TOTP を確かめ、マスターパスワードで解除した管理者だけ。メンバーはできない', async () => {
  const { w, m } = await team();
  assert.deepEqual(await send(m, { type: 'rotateVault' }), { ok: false, error: 'NOT_ADMIN' });
  mock.timers.setTime(T0 + 6 * 60 * 1000);
  assert.deepEqual(await send(w, { type: 'rotateVault' }), { ok: false, error: 'STEP_UP_REQUIRED' });
  assert.equal((await send(w, { type: 'setupQuickUnlock', passcode: '2580' })).ok, true);
  restart(w);
  assert.equal((await send(w, { type: 'quickUnlock', passcode: '2580' }, POPUP)).ok, true);
  assert.deepEqual(await send(w, { type: 'rotateVault' }), { ok: false, error: 'PASSWORD_REQUIRED' });
});

test('開けないアイテムが1つでもあれば、書き換えて中身を失わないよう、送らずに止める', async () => {
  const { w } = await team();
  // 形だけ正しく、今の鍵では開けない暗号文（サーバーに置かれた偽物）
  w.t.db.db.prepare(`INSERT INTO items (id, revision, vault_key_version, ciphertext, created_by, created_at, updated_by, updated_at, change_seq) VALUES ('item_ZZZZZZZZZZZZZZZZZZZZZZ', 1, 1, ?, 'x', 0, 'x', 0, 1)`).run(fakeCiphertext());
  assert.deepEqual(await send(w, { type: 'rotateVault' }), { ok: false, error: 'UNREADABLE_ITEMS' });
  assert.equal(w.calls.filter((c) => c === 'POST /v1/vault/rotate').length, 0);
});

test('承認待ちのメンバーがいても、有効なメンバーの分だけグラントを作って通る', async () => {
  const { w } = await team();
  const p = world(discord, w.t);
  p.chrome.loginAs = newDiscordUser(discord);
  await send(p, { type: 'login', deviceLabel: '承認待ちの端末' }, POPUP);
  const start = await send(p, { type: 'totpSetupStart' });
  await send(p, { type: 'totpSetupConfirm', code: referenceTotp(base32ToBytes(String(start.secret).replace(/ /g, '')), stepAt(Date.now())) });
  assert.equal((await send(p, { type: 'createKey', masterPassword: MEMBER_PASSWORD, replace: false })).vault, 'awaiting-approval');
  assert.deepEqual(await send(w, { type: 'rotateVault' }), { ok: true, vaultKeyVersion: 2, items: 3 });
  assert.equal(Number(w.t.db.db.prepare('SELECT COUNT(*) AS n FROM vault_key_grants').get()!.n), 2, '管理者と承認済みのメンバー');
});

test('ロック解除を保つ設定なら、ローテーションの後に新しい世代の鍵で置き直す（止まった後も入力なしで戻る）', async () => {
  const { w } = await team();
  assert.equal((await send(w, { type: 'setKeepUnlocked', enabled: true })).ok, true);
  assert.equal((await send(w, { type: 'rotateVault' })).ok, true);
  const rec = [...w.chrome.storage.session.values.entries()].find(([k]) => k.startsWith('teampw/v1/unlock|session|'))![1] as { vaultKeyVersion: number };
  assert.equal(rec.vaultKeyVersion, 2);
  restart(w);
  assert.equal((await send(w, { type: 'status' }, POPUP)).unlockedBy, 'session');
  assert.deepEqual(await titles(w), ['A', 'B', 'M']);
});
