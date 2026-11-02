// 管理者が端末を初期化した後の、世代の対面での初期化（P-08。仕様書「メンバーの参加と承認」の8）。
// 管理者の端末は、自分の署名鍵の固定と最後に見た世代を失うと、自分宛てのグラントを開かない（needs-generation-init）。
// メンバーの端末に出ている「固定した管理者の署名鍵」と「最後に見た世代」を対面で見比べ、その値で管理者の端末を初期化する。

import { after, beforeEach, mock, test } from 'node:test';
import assert from 'node:assert/strict';
import { ADMIN_PASSWORD, POPUP, adminReady, newDiscord, newDiscordUser, restart, send, world, type World } from '../helpers/extension-world.ts';
import { base32ToBytes, referenceTotp, stepAt } from '../helpers/totp-reference.ts';

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
  await pin(admin, memberId);
  assert.deepEqual(await send(admin, { type: 'approveMember', memberId }), { ok: true });
  assert.equal((await send(m, { type: 'reopenVault' })).vault, 'ready');
  return { m, memberId };
}

async function pin(admin: World, memberId: string): Promise<void> {
  const row = ((await send(admin, { type: 'listMembers' })).members as { id: string; keyId: string; fingerprint: string }[]).find((x) => x.id === memberId)!;
  assert.equal((await send(admin, { type: 'pinMember', memberId, keyId: row.keyId, fingerprint: row.fingerprint })).ok, true);
}

// 管理者とメンバーがいて、ローテーションで世代2になった後に、管理者が端末を初期化した（storage.local が空になった）
async function adminReset() {
  const w = world(discord);
  await adminReady(w, discord);
  const { m, memberId } = await approvedMember(w);
  assert.equal((await send(w, { type: 'saveItem', item: { type: 'note', title: 'A', body: 'A の中身' } })).ok, true);
  // 世代1のグラント（本物の署名つき）を控えておく。サーバーが巻き戻すときに使う
  const oldGrants = w.t.db.db.prepare('SELECT * FROM vault_key_grants WHERE vault_key_version = 1').all() as Record<string, unknown>[];
  assert.equal((await send(w, { type: 'rotateVault' })).ok, true);
  assert.equal((await send(m, { type: 'sync' })).ok, true);
  w.chrome.storage.local.values.clear();
  restart(w);
  assert.equal((await send(w, { type: 'unlock', masterPassword: ADMIN_PASSWORD }, POPUP)).vault, 'needs-generation-init');
  return { w, m, memberId, oldGrants };
}

test('P-08 メンバーの画面に、固定した管理者の署名鍵と、この端末が最後に見た世代を出す', async () => {
  const { w, m } = await adminReset();
  const shown = await send(w, { type: 'ownSigner' });
  assert.deepEqual(await send(m, { type: 'deviceTrust' }), { ok: true, signerFingerprint: shown.fingerprint, lastSeenGeneration: 2 });
});

test('P-08 管理者の画面に、自分の署名鍵とサーバーの今の世代を出し、一致を押すとその世代で初期化して開く', async () => {
  const { w } = await adminReset();
  const shown = await send(w, { type: 'ownSigner' });
  assert.equal(shown.ok, true);
  assert.equal(shown.vaultKeyVersion, 2);
  assert.equal(shown.needed, true);
  assert.match(String(shown.fingerprint), /^\d{5}( \d{5}){5}$/);
  const r = await send(w, { type: 'confirmGeneration', keyId: shown.keyId, fingerprint: shown.fingerprint, vaultKeyVersion: shown.vaultKeyVersion });
  assert.deepEqual(r, { ok: true, vault: 'ready' });
  assert.equal((await send(w, { type: 'listMembers' })).lastSeenGeneration, 2);
  assert.deepEqual(((await send(w, { type: 'listItems' })).items as { title: string }[]).map((i) => i.title), ['A']);
  assert.equal((await send(w, { type: 'ownSigner' })).needed, false);
});

test('P-08 初期化する前は、承認もローテーションもできない（グラントを作らない）', async () => {
  const { w, memberId } = await adminReset();
  const before = w.calls.length;
  assert.equal((await send(w, { type: 'rotateVault' })).ok, false);
  assert.equal((await send(w, { type: 'approveMember', memberId })).ok, false);
  assert.equal(w.calls.slice(before).filter((c) => c === 'POST /v1/vault/rotate' || c.startsWith('POST /v1/members/')).length, 0);
});

test('P-08 見せた値と、押したときのサーバーの値が違えば、初期化しない', async () => {
  const { w } = await adminReset();
  const shown = await send(w, { type: 'ownSigner' });
  // 見せた後に、サーバーが世代を古く見せた
  w.t.db.db.prepare('UPDATE vault_meta SET current_vault_key_version = 1').run();
  assert.deepEqual(await send(w, { type: 'confirmGeneration', keyId: shown.keyId, fingerprint: shown.fingerprint, vaultKeyVersion: shown.vaultKeyVersion }), { ok: false, error: 'GENERATION_CHANGED' });
  w.t.db.db.prepare('UPDATE vault_meta SET current_vault_key_version = 2').run();
  // フィンガープリントや鍵 ID が違う値も受け付けない
  const other = String(shown.fingerprint).replace(/^\d/, (d) => String((Number(d) + 1) % 10));
  assert.deepEqual(await send(w, { type: 'confirmGeneration', keyId: shown.keyId, fingerprint: other, vaultKeyVersion: 2 }), { ok: false, error: 'GENERATION_CHANGED' });
  assert.deepEqual(await send(w, { type: 'confirmGeneration', keyId: 'key_AAAAAAAAAAAAAAAAAAAAAA', fingerprint: shown.fingerprint, vaultKeyVersion: 2 }), { ok: false, error: 'GENERATION_CHANGED' });
  assert.equal((await send(w, { type: 'listMembers' })).lastSeenGeneration, null);
  assert.equal((await send(w, { type: 'status' }, POPUP)).vault, 'needs-generation-init');
});

test('P-08 初期化した後も、それより古い世代のグラントは開かない', async () => {
  const { w, oldGrants } = await adminReset();
  const shown = await send(w, { type: 'ownSigner' });
  assert.equal((await send(w, { type: 'confirmGeneration', keyId: shown.keyId, fingerprint: shown.fingerprint, vaultKeyVersion: 2 })).ok, true);
  // サーバーが今の世代を1に戻し、控えた世代1のグラントを書き戻した（巻き戻し）
  w.t.db.db.prepare('UPDATE vault_meta SET current_vault_key_version = 1').run();
  for (const g of oldGrants) {
    const cols = Object.keys(g);
    w.t.db.db.prepare(`INSERT INTO vault_key_grants (${cols.join(', ')}) VALUES (${cols.map(() => '?').join(', ')})`).run(...(cols.map((c) => g[c]) as never[]));
  }
  assert.equal((await send(w, { type: 'reopenVault' })).vault, 'grant-rejected');
});

test('P-08 初期化が要らない状態（固定がある）では、上書きしない。メンバーは使えない', async () => {
  const w = world(discord);
  await adminReady(w, discord);
  const shown = await send(w, { type: 'ownSigner' });
  assert.equal(shown.needed, false);
  assert.deepEqual(await send(w, { type: 'confirmGeneration', keyId: shown.keyId, fingerprint: shown.fingerprint, vaultKeyVersion: shown.vaultKeyVersion }), { ok: false, error: 'NOT_NEEDED' });
  const { m } = await approvedMember(w);
  assert.deepEqual(await send(m, { type: 'ownSigner' }), { ok: false, error: 'NOT_ADMIN' });
});

test('P-08 初期化した後、メンバーを照合し直すまでローテーションは止まり、照合し直すと通る', async () => {
  const { w, m, memberId } = await adminReset();
  const shown = await send(w, { type: 'ownSigner' });
  assert.equal((await send(w, { type: 'confirmGeneration', keyId: shown.keyId, fingerprint: shown.fingerprint, vaultKeyVersion: 2 })).ok, true);
  assert.deepEqual(await send(w, { type: 'rotateVault' }), { ok: false, error: 'NOT_PINNED' });
  await pin(w, memberId);
  assert.deepEqual(await send(w, { type: 'rotateVault' }), { ok: true, vaultKeyVersion: 3, items: 1 });
  assert.equal((await send(m, { type: 'sync' })).ok, true);
  assert.deepEqual(((await send(m, { type: 'listItems' })).items as { title: string }[]).map((i) => i.title), ['A']);
});
