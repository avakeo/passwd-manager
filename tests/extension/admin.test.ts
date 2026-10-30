// フェーズ4a：承認の双方向の照合、承認、削除を、拡張機能の Service Worker で通しで確かめる（docs/実装状況.md の12.2・12.3）。
// 管理者とメンバーは、同じサーバー（本物の API ＋ SQLite）につないだ2つの偽の chrome。

import { after, beforeEach, mock, test } from 'node:test';
import assert from 'node:assert/strict';
import { ADMIN_PASSWORD, POPUP, adminReady, newDiscord, newDiscordUser, restart, send, world, type World } from '../helpers/extension-world.ts';
import { base32ToBytes, referenceTotp, stepAt } from '../helpers/totp-reference.ts';
import { fingerprint } from '../../src/crypto/public-key.ts';
import { createMemberKey } from '../../src/crypto/member-key.ts';
import { fromBase64Url, toBase64Url } from '../../src/crypto/bytes.ts';

const T0 = 1_800_000_000_000;
mock.timers.enable({ apis: ['Date'], now: T0 });
after(() => mock.timers.reset());
beforeEach(() => mock.timers.setTime(T0));

const discord = newDiscord();
after(discord.install());

const MEMBER_PASSWORD = 'member-umi-yama-kawa-31';
const otherKey = await createMemberKey('attacker-sashikae-kagi-01');

type Member = { id: string; status: string; fingerprint: string | null; keyId: string | null; pinned: boolean };

// メンバー：ログイン → TOTP の登録 → 鍵の作成。サーバーでは承認待ち
async function memberReady(admin: World): Promise<{ m: World; memberId: string }> {
  const m = world(discord, admin.t);
  m.chrome.loginAs = newDiscordUser(discord);
  assert.equal((await send(m, { type: 'login', deviceLabel: 'メンバーの端末' }, POPUP)).status, 'totp_setup_required');
  const start = await send(m, { type: 'totpSetupStart' });
  const secret = base32ToBytes(String(start.secret).replace(/ /g, ''));
  assert.equal((await send(m, { type: 'totpSetupConfirm', code: referenceTotp(secret, stepAt(Date.now())) })).ok, true);
  const created = await send(m, { type: 'createKey', masterPassword: MEMBER_PASSWORD, replace: false });
  assert.equal(created.vault, 'awaiting-approval', JSON.stringify(created));
  const memberId = String(admin.t.db.db.prepare('SELECT id FROM members WHERE discord_user_id = ?').get(m.chrome.loginAs)!.id);
  return { m, memberId };
}

async function adminWorld(): Promise<World> {
  const w = world(discord);
  await adminReady(w, discord);
  assert.equal((await send(w, { type: 'saveItem', item: { type: 'note', title: 'チームのメモ', body: '中身' } })).ok, true);
  return w;
}

async function members(w: World): Promise<{ list: Member[]; lastSeenGeneration: number }> {
  const r = await send(w, { type: 'listMembers' });
  assert.equal(r.ok, true, JSON.stringify(r));
  return { list: r.members as Member[], lastSeenGeneration: Number(r.lastSeenGeneration) };
}

// メンバーの照合：管理者の署名鍵のフィンガープリントと今の世代を見て、一致を押す
async function memberConfirms(m: World) {
  const shown = await send(m, { type: 'adminSigner' });
  assert.equal(shown.ok, true, JSON.stringify(shown));
  return send(m, { type: 'confirmAdminSigner', keyId: shown.keyId, fingerprint: shown.fingerprint, vaultKeyVersion: shown.vaultKeyVersion });
}

async function adminPinsAndApproves(w: World, memberId: string) {
  const row = (await members(w)).list.find((x) => x.id === memberId)!;
  assert.equal((await send(w, { type: 'pinMember', memberId, keyId: row.keyId, fingerprint: row.fingerprint })).ok, true);
  return send(w, { type: 'approveMember', memberId });
}

test('P-06 照合の画面：メンバーには管理者の署名鍵のフィンガープリント（全桁）と今の世代、管理者にはメンバーの公開鍵のフィンガープリントと最後に見た世代が出る', async () => {
  const w = await adminWorld();
  const { m, memberId } = await memberReady(w);
  const shown = await send(m, { type: 'adminSigner' });
  const adminSign = fromBase64Url(String(w.t.db.db.prepare('SELECT ecdsa_public_key FROM member_keys WHERE ecdsa_public_key IS NOT NULL').get()!.ecdsa_public_key));
  assert.equal(shown.fingerprint, await fingerprint(adminSign));
  assert.match(String(shown.fingerprint), /^\d{5}( \d{5}){5}$/, '6組30桁を省略しない（DeepSeek #13）');
  assert.equal(shown.vaultKeyVersion, 1);
  // 相手が見比べる、自分の鍵のフィンガープリントも出す（メンバーは公開鍵、管理者は署名用公開鍵）
  const memberPub0 = fromBase64Url(String(w.t.db.db.prepare('SELECT ecdh_public_key FROM member_keys WHERE member_id = ?').get(memberId)!.ecdh_public_key));
  assert.equal(shown.ownFingerprint, await fingerprint(memberPub0));
  const listed = await send(w, { type: 'listMembers' });
  assert.equal(listed.signFingerprint, await fingerprint(adminSign));
  const { list, lastSeenGeneration } = await members(w);
  assert.equal(lastSeenGeneration, 1);
  const row = list.find((x) => x.id === memberId)!;
  const memberPub = fromBase64Url(String(w.t.db.db.prepare('SELECT ecdh_public_key FROM member_keys WHERE member_id = ?').get(memberId)!.ecdh_public_key));
  assert.deepEqual([row.status, row.fingerprint, row.pinned], ['pending', await fingerprint(memberPub), false]);
});

test('P-04 P-06 メンバーは「一致」を押すまで固定せず、グラントを開かない。違うフィンガープリントでは固定しない', async () => {
  const w = await adminWorld();
  const { m, memberId } = await memberReady(w);
  const shown = await send(m, { type: 'adminSigner' });
  const wrong = String(shown.fingerprint).replace(/^\d/, (d) => String((Number(d) + 1) % 10));
  assert.deepEqual(await send(m, { type: 'confirmAdminSigner', keyId: shown.keyId, fingerprint: wrong, vaultKeyVersion: shown.vaultKeyVersion }), { ok: false, error: 'SIGNER_CHANGED' });
  assert.deepEqual(await send(m, { type: 'confirmAdminSigner', keyId: shown.keyId, fingerprint: shown.fingerprint, vaultKeyVersion: 2 }), { ok: false, error: 'SIGNER_CHANGED' });
  // 管理者が承認しても、メンバーが照合するまでは開かない（P-04）
  assert.equal((await adminPinsAndApproves(w, memberId)).ok, true);
  await send(m, { type: 'lock' }, POPUP);
  assert.equal((await send(m, { type: 'unlock', masterPassword: MEMBER_PASSWORD }, POPUP)).vault, 'awaiting-approval');
  // 照合すると、その場で開き直して使えるようになる
  const r = await memberConfirms(m);
  assert.deepEqual([r.ok, r.vault], [true, 'ready'], JSON.stringify(r));
  await send(m, { type: 'sync' });
  assert.deepEqual(((await send(m, { type: 'listItems' })).items as { title: string }[]).map((i) => i.title), ['チームのメモ']);
});

test('P-06 管理者は「一致」を押して固定するまで承認できない。違うフィンガープリントでは固定しない', async () => {
  const w = await adminWorld();
  const { memberId } = await memberReady(w);
  assert.deepEqual(await send(w, { type: 'approveMember', memberId }), { ok: false, error: 'NOT_PINNED' });
  const row = (await members(w)).list.find((x) => x.id === memberId)!;
  assert.deepEqual(await send(w, { type: 'pinMember', memberId, keyId: row.keyId, fingerprint: '00000 00000 00000 00000 00000 00000' }), { ok: false, error: 'KEY_CHANGED' });
  assert.equal((await members(w)).list.find((x) => x.id === memberId)!.pinned, false);
  assert.equal((await send(w, { type: 'pinMember', memberId, keyId: row.keyId, fingerprint: row.fingerprint })).ok, true);
  assert.equal((await members(w)).list.find((x) => x.id === memberId)!.pinned, true);
  assert.deepEqual(await send(w, { type: 'approveMember', memberId }), { ok: true });
  assert.equal((await members(w)).list.find((x) => x.id === memberId)!.status, 'active');
});

test('通しで：照合と承認の後、メンバーは管理者が作ったアイテムを読め、自分で作ったアイテムも管理者が読める', async () => {
  const w = await adminWorld();
  const { m, memberId } = await memberReady(w);
  assert.equal((await memberConfirms(m)).ok, true);
  assert.deepEqual(await adminPinsAndApproves(w, memberId), { ok: true });
  assert.equal((await send(m, { type: 'reopenVault' })).vault, 'ready');
  assert.equal((await send(m, { type: 'saveItem', item: { type: 'note', title: 'メンバーのメモ', body: 'x' } })).ok, true);
  await send(w, { type: 'sync' });
  const titles = ((await send(w, { type: 'listItems' })).items as { title: string }[]).map((i) => i.title).sort();
  assert.deepEqual(titles, ['チームのメモ', 'メンバーのメモ'].sort());
});

test('P-01 固定した後にサーバーでメンバーの公開鍵が差し替えられたら、管理者の端末はグラントを作らない', async () => {
  const w = await adminWorld();
  const { memberId } = await memberReady(w);
  const row = (await members(w)).list.find((x) => x.id === memberId)!;
  assert.equal((await send(w, { type: 'pinMember', memberId, keyId: row.keyId, fingerprint: row.fingerprint })).ok, true);
  w.t.db.db.prepare('UPDATE member_keys SET ecdh_public_key = ? WHERE member_id = ?').run(toBase64Url(otherKey.record.publicKey), memberId);
  assert.deepEqual(await send(w, { type: 'approveMember', memberId }), { ok: false, error: 'KEY_MISMATCH' });
  assert.equal(Number(w.t.db.db.prepare('SELECT COUNT(*) AS n FROM vault_key_grants').get()!.n), 1, '管理者自身の分だけ');
  assert.equal(w.calls.filter((c) => c.startsWith('POST /v1/members/')).length, 0, '承認を送らない');
});

test('A-10 E-17 承認は、5分以内に TOTP を確かめ、マスターパスワードで解除した管理者だけ', async () => {
  const w = await adminWorld();
  const { memberId } = await memberReady(w);
  const row = (await members(w)).list.find((x) => x.id === memberId)!;
  assert.equal((await send(w, { type: 'pinMember', memberId, keyId: row.keyId, fingerprint: row.fingerprint })).ok, true);
  mock.timers.setTime(T0 + 6 * 60 * 1000);
  assert.deepEqual(await send(w, { type: 'approveMember', memberId }), { ok: false, error: 'STEP_UP_REQUIRED' });
  // パスコードで戻った状態では、秘密鍵がないので承認できない
  assert.equal((await send(w, { type: 'setupQuickUnlock', passcode: '2580' })).ok, true);
  restart(w);
  assert.equal((await send(w, { type: 'quickUnlock', passcode: '2580' }, POPUP)).ok, true);
  assert.deepEqual(await send(w, { type: 'approveMember', memberId }), { ok: false, error: 'PASSWORD_REQUIRED' });
  assert.equal((await send(w, { type: 'unlock', masterPassword: ADMIN_PASSWORD }, POPUP)).vault, 'ready');
});

test('削除：管理者がメンバーを削除すると、メンバーの端末はログインからやり直しになる。管理者は自分を削除できない', async () => {
  const w = await adminWorld();
  const { m, memberId } = await memberReady(w);
  assert.equal((await memberConfirms(m)).ok, true);
  assert.equal((await adminPinsAndApproves(w, memberId)).ok, true);
  assert.deepEqual(await send(w, { type: 'removeMember', memberId }), { ok: true, rotationRecommended: true });
  assert.equal((await members(w)).list.some((x) => x.id === memberId), false);
  const r = await send(m, { type: 'sync' });
  assert.equal(r.ok, false);
  assert.equal((await send(m, { type: 'status' }, POPUP)).loggedIn, false);
  const adminId = String(w.t.db.db.prepare(`SELECT id FROM members WHERE role = 'admin'`).get()!.id);
  assert.deepEqual(await send(w, { type: 'removeMember', memberId: adminId }), { ok: false, error: 'CANNOT_REMOVE_SELF' });
});

test('Z-02 メンバーは、ほかの人を固定・承認・削除できない', async () => {
  const w = await adminWorld();
  const { m, memberId } = await memberReady(w);
  assert.equal((await memberConfirms(m)).ok, true);
  assert.equal((await adminPinsAndApproves(w, memberId)).ok, true);
  assert.equal((await send(m, { type: 'reopenVault' })).vault, 'ready');
  const { memberId: other } = await memberReady(w);
  assert.deepEqual(await send(m, { type: 'approveMember', memberId: other }), { ok: false, error: 'NOT_ADMIN' });
  assert.deepEqual(await send(m, { type: 'removeMember', memberId: other }), { ok: false, error: 'NOT_ADMIN' });
});
