// フェーズ4a：メンバーの一覧、承認（グラントと同時）、削除、監査ログ（docs/実装状況.md の12章）。
// 仕様書「メンバーの参加と承認」「メンバーの削除とローテーション」、テスト P-02・P-03・A-10・Z-02・Z-05。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toBase64Url } from '../../src/crypto/bytes.ts';
import { createAdminKey, createMemberKey, type MemberKeyRecord } from '../../src/crypto/member-key.ts';
import { createGrant, type GrantSigner } from '../../src/crypto/grant.ts';
import { MemoryPinStore, pinPublicKey } from '../../src/crypto/public-key.ts';
import { pinSigner } from '../../src/crypto/signer.ts';
import { generateVaultKeyRaw } from '../../src/crypto/vault-key.ts';
import { newTrust } from '../helpers/trust.ts';
import { setup } from '../helpers/api.ts';
import { grantBody, insertKey } from '../helpers/vault-admin.ts';

const adminKey = await createAdminKey('admin-hoshi-sora-umi-42');
const cKey = await createMemberKey('c-san-kawa-mori-yama-18');
const cKey2 = await createMemberKey('c-san-atarashii-kagi-77');
const vaultKeyRaw = generateVaultKeyRaw();

type Setup = ReturnType<typeof setup>;

// 管理者（最初の Vault は済み）と、鍵を登録した承認待ちの C さん
async function world() {
  const t = setup();
  const admin = await t.addMember('active', { role: 'admin', totpVerifiedAt: Date.now() });
  const c = await t.addMember('pending');
  insertKey(t, admin.id, adminKey.record);
  insertKey(t, c.id, cKey.record);
  const trust = newTrust(admin.id);
  await pinSigner(trust, { memberId: admin.id, keyId: adminKey.record.keyId, publicKey: adminKey.record.signPublicKey }, 1);
  const signer: GrantSigner = { memberId: admin.id, keyId: adminKey.record.keyId, privateKey: adminKey.signPrivateKey, trust };
  const pins = new MemoryPinStore();
  await pinPublicKey(pins, admin.id, { keyId: adminKey.record.keyId, publicKey: adminKey.record.publicKey });
  const own = await createGrant({ pins, signer, memberId: admin.id, recipient: { keyId: adminKey.record.keyId, publicKey: adminKey.record.publicKey }, vaultKeyVersion: 1, vaultKeyRaw });
  const b = grantBody(own);
  t.db.db
    .prepare(`INSERT INTO vault_key_grants (vault_key_version, recipient_key_id, ephemeral_public_key, wrapped_key, signer_key_id, signature, format_version, created_at) VALUES (1, ?, ?, ?, ?, ?, 1, 0)`)
    .run(b.recipient_key_id, b.ephemeral_public_key, b.wrapped_key, b.signer_key_id, b.signature);
  // 照合した C さんの鍵を固定してから、C さん宛てのグラントを作る
  await pinPublicKey(pins, c.id, { keyId: cKey.record.keyId, publicKey: cKey.record.publicKey });
  const forC = async (record: MemberKeyRecord = cKey.record, version = 1) => {
    await pinPublicKey(pins, c.id, { keyId: record.keyId, publicKey: record.publicKey });
    return grantBody(await createGrant({ pins, signer, memberId: c.id, recipient: { keyId: record.keyId, publicKey: record.publicKey }, vaultKeyVersion: version, vaultKeyRaw }));
  };
  return { t, admin, c, forC };
}

function memberStatus(t: Setup, id: string): string {
  return String(t.db.db.prepare('SELECT status FROM members WHERE id = ?').get(id)!.status);
}

function grantCount(t: Setup, keyId: string): number {
  return Number(t.db.db.prepare('SELECT COUNT(*) AS n FROM vault_key_grants WHERE recipient_key_id = ?').get(keyId)!.n);
}

test('メンバーの一覧：承認待ちの人も、有効な鍵の ID と公開鍵と一緒に出る。トークンやシークレットは出さない', async () => {
  const { t, admin, c } = await world();
  const res = await t.request('GET', '/v1/members', admin.token);
  assert.equal(res.status, 200);
  const body = (await res.json()) as { members: Record<string, unknown>[]; current_vault_key_version: number };
  assert.equal(body.current_vault_key_version, 1);
  const row = body.members.find((m) => m.id === c.id)!;
  assert.deepEqual(row, { id: c.id, display_name: row.display_name, role: 'member', status: 'pending', key: { id: cKey.record.keyId, ecdh_public_key: toBase64Url(cKey.record.publicKey) } });
  assert.ok(!JSON.stringify(body).match(/totp|secret|encrypted|recovery/));
});

test('P-03 承認は、そのメンバー宛ての署名付きのグラントと同時に行う。承認待ちが有効になり、メンバーは自分宛てのグラントを受け取れる', async () => {
  const { t, admin, c, forC } = await world();
  const res = await t.request('POST', `/v1/members/${c.id}/approve`, admin.token, await forC());
  assert.equal(res.status, 200, await res.clone().text());
  assert.equal(memberStatus(t, c.id), 'active');
  assert.equal(grantCount(t, cKey.record.keyId), 1);
  const vault = (await (await t.request('GET', '/v1/vault', c.token)).json()) as { grant: { recipient_key_id: string } | null };
  assert.equal(vault.grant?.recipient_key_id, cKey.record.keyId);
  assert.equal(Number(t.db.db.prepare(`SELECT COUNT(*) AS n FROM audit_logs WHERE action = 'member.approve' AND target_id = ?`).get(c.id)!.n), 1);
});

test('P-03 グラントのない承認、署名の正しくないグラント、ほかの人の鍵宛て、今と違う世代は断り、何も変えない', async () => {
  const { t, admin, c, forC } = await world();
  const good = await forC();
  const url = `/v1/members/${c.id}/approve`;
  assert.equal((await t.request('POST', url, admin.token, {})).status, 400, 'グラントなし');
  const badSig = { ...good, signature: good.signature.slice(0, 10) + (good.signature[10] === 'A' ? 'B' : 'A') + good.signature.slice(11) };
  assert.equal((await t.request('POST', url, admin.token, badSig)).status, 400, '署名が違う');
  assert.equal((await t.request('POST', url, admin.token, { ...good, signature: 'AAAA' })).status, 400, '署名の長さとヘッダーが違う（DeepSeek #9）');
  assert.equal((await t.request('POST', url, admin.token, { ...good, recipient_key_id: adminKey.record.keyId })).status, 409, 'その人の鍵ではない');
  assert.equal((await t.request('POST', url, admin.token, { ...good, vault_key_version: 2 })).status, 409, '今の世代ではない');
  assert.equal((await t.request('POST', url, admin.token, { ...good, extra: 1 })).status, 400);
  assert.equal(memberStatus(t, c.id), 'pending');
  assert.equal(grantCount(t, cKey.record.keyId), 0);
  // 知らない人、もう有効な人
  assert.equal((await t.request('POST', `/v1/members/member_none/approve`, admin.token, good)).status, 404);
  assert.equal((await t.request('POST', url, admin.token, good)).status, 200);
  assert.equal((await t.request('POST', url, admin.token, good)).status, 409, '承認済み');
});

test('P-03 確かめてから保存するまでの間に、相手が承認済みになった・鍵を登録し直した・世代が変わったら、バッチの先頭で 409 にし、何も入れない', async () => {
  for (const change of [
    (t: Setup, id: string) => t.db.db.prepare(`UPDATE members SET status = 'active' WHERE id = ?`).run(id),
    (t: Setup, id: string) => t.db.db.prepare(`UPDATE member_keys SET status = 'revoked' WHERE member_id = ?`).run(id),
    (t: Setup) => t.db.db.prepare('UPDATE vault_meta SET current_vault_key_version = 2').run(),
  ]) {
    const { t, admin, c, forC } = await world();
    const grant = await forC();
    t.db.beforeBatch = async () => {
      change(t, c.id);
      t.db.beforeBatch = null;
    };
    assert.equal((await t.request('POST', `/v1/members/${c.id}/approve`, admin.token, grant)).status, 409);
    assert.equal(grantCount(t, cKey.record.keyId), 0);
  }
});

test('P-02 承認の後にメンバーが鍵を登録し直すと、承認待ちに戻り、新しい鍵宛てのグラントで承認し直すまで受け取れない', async () => {
  const { t, admin, c, forC } = await world();
  assert.equal((await t.request('POST', `/v1/members/${c.id}/approve`, admin.token, await forC())).status, 200);
  // 鍵の登録し直し（PUT /v1/me/keys と同じ結果：前の鍵は revoked、承認待ち）
  t.db.db.prepare(`UPDATE member_keys SET status = 'revoked' WHERE member_id = ?`).run(c.id);
  t.db.db.prepare(`UPDATE members SET status = 'pending' WHERE id = ?`).run(c.id);
  insertKey(t, c.id, cKey2.record);
  assert.equal((await t.request('GET', '/v1/vault', c.token)).status, 403, '承認待ちは Vault を見られない');
  // 古い鍵宛てのグラントでは承認できない
  assert.equal((await t.request('POST', `/v1/members/${c.id}/approve`, admin.token, await forC())).status, 409);
  assert.equal((await t.request('POST', `/v1/members/${c.id}/approve`, admin.token, await forC(cKey2.record))).status, 200);
  const vault = (await (await t.request('GET', '/v1/vault', c.token)).json()) as { grant: { recipient_key_id: string } | null };
  assert.equal(vault.grant?.recipient_key_id, cKey2.record.keyId);
});

test('削除：状態を removed にし、セッション・覚えた端末・その人宛てのグラントを無効にする。削除された人は API を使えない', async () => {
  const { t, admin, c, forC } = await world();
  assert.equal((await t.request('POST', `/v1/members/${c.id}/approve`, admin.token, await forC())).status, 200);
  const res = await t.request('DELETE', `/v1/members/${c.id}`, admin.token);
  assert.equal(res.status, 204);
  assert.equal(memberStatus(t, c.id), 'removed');
  assert.equal(grantCount(t, cKey.record.keyId), 0);
  assert.equal(Number(t.db.db.prepare('SELECT COUNT(*) AS n FROM sessions WHERE member_id = ? AND revoked_at IS NULL').get(c.id)!.n), 0);
  assert.ok([401, 403].includes((await t.request('GET', '/v1/items?after=0', c.token)).status));
  assert.equal((await t.request('DELETE', `/v1/members/${c.id}`, admin.token)).status, 404, 'もう削除済み');
  assert.equal(Number(t.db.db.prepare(`SELECT COUNT(*) AS n FROM audit_logs WHERE action = 'member.remove'`).get()!.n), 1);
});

test('Z-05 管理者は自分を削除できない', async () => {
  const { t, admin } = await world();
  assert.equal((await t.request('DELETE', `/v1/members/${admin.id}`, admin.token)).status, 409);
  assert.equal(memberStatus(t, admin.id), 'active');
});

test('A-10 Z-02 承認・削除・監査ログは、5分以内に TOTP を確かめた管理者だけ', async () => {
  const { t, c, forC } = await world();
  const stale = await t.addMember('active', { role: 'admin', totpVerifiedAt: Date.now() - 6 * 60 * 1000 });
  const member = await t.addMember('active', { totpVerifiedAt: Date.now() });
  const grant = await forC();
  for (const who of [stale, member]) {
    assert.equal((await t.request('POST', `/v1/members/${c.id}/approve`, who.token, grant)).status, 403);
    assert.equal((await t.request('DELETE', `/v1/members/${c.id}`, who.token)).status, 403);
  }
  assert.equal((await t.request('GET', '/v1/audit-logs', member.token)).status, 403);
  assert.equal(memberStatus(t, c.id), 'pending');
});

test('監査ログ：新しい順に、操作した人・操作・対象・時刻だけを返す', async () => {
  const { t, admin, c, forC } = await world();
  await t.request('POST', `/v1/members/${c.id}/approve`, admin.token, await forC());
  await t.request('DELETE', `/v1/members/${c.id}`, admin.token);
  const res = await t.request('GET', '/v1/audit-logs', admin.token);
  assert.equal(res.status, 200);
  const logs = ((await res.json()) as { logs: Record<string, unknown>[] }).logs;
  assert.deepEqual(logs.slice(0, 2).map((l) => l.action), ['member.remove', 'member.approve']);
  assert.deepEqual(Object.keys(logs[0]!).sort(), ['action', 'actor_member_id', 'created_at', 'target_id', 'target_type']);
});
