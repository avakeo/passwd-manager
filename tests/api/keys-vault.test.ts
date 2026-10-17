// 鍵の登録（PUT /v1/me/keys）と、最初の Vault（POST /v1/vault/init）。仕様書「鍵とメンバーのライフサイクル > 初期化（管理者）」。
// 鍵とグラントは暗号コアで本物を作り、API から取ってきたものだけで開けることも確かめる。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fromBase64Url, toBase64Url } from '../../src/crypto/bytes.ts';
import { createAdminKey, createMemberKey, unlockAdminKey, type AdminKeyRecord, type MemberKeyRecord } from '../../src/crypto/member-key.ts';
import { createGrant, openGrant, type Grant } from '../../src/crypto/grant.ts';
import { MemoryPinStore, pinPublicKey } from '../../src/crypto/public-key.ts';
import { pinSigner } from '../../src/crypto/signer.ts';
import { generateVaultKeyRaw } from '../../src/crypto/vault-key.ts';
import { newTrust } from '../helpers/trust.ts';
import { setup } from '../helpers/api.ts';

const ADMIN_PASSWORD = 'admin-hoshi-sora-umi-42';
// 鍵は一度だけ作る（PBKDF2 が重いので）
const adminKey = await createAdminKey(ADMIN_PASSWORD);
const adminKey2 = await createAdminKey('admin-niban-me-no-kagi-7');
const memberKey = await createMemberKey('member-kawa-mori-yama-18');
const memberKey2 = await createMemberKey('member-niban-me-kagi-x9');

type Setup = ReturnType<typeof setup>;

export function keyBody(record: MemberKeyRecord | AdminKeyRecord): Record<string, unknown> {
  const body: Record<string, unknown> = {
    id: record.keyId,
    ecdh_public_key: toBase64Url(record.publicKey),
    encrypted_private_key: toBase64Url(record.encryptedPrivateKey),
    kdf_algorithm: record.kdf.algorithm,
    kdf_params: JSON.stringify({ iterations: record.kdf.iterations, normalization: record.kdf.normalization }),
    kdf_salt: toBase64Url(record.kdf.salt),
    format_version: 1,
  };
  if ('signPublicKey' in record) {
    body.ecdsa_public_key = toBase64Url(record.signPublicKey);
    body.encrypted_sign_private_key = toBase64Url(record.encryptedSignPrivateKey);
  }
  return body;
}

function grantBody(g: Grant): Record<string, unknown> {
  return {
    vault_key_version: g.vaultKeyVersion,
    recipient_key_id: g.recipientKeyId,
    ephemeral_public_key: toBase64Url(g.ephemeralPublicKey),
    wrapped_key: toBase64Url(g.wrappedKey),
    signer_key_id: g.signerKeyId,
    signature: toBase64Url(g.signature),
    format_version: g.formatVersion,
  };
}

// 管理者の端末が、自分宛ての世代1のグラントを作る（自分の組を固定し、世代を1で初期化してから）
async function adminSelfGrant(adminId: string, key = adminKey): Promise<Grant> {
  const trust = newTrust(adminId);
  await pinSigner(trust, { memberId: adminId, keyId: key.record.keyId, publicKey: key.record.signPublicKey }, 1);
  const pins = new MemoryPinStore();
  await pinPublicKey(pins, adminId, { keyId: key.record.keyId, publicKey: key.record.publicKey });
  return createGrant({
    pins,
    signer: { memberId: adminId, keyId: key.record.keyId, privateKey: key.signPrivateKey, trust },
    memberId: adminId,
    recipient: { keyId: key.record.keyId, publicKey: key.record.publicKey },
    vaultKeyVersion: 1,
    vaultKeyRaw: generateVaultKeyRaw(),
  });
}

function count(t: Setup, sql: string, ...params: (string | number)[]): number {
  return Number(t.db.db.prepare(sql).get(...params)!.n);
}

async function registeredAdmin(t: Setup) {
  const admin = await t.addMember('active', { role: 'admin', totpVerifiedAt: Date.now() });
  assert.equal((await t.request('PUT', '/v1/me/keys', admin.token, keyBody(adminKey.record))).status, 204);
  return admin;
}

test('鍵の登録：承認待ちのメンバーの鍵を登録すると、有効な鍵として入り、承認待ちのまま', async () => {
  const t = setup();
  const m = await t.addMember('pending');
  assert.equal((await t.request('PUT', '/v1/me/keys', m.token, keyBody(memberKey.record))).status, 204);
  const row = t.db.db.prepare(`SELECT id, status, ecdsa_public_key FROM member_keys WHERE member_id = ?`).get(m.id)!;
  assert.deepEqual({ ...row }, { id: memberKey.record.keyId, status: 'active', ecdsa_public_key: null });
  assert.equal(t.db.db.prepare('SELECT status FROM members WHERE id = ?').get(m.id)!.status, 'pending');
});

test('I-02 鍵の登録：形・長さ・種類の違い、メンバーの署名鍵、管理者の署名鍵の不足は 400', async () => {
  const t = setup();
  const m = await t.addMember('pending');
  const admin = await t.addMember('active', { role: 'admin', totpVerifiedAt: Date.now() });
  const good = keyBody(memberKey.record);
  const bad: Record<string, unknown>[] = [
    { ...good, id: 'not a key id' },
    { ...good, ecdh_public_key: toBase64Url(new Uint8Array(64).fill(4)) },
    { ...good, ecdh_public_key: toBase64Url(new Uint8Array(65).fill(2)) },
    { ...good, encrypted_private_key: 'AAAA' },
    { ...good, kdf_algorithm: 'MD5' },
    { ...good, kdf_params: JSON.stringify({ iterations: 1000, normalization: 'NFC' }) },
    { ...good, kdf_params: '{' },
    { ...good, kdf_salt: toBase64Url(new Uint8Array(8)) },
    { ...good, format_version: 2 },
    { ...good, extra: 1 },
    keyBody(adminKey.record), // メンバーは署名鍵の列を送れない
  ];
  for (const [i, body] of bad.entries()) assert.equal((await t.request('PUT', '/v1/me/keys', m.token, body)).status, 400, `メンバー ${i}`);
  assert.equal((await t.request('PUT', '/v1/me/keys', admin.token, keyBody(memberKey.record))).status, 400, '管理者は署名鍵が要る');
  assert.equal(count(t, 'SELECT COUNT(*) AS n FROM member_keys'), 0);
});

test('P-02 承認済みのメンバーが鍵を登録し直すと、承認待ちに戻り、前の鍵宛てのグラントでは復号できない', async () => {
  const t = setup();
  const admin = await registeredAdmin(t);
  assert.equal((await t.request('POST', '/v1/vault/init', admin.token, grantBody(await adminSelfGrant(admin.id)))).status, 201);
  const m = await t.addMember('active', { totpVerifiedAt: Date.now() });
  assert.equal((await t.request('PUT', '/v1/me/keys', m.token, keyBody(memberKey.record))).status, 204);
  // 承認されてグラントがある状態（承認の API はフェーズ4なので D1 に直接入れる）
  t.db.db
    .prepare(`INSERT INTO vault_key_grants (vault_key_version, recipient_key_id, ephemeral_public_key, wrapped_key, signer_key_id, signature, format_version, created_at)
              SELECT 1, ?, ephemeral_public_key, wrapped_key, signer_key_id, signature, 1, 0 FROM vault_key_grants LIMIT 1`)
    .run(memberKey.record.keyId);
  assert.notEqual((await (await t.request('GET', '/v1/vault', m.token)).json() as { grant: unknown }).grant, null);
  // 登録し直す
  assert.equal((await t.request('PUT', '/v1/me/keys', m.token, keyBody(memberKey2.record))).status, 204);
  assert.equal(t.db.db.prepare('SELECT status FROM members WHERE id = ?').get(m.id)!.status, 'pending');
  const statuses = t.db.db.prepare('SELECT id, status FROM member_keys WHERE member_id = ? ORDER BY status').all(m.id).map((r) => `${r.id}:${r.status}`);
  assert.deepEqual(statuses, [`${memberKey2.record.keyId}:active`, `${memberKey.record.keyId}:revoked`]);
  // 承認待ちなので Vault は 403。前の鍵宛てのグラントは渡らない
  assert.equal((await t.request('GET', '/v1/vault', m.token)).status, 403);
  const me = (await (await t.request('GET', '/v1/me', m.token)).json()) as { key: { id: string } };
  assert.equal(me.key.id, memberKey2.record.keyId);
});

test('鍵の登録し直しは、直近5分以内に TOTP を確かめたセッションだけができる（初めての登録は要らない）', async () => {
  const t = setup();
  const m = await t.addMember('pending', { totpVerifiedAt: Date.now() - 5 * 60 * 1000 - 1 });
  assert.equal((await t.request('PUT', '/v1/me/keys', m.token, keyBody(memberKey.record))).status, 204, '初めて');
  assert.equal((await t.request('PUT', '/v1/me/keys', m.token, keyBody(memberKey2.record))).status, 403, '登録し直し');
  const fresh = await t.addSession(m.id, { totpVerifiedAt: Date.now() });
  assert.equal((await t.request('PUT', '/v1/me/keys', fresh.token, keyBody(memberKey2.record))).status, 204);
});

test('管理者の鍵の登録し直しは、グラントがまだないときだけ。あれば 409', async () => {
  const t = setup();
  const admin = await registeredAdmin(t);
  assert.equal((await t.request('PUT', '/v1/me/keys', admin.token, keyBody(adminKey2.record))).status, 204, 'グラントがない');
  assert.equal(t.db.db.prepare('SELECT status FROM members WHERE id = ?').get(admin.id)!.status, 'active', '管理者は承認待ちにならない');
  assert.equal((await t.request('POST', '/v1/vault/init', admin.token, grantBody(await adminSelfGrant(admin.id, adminKey2)))).status, 201);
  assert.equal((await t.request('PUT', '/v1/me/keys', admin.token, keyBody(adminKey.record))).status, 409);
  assert.equal(t.db.db.prepare(`SELECT id FROM member_keys WHERE member_id = ? AND status = 'active'`).get(admin.id)!.id, adminKey2.record.keyId);
});

test('最初の Vault：管理者の自分宛てのグラントを保存し、API から取ってきたものだけで開ける', async () => {
  const t = setup();
  t.db.db.exec('DELETE FROM vault_meta; DELETE FROM vault_key_versions'); // 本番と同じく、まだ行がない
  const admin = await registeredAdmin(t);
  const grant = await adminSelfGrant(admin.id);
  const res = await t.request('POST', '/v1/vault/init', admin.token, grantBody(grant));
  assert.equal(res.status, 201);
  assert.deepEqual({ ...t.db.db.prepare('SELECT current_vault_key_version AS v, vault_revision AS r FROM vault_meta').get()! }, { v: 1, r: 0 });
  assert.equal(t.db.db.prepare('SELECT status FROM vault_key_versions WHERE version = 1').get()!.status, 'current');
  // 管理者の端末：API の行から署名鍵と ECDH の鍵を開け、自分の組を固定して、グラントを開く
  const me = (await (await t.request('GET', '/v1/me', admin.token)).json()) as { key: Record<string, string> };
  const vault = (await (await t.request('GET', '/v1/vault', admin.token)).json()) as { current_vault_key_version: number; grant: Record<string, string | number> };
  const unlocked = await unlockAdminKey(ADMIN_PASSWORD, {
    keyId: me.key.id!,
    publicKey: fromBase64Url(me.key.ecdh_public_key!),
    encryptedPrivateKey: fromBase64Url(me.key.encrypted_private_key!),
    kdf: { algorithm: 'PBKDF2-HMAC-SHA256', ...(JSON.parse(me.key.kdf_params!) as { iterations: number; normalization: 'NFC' }), salt: fromBase64Url(me.key.kdf_salt!) },
    signPublicKey: fromBase64Url(me.key.ecdsa_public_key!),
    encryptedSignPrivateKey: fromBase64Url(me.key.encrypted_sign_private_key!),
  });
  const trust = newTrust(admin.id);
  await pinSigner(trust, { memberId: admin.id, keyId: me.key.id!, publicKey: fromBase64Url(me.key.ecdsa_public_key!) }, 1);
  const g = vault.grant;
  const opened = await openGrant(
    { memberId: admin.id, keyId: me.key.id!, publicKey: fromBase64Url(me.key.ecdh_public_key!), privateKey: unlocked.privateKey },
    trust,
    {
      vaultKeyVersion: Number(g.vault_key_version),
      recipientKeyId: String(g.recipient_key_id),
      ephemeralPublicKey: fromBase64Url(String(g.ephemeral_public_key)),
      wrappedKey: fromBase64Url(String(g.wrapped_key)),
      signerKeyId: String(g.signer_key_id),
      signature: fromBase64Url(String(g.signature)),
      formatVersion: Number(g.format_version),
    },
    vault.current_vault_key_version,
  );
  assert.equal(opened.extractable, false);
});

test('P-11 最初の Vault を同時に2回作ろうとしても、片方しか通らず、グラントは1つだけ', async () => {
  const t = setup();
  const admin = await registeredAdmin(t);
  const [g1, g2] = [await adminSelfGrant(admin.id), await adminSelfGrant(admin.id)];
  const results = await Promise.all([t.request('POST', '/v1/vault/init', admin.token, grantBody(g1)), t.request('POST', '/v1/vault/init', admin.token, grantBody(g2))]);
  assert.deepEqual(results.map((r) => r.status).sort(), [201, 409]);
  assert.equal(count(t, 'SELECT COUNT(*) AS n FROM vault_key_grants'), 1);
  assert.equal(count(t, 'SELECT COUNT(*) AS n FROM rotation_guard'), 0, '確認用の行は残らない');
  // 作った後にもう一度呼んでも 409
  assert.equal((await t.request('POST', '/v1/vault/init', admin.token, grantBody(await adminSelfGrant(admin.id)))).status, 409);
  assert.equal(count(t, 'SELECT COUNT(*) AS n FROM vault_key_grants'), 1);
});

test('P-11 別の鍵宛てのグラントが1つでもあれば、最初の Vault は作れない（確認はバッチの中で行う）', async () => {
  const t = setup();
  const admin = await registeredAdmin(t);
  const grant = await adminSelfGrant(admin.id);
  t.db.db
    .prepare(`INSERT INTO vault_key_grants (vault_key_version, recipient_key_id, ephemeral_public_key, wrapped_key, signer_key_id, signature, format_version, created_at)
              VALUES (1, ?, 'x', 'x', 'x', 'x', 1, 0)`)
    .run(memberKey.record.keyId);
  assert.equal((await t.request('POST', '/v1/vault/init', admin.token, grantBody(grant))).status, 409);
  assert.equal(count(t, 'SELECT COUNT(*) AS n FROM vault_key_grants WHERE recipient_key_id = ?', adminKey.record.keyId), 0);
  assert.equal(count(t, 'SELECT COUNT(*) AS n FROM rotation_guard'), 0);
});

test('P-11 最初の Vault は、宛先と署名が管理者自身の有効な鍵で、世代1のときだけ。形の違いは 400', async () => {
  const t = setup();
  const admin = await registeredAdmin(t);
  const grant = grantBody(await adminSelfGrant(admin.id));
  const cases: [Record<string, unknown>, number][] = [
    [{ ...grant, vault_key_version: 2 }, 400],
    [{ ...grant, recipient_key_id: memberKey.record.keyId, signer_key_id: memberKey.record.keyId }, 409], // 自分の有効な鍵ではない
    [{ ...grant, signer_key_id: memberKey.record.keyId }, 400], // 宛先と署名の鍵が違う
    [{ ...grant, ephemeral_public_key: toBase64Url(new Uint8Array(65)) }, 400],
    [{ ...grant, wrapped_key: toBase64Url(new Uint8Array(50)) }, 400],
    [{ ...grant, signature: toBase64Url(new Uint8Array(66)) }, 400],
    [{ ...grant, format_version: 2 }, 400],
    [{ ...grant, extra: 1 }, 400],
  ];
  for (const [i, [body, status]] of cases.entries()) assert.equal((await t.request('POST', '/v1/vault/init', admin.token, body)).status, status, `${i}`);
  assert.equal(count(t, 'SELECT COUNT(*) AS n FROM vault_key_grants'), 0);
});

test('P-11 最初の Vault は、管理者の、直近5分以内に TOTP を確かめたセッションだけが作れる', async () => {
  const t = setup();
  const admin = await registeredAdmin(t);
  const grant = grantBody(await adminSelfGrant(admin.id));
  const stale = await t.addSession(admin.id, { totpVerifiedAt: Date.now() - 5 * 60 * 1000 - 1 });
  assert.equal((await t.request('POST', '/v1/vault/init', stale.token, grant)).status, 403);
  const member = await t.addMember('active', { totpVerifiedAt: Date.now() });
  assert.equal((await t.request('POST', '/v1/vault/init', member.token, grant)).status, 403);
  assert.equal(count(t, 'SELECT COUNT(*) AS n FROM vault_key_grants'), 0);
});
