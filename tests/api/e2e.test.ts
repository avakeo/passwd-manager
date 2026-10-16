// 暗号コアと API をつないだ通しのテスト。サーバー（SQLite）に残るのは暗号文と公開情報だけで、
// 受け取った側が API から取ってきたものだけで復号できることを確かめる。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fromBase64Url, toBase64Url } from '../../src/crypto/bytes.ts';
import { createAdminKey, createMemberKey, unlockMemberKey, type AdminKeyRecord, type MemberKeyRecord } from '../../src/crypto/member-key.ts';
import { createGrant, openGrant, type Grant, type GrantSigner } from '../../src/crypto/grant.ts';
import { MemoryPinStore, fingerprint, pinPublicKey } from '../../src/crypto/public-key.ts';
import { assertSignerPinned, pinSigner } from '../../src/crypto/signer.ts';
import { newTrust } from '../helpers/trust.ts';
import { CryptoError } from '../../src/crypto/errors.ts';
import { decryptItem, encryptItem } from '../../src/crypto/item.ts';
import { generateVaultKeyRaw, importVaultKey } from '../../src/crypto/vault-key.ts';
import { newId } from '../../src/crypto/random.ts';
import { setup } from '../helpers/api.ts';

const ADMIN_PASSWORD = 'admin-hoshi-sora-umi-42';
const C_PASSWORD = 'c-san-kawa-mori-yama-18';

// 鍵は一度だけ作る（PBKDF2 が重いので）
const adminKey = await createAdminKey(ADMIN_PASSWORD);
const attackerKey = await createAdminKey('attacker-kuro-yami-99x-zz');
const cKey = await createMemberKey(C_PASSWORD);

type Setup = ReturnType<typeof setup>;

// 鍵の登録 API は提出版の範囲外なので D1 に直接入れる
function insertKey(t: Setup, memberId: string, record: MemberKeyRecord | AdminKeyRecord) {
  const sign = 'signPublicKey' in record ? record : undefined;
  t.db.db
    .prepare(
      `INSERT INTO member_keys (id, member_id, ecdh_public_key, encrypted_private_key, ecdsa_public_key, encrypted_sign_private_key,
                                kdf_algorithm, kdf_params, kdf_salt, format_version, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'active', 0)`,
    )
    .run(
      record.keyId,
      memberId,
      toBase64Url(record.publicKey),
      toBase64Url(record.encryptedPrivateKey),
      sign ? toBase64Url(sign.signPublicKey) : null,
      sign ? toBase64Url(sign.encryptedSignPrivateKey) : null,
      record.kdf.algorithm,
      JSON.stringify({ iterations: record.kdf.iterations, normalization: record.kdf.normalization }),
      toBase64Url(record.kdf.salt),
    );
}

// 承認 API は提出版の範囲外なので D1 に直接入れる
function insertGrant(t: Setup, grant: Grant) {
  t.db.db
    .prepare(
      `INSERT OR REPLACE INTO vault_key_grants (vault_key_version, recipient_key_id, ephemeral_public_key, wrapped_key, signer_key_id, signature, format_version, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 1, 0)`,
    )
    .run(
      grant.vaultKeyVersion,
      grant.recipientKeyId,
      toBase64Url(grant.ephemeralPublicKey),
      toBase64Url(grant.wrappedKey),
      grant.signerKeyId,
      toBase64Url(grant.signature),
    );
}

type MeResponse = {
  id: string;
  current_vault_key_version: number;
  key: { id: string; ecdh_public_key: string; encrypted_private_key: string; kdf_algorithm: string; kdf_params: string; kdf_salt: string };
  admin_signer: { member_id: string; key_id: string; ecdsa_public_key: string } | null;
};
type VaultResponse = {
  current_vault_key_version: number;
  grant: { vault_key_version: number; recipient_key_id: string; ephemeral_public_key: string; wrapped_key: string; signer_key_id: string; signature: string };
};

function grantFromApi(g: VaultResponse['grant']): Grant {
  return {
    vaultKeyVersion: g.vault_key_version,
    recipientKeyId: g.recipient_key_id,
    ephemeralPublicKey: fromBase64Url(g.ephemeral_public_key),
    wrappedKey: fromBase64Url(g.wrapped_key),
    signerKeyId: g.signer_key_id,
    signature: fromBase64Url(g.signature),
  };
}

function signerFromApi(s: NonNullable<MeResponse['admin_signer']>) {
  return { memberId: s.member_id, keyId: s.key_id, publicKey: fromBase64Url(s.ecdsa_public_key) };
}

// 管理者と C さんを登録し、承認のときの双方向の照合を済ませた状態を作る
async function approved() {
  const t = setup();
  const adminSession = await t.addMember('active', { role: 'admin' });
  const cSession = await t.addMember('active');
  insertKey(t, adminSession.id, adminKey.record);
  insertKey(t, cSession.id, cKey.record);

  // 管理者の端末：自分の組を固定し、世代1で初期化済み（初期化のときに世代1を作った）
  const adminPin = { memberId: adminSession.id, keyId: adminKey.record.keyId, publicKey: adminKey.record.signPublicKey };
  const adminTrust = newTrust(adminSession.id);
  await pinSigner(adminTrust, adminPin, 1);

  // 承認のときの双方向の照合。C さんの端末は、API から受け取った管理者の署名鍵のフィンガープリントと今の世代を、
  // 管理者の画面（管理者の端末が持つ値）と見比べ、一致したら組を固定し、その世代で最後に見た世代を初期化する
  const me = (await (await t.request('GET', '/v1/me', cSession.token)).json()) as MeResponse;
  const fromServer = signerFromApi(me.admin_signer!);
  assert.equal(await fingerprint(fromServer.publicKey), await fingerprint(adminKey.record.signPublicKey));
  assert.equal(me.current_vault_key_version, await adminTrust.generations.get());
  const cTrust = newTrust(cSession.id);
  await pinSigner(cTrust, fromServer, me.current_vault_key_version);

  // 管理者の端末は、C さんの公開鍵を照合して固定する
  const pins = new MemoryPinStore();
  await pinPublicKey(pins, cSession.id, { keyId: cKey.record.keyId, publicKey: cKey.record.publicKey });
  const signer: GrantSigner = { memberId: adminSession.id, keyId: adminKey.record.keyId, privateKey: adminKey.signPrivateKey, trust: adminTrust };
  return { t, adminSession, cSession, cTrust, pins, signer };
}

// C さん：API から取ってきた自分の鍵と、自分宛てのグラントだけで、Vault 鍵を開く
async function cOpensFromApi(t: Setup, token: string, cTrust: Parameters<typeof openGrant>[1]) {
  const me = (await (await t.request('GET', '/v1/me', token)).json()) as MeResponse;
  const vault = (await (await t.request('GET', '/v1/vault', token)).json()) as VaultResponse;
  const publicKey = fromBase64Url(me.key.ecdh_public_key);
  const cPrivate = await unlockMemberKey(C_PASSWORD, {
    keyId: me.key.id,
    publicKey,
    encryptedPrivateKey: fromBase64Url(me.key.encrypted_private_key),
    kdf: {
      algorithm: me.key.kdf_algorithm as 'PBKDF2-HMAC-SHA256',
      ...(JSON.parse(me.key.kdf_params) as { iterations: number; normalization: 'NFC' }),
      salt: fromBase64Url(me.key.kdf_salt),
    },
  });
  // サーバーが返す管理者の鍵が、固定と違っていれば止める（P-05）
  await assertSignerPinned(cTrust, signerFromApi(me.admin_signer!));
  return openGrant({ memberId: me.id, keyId: me.key.id, publicKey, privateKey: cPrivate }, cTrust, grantFromApi(vault.grant));
}

test('C-13（API 経由） 管理者が保存した暗号文と署名付きのグラントを、C さんが API から取得して確かめ、復号できる', async () => {
  const { t, adminSession, cSession, cTrust, pins, signer } = await approved();

  // 管理者：グラントを作って署名する
  const vaultKeyRaw = generateVaultKeyRaw();
  insertGrant(
    t,
    await createGrant({
      pins,
      signer,
      memberId: cSession.id,
      recipient: { keyId: cKey.record.keyId, publicKey: cKey.record.publicKey },
      vaultKeyVersion: 1,
      vaultKeyRaw: vaultKeyRaw.slice(),
    }),
  );

  // 管理者：アイテムを暗号化して API で保存する
  const vaultKey = await importVaultKey(vaultKeyRaw);
  vaultKeyRaw.fill(0);
  const itemId = newId('item');
  const item = { type: 'login' as const, title: '社内Wiki', username: 'team@example.com', password: 'Tr7#qLm2!vX9pK' };
  const ciphertext = await encryptItem(vaultKey, { itemId, vaultKeyVersion: 1 }, item);
  const created = await t.request('POST', '/v1/items', adminSession.token, {
    id: itemId,
    vault_key_version: 1,
    ciphertext: toBase64Url(ciphertext),
  });
  assert.equal(created.status, 201);

  // サーバーに平文が残っていない
  const dump = JSON.stringify(t.db.db.prepare('SELECT * FROM items').all());
  for (const secret of ['Tr7#qLm2!vX9pK', 'team@example.com', '社内Wiki']) assert.ok(!dump.includes(secret));

  const cVaultKey = await cOpensFromApi(t, cSession.token, cTrust);
  const list = (await (await t.request('GET', '/v1/items?since=0', cSession.token)).json()) as {
    items: { id: string; vault_key_version: number; ciphertext: string }[];
  };
  const got = list.items[0]!;
  assert.deepEqual(
    await decryptItem(cVaultKey, { itemId: got.id, vaultKeyVersion: got.vault_key_version }, fromBase64Url(got.ciphertext)),
    item,
  );
  assert.equal(await cTrust.generations.get(), 1);
});

// 攻撃者レビュー #1 を API 経由で：乗っ取られたサーバーが、C さん宛てのグラントの行を、
// 管理者の鍵ID を名乗って攻撃者の鍵で署名した偽グラントに書き換える
test('C-18（API 経由） サーバーが書き換えた偽グラントを、C さんは開かずに拒否する（攻撃者レビュー #1）', async () => {
  const { t, cSession, cTrust } = await approved();
  const attackerPins = new MemoryPinStore();
  await pinPublicKey(attackerPins, cSession.id, { keyId: cKey.record.keyId, publicKey: cKey.record.publicKey });
  // 攻撃者の手元の端末（管理者の名前と鍵ID を名乗り、自分の署名鍵を固定したことにする）
  const attackerTrust = newTrust('member_1');
  await pinSigner(attackerTrust, { memberId: 'member_1', keyId: adminKey.record.keyId, publicKey: attackerKey.record.signPublicKey }, 1);
  const evil = await createGrant({
    pins: attackerPins,
    signer: { memberId: 'member_1', keyId: adminKey.record.keyId, privateKey: attackerKey.signPrivateKey, trust: attackerTrust },
    memberId: cSession.id,
    recipient: { keyId: cKey.record.keyId, publicKey: cKey.record.publicKey },
    vaultKeyVersion: 1, // 本物の C さん宛ての行（世代1）を置き換える
    vaultKeyRaw: generateVaultKeyRaw(),
  });
  insertGrant(t, evil);
  await assert.rejects(cOpensFromApi(t, cSession.token, cTrust), (e: unknown) => e instanceof CryptoError && e.code === 'SIGNATURE_INVALID');
  assert.equal(await cTrust.generations.get(), 1, '照合のときに初期化した世代のまま');
});

test('P-05（API 経由） サーバーが /v1/me で返す管理者の署名用公開鍵を差し替えると、C さんの端末が検知する', async () => {
  const { t, cSession, cTrust } = await approved();
  t.db.db
    .prepare(`UPDATE member_keys SET ecdsa_public_key = ? WHERE id = ?`)
    .run(toBase64Url(attackerKey.record.signPublicKey), adminKey.record.keyId);
  await assert.rejects(cOpensFromApi(t, cSession.token, cTrust), (e: unknown) => e instanceof CryptoError && e.code === 'SIGNER_MISMATCH');
});

test('双方向の照合のため、承認待ちのメンバーも GET /v1/me で管理者の署名用公開鍵を受け取れる（Vault は 403 のまま）', async () => {
  const t = setup();
  const adminSession = await t.addMember('active', { role: 'admin' });
  insertKey(t, adminSession.id, adminKey.record);
  const pending = await t.addMember('pending');
  const res = await t.request('GET', '/v1/me', pending.token);
  assert.equal(res.status, 200);
  const me = (await res.json()) as MeResponse;
  assert.deepEqual(me.admin_signer, {
    member_id: adminSession.id,
    key_id: adminKey.record.keyId,
    ecdsa_public_key: toBase64Url(adminKey.record.signPublicKey),
  });
  assert.equal((await t.request('GET', '/v1/vault', pending.token)).status, 403);
  // 削除済みは /v1/me も 403
  const removed = await t.addMember('removed');
  assert.equal((await t.request('GET', '/v1/me', removed.token)).status, 403);
});

test('Z-04 他のメンバー宛てのグラントは取得できない（GET /v1/vault は自分の鍵宛てのものだけを返す）', async () => {
  const t = setup();
  const a = await t.addMember('active');
  const b = await t.addMember('active');
  for (const [m, keyId] of [[a, 'key_a'], [b, 'key_b']] as const) {
    t.db.db
      .prepare(
        `INSERT INTO member_keys (id, member_id, ecdh_public_key, encrypted_private_key, kdf_algorithm, kdf_params, kdf_salt, format_version, status, created_at)
         VALUES (?, ?, 'pk', 'sk', 'PBKDF2-HMAC-SHA256', '{"iterations":600000,"normalization":"NFC"}', 'salt', 1, 'active', 0)`,
      )
      .run(keyId, m.id);
    t.db.db
      .prepare(
        `INSERT INTO vault_key_grants (vault_key_version, recipient_key_id, ephemeral_public_key, wrapped_key, signer_key_id, signature, format_version, created_at)
         VALUES (1, ?, 'enc', ?, 'key_admin', 'sig', 1, 0)`,
      )
      .run(keyId, `wrapped_for_${keyId}`);
  }
  const vault = (await (await t.request('GET', '/v1/vault', a.token)).json()) as { grant: { recipient_key_id: string; wrapped_key: string } };
  assert.equal(vault.grant.recipient_key_id, 'key_a');
  assert.equal(vault.grant.wrapped_key, 'wrapped_for_key_a');
});
