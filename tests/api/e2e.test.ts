// 暗号コアと API をつないだ通しのテスト。サーバー（SQLite）に残るのは暗号文と公開情報だけで、
// 受け取った側が API から取ってきたものだけで復号できることを確かめる。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fromBase64Url, toBase64Url } from '../../src/crypto/bytes.ts';
import { createMemberKey, unlockMemberKey } from '../../src/crypto/member-key.ts';
import { createGrant, openGrant } from '../../src/crypto/grant.ts';
import { MemoryPinStore, pinPublicKey } from '../../src/crypto/public-key.ts';
import { decryptItem, encryptItem } from '../../src/crypto/item.ts';
import { generateVaultKeyRaw, importVaultKey } from '../../src/crypto/vault-key.ts';
import { newId } from '../../src/crypto/random.ts';
import { setup } from '../helpers/api.ts';

test('C-13（API 経由） 管理者が保存した暗号文とグラントを、C さんが API から取得して復号できる', async () => {
  const t = setup();
  const adminSession = await t.addMember('active', { role: 'admin' });
  const cSession = await t.addMember('active');

  // C さん：鍵を作り、公開鍵と暗号化した秘密鍵を登録する（登録 API は提出版の範囲外なので D1 に直接入れる）
  const cPassword = 'c-san-kawa-mori-yama-18';
  const c = await createMemberKey(cPassword);
  t.db.db
    .prepare(
      `INSERT INTO member_keys (id, member_id, ecdh_public_key, encrypted_private_key, kdf_algorithm, kdf_params, kdf_salt, format_version, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'active', 0)`,
    )
    .run(
      c.record.keyId,
      cSession.id,
      toBase64Url(c.record.publicKey),
      toBase64Url(c.record.encryptedPrivateKey),
      c.record.kdf.algorithm,
      JSON.stringify({ iterations: c.record.kdf.iterations }),
      toBase64Url(c.record.kdf.salt),
    );

  // 管理者：照合して固定し、グラントを作る（承認 API は提出版の範囲外なので D1 に直接入れる）
  const pins = new MemoryPinStore();
  await pinPublicKey(pins, cSession.id, c.record.publicKey);
  const vaultKeyRaw = generateVaultKeyRaw();
  const grant = await createGrant({
    pins,
    memberId: cSession.id,
    recipient: { keyId: c.record.keyId, publicKey: c.record.publicKey },
    vaultKeyVersion: 1,
    vaultKeyRaw,
  });
  t.db.db
    .prepare(
      `INSERT INTO vault_key_grants (vault_key_version, recipient_key_id, ephemeral_public_key, wrapped_key, format_version, created_at)
       VALUES (1, ?, ?, ?, 1, 0)`,
    )
    .run(grant.recipientKeyId, toBase64Url(grant.ephemeralPublicKey), toBase64Url(grant.wrappedKey));

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

  // C さん：API から自分宛てのグラントとアイテムを取り、マスターパスワードだけで復号する
  const me = (await (await t.request('GET', '/v1/me', cSession.token)).json()) as { key: { id: string; ecdh_public_key: string; encrypted_private_key: string; kdf_algorithm: string; kdf_params: string; kdf_salt: string } };
  const vault = (await (await t.request('GET', '/v1/vault', cSession.token)).json()) as {
    current_vault_key_version: number;
    grant: { vault_key_version: number; recipient_key_id: string; ephemeral_public_key: string; wrapped_key: string };
  };
  const cPrivate = await unlockMemberKey(cPassword, {
    keyId: me.key.id,
    publicKey: fromBase64Url(me.key.ecdh_public_key),
    encryptedPrivateKey: fromBase64Url(me.key.encrypted_private_key),
    kdf: {
      algorithm: me.key.kdf_algorithm as 'PBKDF2-HMAC-SHA256',
      iterations: (JSON.parse(me.key.kdf_params) as { iterations: number }).iterations,
      salt: fromBase64Url(me.key.kdf_salt),
    },
  });
  const cVaultKey = await openGrant(
    { keyId: me.key.id, publicKey: fromBase64Url(me.key.ecdh_public_key), privateKey: cPrivate },
    {
      vaultKeyVersion: vault.grant.vault_key_version,
      recipientKeyId: vault.grant.recipient_key_id,
      ephemeralPublicKey: fromBase64Url(vault.grant.ephemeral_public_key),
      wrappedKey: fromBase64Url(vault.grant.wrapped_key),
    },
  );
  const list = (await (await t.request('GET', '/v1/items?since=0', cSession.token)).json()) as {
    items: { id: string; vault_key_version: number; ciphertext: string }[];
  };
  const got = list.items[0]!;
  assert.deepEqual(
    await decryptItem(cVaultKey, { itemId: got.id, vaultKeyVersion: got.vault_key_version }, fromBase64Url(got.ciphertext)),
    item,
  );
});

test('Z-04 他のメンバー宛てのグラントは取得できない（GET /v1/vault は自分の鍵宛てのものだけを返す）', async () => {
  const t = setup();
  const a = await t.addMember('active');
  const b = await t.addMember('active');
  for (const [m, keyId] of [[a, 'key_a'], [b, 'key_b']] as const) {
    t.db.db
      .prepare(
        `INSERT INTO member_keys (id, member_id, ecdh_public_key, encrypted_private_key, kdf_algorithm, kdf_params, kdf_salt, format_version, status, created_at)
         VALUES (?, ?, 'pk', 'sk', 'PBKDF2-HMAC-SHA256', '{"iterations":600000}', 'salt', 1, 'active', 0)`,
      )
      .run(keyId, m.id);
    t.db.db
      .prepare(
        `INSERT INTO vault_key_grants (vault_key_version, recipient_key_id, ephemeral_public_key, wrapped_key, format_version, created_at)
         VALUES (1, ?, 'enc', ?, 1, 0)`,
      )
      .run(keyId, `wrapped_for_${keyId}`);
  }
  const vault = (await (await t.request('GET', '/v1/vault', a.token)).json()) as { grant: { recipient_key_id: string; wrapped_key: string } };
  assert.equal(vault.grant.recipient_key_id, 'key_a');
  assert.equal(vault.grant.wrapped_key, 'wrapped_for_key_a');
});
