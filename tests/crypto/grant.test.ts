import { test } from 'node:test';
import assert from 'node:assert/strict';
import { utf8 } from '../../src/crypto/bytes.ts';
import { createMemberKey, unlockMemberKey } from '../../src/crypto/member-key.ts';
import { createGrant, grantInfo, openGrant, openGrantForAdmin, type Grant, type OwnKey } from '../../src/crypto/grant.ts';
import { decryptItem, encryptItem } from '../../src/crypto/item.ts';
import { generateVaultKeyRaw, importVaultKey } from '../../src/crypto/vault-key.ts';
import { ALG_HPKE_BASE, FORMAT_V1 } from '../../src/crypto/format.ts';
import { CryptoError } from '../../src/crypto/errors.ts';
import { MemoryPinStore, pinPublicKey } from '../../src/crypto/public-key.ts';

const ADMIN_PASSWORD = 'admin-hoshi-sora-umi-42';
const C_PASSWORD = 'c-san-kawa-mori-yama-18';
const B_PASSWORD = 'b-san-hana-tsuki-kaze-77';

function isDecryptFailed(e: unknown) {
  return e instanceof CryptoError && e.code === 'DECRYPT_FAILED';
}

// 3人分の鍵を一度だけ作る（PBKDF2 が重いので）
const admin = await createMemberKey(ADMIN_PASSWORD);
const memberC = await createMemberKey(C_PASSWORD);
const memberB = await createMemberKey(B_PASSWORD);

function ownKey(m: typeof admin, privateKey: CryptoKey = m.privateKey): OwnKey {
  return { keyId: m.record.keyId, publicKey: m.record.publicKey, privateKey };
}

function recipient(m: typeof admin) {
  return { keyId: m.record.keyId, publicKey: m.record.publicKey };
}

// 管理者の端末：3人とも照合済みとして公開鍵を固定しておく
const pins = new MemoryPinStore();
for (const [id, m] of [['member_admin', admin], ['member_c', memberC], ['member_b', memberB]] as const) {
  await pinPublicKey(pins, id, m.record.publicKey);
}
const memberIdOf = new Map([[admin, 'member_admin'], [memberC, 'member_c'], [memberB, 'member_b']]);

function grantFor(m: typeof admin, vaultKeyVersion: number, vaultKeyRaw: Uint8Array<ArrayBuffer>) {
  return createGrant({ pins, memberId: memberIdOf.get(m)!, recipient: recipient(m), vaultKeyVersion, vaultKeyRaw });
}

test('info は teampw/v1/vault-key-grant|世代|宛先の鍵ID', () => {
  assert.deepEqual(grantInfo(3, 'key_abc'), utf8('teampw/v1/vault-key-grant|3|key_abc'));
});

test('グラントの保存形式は 形式・アルゴリズムID（0x02）・暗号文 で、ノンスを持たない', async () => {
  const grant = await grantFor(memberC, 1, generateVaultKeyRaw());
  assert.equal(grant.wrappedKey[0], FORMAT_V1);
  assert.equal(grant.wrappedKey[1], ALG_HPKE_BASE);
  assert.equal(grant.wrappedKey.length, 2 + 32 + 16); // Vault 鍵32バイト ＋ 認証タグ16バイト
  assert.equal(grant.ephemeralPublicKey.length, 65);
});

test('C-13 2人のメンバー間でグラントを作り、受け取った側が開いてアイテムを復号できる', async () => {
  // 管理者：Vault 鍵（世代1）を作り、アイテムを暗号化し、C さん宛てのグラントを作る
  const vaultKeyRaw = generateVaultKeyRaw();
  const adminVaultKey = await importVaultKey(vaultKeyRaw);
  const ctx = { itemId: 'item_3c9a', vaultKeyVersion: 1 };
  const item = { type: 'login' as const, title: '社内Wiki', username: 'team@example.com', password: 'Tr7#qLm2!vX9pK' };
  const ciphertext = await encryptItem(adminVaultKey, ctx, item);
  const grant = await grantFor(memberC, 1, vaultKeyRaw);
  vaultKeyRaw.fill(0);

  // C さん：別の端末でマスターパスワードから秘密鍵を開け、グラントを開いて、アイテムを復号する
  const cPrivate = await unlockMemberKey(C_PASSWORD, memberC.record);
  const cVaultKey = await openGrant(ownKey(memberC, cPrivate), grant);
  assert.deepEqual(await decryptItem(cVaultKey, ctx, ciphertext), item);
});

test('C-06 他のメンバー宛てのグラントを自分の秘密鍵で開くと失敗する', async () => {
  const grant = await grantFor(memberC, 1, generateVaultKeyRaw());
  // B さんが、C さん宛てのグラントを自分宛てと偽って開こうとする
  const forged: Grant = { ...grant, recipientKeyId: memberB.record.keyId };
  await assert.rejects(openGrant(ownKey(memberB), forged), isDecryptFailed);
  await assert.rejects(openGrant(ownKey(memberB), grant), isDecryptFailed);
});

test('C-06 グラントを作った管理者自身も、そのグラントは開けない', async () => {
  const grant = await grantFor(memberC, 1, generateVaultKeyRaw());
  await assert.rejects(openGrant(ownKey(admin), { ...grant, recipientKeyId: admin.record.keyId }), isDecryptFailed);
});

test('グラントの世代を書き換えると開けない（info に世代が入っている）', async () => {
  const grant = await grantFor(memberC, 1, generateVaultKeyRaw());
  await assert.rejects(openGrant(ownKey(memberC), { ...grant, vaultKeyVersion: 2 }), isDecryptFailed);
});

test('C-03 グラントの暗号文や使い捨ての公開鍵を改ざんすると開けない', async () => {
  const grant = await grantFor(memberC, 1, generateVaultKeyRaw());
  for (const i of [2, 20, grant.wrappedKey.length - 1]) {
    const wrappedKey = grant.wrappedKey.slice();
    wrappedKey[i]! ^= 1;
    await assert.rejects(openGrant(ownKey(memberC), { ...grant, wrappedKey }), isDecryptFailed, `wrappedKey[${i}]`);
  }
  const enc = grant.ephemeralPublicKey.slice();
  enc[40]! ^= 1;
  await assert.rejects(openGrant(ownKey(memberC), { ...grant, ephemeralPublicKey: enc }), isDecryptFailed);
});

test('C-10 グラントの保存形式に AES-GCM のアルゴリズムID（0x01）が付いていたら拒否する', async () => {
  const grant = await grantFor(memberC, 1, generateVaultKeyRaw());
  const wrappedKey = grant.wrappedKey.slice();
  wrappedKey[1] = 0x01;
  await assert.rejects(
    openGrant(ownKey(memberC), { ...grant, wrappedKey }),
    (e: unknown) => e instanceof CryptoError && e.code === 'UNSUPPORTED_FORMAT',
  );
});

test('C-16 グラントを開いて得た Vault 鍵は書き出せない（取り出し不可）', async () => {
  const grant = await grantFor(memberC, 1, generateVaultKeyRaw());
  const vaultKey = await openGrant(ownKey(memberC), grant);
  assert.equal(vaultKey.extractable, false);
  await assert.rejects(crypto.subtle.exportKey('raw', vaultKey));
  await assert.rejects(crypto.subtle.exportKey('jwk', vaultKey));
});

test('管理操作では、グラントを開き直して生の Vault 鍵を得て、別のメンバー宛てに包み直せる', async () => {
  const raw = generateVaultKeyRaw();
  const toAdmin = await grantFor(admin, 1, raw.slice());
  const reopened = await openGrantForAdmin(ownKey(admin), toAdmin);
  assert.deepEqual(reopened, raw);
  const toC = await grantFor(memberC, 1, reopened);
  reopened.fill(0);
  const cKey = await openGrant(ownKey(memberC), toC);
  const ctx = { itemId: 'item_x', vaultKeyVersion: 1 };
  const env = await encryptItem(await importVaultKey(raw), ctx, { type: 'note', title: 't', body: 'b' });
  assert.deepEqual(await decryptItem(cKey, ctx, env), { type: 'note', title: 't', body: 'b' });
});
