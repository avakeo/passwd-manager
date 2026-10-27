import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fromHex, toBase64Url, toHex, utf8 } from '../../src/crypto/bytes.ts';
import { createAdminKey, createMemberKey, unlockMemberKey } from '../../src/crypto/member-key.ts';
import {
  createGrant,
  grantInfo,
  grantSignedMessage,
  openGrant,
  openGrantForAdmin,
  type Grant,
  type GrantSigner,
  type GrantTrust,
  type OwnKey,
} from '../../src/crypto/grant.ts';
import { decryptItem, encryptItem } from '../../src/crypto/item.ts';
import { generateVaultKeyRaw, importVaultKey } from '../../src/crypto/vault-key.ts';
import { ALG_HPKE_BASE, FORMAT_V1, encodeGrantEnvelope, encodeSignatureEnvelope } from '../../src/crypto/format.ts';
import { AEAD_AES_256_GCM, setupBaseSWithEphemeral } from '../../src/crypto/hpke-core.ts';
import { CryptoError } from '../../src/crypto/errors.ts';
import { MemoryPinStore, pinPublicKey } from '../../src/crypto/public-key.ts';
import { pinSigner, signMessage } from '../../src/crypto/signer.ts';
import { newTrust, served } from '../helpers/trust.ts';

const ADMIN_PASSWORD = 'admin-hoshi-sora-umi-42';
const C_PASSWORD = 'c-san-kawa-mori-yama-18';
const B_PASSWORD = 'b-san-hana-tsuki-kaze-77';

function isDecryptFailed(e: unknown) {
  return e instanceof CryptoError && e.code === 'DECRYPT_FAILED';
}

// 管理者署名を入れたので、署名の対象を書き換えたものは、開く前の署名の確認で止まる
function isSignatureOrDecryptFailed(e: unknown) {
  return e instanceof CryptoError && (e.code === 'SIGNATURE_INVALID' || e.code === 'DECRYPT_FAILED');
}

// 3人分の鍵を一度だけ作る（PBKDF2 が重いので）
const admin = await createAdminKey(ADMIN_PASSWORD);
const memberC = await createMemberKey(C_PASSWORD);
const memberB = await createMemberKey(B_PASSWORD);

type Member = typeof memberC;

function recipient(m: Member) {
  return { keyId: m.record.keyId, publicKey: m.record.publicKey };
}

// 管理者の端末：3人とも照合済みとして公開鍵を固定しておく
const pins = new MemoryPinStore();
for (const [id, m] of [['member_admin', admin], ['member_c', memberC], ['member_b', memberB]] as const) {
  await pinPublicKey(pins, id, recipient(m));
}
const memberIdOf = new Map<Member, string>([[admin, 'member_admin'], [memberC, 'member_c'], [memberB, 'member_b']]);

function ownKey(m: Member, privateKey: CryptoKey = m.privateKey): OwnKey {
  return { memberId: memberIdOf.get(m)!, keyId: m.record.keyId, publicKey: m.record.publicKey, privateKey };
}

const adminPin = { memberId: 'member_admin', keyId: admin.record.keyId, publicKey: admin.record.signPublicKey };
const adminTrust = newTrust('member_admin');
await pinSigner(adminTrust, adminPin, 1);
const signer: GrantSigner = { memberId: 'member_admin', keyId: admin.record.keyId, privateKey: admin.signPrivateKey, trust: adminTrust };

// 各メンバーの端末：管理者の署名鍵を照合して固定済み
async function trust(): Promise<GrantTrust> {
  const t = newTrust();
  await pinSigner(t, adminPin, 1);
  return t;
}

function grantFor(m: Member, vaultKeyVersion: number, vaultKeyRaw: Uint8Array<ArrayBuffer>) {
  return createGrant({ pins, signer, memberId: memberIdOf.get(m)!, recipient: recipient(m), vaultKeyVersion, vaultKeyRaw });
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
  const ctx = { itemId: 'item_3c9a', vaultKeyVersion: 1, revision: 1 };
  const item = { type: 'login' as const, title: '社内Wiki', username: 'team@example.com', password: 'Tr7#qLm2!vX9pK' };
  const ciphertext = await encryptItem(adminVaultKey, ctx, item);
  const grant = await grantFor(memberC, 1, vaultKeyRaw);
  vaultKeyRaw.fill(0);

  // C さん：別の端末でマスターパスワードから秘密鍵を開け、グラントを開いて、アイテムを復号する
  const cPrivate = await unlockMemberKey(C_PASSWORD, memberC.record);
  const cVaultKey = await openGrant(ownKey(memberC, cPrivate), await trust(), ...served(grant));
  assert.deepEqual(await decryptItem(cVaultKey, ctx, ciphertext), item);
});

test('C-06 他のメンバー宛てのグラントを自分の秘密鍵で開くと失敗する', async () => {
  const grant = await grantFor(memberC, 1, generateVaultKeyRaw());
  // B さんが、C さん宛てのグラントを自分宛てと偽って開こうとする
  const forged: Grant = { ...grant, recipientKeyId: memberB.record.keyId };
  await assert.rejects(openGrant(ownKey(memberB), await trust(), ...served(forged)), isSignatureOrDecryptFailed);
  await assert.rejects(openGrant(ownKey(memberB), await trust(), ...served(grant)), isDecryptFailed);
});

test('C-06 グラントを作った管理者自身も、そのグラントは開けない', async () => {
  const grant = await grantFor(memberC, 1, generateVaultKeyRaw());
  await assert.rejects(openGrant(ownKey(admin), await trust(), ...served({ ...grant, recipientKeyId: admin.record.keyId })), isSignatureOrDecryptFailed);
});

test('グラントの世代を書き換えると開けない（署名と info に世代が入っている）', async () => {
  const grant = await grantFor(memberC, 1, generateVaultKeyRaw());
  await assert.rejects(openGrant(ownKey(memberC), await trust(), ...served({ ...grant, vaultKeyVersion: 2 })), isSignatureOrDecryptFailed);
});

test('C-03 グラントの暗号文や使い捨ての公開鍵を改ざんすると開けない', async () => {
  const grant = await grantFor(memberC, 1, generateVaultKeyRaw());
  for (const i of [2, 20, grant.wrappedKey.length - 1]) {
    const wrappedKey = grant.wrappedKey.slice();
    wrappedKey[i]! ^= 1;
    await assert.rejects(openGrant(ownKey(memberC), await trust(), ...served({ ...grant, wrappedKey })), isSignatureOrDecryptFailed, `wrappedKey[${i}]`);
  }
  const enc = grant.ephemeralPublicKey.slice();
  enc[40]! ^= 1;
  await assert.rejects(openGrant(ownKey(memberC), await trust(), ...served({ ...grant, ephemeralPublicKey: enc })), isSignatureOrDecryptFailed);
});

test('C-10 グラントの保存形式に AES-GCM のアルゴリズムID（0x01）が付いていたら拒否する', async () => {
  const grant = await grantFor(memberC, 1, generateVaultKeyRaw());
  const wrappedKey = grant.wrappedKey.slice();
  wrappedKey[1] = 0x01;
  // 管理者がその形のまま署名したとしても（署名の確認を通っても）、形式の確認で拒否する
  const signature = await resign({ ...grant, wrappedKey }, memberC);
  await assert.rejects(
    openGrant(ownKey(memberC), await trust(), ...served({ ...grant, wrappedKey, signature })),
    (e: unknown) => e instanceof CryptoError && e.code === 'UNSUPPORTED_FORMAT',
  );
});

// テスト用：管理者の署名鍵で、グラントに署名し直す
async function resign(grant: Grant, m: Member) {
  const message = grantSignedMessage({
    signerMemberId: 'member_admin',
    signerKeyId: admin.record.keyId,
    vaultKeyVersion: grant.vaultKeyVersion,
    recipientMemberId: memberIdOf.get(m) ?? 'member_kat',
    recipientKeyId: grant.recipientKeyId,
    recipientPublicKeySha256: new Uint8Array(await crypto.subtle.digest('SHA-256', m.record.publicKey)),
    ephemeralPublicKey: grant.ephemeralPublicKey,
    wrappedKey: grant.wrappedKey,
  });
  return encodeSignatureEnvelope(await signMessage(admin.signPrivateKey, message));
}

test('C-16 グラントを開いて得た Vault 鍵は書き出せない（取り出し不可）', async () => {
  const grant = await grantFor(memberC, 1, generateVaultKeyRaw());
  const vaultKey = await openGrant(ownKey(memberC), await trust(), ...served(grant));
  assert.equal(vaultKey.extractable, false);
  await assert.rejects(crypto.subtle.exportKey('raw', vaultKey));
  await assert.rejects(crypto.subtle.exportKey('jwk', vaultKey));
});

test('管理操作では、グラントを開き直して生の Vault 鍵を得て、別のメンバー宛てに包み直せる', async () => {
  const raw = generateVaultKeyRaw();
  const toAdmin = await grantFor(admin, 1, raw.slice());
  const reopened = await openGrantForAdmin(ownKey(admin), await trust(), ...served(toAdmin));
  assert.deepEqual(reopened, raw);
  const toC = await grantFor(memberC, 1, reopened);
  reopened.fill(0);
  const cKey = await openGrant(ownKey(memberC), await trust(), ...served(toC));
  const ctx = { itemId: 'item_x', vaultKeyVersion: 1, revision: 1 };
  const env = await encryptItem(await importVaultKey(raw), ctx, { type: 'note', title: 't', body: 'b' });
  assert.deepEqual(await decryptItem(cKey, ctx, env), { type: 'note', title: 't', body: 'b' });
});

// 攻撃者レビュー #1（乗っ取られたサーバーが偽グラントを作れる）の「既知の弱点（範囲外）」のテストは、
// 管理者署名を入れたので、攻撃が失敗することを確かめる C-18（tests/crypto/signature.test.ts）に書き換えた。

// Codex レビュー #5：既知解テスト。固定の入力（受け手と使い捨ての鍵ペア、世代、鍵ID、Vault 鍵）から作るグラントが、決まった値になる。
// 期待値は src を使わず、node:crypto で RFC 9180 の SealBase を別に組んで計算した。
// C-13 は往復のテストなので、info のラベルなどを送り手と受け手の両方で同じように間違えると捕まえられない（step-5.md の M2）。
// このテストは、info を含めて仕様どおりの値になっているかを確かめる。
const kat = {
  skR: '902e2bae2815c7e1d5ef6a62e6f0897b46ab72459803d3f7870e99bd603d4e1f',
  pkR: '0419f4143f62326f7c03bc9f89316030b4d20be5118a4a1639966b4f51add21fd2e7583be2fe7b5d03a87173c108b7ad053745cf071fccf77be21be411b74d7b5b',
  skE: '400d69b5a703a01a37d111df3a8f41e0375d9a86a399bb643f50bcc27d17c15c',
  pkE: '042f78978cc2ca7b22d5cf175993585412e687a3c19478e65b0f6685c37baabda3d76faac87e8278570fb6c8132d8b9db27137931eddbba461b34c41215e86b284',
  vaultKeyVersion: 1,
  recipientKeyId: 'key_kat_recipient',
  vaultKey: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
  enc: '042f78978cc2ca7b22d5cf175993585412e687a3c19478e65b0f6685c37baabda3d76faac87e8278570fb6c8132d8b9db27137931eddbba461b34c41215e86b284',
  wrappedKey: '0102e35dbd6a4bad3759133f2bfa50b2294a1848338bccb8d87d505d9bea866189250f75d29bc429b42f22d65ab1643c0d2a',
};

// 秘密鍵は d と公開鍵の x、y を JWK にして読み込む（点の計算はしない）。enc を書き出すので、公開鍵は取り出し可にする。
async function importKatPair(skHex: string, pkHex: string): Promise<CryptoKeyPair> {
  const pk = fromHex(pkHex);
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    { kty: 'EC', crv: 'P-256', d: toBase64Url(fromHex(skHex)), x: toBase64Url(pk.slice(1, 33)), y: toBase64Url(pk.slice(33, 65)) },
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  );
  const publicKey = await crypto.subtle.importKey('raw', pk, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
  return { privateKey, publicKey };
}

test('既知解 固定の入力から作ったグラントが、決まった enc と wrapped_key になる', async () => {
  const info = grantInfo(kat.vaultKeyVersion, kat.recipientKeyId);
  assert.equal(new TextDecoder().decode(info), 'teampw/v1/vault-key-grant|1|key_kat_recipient');
  const { enc, context } = await setupBaseSWithEphemeral(AEAD_AES_256_GCM, fromHex(kat.pkR), info, await importKatPair(kat.skE, kat.pkE));
  const wrappedKey = encodeGrantEnvelope(await context.seal(new Uint8Array(0), fromHex(kat.vaultKey)));
  assert.equal(toHex(enc), kat.enc);
  assert.equal(toHex(wrappedKey), kat.wrappedKey);
});

test('既知解 決まったグラントを、固定の受け手の秘密鍵で開くと、決まった Vault 鍵になる', async () => {
  const own: OwnKey = {
    memberId: 'member_kat',
    keyId: kat.recipientKeyId,
    publicKey: fromHex(kat.pkR),
    privateKey: (await importKatPair(kat.skR, kat.pkR)).privateKey,
  };
  // HPKE の部分（enc と wrapped_key）は変わらない。署名は毎回変わるので、ここで管理者の鍵で付ける。
  const unsigned = {
    vaultKeyVersion: kat.vaultKeyVersion,
    recipientKeyId: kat.recipientKeyId,
    ephemeralPublicKey: fromHex(kat.enc),
    wrappedKey: fromHex(kat.wrappedKey),
    signerKeyId: admin.record.keyId,
    signature: new Uint8Array(0),
    formatVersion: 1,
  };
  const katMember = { record: { ...memberC.record, keyId: kat.recipientKeyId, publicKey: fromHex(kat.pkR) }, privateKey: own.privateKey };
  const grant: Grant = { ...unsigned, signature: await resign(unsigned, katMember) };
  assert.equal(toHex(await openGrantForAdmin(own, await trust(), ...served(grant))), kat.vaultKey);
  const vaultKey = await openGrant(own, await trust(), ...served(grant));
  const ctx = { itemId: 'item_kat', vaultKeyVersion: 1, revision: 1 };
  const env = await encryptItem(await importVaultKey(fromHex(kat.vaultKey)), ctx, { type: 'note', title: 't', body: 'b' });
  assert.deepEqual(await decryptItem(vaultKey, ctx, env), { type: 'note', title: 't', body: 'b' });
});
