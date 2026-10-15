import { test } from 'node:test';
import assert from 'node:assert/strict';
import { concat, fromHex, toBase64Url, toHex } from '../../src/crypto/bytes.ts';
import { createMemberKey, unlockMemberKey, type MemberKeyRecord } from '../../src/crypto/member-key.ts';
import { CryptoError } from '../../src/crypto/errors.ts';

const subtle = crypto.subtle;
const ECDH_P256 = { name: 'ECDH', namedCurve: 'P-256' } as const;
const PASSWORD = 'sakura-kumo-ringo-73';

function isDecryptFailed(e: unknown) {
  return e instanceof CryptoError && e.code === 'DECRYPT_FAILED';
}

async function otherPublicKey() {
  return (await subtle.generateKey(ECDH_P256, false, ['deriveBits'])).publicKey;
}

async function ecdh(privateKey: CryptoKey, publicKey: CryptoKey) {
  return toHex(new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256)));
}

// 学習メモ「楕円曲線暗号ノート」10章の値。A-1 の手順で、メモの秘密鍵をメモのノンスと AAD で暗号化したもの。
const memo = {
  salt: '9f2c4a71e03b5d88c16a2f0b7e4d9153',
  nonce: '3b7e19c04a52d6f8e1a09c27',
  keyId: 'key_7f3a',
  ciphertext:
    '9fb32638cfb3703207827df311bbf2428b256d0529ac87ae069cd81b2ba12d1a45f9e8c4c4138b23f4efdaa118d0b77975ff631ec2f53844c87c5006be41e318a972bd2a7b22c0c6dbde1748c36dfd4a3a54dd68075e022d17b0386bb18264e0f93abafae1c10586cb3af1a5c3e932e50868ae10dad4bebb54cd54d4c1a8537ad0403e483828a2dff72a5eb5d8580c35152dbbe0c7f2c53546f0',
  d: 62959851324257542584805810004659076169591458047909207254651228379856561577241n,
  x: 46749387051993978084910577706322439418722029122079100901817284889689444358162n,
  y: 15385064884553841494372430373701728411482615718101619707862451283578032743044n,
};

function memoRecord(): MemberKeyRecord {
  const b64 = (n: bigint) => fromHex(n.toString(16).padStart(64, '0'));
  return {
    keyId: memo.keyId,
    publicKey: concat(new Uint8Array([0x04]), b64(memo.x), b64(memo.y)),
    encryptedPrivateKey: concat(new Uint8Array([0x01, 0x01]), fromHex(memo.nonce), fromHex(memo.ciphertext)),
    kdf: { algorithm: 'PBKDF2-HMAC-SHA256', iterations: 600000, normalization: 'NFC', salt: fromHex(memo.salt) },
  };
}

test('A-3 学習メモの値（sakura-kumo-ringo-73）で秘密鍵を開け、メモの秘密鍵と同じ ECDH 結果になる', async () => {
  const unlocked = await unlockMemberKey(PASSWORD, memoRecord());
  const b64u = (n: bigint) => toBase64Url(fromHex(n.toString(16).padStart(64, '0')));
  const expected = await subtle.importKey(
    'jwk',
    { kty: 'EC', crv: 'P-256', d: b64u(memo.d), x: b64u(memo.x), y: b64u(memo.y) },
    ECDH_P256,
    false,
    ['deriveBits'],
  );
  const peer = await otherPublicKey();
  assert.equal(await ecdh(unlocked, peer), await ecdh(expected, peer));
});

test('A-3 作った鍵を同じパスワードで開ける', async () => {
  const { record, privateKey } = await createMemberKey(PASSWORD);
  const unlocked = await unlockMemberKey(PASSWORD, record);
  const peer = await otherPublicKey();
  assert.equal(await ecdh(unlocked, peer), await ecdh(privateKey, peer));
});

test('C-07 間違ったマスターパスワードでは失敗し、途中の情報も出ない', async () => {
  const record = memoRecord();
  const wrong = await unlockMemberKey('sakura-kumo-ringo-74', record).then(
    () => assert.fail('開けてはいけない'),
    (e: unknown) => e,
  );
  assert.ok(isDecryptFailed(wrong));
  // 改ざんされた場合と、まったく同じエラーになる（理由を返し分けない）
  const tampered = memoRecord();
  tampered.encryptedPrivateKey[20]! ^= 1;
  const tamperedError = await unlockMemberKey(PASSWORD, tampered).then(
    () => assert.fail('開けてはいけない'),
    (e: unknown) => e,
  );
  assert.ok(wrong instanceof CryptoError && tamperedError instanceof CryptoError);
  assert.equal(wrong.code, tamperedError.code);
  assert.equal(wrong.message, tamperedError.message);
  assert.equal(wrong.cause, undefined);
  // エラーに付くのは code と name だけ（原因や途中の値は付かない）
  assert.equal(Object.keys(wrong).sort().join(','), 'code,name');
});

test('C-03 秘密鍵の暗号文・ノンス・認証タグを1ビット改ざんすると失敗する', async () => {
  for (const index of [2, 13, 14, 100, 2 + 12 + 154 - 1]) {
    const record = memoRecord();
    record.encryptedPrivateKey[index]! ^= 0x01;
    await assert.rejects(unlockMemberKey(PASSWORD, record), isDecryptFailed, `byte ${index}`);
  }
});

test('秘密鍵の暗号文を別の鍵IDの行に移すと失敗する（AAD の鍵ID）', async () => {
  const record = memoRecord();
  record.keyId = 'key_0001';
  await assert.rejects(unlockMemberKey(PASSWORD, record), isDecryptFailed);
});

test('C-14 サーバーが返した KDF 設定が弱ければ、復号を試さずに拒否する', async () => {
  const record = memoRecord();
  record.kdf = { ...record.kdf, iterations: 1000 };
  await assert.rejects(
    unlockMemberKey(PASSWORD, record),
    (e: unknown) => e instanceof CryptoError && e.code === 'KDF_PARAMS_REJECTED',
  );
});

test('C-10 秘密鍵の保存形式が未知なら拒否する', async () => {
  const record = memoRecord();
  record.encryptedPrivateKey[0] = 0x02;
  await assert.rejects(
    unlockMemberKey(PASSWORD, record),
    (e: unknown) => e instanceof CryptoError && e.code === 'UNSUPPORTED_FORMAT',
  );
});

test('C-16 ロック解除後の秘密鍵は書き出せない（取り出し不可）', async () => {
  const unlocked = await unlockMemberKey(PASSWORD, memoRecord());
  assert.equal(unlocked.extractable, false);
  assert.deepEqual(unlocked.usages, ['deriveBits']);
  for (const format of ['pkcs8', 'jwk'] as const) {
    await assert.rejects(subtle.exportKey(format, unlocked), `${format} で書き出せてはいけない`);
  }
});
