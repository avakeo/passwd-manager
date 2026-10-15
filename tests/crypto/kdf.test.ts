import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fromHex, toHex, utf8 } from '../../src/crypto/bytes.ts';
import {
  PBKDF2_MIN_ITERATIONS,
  WRAP_KEY_INFO,
  assertKdfParams,
  deriveWrapKey,
  newKdfParams,
  type KdfParams,
} from '../../src/crypto/kdf.ts';
import { createMemberKey } from '../../src/crypto/member-key.ts';
import { CryptoError } from '../../src/crypto/errors.ts';
import { ALG_AES_256_GCM, FORMAT_V1 } from '../../src/crypto/format.ts';

const subtle = crypto.subtle;

async function pbkdf2(password: string, salt: Uint8Array<ArrayBuffer>, iterations: number, bytes: number) {
  const key = await subtle.importKey('raw', utf8(password), 'PBKDF2', false, ['deriveBits']);
  return toHex(new Uint8Array(await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, bytes * 8)));
}

async function hkdf(ikm: Uint8Array<ArrayBuffer>, salt: Uint8Array<ArrayBuffer>, info: Uint8Array<ArrayBuffer>, bytes: number) {
  const key = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return toHex(new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, bytes * 8)));
}

// RFC 7914 §11（PBKDF2-HMAC-SHA256 のテストベクタ）
test('C-01 PBKDF2-HMAC-SHA256 が RFC 7914 のテストベクタと一致する', async () => {
  assert.equal(
    await pbkdf2('passwd', utf8('salt'), 1, 64),
    '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783',
  );
  assert.equal(
    await pbkdf2('Password', utf8('NaCl'), 80000, 64),
    '4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d',
  );
});

// RFC 5869 付録 A.1、A.3（HKDF-SHA256 のテストベクタ）
test('C-01 HKDF-SHA256 が RFC 5869 のテストベクタと一致する', async () => {
  const ikm = new Uint8Array(22).fill(0x0b);
  assert.equal(
    await hkdf(ikm, fromHex('000102030405060708090a0b0c'), fromHex('f0f1f2f3f4f5f6f7f8f9'), 42),
    '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
  );
  assert.equal(
    await hkdf(ikm, new Uint8Array(0), new Uint8Array(0), 42),
    '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8',
  );
});

// GCM の仕様書（McGrew & Viega）の Test Case 16：AES-256、96ビットのIV、AAD あり
test('C-01 AES-256-GCM が GCM 仕様の Test Case 16 と一致する', async () => {
  const key = await subtle.importKey(
    'raw',
    fromHex('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308'),
    'AES-GCM',
    false,
    ['encrypt', 'decrypt'],
  );
  const iv = fromHex('cafebabefacedbaddecaf888');
  const aad = fromHex('feedfacedeadbeeffeedfacedeadbeefabaddad2');
  const pt = fromHex(
    'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
  );
  const out = toHex(new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, pt)));
  assert.equal(
    out,
    '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662' +
      '76fc6ece0f4e1768cddf8853bb2d551b',
  );
});

test('ラップ鍵の用途ラベルは teampw/v1/private-key-wrap', () => {
  assert.deepEqual(WRAP_KEY_INFO, utf8('teampw/v1/private-key-wrap'));
});

test('新しい KDF パラメータは PBKDF2-HMAC-SHA256、60万回、乱数16バイトのソルト', () => {
  const a = newKdfParams();
  const b = newKdfParams();
  assert.equal(a.algorithm, 'PBKDF2-HMAC-SHA256');
  assert.equal(a.iterations, 600000);
  assert.equal(a.salt.length, 16);
  assert.notDeepEqual(a.salt, b.salt);
});

function isKdfRejected(e: unknown) {
  return e instanceof CryptoError && e.code === 'KDF_PARAMS_REJECTED';
}

const goodSalt = new Uint8Array(16).fill(1);

test('C-14 KDF の反復回数が下限（60万回）未満のパラメータは拒否される', async () => {
  assert.equal(PBKDF2_MIN_ITERATIONS, 600000);
  for (const iterations of [599999, 100000, 1, 0, -1, 600000.5, Number.NaN]) {
    const params = { algorithm: 'PBKDF2-HMAC-SHA256', iterations, normalization: 'NFC', salt: goodSalt } as KdfParams;
    assert.throws(() => assertKdfParams(params), isKdfRejected, `iterations=${iterations}`);
    // 重い計算に入る前に拒否する（1回で終わるはずの呼び出しが即座に失敗する）
    await assert.rejects(deriveWrapKey('correct horse battery staple', params), isKdfRejected);
  }
});

test('C-14 KDF の種類が PBKDF2-HMAC-SHA256 以外なら拒否される', async () => {
  for (const algorithm of ['PBKDF2-HMAC-SHA1', 'argon2id', '']) {
    const params = { algorithm, iterations: 600000, normalization: 'NFC', salt: goodSalt } as unknown as KdfParams;
    assert.throws(() => assertKdfParams(params), isKdfRejected, algorithm);
  }
});

test('C-14 ソルトが16バイトでなければ拒否される', () => {
  for (const salt of [new Uint8Array(0), new Uint8Array(8), new Uint8Array(32)]) {
    assert.throws(() => assertKdfParams({ algorithm: 'PBKDF2-HMAC-SHA256', iterations: 600000, normalization: 'NFC', salt }), isKdfRejected);
  }
});

test('KDF の反復回数が極端に大きいと拒否される（端末を止める攻撃の防止）', () => {
  assert.throws(
    () => assertKdfParams({ algorithm: 'PBKDF2-HMAC-SHA256', iterations: 1e12, normalization: 'NFC', salt: goodSalt }),
    isKdfRejected,
  );
});

test('A-1 鍵ペアを作り、公開鍵・暗号化した秘密鍵・KDF 設定を返す', async () => {
  const { record, privateKey } = await createMemberKey('sakura-kumo-ringo-73');
  assert.match(record.keyId, /^key_[A-Za-z0-9_-]{22}$/);
  assert.equal(record.publicKey.length, 65);
  assert.equal(record.publicKey[0], 0x04);
  assert.equal(record.encryptedPrivateKey[0], FORMAT_V1);
  assert.equal(record.encryptedPrivateKey[1], ALG_AES_256_GCM);
  // 形式2 ＋ ノンス12 ＋ PKCS#8（138）＋ 認証タグ16
  assert.equal(record.encryptedPrivateKey.length, 2 + 12 + 138 + 16);
  assert.equal(record.kdf.iterations, 600000);
  assert.equal(record.kdf.salt.length, 16);
  // 生成後に手元に残る秘密鍵は取り出し不可
  assert.equal(privateKey.extractable, false);
});

test('A-1 マスターパスワードが14文字未満なら鍵を作らない', async () => {
  await assert.rejects(createMemberKey('short-pass'), (e: unknown) => e instanceof CryptoError && e.code === 'INVALID_INPUT');
});
