// マスターパスワードの Unicode 正規化（RFC 8265 の OpaqueString に合わせて NFC。前後の空白は削らない）。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assertKdfParams, newKdfParams, normalizePassword, type KdfParams } from '../../src/crypto/kdf.ts';
import { createMemberKey, unlockMemberKey } from '../../src/crypto/member-key.ts';
import { CryptoError } from '../../src/crypto/errors.ts';

const COMPOSED = 'が'; // 「が」（合成済みの1文字）
const DECOMPOSED = 'が'; // 「か」＋ 結合用の濁点（2文字）
const SUFFIX = 'っこうのかぎ-sakura-2026';

function isDecryptFailed(e: unknown) {
  return e instanceof CryptoError && e.code === 'DECRYPT_FAILED';
}

test('合成済みの「が」と「か」＋濁点は、見た目が同じでもバイト列が違う（正規化の前提）', () => {
  assert.notEqual(COMPOSED, DECOMPOSED);
  assert.equal(COMPOSED.length, 1);
  assert.equal(DECOMPOSED.length, 2);
  assert.equal(normalizePassword(DECOMPOSED), COMPOSED);
});

test('合成済みの「が」で作った鍵を、「か」＋濁点で入力したパスワードで開ける（NFC で同じ鍵になる）', async () => {
  const { record } = await createMemberKey(COMPOSED + SUFFIX);
  await unlockMemberKey(DECOMPOSED + SUFFIX, record);
});

test('「か」＋濁点で作った鍵を、合成済みの「が」で開ける（逆向き）', async () => {
  const { record } = await createMemberKey(DECOMPOSED + SUFFIX);
  await unlockMemberKey(COMPOSED + SUFFIX, record);
});

test('前後の空白は削らない（空白を足すと別のパスワードになる）', async () => {
  const password = COMPOSED + SUFFIX;
  assert.equal(normalizePassword(` ${password} `), ` ${password} `);
  const { record } = await createMemberKey(password);
  await assert.rejects(unlockMemberKey(` ${password}`, record), isDecryptFailed);
  await assert.rejects(unlockMemberKey(`${password} `, record), isDecryptFailed);
});

test('正規化の方式（NFC）は KDF の設定として保存される', () => {
  assert.equal(newKdfParams().normalization, 'NFC');
});

test('C-14 KDF の設定の正規化の方式が NFC 以外、または無い場合は拒否する', () => {
  const salt = new Uint8Array(16).fill(1);
  for (const normalization of ['NFD', 'NFKC', 'none', undefined]) {
    const params = { algorithm: 'PBKDF2-HMAC-SHA256', iterations: 600000, normalization, salt } as unknown as KdfParams;
    assert.throws(
      () => assertKdfParams(params),
      (e: unknown) => e instanceof CryptoError && e.code === 'KDF_PARAMS_REJECTED',
      String(normalization),
    );
  }
});
