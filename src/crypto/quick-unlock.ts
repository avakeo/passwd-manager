// A-5 クイックロック解除：4桁のパスコードから作った鍵で、Vault 鍵だけを包む。仕様書「クイックロック解除」。
//   パスコード →（PBKDF2-HMAC-SHA256、60万回、端末ごとのソルト16バイト）→（HKDF、用途ラベル quick-unlock-wrap）→ AES-256-GCM の鍵（取り出し不可）
//   包んだもの：形式、アルゴリズムID、ノンス、暗号文と認証タグ。AAD は v1|quick-unlock|<接続先>|<メンバーID>|<世代>
// 秘密鍵は包まない（戻った状態は Vault 鍵だけを持つ：E-17）。
// 4桁は1万通りしかないので、包んだものを読まれれば総当たりで破られる。守りは「読まれないこと」（storage.session）に置く。

import { fromBase64Url, toBase64Url, wipe, type Bytes } from './bytes.ts';
import { aesGcmDecrypt, aesGcmEncrypt } from './aead.ts';
import { CryptoError } from './errors.ts';
import { encodeAeadEnvelope, parseAeadEnvelope, quickUnlockAad } from './format.ts';
import { KDF_PBKDF2_SHA256, PASSWORD_NORMALIZATION, PBKDF2_MIN_ITERATIONS, QUICK_UNLOCK_WRAP_INFO, SALT_LENGTH, deriveWrapKeys, type KdfParams } from './kdf.ts';
import { randomBytes } from './random.ts';
import { VAULT_KEY_LENGTH, importVaultKeyAndWipe } from './vault-key.ts';

export const QUICK_UNLOCK_ITERATIONS = PBKDF2_MIN_ITERATIONS; // 60万回（判断待ち 2b-2）
const PASSCODE = /^\d{4}$/;

export type QuickUnlockContext = { apiOrigin: string; memberId: string; vaultKeyVersion: number };

// storage.session に置く形（失敗の回数は呼び出し側が持つ）
export type QuickUnlockRecord = { salt: string; iterations: number; vaultKeyVersion: number; wrapped: string };

function kdfFor(salt: Bytes, iterations: number): KdfParams {
  return { algorithm: KDF_PBKDF2_SHA256, iterations, normalization: PASSWORD_NORMALIZATION, salt };
}

async function passcodeKey(passcode: string, salt: Bytes, iterations: number): Promise<CryptoKey> {
  if (typeof passcode !== 'string' || !PASSCODE.test(passcode)) throw new CryptoError('INVALID_INPUT');
  const [key] = await deriveWrapKeys(passcode, kdfFor(salt, iterations), [QUICK_UNLOCK_WRAP_INFO]);
  return key!;
}

// 生の Vault 鍵を包む。呼び出し側は、この後すぐに raw を wipe する
export async function sealQuickUnlock(passcode: string, raw: Bytes, ctx: QuickUnlockContext): Promise<QuickUnlockRecord> {
  if (raw.length !== VAULT_KEY_LENGTH) throw new CryptoError('INVALID_INPUT');
  const salt = randomBytes(SALT_LENGTH);
  const key = await passcodeKey(passcode, salt, QUICK_UNLOCK_ITERATIONS);
  const { nonce, ciphertext } = await aesGcmEncrypt(key, quickUnlockAad(ctx), raw);
  return { salt: toBase64Url(salt), iterations: QUICK_UNLOCK_ITERATIONS, vaultKeyVersion: ctx.vaultKeyVersion, wrapped: toBase64Url(encodeAeadEnvelope('quick-unlock', nonce, ciphertext)) };
}

// パスコードで開き、Vault 鍵を取り出し不可で読み込む。パスコードが違えば DECRYPT_FAILED
export async function openQuickUnlock(passcode: string, record: QuickUnlockRecord, ctx: { apiOrigin: string; memberId: string }): Promise<CryptoKey> {
  // storage.session の値も、形と反復回数を確かめてから重い計算をする
  if (record.iterations !== QUICK_UNLOCK_ITERATIONS || typeof record.salt !== 'string' || typeof record.wrapped !== 'string') throw new CryptoError('KDF_PARAMS_REJECTED');
  const salt = fromBase64Url(record.salt);
  if (salt.length !== SALT_LENGTH) throw new CryptoError('KDF_PARAMS_REJECTED');
  const { nonce, ciphertext } = parseAeadEnvelope('quick-unlock', fromBase64Url(record.wrapped));
  const key = await passcodeKey(passcode, salt, record.iterations);
  const raw = await aesGcmDecrypt(key, nonce, quickUnlockAad({ ...ctx, vaultKeyVersion: record.vaultKeyVersion }), ciphertext);
  if (raw.length !== VAULT_KEY_LENGTH) {
    wipe(raw);
    throw new CryptoError('DECRYPT_FAILED');
  }
  return importVaultKeyAndWipe(raw);
}
