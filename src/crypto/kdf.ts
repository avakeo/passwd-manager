// 鍵導出：マスターパスワード →（PBKDF2-HMAC-SHA256）マスターキー →（HKDF-SHA256）ラップ鍵、署名鍵のラップ鍵。
// 仕様書「暗号仕様 > 鍵導出（KDF）」「用途別の鍵」。

import { utf8, wipe, type Bytes } from './bytes.ts';
import { CryptoError } from './errors.ts';
import { randomBytes } from './random.ts';

export const KDF_PBKDF2_SHA256 = 'PBKDF2-HMAC-SHA256';
export const PBKDF2_MIN_ITERATIONS = 600_000;
// 下限は仕様の決定事項。上限は、サーバーが巨大な値を返して端末を止める攻撃を防ぐための安全弁。
export const PBKDF2_MAX_ITERATIONS = 10_000_000;
export const SALT_LENGTH = 16;
// マスターパスワードの正規化の方式（RFC 8265 の OpaqueString に合わせて NFC。前後の空白は削らない）
export const PASSWORD_NORMALIZATION = 'NFC';

// ラップ鍵の用途ラベル（ドメイン分離）。HPKE の内部ラベル（HPKE-v1…）と重ならない。
export const WRAP_KEY_INFO = utf8('teampw/v1/private-key-wrap');
// 管理者の署名用秘密鍵を包む鍵の用途ラベル。ECDH の秘密鍵用のラップ鍵とは別の鍵にする。
export const SIGN_KEY_WRAP_INFO = utf8('teampw/v1/sign-key-wrap');
// クイックロック解除で、パスコードから Vault 鍵を包む鍵を作るときの用途ラベル
export const QUICK_UNLOCK_WRAP_INFO = utf8('teampw/v1/quick-unlock-wrap');

export type KdfParams = {
  algorithm: typeof KDF_PBKDF2_SHA256;
  iterations: number;
  normalization: typeof PASSWORD_NORMALIZATION;
  salt: Bytes;
};

export function newKdfParams(): KdfParams {
  return {
    algorithm: KDF_PBKDF2_SHA256,
    iterations: PBKDF2_MIN_ITERATIONS,
    normalization: PASSWORD_NORMALIZATION,
    salt: randomBytes(SALT_LENGTH),
  };
}

// D1 から来た KDF 設定は改ざんされうる。重い計算の前に、種類・回数・正規化の方式・ソルトの長さを確かめる（C-14）。
export function assertKdfParams(params: KdfParams): void {
  if (params.algorithm !== KDF_PBKDF2_SHA256) throw new CryptoError('KDF_PARAMS_REJECTED');
  const n = params.iterations;
  if (!Number.isSafeInteger(n) || n < PBKDF2_MIN_ITERATIONS || n > PBKDF2_MAX_ITERATIONS) {
    throw new CryptoError('KDF_PARAMS_REJECTED');
  }
  if (params.normalization !== PASSWORD_NORMALIZATION) throw new CryptoError('KDF_PARAMS_REJECTED');
  if (!(params.salt instanceof Uint8Array) || params.salt.length !== SALT_LENGTH) {
    throw new CryptoError('KDF_PARAMS_REJECTED');
  }
}

// マスターパスワードを NFC で正規化する。前後の空白は削らない（空白もパスワードの一部として扱う）。
// 見た目が同じでも、合成済みの「が」と「か」＋濁点はバイト列が違う。正規化しないと、端末や入力方法によって
// 同じパスワードでもロックを解除できなくなる。
export function normalizePassword(password: string): string {
  return password.normalize(PASSWORD_NORMALIZATION);
}

// ラップ鍵（AES-256-GCM、取り出し不可）を作る。
export async function deriveWrapKey(password: string, params: KdfParams): Promise<CryptoKey> {
  const [wrapKey] = await deriveWrapKeys(password, params, [WRAP_KEY_INFO]);
  return wrapKey!;
}

// 1回の PBKDF2 から、用途ラベルごとの鍵（AES-256-GCM、取り出し不可）を HKDF で作る。
// 管理者は ECDH の秘密鍵と署名用秘密鍵の両方を開くので、重い PBKDF2 を2回しないで済む。
// マスターキーは途中で生のバイト列になるので、使ったらすぐ上書きする。
export async function deriveWrapKeys(password: string, params: KdfParams, infos: Bytes[]): Promise<CryptoKey[]> {
  assertKdfParams(params);
  const passwordBytes = utf8(normalizePassword(password));
  let masterKey: Bytes | undefined;
  try {
    const passwordKey = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveBits']);
    masterKey = new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: 'PBKDF2', hash: 'SHA-256', salt: params.salt, iterations: params.iterations },
        passwordKey,
        256,
      ),
    );
    const hkdfKey = await crypto.subtle.importKey('raw', masterKey, 'HKDF', false, ['deriveKey']);
    const keys: CryptoKey[] = [];
    for (const info of infos) {
      keys.push(
        await crypto.subtle.deriveKey(
          { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info },
          hkdfKey,
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt', 'decrypt'],
        ),
      );
    }
    return keys;
  } finally {
    wipe(passwordBytes);
    if (masterKey) wipe(masterKey);
  }
}
