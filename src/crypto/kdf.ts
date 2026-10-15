// 鍵導出：マスターパスワード →（PBKDF2-HMAC-SHA256）マスターキー →（HKDF-SHA256）ラップ鍵。
// 仕様書「暗号仕様 > 鍵導出（KDF）」「用途別の鍵」。

import { utf8, wipe, type Bytes } from './bytes.ts';
import { CryptoError } from './errors.ts';
import { randomBytes } from './random.ts';

export const KDF_PBKDF2_SHA256 = 'PBKDF2-HMAC-SHA256';
export const PBKDF2_MIN_ITERATIONS = 600_000;
// 下限は仕様の決定事項。上限は、サーバーが巨大な値を返して端末を止める攻撃を防ぐための安全弁。
export const PBKDF2_MAX_ITERATIONS = 10_000_000;
export const SALT_LENGTH = 16;

// ラップ鍵の用途ラベル（ドメイン分離）。HPKE の内部ラベル（HPKE-v1…）と重ならない。
export const WRAP_KEY_INFO = utf8('teampw/v1/private-key-wrap');

export type KdfParams = {
  algorithm: typeof KDF_PBKDF2_SHA256;
  iterations: number;
  salt: Bytes;
};

export function newKdfParams(): KdfParams {
  return { algorithm: KDF_PBKDF2_SHA256, iterations: PBKDF2_MIN_ITERATIONS, salt: randomBytes(SALT_LENGTH) };
}

// D1 から来た KDF 設定は改ざんされうる。重い計算の前に、種類・回数・ソルトの長さを確かめる（C-14）。
export function assertKdfParams(params: KdfParams): void {
  if (params.algorithm !== KDF_PBKDF2_SHA256) throw new CryptoError('KDF_PARAMS_REJECTED');
  const n = params.iterations;
  if (!Number.isSafeInteger(n) || n < PBKDF2_MIN_ITERATIONS || n > PBKDF2_MAX_ITERATIONS) {
    throw new CryptoError('KDF_PARAMS_REJECTED');
  }
  if (!(params.salt instanceof Uint8Array) || params.salt.length !== SALT_LENGTH) {
    throw new CryptoError('KDF_PARAMS_REJECTED');
  }
}

// ラップ鍵（AES-256-GCM、取り出し不可）を作る。マスターキーは途中で生のバイト列になるので、使ったらすぐ上書きする。
export async function deriveWrapKey(password: string, params: KdfParams): Promise<CryptoKey> {
  assertKdfParams(params);
  const passwordBytes = utf8(password);
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
    return await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: WRAP_KEY_INFO },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  } finally {
    wipe(passwordBytes);
    if (masterKey) wipe(masterKey);
  }
}
