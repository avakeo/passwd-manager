// AES-256-GCM の暗号化と復号（アイテムと秘密鍵で使う）。
// ノンスは暗号化のたびにここで96ビットの乱数を作る。外からノンスを渡す口は作らない。

import type { Bytes } from './bytes.ts';
import { decryptFailed } from './errors.ts';
import { NONCE_LENGTH } from './format.ts';
import { randomBytes } from './random.ts';

export async function aesGcmEncrypt(
  key: CryptoKey,
  aad: Bytes,
  plaintext: Bytes,
): Promise<{ nonce: Bytes; ciphertext: Bytes }> {
  const nonce = randomBytes(NONCE_LENGTH);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, key, plaintext),
  );
  return { nonce, ciphertext };
}

export async function aesGcmDecrypt(key: CryptoKey, nonce: Bytes, aad: Bytes, ciphertext: Bytes): Promise<Bytes> {
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, key, ciphertext),
    );
  } catch {
    throw decryptFailed();
  }
}
