// Vault 鍵（チーム共通の AES-256-GCM の鍵）。
// 仕様書「鍵のライフサイクルと取り出し可否」：通常は取り出し不可で持つ。
// 生の32バイトを扱うのは、管理操作（新しい世代の生成、グラントを作るとき）だけ。

import { wipe, type Bytes } from './bytes.ts';
import { CryptoError } from './errors.ts';
import { randomBytes } from './random.ts';

export const VAULT_KEY_LENGTH = 32;

// 新しい世代の Vault 鍵。管理者の端末で、全員分のグラントを作るためだけに生のバイト列で持つ。
export function generateVaultKeyRaw(): Bytes {
  return randomBytes(VAULT_KEY_LENGTH);
}

// 取り出し不可で読み込む。読み込んだ後、呼び出し側は生のバイト列を wipe する。
export async function importVaultKey(raw: Bytes): Promise<CryptoKey> {
  if (raw.length !== VAULT_KEY_LENGTH) throw new CryptoError('INVALID_INPUT');
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

// 生のバイト列を読み込んで、すぐに上書きする。
export async function importVaultKeyAndWipe(raw: Bytes): Promise<CryptoKey> {
  try {
    return await importVaultKey(raw);
  } finally {
    wipe(raw);
  }
}
