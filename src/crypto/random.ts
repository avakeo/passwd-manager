// 乱数はすべてここを通す。WebCrypto の getRandomValues 以外は使わない（Math.random は禁止）。

import { toBase64Url, type Bytes } from './bytes.ts';

export function randomBytes(length: number): Bytes {
  return crypto.getRandomValues(new Uint8Array(length));
}

// 32バイトの乱数を base64url（43文字）にしたもの。API のアクセストークン、リフレッシュトークン、一時トークンに使う。
export function newToken(): string {
  return toBase64Url(randomBytes(32));
}

// アイテムIDと鍵ID。乱数16バイト（128ビット）を base64url（22文字）にして接頭辞を付ける。
export function newId(prefix: 'item' | 'key' | 'member' | 'session' | 'challenge'): string {
  return `${prefix}_${toBase64Url(randomBytes(16))}`;
}
