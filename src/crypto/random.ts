// 乱数はすべてここを通す。WebCrypto の getRandomValues 以外は使わない（Math.random は禁止）。

import { toBase64Url, type Bytes } from './bytes.ts';

export function randomBytes(length: number): Bytes {
  return crypto.getRandomValues(new Uint8Array(length));
}

// アイテムIDと鍵ID。乱数16バイト（128ビット）を base64url（22文字）にして接頭辞を付ける。
export function newId(prefix: 'item' | 'key'): string {
  return `${prefix}_${toBase64Url(randomBytes(16))}`;
}
