// HKDF-SHA256 の Extract と Expand（RFC 5869）を、WebCrypto の HMAC-SHA256 で組む。
// WebCrypto の HKDF は Extract と Expand を一度に行い別々に呼べないが、RFC 9180 は別々に必要とする。
// 標準の構成をそのまま組むだけで、独自の暗号プリミティブではない（仕様書「Vault鍵の受け渡し > 実装上の決まり」）。
// RFC 5869 のテストベクタを当てて確かめる（C-01）。

import { concat, type Bytes } from './bytes.ts';

const HASH_LENGTH = 32;

async function hmacSha256(key: Bytes, data: Bytes): Promise<Bytes> {
  // WebCrypto は長さ0の HMAC の鍵を受け付けない。HMAC は鍵をブロック長（64バイト）まで0で埋めるので、
  // 空の鍵と、32バイトの0の鍵は同じ結果になる。RFC 5869 も、ソルトがなければ HashLen 個の0を使うと定めている。
  const k = key.length === 0 ? new Uint8Array(HASH_LENGTH) : key;
  const hmacKey = await crypto.subtle.importKey('raw', k, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, data));
}

// PRK = HMAC-Hash(salt, IKM)
export function hkdfExtract(salt: Bytes, ikm: Bytes): Promise<Bytes> {
  return hmacSha256(salt, ikm);
}

// T(i) = HMAC-Hash(PRK, T(i-1) | info | i)、OKM は T(1) | T(2) | … の先頭 L バイト
export async function hkdfExpand(prk: Bytes, info: Bytes, length: number): Promise<Bytes> {
  if (!Number.isSafeInteger(length) || length < 0 || length > 255 * HASH_LENGTH) throw new RangeError('HKDF の長さが不正です');
  const blocks: Bytes[] = [];
  let t: Bytes = new Uint8Array(0);
  for (let i = 1; blocks.length * HASH_LENGTH < length; i++) {
    t = await hmacSha256(prk, concat(t, info, new Uint8Array([i])));
    blocks.push(t);
  }
  return concat(...blocks).slice(0, length);
}
