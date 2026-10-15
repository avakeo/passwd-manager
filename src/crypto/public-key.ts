// 公開鍵の読み込み（手順5）と、フィンガープリント・固定（手順6）。
// 仕様書「暗号仕様 > メンバー鍵ペア」。

import type { Bytes } from './bytes.ts';
import { CryptoError } from './errors.ts';

export const PUBLIC_KEY_LENGTH = 65;

// サーバーから来た公開鍵を読み込む。受け付けるのは非圧縮形式（先頭 0x04、65バイト）だけ。
// 曲線上にあるかの検査は WebCrypto に任せる（点の計算は自前で書かない）。C-12。
export async function importPublicKey(raw: Bytes): Promise<CryptoKey> {
  if (!(raw instanceof Uint8Array) || raw.length !== PUBLIC_KEY_LENGTH || raw[0] !== 0x04) {
    throw new CryptoError('INVALID_PUBLIC_KEY');
  }
  try {
    return await crypto.subtle.importKey('raw', raw, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
  } catch {
    throw new CryptoError('INVALID_PUBLIC_KEY');
  }
}
