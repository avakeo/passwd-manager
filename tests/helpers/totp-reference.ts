// テスト用：src を使わずに TOTP のコードを計算する（RFC 6238、HMAC-SHA1、30秒、6桁）。
// 期待値を実装と別の道筋で作るため、node:crypto の HMAC と、ここに書いた base32 の読み方だけを使う。

import { createHmac } from 'node:crypto';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32ToBytes(s: string): Uint8Array {
  const clean = s.replace(/=+$/, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const v = ALPHABET.indexOf(ch);
    if (v < 0) throw new Error(`base32 でない文字: ${ch}`);
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export function referenceTotp(secret: Uint8Array, step: number, digits = 6): string {
  const counter = new Uint8Array(8);
  let v = step;
  for (let i = 7; i >= 0; i--) {
    counter[i] = v % 256;
    v = Math.floor(v / 256);
  }
  const mac = createHmac('sha1', secret).update(counter).digest();
  const offset = mac[mac.length - 1]! & 0x0f;
  const bin = ((mac[offset]! & 0x7f) << 24) | (mac[offset + 1]! << 16) | (mac[offset + 2]! << 8) | mac[offset + 3]!;
  return String(bin % 10 ** digits).padStart(digits, '0');
}

export function stepAt(ms: number): number {
  return Math.floor(ms / 1000 / 30);
}
