// TOTP（RFC 6238、HMAC-SHA1、30秒、6桁）の中身。WebCrypto だけで書く（依存なし）。
// 仕様書「認証・認可フロー > 二要素認証（TOTP）」。
//   シークレットは乱数20バイト。サーバーが検証に使うので E2EE にはできず、Workers のシークレットの鍵
//   （TOTP_ENCRYPTION_KEY、32バイト）と AES-256-GCM で暗号化して D1 に置く。暗号文は「形式、アルゴリズムID、ノンス、暗号文と認証タグ」。

import { fromBase64Url, toBase64Url, toHex, utf8, wipe, type Bytes } from '../crypto/bytes.ts';
import { aesGcmDecrypt, aesGcmEncrypt } from '../crypto/aead.ts';
import { CryptoError } from '../crypto/errors.ts';
import { assertId, encodeAeadEnvelope, parseAeadEnvelope } from '../crypto/format.ts';
import { randomBytes } from '../crypto/random.ts';

export const TOTP_STEP_SECONDS = 30;
export const TOTP_DIGITS = 6;
export const TOTP_SECRET_BYTES = 20;
export const RECOVERY_CODE_COUNT = 10;
export const RECOVERY_CODE_BYTES = 10; // 80ビット
const ISSUER = 'teampw';

// ---- base32（RFC 4648、パディングなし） ----

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(s: string): Bytes {
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of s.toUpperCase()) {
    const v = ALPHABET.indexOf(ch);
    if (v < 0) throw new CryptoError('INVALID_INPUT');
    value = ((value << 5) | v) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

// ---- TOTP ----

export function newTotpSecret(): Bytes {
  return randomBytes(TOTP_SECRET_BYTES);
}

function counterBytes(step: number): Bytes {
  if (!Number.isSafeInteger(step) || step < 0) throw new CryptoError('INVALID_INPUT');
  const out = new Uint8Array(8);
  let v = step;
  for (let i = 7; i >= 0; i--) {
    out[i] = v % 256;
    v = Math.floor(v / 256);
  }
  return out;
}

// RFC 4226 の HOTP（動的な切り詰め）
export async function totpCode(secret: Bytes, step: number, digits = TOTP_DIGITS): Promise<string> {
  const key = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBytes(step)));
  const offset = mac[mac.length - 1]! & 0x0f;
  const bin = ((mac[offset]! & 0x7f) << 24) | (mac[offset + 1]! << 16) | (mac[offset + 2]! << 8) | mac[offset + 3]!;
  return String(bin % 10 ** digits).padStart(digits, '0');
}

export function stepAt(nowMs: number): number {
  return Math.floor(nowMs / 1000 / TOTP_STEP_SECONDS);
}

// 前後1ステップまでを許し、最後に使ったステップ以前は拒否する（同じコードの再利用を拒否：A-09）。
// 合えば、そのステップを返す。呼び出し側は、そのステップを「最後に使った」として保存する。
export async function verifyTotp(secret: Bytes, code: string, nowMs: number, lastStep: number | null): Promise<number | null> {
  if (typeof code !== 'string' || !/^[0-9]{6}$/.test(code)) return null;
  const now = stepAt(nowMs);
  for (const step of [now - 1, now, now + 1]) {
    if (lastStep !== null && step <= lastStep) continue;
    if ((await totpCode(secret, step)) === code) return step;
  }
  return null;
}

export function otpauthUri(secret: Bytes, accountName: string): string {
  const label = encodeURIComponent(`${ISSUER}:${accountName}`);
  const params = new URLSearchParams({ secret: base32Encode(secret), issuer: ISSUER, algorithm: 'SHA1', digits: String(TOTP_DIGITS), period: String(TOTP_STEP_SECONDS) });
  return `otpauth://totp/${label}?${params.toString()}`;
}

// ---- シークレットの暗号化（サーバー鍵。E2EE ではない） ----

export type TotpSecretKind = 'totp-secret' | 'totp-pending-secret';

async function importServerKey(keyB64: string): Promise<CryptoKey> {
  let raw: Bytes;
  try {
    raw = fromBase64Url(keyB64);
  } catch {
    throw new CryptoError('INVALID_INPUT');
  }
  if (raw.length !== 32) throw new CryptoError('INVALID_INPUT');
  try {
    return await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  } finally {
    wipe(raw);
  }
}

// v1|totp-secret|<メンバーID>：別のメンバーの行や、登録途中の列への移し替えを防ぐ
function totpAad(kind: TotpSecretKind, memberId: string): Bytes {
  assertId(memberId);
  return utf8(`v1|${kind}|${memberId}`);
}

export async function encryptTotpSecret(keyB64: string, memberId: string, secret: Bytes, kind: TotpSecretKind): Promise<string> {
  const key = await importServerKey(keyB64);
  const { nonce, ciphertext } = await aesGcmEncrypt(key, totpAad(kind, memberId), secret);
  return toBase64Url(encodeAeadEnvelope('totp-secret', nonce, ciphertext));
}

export async function decryptTotpSecret(keyB64: string, memberId: string, envelope: string, kind: TotpSecretKind): Promise<Bytes> {
  let bytes: Bytes;
  try {
    bytes = fromBase64Url(envelope);
  } catch {
    throw new CryptoError('MALFORMED');
  }
  const { nonce, ciphertext } = parseAeadEnvelope('totp-secret', bytes); // 形式とアルゴリズムID を先に確かめる
  const key = await importServerKey(keyB64);
  return aesGcmDecrypt(key, nonce, totpAad(kind, memberId), ciphertext);
}

// ---- 回復コード ----

// 10個。それぞれ乱数10バイト（80ビット）を base32（16文字）にし、4文字ずつ区切る
export function newRecoveryCodes(): string[] {
  const codes: string[] = [];
  for (let i = 0; i < RECOVERY_CODE_COUNT; i++) {
    const s = base32Encode(randomBytes(RECOVERY_CODE_BYTES));
    codes.push(s.match(/.{4}/g)!.join('-'));
  }
  return codes;
}

// 区切りと大文字小文字をそろえてから SHA-256 にする。D1 にはこのハッシュだけを置く
export async function hashRecoveryCode(code: string): Promise<string> {
  const normalized = code.replace(/[-\s]/g, '').toUpperCase();
  return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(normalized))));
}
