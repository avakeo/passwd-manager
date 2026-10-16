// 保存形式（形式バージョンとアルゴリズムIDのヘッダー）、ID、AAD の組み立て。
// 仕様書「暗号仕様 > 共通の規則」「アイテムの暗号化」「メンバー鍵ペア」「管理者の署名鍵ペア」。

import { concat, toHex, utf8, type Bytes } from './bytes.ts';
import { CryptoError } from './errors.ts';

export const FORMAT_V1 = 0x01;

// アルゴリズムIDの表（仕様書で1つの表にまとめたもの）
export const ALG_AES_256_GCM = 0x01;
export const ALG_HPKE_BASE = 0x02; // KEM 0x0010・KDF 0x0001・AEAD 0x0002
export const ALG_ECDSA_P256_SHA256 = 0x03; // 署名は64バイト（r と s を32バイトずつ）

export const NONCE_LENGTH = 12;
export const TAG_LENGTH = 16;
export const SIGNATURE_LENGTH = 64;
// グラントの wrapped_key の長さ：形式1 ＋ アルゴリズムID1 ＋ Vault 鍵32 ＋ 認証タグ16
export const GRANT_ENVELOPE_LENGTH = 2 + 32 + TAG_LENGTH;

export type AeadUsage = 'item' | 'member-key' | 'admin-sign-key';

const ALG_FOR_USAGE: Record<AeadUsage | 'grant' | 'signature', number> = {
  item: ALG_AES_256_GCM,
  'member-key': ALG_AES_256_GCM,
  'admin-sign-key': ALG_AES_256_GCM,
  grant: ALG_HPKE_BASE,
  signature: ALG_ECDSA_P256_SHA256,
};

const ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

// AAD の区切りの `|` が入らないよう、ID に使える文字と長さを限る。
export function assertId(id: string): void {
  if (typeof id !== 'string' || !ID_PATTERN.test(id)) throw new CryptoError('INVALID_INPUT');
}

export function assertVersion(v: number): void {
  if (!Number.isSafeInteger(v) || v < 1) throw new CryptoError('INVALID_INPUT');
}

function checkHeader(bytes: Uint8Array, usage: AeadUsage | 'grant' | 'signature', minLength: number): void {
  if (bytes.length < 2) throw new CryptoError('MALFORMED');
  // 復号を試す前に、ヘッダーの形式バイトが AAD の形式（v1）と一致することを確かめる。
  if (bytes[0] !== FORMAT_V1) throw new CryptoError('UNSUPPORTED_FORMAT');
  if (bytes[1] !== ALG_FOR_USAGE[usage]) throw new CryptoError('UNSUPPORTED_FORMAT');
  if (bytes.length < minLength) throw new CryptoError('MALFORMED');
}

// アイテムと秘密鍵：形式（1B）、アルゴリズムID（1B）、ノンス（12B）、暗号文と認証タグ
export function encodeAeadEnvelope(usage: AeadUsage, nonce: Uint8Array, ciphertext: Uint8Array): Bytes {
  if (nonce.length !== NONCE_LENGTH) throw new CryptoError('INVALID_INPUT');
  return concat(new Uint8Array([FORMAT_V1, ALG_FOR_USAGE[usage]]), nonce, ciphertext);
}

export function parseAeadEnvelope(usage: AeadUsage, bytes: Uint8Array): { nonce: Bytes; ciphertext: Bytes } {
  checkHeader(bytes, usage, 2 + NONCE_LENGTH + TAG_LENGTH);
  return {
    nonce: bytes.slice(2, 2 + NONCE_LENGTH),
    ciphertext: bytes.slice(2 + NONCE_LENGTH),
  };
}

// グラント：形式（1B）、アルゴリズムID（1B）、暗号文と認証タグ。
// ノンスは HPKE の鍵スケジュールから作るので持たない。
export function encodeGrantEnvelope(ciphertext: Uint8Array): Bytes {
  return concat(new Uint8Array([FORMAT_V1, ALG_HPKE_BASE]), ciphertext);
}

export function parseGrantEnvelope(bytes: Uint8Array): Bytes {
  checkHeader(bytes, 'grant', 2 + TAG_LENGTH);
  return bytes.slice(2);
}

// グラントの署名：形式（1B）、アルゴリズムID（1B）、署名（64B）。
export function encodeSignatureEnvelope(signature: Uint8Array): Bytes {
  if (signature.length !== SIGNATURE_LENGTH) throw new CryptoError('INVALID_INPUT');
  return concat(new Uint8Array([FORMAT_V1, ALG_ECDSA_P256_SHA256]), signature);
}

// 列が空、長さ違い、形式やアルゴリズムID の違いは、どれも「署名がない」と同じ扱いにする（C-17）。
export function parseSignatureEnvelope(bytes: Uint8Array): Bytes {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 2 + SIGNATURE_LENGTH) throw new CryptoError('SIGNATURE_INVALID');
  try {
    checkHeader(bytes, 'signature', 2 + SIGNATURE_LENGTH);
  } catch {
    throw new CryptoError('SIGNATURE_INVALID');
  }
  return bytes.slice(2);
}

export type ItemContext = { itemId: string; vaultKeyVersion: number };
export type MemberKeyContext = { keyId: string; publicKeySha256: Bytes };

// v1|item|<アイテムID>|<世代>
export function itemAad(ctx: ItemContext): Bytes {
  assertId(ctx.itemId);
  assertVersion(ctx.vaultKeyVersion);
  return utf8(`v${FORMAT_V1}|item|${ctx.itemId}|${ctx.vaultKeyVersion}`);
}

function keyAad(kind: 'member-key' | 'admin-sign-key', ctx: MemberKeyContext): Bytes {
  assertId(ctx.keyId);
  if (ctx.publicKeySha256.length !== 32) throw new CryptoError('INVALID_INPUT');
  return utf8(`v${FORMAT_V1}|${kind}|${ctx.keyId}|${toHex(ctx.publicKeySha256)}`);
}

// v1|member-key|<鍵ID>|<公開鍵（65バイト）の SHA-256 の16進>
// 公開鍵の SHA-256 を入れるので、サーバーが公開鍵だけを差し替えた行では、ロック解除に失敗する。
export function memberKeyAad(ctx: MemberKeyContext): Bytes {
  return keyAad('member-key', ctx);
}

// v1|admin-sign-key|<鍵ID>|<署名用公開鍵（65バイト）の SHA-256 の16進>
// 管理者の署名用秘密鍵の AAD。署名用公開鍵だけを差し替えた行では、ロック解除に失敗する（C-21）。
export function adminSignKeyAad(ctx: MemberKeyContext): Bytes {
  return keyAad('admin-sign-key', ctx);
}
