// メンバー鍵ペア。A-1（生成と保存）と A-3 前半（ロック解除）。管理者は署名鍵ペアも持つ。
// 仕様書「暗号仕様 > メンバー鍵ペア」「管理者の署名鍵ペア」「鍵のライフサイクルと取り出し可否」。
//   秘密鍵はパスワードから作らず、乱数で生成する。パスワード由来のラップ鍵は、秘密鍵を包むためだけに使う。

import { wipe, type Bytes } from './bytes.ts';
import { aesGcmDecrypt, aesGcmEncrypt } from './aead.ts';
import { CryptoError, decryptFailed } from './errors.ts';
import { adminSignKeyAad, encodeAeadEnvelope, memberKeyAad, parseAeadEnvelope } from './format.ts';
import { PUBLIC_KEY_LENGTH } from './public-key.ts';
import {
  SIGN_KEY_WRAP_INFO,
  WRAP_KEY_INFO,
  assertKdfParams,
  deriveWrapKey,
  deriveWrapKeys,
  newKdfParams,
  normalizePassword,
  type KdfParams,
} from './kdf.ts';
import { newId } from './random.ts';

export const MIN_MASTER_PASSWORD_LENGTH = 14;

const ECDH_P256 = { name: 'ECDH', namedCurve: 'P-256' } as const;
const ECDSA_P256 = { name: 'ECDSA', namedCurve: 'P-256' } as const;

// D1 の member_keys に保存するもの
export type MemberKeyRecord = {
  keyId: string;
  publicKey: Bytes; // 非圧縮形式の65バイト（平文で保存）
  encryptedPrivateKey: Bytes; // 形式、アルゴリズムID、ノンス、暗号文と認証タグ
  kdf: KdfParams; // 平文で保存
};

// 管理者の行には、署名用の鍵ペアも同じ鍵ID で置く（member_keys の ecdsa_public_key、encrypted_sign_private_key）
export type AdminKeyRecord = MemberKeyRecord & {
  signPublicKey: Bytes; // ECDSA P-256 の非圧縮形式の65バイト（平文で保存）
  encryptedSignPrivateKey: Bytes; // 形式、アルゴリズムID、ノンス、暗号文と認証タグ
};

type KeyKind = 'member-key' | 'admin-sign-key';

// ECDH の秘密鍵は鍵交換だけに、署名用秘密鍵は署名だけに使う
const KEY_PARAMS: Record<KeyKind, { algorithm: EcKeyImportParams; usages: KeyUsage[] }> = {
  'member-key': { algorithm: ECDH_P256, usages: ['deriveBits'] },
  'admin-sign-key': { algorithm: ECDSA_P256, usages: ['sign'] },
};

// 秘密鍵の AAD。種別、鍵ID と、組になる公開鍵の SHA-256 を入れる。
async function privateKeyAad(kind: KeyKind, keyId: string, publicKey: Bytes): Promise<Bytes> {
  if (publicKey.length !== PUBLIC_KEY_LENGTH) throw new CryptoError('INVALID_INPUT');
  const publicKeySha256 = new Uint8Array(await crypto.subtle.digest('SHA-256', publicKey));
  return kind === 'member-key' ? memberKeyAad({ keyId, publicKeySha256 }) : adminSignKeyAad({ keyId, publicKeySha256 });
}

// 取り出し可にするのは、生成して PKCS#8 で書き出すこの場面だけ。
// 包んだ後、手元で使い続ける秘密鍵は、取り出し不可で読み込み直す。
async function generateAndWrap(
  kind: KeyKind,
  keyId: string,
  wrapKey: CryptoKey,
): Promise<{ publicKey: Bytes; encrypted: Bytes; privateKey: CryptoKey }> {
  const pair =
    kind === 'member-key'
      ? await crypto.subtle.generateKey(ECDH_P256, true, ['deriveBits'])
      : await crypto.subtle.generateKey(ECDSA_P256, true, ['sign', 'verify']);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  try {
    const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
    const { nonce, ciphertext } = await aesGcmEncrypt(wrapKey, await privateKeyAad(kind, keyId, publicKey), pkcs8);
    const { algorithm, usages } = KEY_PARAMS[kind];
    const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, algorithm, false, usages);
    return { publicKey, encrypted: encodeAeadEnvelope(kind, nonce, ciphertext), privateKey };
  } finally {
    wipe(pkcs8);
  }
}

// AAD を組み立て直して復号し、取り出し不可で読み込む。
// パスワードの誤り、改ざん、行の入れ替え、公開鍵の差し替えは、どれも同じ DECRYPT_FAILED になる
async function unwrap(kind: KeyKind, aad: Bytes, encrypted: Bytes, wrapKey: CryptoKey): Promise<CryptoKey> {
  const { nonce, ciphertext } = parseAeadEnvelope(kind, encrypted);
  const pkcs8 = await aesGcmDecrypt(wrapKey, nonce, aad, ciphertext);
  try {
    const { algorithm, usages } = KEY_PARAMS[kind];
    return await crypto.subtle.importKey('pkcs8', pkcs8, algorithm, false, usages);
  } catch {
    throw decryptFailed();
  } finally {
    wipe(pkcs8);
  }
}

function assertPasswordLength(password: string): void {
  if ([...normalizePassword(password)].length < MIN_MASTER_PASSWORD_LENGTH) throw new CryptoError('INVALID_INPUT');
}

export async function createMemberKey(password: string): Promise<{ record: MemberKeyRecord; privateKey: CryptoKey }> {
  assertPasswordLength(password);
  const kdf = newKdfParams();
  const keyId = newId('key'); // 暗号化の前に AAD へ入れるので、クライアントで作る
  const wrapKey = await deriveWrapKey(password, kdf);
  const { publicKey, encrypted, privateKey } = await generateAndWrap('member-key', keyId, wrapKey);
  return { record: { keyId, publicKey, encryptedPrivateKey: encrypted, kdf }, privateKey };
}

// 管理者の鍵：ECDH の鍵ペアと、ECDSA P-256 の署名鍵ペア。
// 同じ鍵ID と KDF の設定を使い、1回の PBKDF2 から HKDF の別ラベルで2つのラップ鍵を作る。
export async function createAdminKey(
  password: string,
): Promise<{ record: AdminKeyRecord; privateKey: CryptoKey; signPrivateKey: CryptoKey }> {
  assertPasswordLength(password);
  const kdf = newKdfParams();
  const keyId = newId('key');
  const [wrapKey, signKeyWrapKey] = await deriveWrapKeys(password, kdf, [WRAP_KEY_INFO, SIGN_KEY_WRAP_INFO]);
  const ecdh = await generateAndWrap('member-key', keyId, wrapKey!);
  const sign = await generateAndWrap('admin-sign-key', keyId, signKeyWrapKey!);
  return {
    record: {
      keyId,
      publicKey: ecdh.publicKey,
      encryptedPrivateKey: ecdh.encrypted,
      kdf,
      signPublicKey: sign.publicKey,
      encryptedSignPrivateKey: sign.encrypted,
    },
    privateKey: ecdh.privateKey,
    signPrivateKey: sign.privateKey,
  };
}

// A-3 前半：マスターパスワードで秘密鍵を開け、取り出し不可の ECDH 秘密鍵として読み込む。
// 順番：形式の確認 → KDF の下限の確認 → AAD を組み立て直す（鍵ID と、行の公開鍵の SHA-256） → PBKDF2 → HKDF → AES-GCM で復号 → 取り出し不可で読み込む
export async function unlockMemberKey(password: string, record: MemberKeyRecord): Promise<CryptoKey> {
  parseAeadEnvelope('member-key', record.encryptedPrivateKey);
  assertKdfParams(record.kdf);
  const aad = await privateKeyAad('member-key', record.keyId, record.publicKey);
  const wrapKey = await deriveWrapKey(password, record.kdf);
  return unwrap('member-key', aad, record.encryptedPrivateKey, wrapKey);
}

// 管理者のロック解除：1回の PBKDF2 で、ECDH の秘密鍵と署名用秘密鍵の両方を開く（順番は unlockMemberKey と同じ）。
// 署名用公開鍵だけを差し替えた行では、署名用秘密鍵の AAD が合わずに失敗する（C-21）。
export async function unlockAdminKey(
  password: string,
  record: AdminKeyRecord,
): Promise<{ privateKey: CryptoKey; signPrivateKey: CryptoKey }> {
  parseAeadEnvelope('member-key', record.encryptedPrivateKey);
  parseAeadEnvelope('admin-sign-key', record.encryptedSignPrivateKey);
  assertKdfParams(record.kdf);
  const aad = await privateKeyAad('member-key', record.keyId, record.publicKey);
  const signAad = await privateKeyAad('admin-sign-key', record.keyId, record.signPublicKey);
  const [wrapKey, signKeyWrapKey] = await deriveWrapKeys(password, record.kdf, [WRAP_KEY_INFO, SIGN_KEY_WRAP_INFO]);
  return {
    privateKey: await unwrap('member-key', aad, record.encryptedPrivateKey, wrapKey!),
    signPrivateKey: await unwrap('admin-sign-key', signAad, record.encryptedSignPrivateKey, signKeyWrapKey!),
  };
}
