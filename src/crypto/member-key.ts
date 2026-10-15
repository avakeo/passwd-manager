// メンバー鍵ペア。A-1（生成と保存）と A-3 前半（ロック解除）。
// 仕様書「暗号仕様 > メンバー鍵ペア」「鍵のライフサイクルと取り出し可否」。
//   秘密鍵はパスワードから作らず、乱数で生成する。パスワード由来のラップ鍵は、秘密鍵を包むためだけに使う。

import { wipe, type Bytes } from './bytes.ts';
import { aesGcmDecrypt, aesGcmEncrypt } from './aead.ts';
import { CryptoError, decryptFailed } from './errors.ts';
import { encodeAeadEnvelope, memberKeyAad, parseAeadEnvelope } from './format.ts';
import { assertKdfParams, deriveWrapKey, newKdfParams, type KdfParams } from './kdf.ts';
import { newId } from './random.ts';

export const MIN_MASTER_PASSWORD_LENGTH = 14;

const ECDH_P256 = { name: 'ECDH', namedCurve: 'P-256' } as const;

// D1 の member_keys に保存するもの
export type MemberKeyRecord = {
  keyId: string;
  publicKey: Bytes; // 非圧縮形式の65バイト（平文で保存）
  encryptedPrivateKey: Bytes; // 形式、アルゴリズムID、ノンス、暗号文と認証タグ
  kdf: KdfParams; // 平文で保存
};

export async function createMemberKey(password: string): Promise<{ record: MemberKeyRecord; privateKey: CryptoKey }> {
  if ([...password].length < MIN_MASTER_PASSWORD_LENGTH) throw new CryptoError('INVALID_INPUT');

  const kdf = newKdfParams();
  const keyId = newId('key'); // 暗号化の前に AAD へ入れるので、クライアントで作る
  const wrapKey = await deriveWrapKey(password, kdf);

  // 取り出し可にするのは、生成して PKCS#8 で書き出すこの場面だけ
  const pair = await crypto.subtle.generateKey(ECDH_P256, true, ['deriveBits']);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  try {
    const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
    const { nonce, ciphertext } = await aesGcmEncrypt(wrapKey, memberKeyAad({ keyId }), pkcs8);
    // 手元で使い続ける秘密鍵は、取り出し不可で読み込み直す
    const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, ECDH_P256, false, ['deriveBits']);
    return {
      record: { keyId, publicKey, encryptedPrivateKey: encodeAeadEnvelope('member-key', nonce, ciphertext), kdf },
      privateKey,
    };
  } finally {
    wipe(pkcs8);
  }
}

// A-3 前半：マスターパスワードで秘密鍵を開け、取り出し不可の ECDH 秘密鍵として読み込む。
// 順番：形式の確認 → KDF の下限の確認 → AAD を組み立て直す → PBKDF2 → HKDF → AES-GCM で復号 → 取り出し不可で読み込む
export async function unlockMemberKey(password: string, record: MemberKeyRecord): Promise<CryptoKey> {
  const { nonce, ciphertext } = parseAeadEnvelope('member-key', record.encryptedPrivateKey);
  assertKdfParams(record.kdf);
  const aad = memberKeyAad({ keyId: record.keyId });
  const wrapKey = await deriveWrapKey(password, record.kdf);
  // パスワードの誤り、改ざん、行の入れ替えは、どれも同じ DECRYPT_FAILED になる
  const pkcs8 = await aesGcmDecrypt(wrapKey, nonce, aad, ciphertext);
  try {
    return await crypto.subtle.importKey('pkcs8', pkcs8, ECDH_P256, false, ['deriveBits']);
  } catch {
    throw decryptFailed();
  } finally {
    wipe(pkcs8);
  }
}
