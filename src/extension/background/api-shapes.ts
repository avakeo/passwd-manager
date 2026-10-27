// API の応答・本文と、暗号コアの型との変換（状態を持たない関数だけ）。

import { fromBase64Url, toBase64Url } from '../../crypto/bytes.ts';
import type { Grant } from '../../crypto/grant.ts';
import type { KdfParams } from '../../crypto/kdf.ts';
import type { AdminKeyRecord, MemberKeyRecord } from '../../crypto/member-key.ts';

export type MeKey = Record<string, string | number | null>;

export function groupBase32(s: string): string {
  return s.replace(/(.{4})(?=.)/g, '$1 ');
}

export function keyRecordFromMe(key: MeKey): MemberKeyRecord | AdminKeyRecord {
  const params = JSON.parse(String(key.kdf_params)) as { iterations: number; normalization: KdfParams['normalization'] };
  const base: MemberKeyRecord = {
    keyId: String(key.id),
    publicKey: fromBase64Url(String(key.ecdh_public_key)),
    encryptedPrivateKey: fromBase64Url(String(key.encrypted_private_key)),
    kdf: { algorithm: String(key.kdf_algorithm) as KdfParams['algorithm'], iterations: params.iterations, normalization: params.normalization, salt: fromBase64Url(String(key.kdf_salt)) },
  };
  if (typeof key.ecdsa_public_key !== 'string' || typeof key.encrypted_sign_private_key !== 'string') return base;
  return { ...base, signPublicKey: fromBase64Url(key.ecdsa_public_key), encryptedSignPrivateKey: fromBase64Url(key.encrypted_sign_private_key) };
}

export function keyBody(record: MemberKeyRecord | AdminKeyRecord): Record<string, unknown> {
  const body: Record<string, unknown> = {
    id: record.keyId,
    ecdh_public_key: toBase64Url(record.publicKey),
    encrypted_private_key: toBase64Url(record.encryptedPrivateKey),
    kdf_algorithm: record.kdf.algorithm,
    kdf_params: JSON.stringify({ iterations: record.kdf.iterations, normalization: record.kdf.normalization }),
    kdf_salt: toBase64Url(record.kdf.salt),
    format_version: 1,
  };
  if ('signPublicKey' in record) {
    body.ecdsa_public_key = toBase64Url(record.signPublicKey);
    body.encrypted_sign_private_key = toBase64Url(record.encryptedSignPrivateKey);
  }
  return body;
}

export function grantFromApi(g: Record<string, unknown>): Grant {
  return {
    vaultKeyVersion: Number(g.vault_key_version),
    recipientKeyId: String(g.recipient_key_id),
    ephemeralPublicKey: fromBase64Url(String(g.ephemeral_public_key)),
    wrappedKey: fromBase64Url(String(g.wrapped_key)),
    signerKeyId: String(g.signer_key_id),
    signature: fromBase64Url(String(g.signature)),
    formatVersion: Number(g.format_version),
  };
}
