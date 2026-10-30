// 管理操作の API テストの準備：鍵を D1 に直接入れる、グラントを API の形にする（members.test.ts、rotate.test.ts）

import { toBase64Url } from '../../src/crypto/bytes.ts';
import type { AdminKeyRecord, MemberKeyRecord } from '../../src/crypto/member-key.ts';
import type { Grant } from '../../src/crypto/grant.ts';
import type { setup } from './api.ts';

type Setup = ReturnType<typeof setup>;

export function insertKey(t: Setup, memberId: string, record: MemberKeyRecord | AdminKeyRecord, status = 'active') {
  const sign = 'signPublicKey' in record ? record : undefined;
  t.db.db
    .prepare(
      `INSERT INTO member_keys (id, member_id, ecdh_public_key, encrypted_private_key, ecdsa_public_key, encrypted_sign_private_key,
                                kdf_algorithm, kdf_params, kdf_salt, format_version, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 0)`,
    )
    .run(
      record.keyId,
      memberId,
      toBase64Url(record.publicKey),
      toBase64Url(record.encryptedPrivateKey),
      sign ? toBase64Url(sign.signPublicKey) : null,
      sign ? toBase64Url(sign.encryptedSignPrivateKey) : null,
      record.kdf.algorithm,
      JSON.stringify({ iterations: record.kdf.iterations, normalization: record.kdf.normalization }),
      toBase64Url(record.kdf.salt),
      status,
    );
}

export function grantBody(g: Grant) {
  return {
    vault_key_version: g.vaultKeyVersion,
    recipient_key_id: g.recipientKeyId,
    ephemeral_public_key: toBase64Url(g.ephemeralPublicKey),
    wrapped_key: toBase64Url(g.wrappedKey),
    signer_key_id: g.signerKeyId,
    signature: toBase64Url(g.signature),
    format_version: g.formatVersion,
  };
}
