// 端末の信頼の状態（管理者の署名鍵の固定と、最後に見た世代）の保存先。
// PR #2 のレビューの指摘（DeepSeek #4）への対応。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createAdminKey, createMemberKey } from '../../src/crypto/member-key.ts';
import { createGrant, openGrant, type GrantSigner, type OwnKey } from '../../src/crypto/grant.ts';
import { generateVaultKeyRaw } from '../../src/crypto/vault-key.ts';
import { CryptoError } from '../../src/crypto/errors.ts';
import { MemoryPinStore, pinPublicKey } from '../../src/crypto/public-key.ts';
import { MemoryTrustStorage, openTrust, pinSigner } from '../../src/crypto/signer.ts';

const API = 'https://pw-api.example.com';

function isCode(code: string) {
  return (e: unknown) => e instanceof CryptoError && e.code === code;
}

const admin = await createAdminKey('admin-hoshi-sora-umi-42');
const memberA = await createMemberKey('a-san-kawa-mori-yama-18');
const memberB = await createMemberKey('b-san-hana-tsuki-kaze-77');
const signer: GrantSigner = { memberId: 'member_admin', keyId: admin.record.keyId, privateKey: admin.signPrivateKey };
const adminPin = { memberId: 'member_admin', keyId: admin.record.keyId, publicKey: admin.record.signPublicKey };

const pins = new MemoryPinStore();
await pinPublicKey(pins, 'member_a', { keyId: memberA.record.keyId, publicKey: memberA.record.publicKey });
await pinPublicKey(pins, 'member_b', { keyId: memberB.record.keyId, publicKey: memberB.record.publicKey });

function own(m: typeof memberA, memberId: string): OwnKey {
  return { memberId, keyId: m.record.keyId, publicKey: m.record.publicKey, privateKey: m.privateKey };
}

function grantTo(m: typeof memberA, memberId: string, vaultKeyVersion: number) {
  return createGrant({
    pins,
    signer,
    memberId,
    recipient: { keyId: m.record.keyId, publicKey: m.record.publicKey },
    vaultKeyVersion,
    vaultKeyRaw: generateVaultKeyRaw(),
  });
}

test('P-09 固定と最後に見た世代は、API の接続先とメンバー ID の組ごとに分かれ、別の組の値は効かない（DeepSeek #4）', async () => {
  // 同じブラウザのプロファイル（同じ保存先）を、A さんと B さんが続けて使う
  const storage = new MemoryTrustStorage();
  const trustA = openTrust(storage, { apiOrigin: API, memberId: 'member_a' });
  await pinSigner(trustA, adminPin);
  await openGrant(own(memberA, 'member_a'), trustA, await grantTo(memberA, 'member_a', 5));
  assert.equal(await trustA.generations.get(), 5);

  // B さんの組には、A さんの固定も世代も効かない
  const trustB = openTrust(storage, { apiOrigin: API, memberId: 'member_b' });
  assert.equal(await trustB.signerPins.get(), undefined);
  assert.equal(await trustB.generations.get(), undefined);
  await assert.rejects(openGrant(own(memberB, 'member_b'), trustB, await grantTo(memberB, 'member_b', 5)), isCode('SIGNER_NOT_PINNED'));

  // B さんが自分で照合して固定すれば、A さんの世代（5）に引きずられずに世代3を開ける
  await pinSigner(trustB, adminPin);
  await openGrant(own(memberB, 'member_b'), trustB, await grantTo(memberB, 'member_b', 3));
  assert.equal(await trustB.generations.get(), 3);
  assert.equal(await trustA.generations.get(), 5);

  // 同じメンバー ID でも、API の接続先が違えば別の組
  const otherApi = openTrust(storage, { apiOrigin: 'https://other-api.example.com', memberId: 'member_a' });
  assert.equal(await otherApi.signerPins.get(), undefined);
  assert.equal(await otherApi.generations.get(), undefined);

  // 同じ組を開き直すと、同じ値が見える（拡張機能の再起動）
  const reopened = openTrust(storage, { apiOrigin: API, memberId: 'member_a' });
  assert.deepEqual(await reopened.signerPins.get(), adminPin);
  assert.equal(await reopened.generations.get(), 5);
});

test('P-09 接続先は https のオリジンだけ、メンバー ID は ID の形のものだけを受け付ける', () => {
  const storage = new MemoryTrustStorage();
  for (const apiOrigin of ['http://pw-api.example.com', 'https://pw-api.example.com/v1', 'pw-api.example.com', 'https://a|b.example.com']) {
    assert.throws(() => openTrust(storage, { apiOrigin, memberId: 'member_a' }), isCode('INVALID_INPUT'), apiOrigin);
  }
  assert.throws(() => openTrust(storage, { apiOrigin: API, memberId: 'member|a' }), isCode('INVALID_INPUT'));
});
