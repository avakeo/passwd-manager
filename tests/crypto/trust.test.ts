// 端末の信頼の状態（管理者の署名鍵の固定と、最後に見た世代）の保存先。
// PR #2 のレビューの指摘（DeepSeek #4）への対応。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createAdminKey, createMemberKey } from '../../src/crypto/member-key.ts';
import { createGrant, openGrant, openGrantForAdmin, type GrantSigner, type OwnKey } from '../../src/crypto/grant.ts';
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
const adminPin = { memberId: 'member_admin', keyId: admin.record.keyId, publicKey: admin.record.signPublicKey };
// 管理者の端末：自分の組を固定し、世代1で初期化済み
const adminTrust = openTrust(new MemoryTrustStorage(), { apiOrigin: API, memberId: 'member_admin' });
await pinSigner(adminTrust, adminPin, 1);
const signer: GrantSigner = { memberId: 'member_admin', keyId: admin.record.keyId, privateKey: admin.signPrivateKey, trust: adminTrust };

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
  await pinSigner(trustA, adminPin, 1);
  await openGrant(own(memberA, 'member_a'), trustA, await grantTo(memberA, 'member_a', 5));
  assert.equal(await trustA.generations.get(), 5);

  // B さんの組には、A さんの固定も世代も効かない
  const trustB = openTrust(storage, { apiOrigin: API, memberId: 'member_b' });
  assert.equal(await trustB.signerPins.get(), undefined);
  assert.equal(await trustB.generations.get(), undefined);
  await assert.rejects(openGrant(own(memberB, 'member_b'), trustB, await grantTo(memberB, 'member_b', 5)), isCode('SIGNER_NOT_PINNED'));

  // B さんが自分で照合して固定すれば、A さんの世代（5）に引きずられずに世代3を開ける
  await pinSigner(trustB, adminPin, 1);
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

// 非同期の保存先（chrome.storage.local など）を真似る。書き込みは、小さい世代ほど遅く終わる。
// 「読んでから比べて書く」を別々の操作で行うと、同時に開いたときに小さい世代が後から上書きしてしまう。
class SlowStorage extends MemoryTrustStorage {
  override async get(key: string): Promise<string | undefined> {
    await new Promise((r) => setTimeout(r, 5));
    return super.get(key);
  }

  override async set(key: string, value: string): Promise<void> {
    const n = Number(value);
    await new Promise((r) => setTimeout(r, Number.isFinite(n) ? Math.max(0, 60 - 20 * n) : 0));
    return super.set(key, value);
  }
}

test('C-20 最後に見た世代の更新は保存先の1つの操作で、同時に開いても大きい方が残る（Codex #1）', async () => {
  for (const versions of [[1, 2], [2, 1], [3, 2], [2, 3]]) {
    const trust = openTrust(new SlowStorage(), { apiOrigin: API, memberId: 'member_a' });
    await pinSigner(trust, adminPin, 1);
    const grants = await Promise.all(versions.map((v) => grantTo(memberA, 'member_a', v)));
    await Promise.all(grants.map((g) => openGrant(own(memberA, 'member_a'), trust, g)));
    assert.equal(await trust.generations.get(), Math.max(...versions), `同時に開いた世代 ${versions.join('、')}`);
  }
});

test('C-20 世代の記録は上げるだけで、下げられない（Codex #1）', async () => {
  const trust = openTrust(new SlowStorage(), { apiOrigin: API, memberId: 'member_a' });
  await Promise.all([trust.generations.raise(4), trust.generations.raise(2), trust.generations.raise(3)]);
  assert.equal(await trust.generations.get(), 4);
  assert.equal(await trust.generations.raise(1), 4);
  assert.equal(await trust.generations.get(), 4);
  assert.equal(await trust.generations.raise(5), 5);
});

// DeepSeek #1：最後に見た世代が未設定の端末（新規の承認直後、初回の同期、保存先の消失、別のプロファイル）を狙い、
// サーバーが D1 にある一番古い本物のグラントを「現在」として返す。未設定のまま受け入れると、それが基準になってしまう。
test('P-07 最後に見た世代が未設定の端末は、署名鍵を固定していても、本物のグラントを開かない（DeepSeek #1）', async () => {
  const trust = openTrust(new MemoryTrustStorage(), { apiOrigin: API, memberId: 'member_a' });
  // 署名鍵の固定だけがあり、世代がない状態（保存先の一部が消えた場合など）
  await trust.signerPins.set(adminPin);
  const oldest = await grantTo(memberA, 'member_a', 1);
  await assert.rejects(openGrant(own(memberA, 'member_a'), trust, oldest), isCode('SIGNER_NOT_PINNED'));
  assert.equal(await trust.generations.get(), undefined);
});

test('P-07 承認の照合で、管理者の画面の「今の世代」で初期化した端末は、それより古い本物のグラントを受け付けない（DeepSeek #1）', async () => {
  const trust = openTrust(new MemoryTrustStorage(), { apiOrigin: API, memberId: 'member_a' });
  // 対面で、フィンガープリントと一緒に今の世代（5）を見比べ、固定と同時に初期化する
  await pinSigner(trust, adminPin, 5);
  assert.equal(await trust.generations.get(), 5);
  await assert.rejects(openGrant(own(memberA, 'member_a'), trust, await grantTo(memberA, 'member_a', 1)), isCode('STALE_GENERATION'));
  await openGrant(own(memberA, 'member_a'), trust, await grantTo(memberA, 'member_a', 5));
});

// DeepSeek #7：管理者の端末の世代の記録が空のときに、サーバーが管理者自身宛ての本物の古いグラントを「現在」として返す。
test('P-08 管理者の端末を初期化した後は、世代を対面で初期化するまで、自分宛てのグラントを開かず、グラントも作らない（DeepSeek #7）', async () => {
  const adminOwn: OwnKey = { memberId: 'member_admin', keyId: admin.record.keyId, publicKey: admin.record.publicKey, privateKey: admin.privateKey };
  await pinPublicKey(pins, 'member_admin', { keyId: admin.record.keyId, publicKey: admin.record.publicKey });
  const oldSelf = await grantTo(admin, 'member_admin', 1);

  // 初期化した管理者の端末：ロック解除できた自分の行から署名鍵は固定できるが、世代はまだない
  const fresh = openTrust(new MemoryTrustStorage(), { apiOrigin: API, memberId: 'member_admin' });
  await fresh.signerPins.set(adminPin);
  await assert.rejects(openGrantForAdmin(adminOwn, fresh, oldSelf), isCode('SIGNER_NOT_PINNED'));
  // 承認もローテーションもできない（グラントを作らない）
  const freshSigner: GrantSigner = { ...signer, trust: fresh };
  await assert.rejects(
    createGrant({ pins, signer: freshSigner, memberId: 'member_a', recipient: { keyId: memberA.record.keyId, publicKey: memberA.record.publicKey }, vaultKeyVersion: 2, vaultKeyRaw: generateVaultKeyRaw() }),
    isCode('SIGNER_NOT_PINNED'),
  );

  // メンバーの端末に出ている世代（2）と対面で見比べて初期化すると、古い自分宛てのグラントは拒否し、今の世代なら作れる
  await pinSigner(fresh, adminPin, 2);
  await assert.rejects(openGrantForAdmin(adminOwn, fresh, oldSelf), isCode('STALE_GENERATION'));
  await assert.rejects(
    createGrant({ pins, signer: freshSigner, memberId: 'member_a', recipient: { keyId: memberA.record.keyId, publicKey: memberA.record.publicKey }, vaultKeyVersion: 1, vaultKeyRaw: generateVaultKeyRaw() }),
    isCode('STALE_GENERATION'),
  );
  await createGrant({ pins, signer: freshSigner, memberId: 'member_a', recipient: { keyId: memberA.record.keyId, publicKey: memberA.record.publicKey }, vaultKeyVersion: 2, vaultKeyRaw: generateVaultKeyRaw() });
});

test('P-08 グラントを作る署名者は、管理者の端末に固定した自分の組と一致していなければならない', async () => {
  const other = { ...signer, keyId: 'key_other_admin' };
  await assert.rejects(
    createGrant({ pins, signer: other, memberId: 'member_a', recipient: { keyId: memberA.record.keyId, publicKey: memberA.record.publicKey }, vaultKeyVersion: 1, vaultKeyRaw: generateVaultKeyRaw() }),
    isCode('SIGNER_MISMATCH'),
  );
});
