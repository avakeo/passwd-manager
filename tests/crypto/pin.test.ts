import { test } from 'node:test';
import assert from 'node:assert/strict';
import { concat, fromHex, toHex } from '../../src/crypto/bytes.ts';
import { MemoryPinStore, assertPinned, fingerprint, pinPublicKey } from '../../src/crypto/public-key.ts';
import { createGrant, openGrant, type GrantSigner } from '../../src/crypto/grant.ts';
import { createAdminKey, createMemberKey } from '../../src/crypto/member-key.ts';
import { pinSigner } from '../../src/crypto/signer.ts';
import { newTrust, served } from '../helpers/trust.ts';
import { generateVaultKeyRaw } from '../../src/crypto/vault-key.ts';
import { CryptoError } from '../../src/crypto/errors.ts';

function isCode(code: string) {
  return (e: unknown) => e instanceof CryptoError && e.code === code;
}

async function newPublicKey() {
  const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
}

const admin = await createAdminKey('admin-hoshi-sora-umi-42');
const adminPin = { memberId: 'member_admin', keyId: admin.record.keyId, publicKey: admin.record.signPublicKey };
const adminTrust = newTrust('member_admin');
await pinSigner(adminTrust, adminPin, 1);
const signer: GrantSigner = { memberId: 'member_admin', keyId: admin.record.keyId, privateKey: admin.signPrivateKey, trust: adminTrust };

// 学習メモの公開鍵
const memoPublicKey = concat(
  new Uint8Array([0x04]),
  fromHex(46749387051993978084910577706322439418722029122079100901817284889689444358162n.toString(16).padStart(64, '0')),
  fromHex(15385064884553841494372430373701728411482615718101619707862451283578032743044n.toString(16).padStart(64, '0')),
);

test('フィンガープリントは SHA-256 の先頭30バイトを5バイトずつ6組にし、10万で割った余りを5桁で表す', async () => {
  const fp = await fingerprint(memoPublicKey);
  assert.match(fp, /^\d{5}( \d{5}){5}$/);
  // 仕様どおりに、テストの中で別に計算して比べる
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', memoPublicKey));
  assert.equal(toHex(digest).slice(0, 20), '70dd2685e8369120b12d'); // 学習メモの値
  const groups: string[] = [];
  for (let i = 0; i < 6; i++) {
    let n = 0n;
    for (const b of digest.slice(i * 5, i * 5 + 5)) n = n * 256n + BigInt(b);
    groups.push((n % 100000n).toString().padStart(5, '0'));
  }
  assert.equal(fp, groups.join(' '));
});

test('フィンガープリントは公開鍵が1ビット違えば変わる', async () => {
  const a = await newPublicKey();
  const fa = await fingerprint(a);
  assert.equal(fa, await fingerprint(a.slice()));
  assert.notEqual(fa, await fingerprint(await newPublicKey()));
});

test('固定できるのは正しい公開鍵だけ', async () => {
  const store = new MemoryPinStore();
  const bad = memoPublicKey.slice();
  bad[64]! ^= 1; // 曲線上にない点になる
  await assert.rejects(pinPublicKey(store, 'member_c', { keyId: 'key_c', publicKey: bad }), isCode('INVALID_PUBLIC_KEY'));
});

test('固定値との比較は、表示用の文字列ではなく公開鍵のバイト列で行う', async () => {
  const store = new MemoryPinStore();
  const a = await newPublicKey();
  await pinPublicKey(store, 'member_c', { keyId: 'key_c', publicKey: a });
  await assertPinned(store, 'member_c', { keyId: 'key_c', publicKey: a.slice() });
  await assert.rejects(assertPinned(store, 'member_c', { keyId: 'key_c', publicKey: await newPublicKey() }), isCode('PUBLIC_KEY_MISMATCH'));
  // 固定した後で呼び出し側の配列を書き換えても、固定値は変わらない
  a[10]! ^= 1;
  await assert.rejects(assertPinned(store, 'member_c', { keyId: 'key_c', publicKey: a }), isCode('PUBLIC_KEY_MISMATCH'));
});

// P-01 の場面：
//   1. 管理者は承認のとき、C さんのフィンガープリントを Discord 以外の経路で照合し、公開鍵を端末に固定した
//   2. その後、乗っ取られたサーバーが D1 の C さんの公開鍵を、攻撃者の公開鍵に差し替えた
//   3. 管理者がグラントを作ろうとする（ローテーションなど）
test('P-01 承認済みメンバーの公開鍵をサーバー側で差し替えてから、管理者がグラントを作ると、検知してグラントを作らない', async () => {
  const memberC = await createMemberKey('c-san-kawa-mori-yama-18');
  const attacker = await createMemberKey('attacker-kuro-yami-99x');
  const pins = new MemoryPinStore();
  await pinPublicKey(pins, 'member_c', { keyId: memberC.record.keyId, publicKey: memberC.record.publicKey });

  // サーバーが返す C さんの鍵情報（公開鍵だけ攻撃者のものに差し替えられている）
  const fromServer = { keyId: memberC.record.keyId, publicKey: attacker.record.publicKey };

  let grant: unknown;
  await assert.rejects(
    (async () => {
      grant = await createGrant({ pins, signer, memberId: 'member_c', recipient: fromServer, vaultKeyVersion: 2, vaultKeyRaw: generateVaultKeyRaw() });
    })(),
    isCode('PUBLIC_KEY_MISMATCH'),
  );
  assert.equal(grant, undefined, 'グラントが作られていない');

  // 差し替えがなければ作れて、C さんが開ける
  const ok = await createGrant({
    pins,
    signer,
    memberId: 'member_c',
    recipient: { keyId: memberC.record.keyId, publicKey: memberC.record.publicKey },
    vaultKeyVersion: 2,
    vaultKeyRaw: generateVaultKeyRaw(),
  });
  const trust = newTrust('member_c');
  await pinSigner(trust, adminPin, 1);
  await openGrant(
    { memberId: 'member_c', keyId: memberC.record.keyId, publicKey: memberC.record.publicKey, privateKey: memberC.privateKey },
    trust,
    ...served(ok),
  );
});

test('P-01 固定していないメンバー宛てには、グラントを作らない（照合と承認が先）', async () => {
  const memberC = await createMemberKey('c-san-kawa-mori-yama-18');
  await assert.rejects(
    createGrant({
      pins: new MemoryPinStore(),
      signer,
      memberId: 'member_c',
      recipient: { keyId: memberC.record.keyId, publicKey: memberC.record.publicKey },
      vaultKeyVersion: 1,
      vaultKeyRaw: generateVaultKeyRaw(),
    }),
    isCode('PUBLIC_KEY_NOT_PINNED'),
  );
});

test('P-01 鍵を再登録したメンバーは、照合し直して固定するまでグラントを作れない', async () => {
  const pins = new MemoryPinStore();
  const oldKey = await newPublicKey();
  await pinPublicKey(pins, 'member_c', { keyId: 'key_old', publicKey: oldKey });
  const reRegistered = await createMemberKey('c-san-atarashii-kagi-2026');
  const recipient = { keyId: reRegistered.record.keyId, publicKey: reRegistered.record.publicKey };
  const args = { pins, signer, memberId: 'member_c', recipient, vaultKeyVersion: 1, vaultKeyRaw: generateVaultKeyRaw() };
  await assert.rejects(createGrant(args), isCode('PUBLIC_KEY_MISMATCH'));
  // 照合し直して固定すれば作れる
  await pinPublicKey(pins, 'member_c', recipient);
  await createGrant({ ...args, vaultKeyRaw: generateVaultKeyRaw() });
});

// 攻撃者レビュー #2：サーバーが、公開鍵は固定値のままで、鍵ID だけを別の値にして返す。
// 通してしまうと、正しい鍵ID 宛てのグラントが作られず、C さんは開けない（承認が気づかれずに失敗する）。
test('P-01 公開鍵が固定値と同じでも、鍵ID が固定した値と違えばグラントを作らない（攻撃者レビュー #2）', async () => {
  const memberC = await createMemberKey('c-san-kawa-mori-yama-18');
  const pins = new MemoryPinStore();
  await pinPublicKey(pins, 'member_c', { keyId: memberC.record.keyId, publicKey: memberC.record.publicKey });
  await assert.rejects(
    createGrant({
      pins,
      signer,
      memberId: 'member_c',
      recipient: { keyId: 'key_attacker', publicKey: memberC.record.publicKey },
      vaultKeyVersion: 1,
      vaultKeyRaw: generateVaultKeyRaw(),
    }),
    isCode('PUBLIC_KEY_MISMATCH'),
  );
});

// 攻撃者レビュー #4：「照合なしで包む関数を export しない」を、ソースの文字列ではなく、読み込んだモジュールの中身で確かめる。
// 別名を付けて export しても（export { sealGrant as createGrantInner } など）、ここで見つかる。
// 開く側の関数は、署名を確かめてから開くものだけ（署名を確かめない開封の入口を作らない）。
test('P-01 grant.ts が export する関数は、照合してから包む createGrant と、署名を確かめて開く関数と、中身を組み立てる関数だけ', async () => {
  const grant = await import('../../src/crypto/grant.ts');
  const functions = Object.entries(grant).filter(([, v]) => typeof v === 'function').map(([k]) => k).sort();
  // openGrantForQuickUnlock も、署名を確かめてから開く（仕様書「鍵のライフサイクル」の Vault 鍵（クイックロック解除）。フェーズ2b）
  assert.deepEqual(functions, ['createGrant', 'grantInfo', 'grantSignedMessage', 'openGrant', 'openGrantForAdmin', 'openGrantForQuickUnlock']);
});
