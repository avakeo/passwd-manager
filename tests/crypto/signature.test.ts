// 管理者署名（docs/設計案_グラントの送り手認証.md）。
// 受け手は、固定した管理者の署名用公開鍵で署名を確かめてからグラントを開く。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createVerify, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { concat, fromHex, i2osp, toBase64Url, toHex, utf8 } from '../../src/crypto/bytes.ts';
import { createAdminKey, createMemberKey, unlockAdminKey, type AdminKeyRecord } from '../../src/crypto/member-key.ts';
import {
  createGrant,
  grantSignedMessage,
  openGrant,
  openGrantForAdmin,
  type Grant,
  type GrantSigner,
  type GrantTrust,
  type OwnKey,
} from '../../src/crypto/grant.ts';
import { decryptItem, encryptItem } from '../../src/crypto/item.ts';
import { generateVaultKeyRaw, importVaultKey } from '../../src/crypto/vault-key.ts';
import { ALG_ECDSA_P256_SHA256, FORMAT_V1 } from '../../src/crypto/format.ts';
import { CryptoError } from '../../src/crypto/errors.ts';
import { MemoryPinStore, pinPublicKey } from '../../src/crypto/public-key.ts';
import { newTrust, served } from '../helpers/trust.ts';
import { pinSigner as pinSignerForAdmin } from '../../src/crypto/signer.ts';
import {
  assertSignerPinned,
  importSignPublicKey,
  pinSigner,
  verifySignature,
} from '../../src/crypto/signer.ts';

const ADMIN_PASSWORD = 'admin-hoshi-sora-umi-42';
const C_PASSWORD = 'c-san-kawa-mori-yama-18';

function isCode(code: string) {
  return (e: unknown) => e instanceof CryptoError && e.code === code;
}

// 鍵は一度だけ作る（PBKDF2 が重いので）
const admin = await createAdminKey(ADMIN_PASSWORD);
const attacker = await createAdminKey('attacker-kuro-yami-99x-zz');
const memberC = await createMemberKey(C_PASSWORD);

const ADMIN_ID = 'member_admin';
const C_ID = 'member_c';

const adminPin = { memberId: ADMIN_ID, keyId: admin.record.keyId, publicKey: admin.record.signPublicKey };
// 管理者の端末：自分の組を固定し、世代1で初期化済み
const adminTrust = newTrust(ADMIN_ID);
await pinSignerForAdmin(adminTrust, adminPin, 1);

const adminSigner: GrantSigner = { memberId: ADMIN_ID, keyId: admin.record.keyId, privateKey: admin.signPrivateKey, trust: adminTrust };
// 攻撃者（乗っ取られたサーバー）は管理者の名前と鍵ID を名乗れるが、管理者の署名鍵は持たない
const attackerSigner: GrantSigner = { memberId: ADMIN_ID, keyId: admin.record.keyId, privateKey: attacker.signPrivateKey, trust: adminTrust };

// 管理者の端末：C さんと自分の ECDH の公開鍵を固定済み
const pins = new MemoryPinStore();
await pinPublicKey(pins, C_ID, { keyId: memberC.record.keyId, publicKey: memberC.record.publicKey });
await pinPublicKey(pins, ADMIN_ID, { keyId: admin.record.keyId, publicKey: admin.record.publicKey });

function cOwn(): OwnKey {
  return { memberId: C_ID, keyId: memberC.record.keyId, publicKey: memberC.record.publicKey, privateKey: memberC.privateKey };
}

function adminOwn(): OwnKey {
  return { memberId: ADMIN_ID, keyId: admin.record.keyId, publicKey: admin.record.publicKey, privateKey: admin.privateKey };
}

// 照合を済ませた端末の信頼の状態（管理者の署名鍵を固定、最後に見た世代はまだない）
async function trusted(): Promise<GrantTrust> {
  const t = newTrust(C_ID);
  await pinSigner(t, adminPin, 1);
  return t;
}

function grantToC(signer: GrantSigner, vaultKeyVersion: number, vaultKeyRaw = generateVaultKeyRaw()) {
  return createGrant({
    pins,
    signer,
    memberId: C_ID,
    recipient: { keyId: memberC.record.keyId, publicKey: memberC.record.publicKey },
    vaultKeyVersion,
    vaultKeyRaw,
  });
}

test('署名付きのグラントを、管理者の署名鍵を固定した C さんが開ける', async () => {
  const raw = generateVaultKeyRaw();
  const grant = await grantToC(adminSigner, 1, raw.slice());
  assert.equal(grant.signerKeyId, admin.record.keyId);
  assert.equal(grant.signature.length, 66);
  assert.equal(grant.signature[0], FORMAT_V1);
  assert.equal(grant.signature[1], ALG_ECDSA_P256_SHA256);
  const trust = await trusted();
  const vaultKey = await openGrant(cOwn(), trust, ...served(grant));
  const ctx = { itemId: 'item_sig', vaultKeyVersion: 1 };
  const env = await encryptItem(await importVaultKey(raw), ctx, { type: 'note', title: 't', body: 'b' });
  assert.deepEqual(await decryptItem(vaultKey, ctx, env), { type: 'note', title: 't', body: 'b' });
  assert.equal(await trust.generations.get(), 1, '最後に見た世代が記録される');
});

test('C-17 署名のないグラント（空、長さ違い、形式やアルゴリズムIDが違う署名）は開かずに拒否される', async () => {
  const grant = await grantToC(adminSigner, 1);
  const variants: [string, Uint8Array<ArrayBuffer>][] = [
    ['空', new Uint8Array(0)],
    ['署名本体だけ（ヘッダーなし）', grant.signature.slice(2)],
    ['1バイト短い', grant.signature.slice(0, 65)],
    ['形式が 0x02', concat(new Uint8Array([0x02]), grant.signature.slice(1))],
    ['アルゴリズムIDが HPKE（0x02）', concat(new Uint8Array([FORMAT_V1, 0x02]), grant.signature.slice(2))],
    ['アルゴリズムIDが AES-GCM（0x01）', concat(new Uint8Array([FORMAT_V1, 0x01]), grant.signature.slice(2))],
  ];
  for (const [name, signature] of variants) {
    await assert.rejects(openGrant(cOwn(), await trusted(), ...served({ ...grant, signature })), isCode('SIGNATURE_INVALID'), name);
  }
});

// 攻撃者レビュー #1 の再現：乗っ取られたサーバーは、C さんの公開鍵（公開情報）だけから偽のグラントを作れる。
// 管理者の名前と鍵ID を名乗って自分の署名鍵で署名しても、C さんの端末は固定した管理者の公開鍵で確かめるので通らない。
test('C-18 固定した管理者の鍵とは別の鍵で署名した偽グラントは開かずに拒否され、偽の Vault 鍵は使われない（攻撃者レビュー #1）', async () => {
  const attackerPins = new MemoryPinStore();
  await pinPublicKey(attackerPins, C_ID, { keyId: memberC.record.keyId, publicKey: memberC.record.publicKey });
  const evilVaultKeyRaw = generateVaultKeyRaw();
  const evilGrant = await createGrant({
    pins: attackerPins,
    signer: attackerSigner,
    memberId: C_ID,
    recipient: { keyId: memberC.record.keyId, publicKey: memberC.record.publicKey },
    vaultKeyVersion: 2, // 新しい世代を名乗る
    vaultKeyRaw: evilVaultKeyRaw.slice(),
  });
  const trust = await trusted();
  let vaultKey: CryptoKey | undefined;
  await assert.rejects(
    (async () => {
      vaultKey = await openGrant(cOwn(), trust, ...served(evilGrant));
    })(),
    isCode('SIGNATURE_INVALID'),
  );
  assert.equal(vaultKey, undefined, '偽の Vault 鍵は手に入らない');
  assert.equal(await trust.generations.get(), 1, '偽のグラントで世代の記録は進まない');

  // 署名を外して、署名のない（提出版の）形で差し替えても通らない
  await assert.rejects(openGrant(cOwn(), trust, ...served({ ...evilGrant, signature: new Uint8Array(0) })), isCode('SIGNATURE_INVALID'));
  // 本物のグラントの署名を偽グラントに付け替えても通らない（署名の対象に enc と wrapped_key が入っている）
  const real = await grantToC(adminSigner, 1);
  await assert.rejects(openGrant(cOwn(), trust, ...served({ ...evilGrant, signature: real.signature })), isCode('SIGNATURE_INVALID'));
});

test('C-19 署名の対象のフィールドを1つずつ書き換えたグラントは、どれも開かずに拒否される', async () => {
  const grant = await grantToC(adminSigner, 3);
  const flip = (b: Uint8Array<ArrayBuffer>, i: number) => {
    const c = b.slice();
    c[i]! ^= 1;
    return c;
  };
  // 宛先のメンバーID と公開鍵は、受け手が自分の値から組み立てる。サーバーが「自分の値」を偽った場合を見る。
  const otherPublicKey = (await createMemberKey('other-member-hikari-55')).record.publicKey;
  const cases: [string, Grant, OwnKey, string][] = [
    ['署名者の鍵ID', { ...grant, signerKeyId: 'key_other_admin' }, cOwn(), 'SIGNER_MISMATCH'],
    ['世代', { ...grant, vaultKeyVersion: 4 }, cOwn(), 'SIGNATURE_INVALID'],
    ['宛先の鍵ID', { ...grant, recipientKeyId: 'key_other' }, { ...cOwn(), keyId: 'key_other' }, 'SIGNATURE_INVALID'],
    ['宛先のメンバーID', grant, { ...cOwn(), memberId: 'member_other' }, 'SIGNATURE_INVALID'],
    ['宛先の公開鍵', grant, { ...cOwn(), publicKey: otherPublicKey }, 'SIGNATURE_INVALID'],
    ['enc', { ...grant, ephemeralPublicKey: flip(grant.ephemeralPublicKey, 40) }, cOwn(), 'SIGNATURE_INVALID'],
    ['wrapped_key', { ...grant, wrappedKey: flip(grant.wrappedKey, 10) }, cOwn(), 'SIGNATURE_INVALID'],
    ['署名そのもの', { ...grant, signature: flip(grant.signature, 30) }, cOwn(), 'SIGNATURE_INVALID'],
  ];
  for (const [name, g, own, code] of cases) {
    await assert.rejects(openGrant(own, await trusted(), ...served(g)), isCode(code), name);
  }
  // 書き換えなければ開ける
  await openGrant(cOwn(), await trusted(), ...served(grant));
});

// 攻撃者レビュー #7 の再現：サーバーが「現在の世代」を古い値にし、古い世代の（本物の署名が付いた）グラントを返す。
test('C-20 最後に見た世代より古い世代の、正しく署名されたグラントは開かずに拒否される（攻撃者レビュー #7）', async () => {
  const oldGrant = await grantToC(adminSigner, 1);
  const newGrant = await grantToC(adminSigner, 2);
  const trust = await trusted();
  await openGrant(cOwn(), trust, ...served(oldGrant));
  await openGrant(cOwn(), trust, ...served(newGrant));
  assert.equal(await trust.generations.get(), 2);
  await assert.rejects(openGrant(cOwn(), trust, ...served(oldGrant)), isCode('STALE_GENERATION'));
  await assert.rejects(openGrantForAdmin(cOwn(), trust, ...served(oldGrant)), isCode('STALE_GENERATION'));
  // 同じ世代はもう一度開ける（Service Worker の再起動など）
  await openGrant(cOwn(), trust, ...served(newGrant));
  assert.equal(await trust.generations.get(), 2);
});

// 攻撃者レビュー #3 と同じ考え方：サーバーが ecdsa_public_key だけを別の点に差し替える。
test('C-21 管理者の署名用公開鍵だけを差し替えた行では、署名鍵のロック解除に失敗する', async () => {
  const swapped: AdminKeyRecord = { ...admin.record, signPublicKey: attacker.record.signPublicKey };
  await assert.rejects(unlockAdminKey(ADMIN_PASSWORD, swapped), isCode('DECRYPT_FAILED'));
  // ECDH の秘密鍵の暗号文を署名鍵の列に移しても開けない（種別とラップ鍵が違う）
  const moved: AdminKeyRecord = { ...admin.record, encryptedSignPrivateKey: admin.record.encryptedPrivateKey };
  await assert.rejects(unlockAdminKey(ADMIN_PASSWORD, moved), isCode('DECRYPT_FAILED'));
  // 差し替えなければ開け、開いた署名鍵の署名は行の公開鍵で通る
  const unlocked = await unlockAdminKey(ADMIN_PASSWORD, admin.record);
  const grant = await grantToC({ ...adminSigner, privateKey: unlocked.signPrivateKey }, 1);
  await openGrant(cOwn(), await trusted(), ...served(grant));
});

test('C-16 ロック解除後の署名用秘密鍵は書き出せない（取り出し不可、用途は署名だけ）', async () => {
  const unlocked = await unlockAdminKey(ADMIN_PASSWORD, admin.record);
  for (const key of [admin.signPrivateKey, unlocked.signPrivateKey]) {
    assert.equal(key.extractable, false);
    assert.deepEqual(key.usages, ['sign']);
    await assert.rejects(crypto.subtle.exportKey('pkcs8', key));
    await assert.rejects(crypto.subtle.exportKey('jwk', key));
  }
  for (const key of [admin.privateKey, unlocked.privateKey]) {
    assert.equal(key.extractable, false);
    await assert.rejects(crypto.subtle.exportKey('pkcs8', key));
  }
});

type EcdsaTest = { tcId: number; comment: string; msg: string; sig: string; result: 'valid' | 'invalid' | 'acceptable' };
type EcdsaGroup = { publicKey: { uncompressed: string }; sha: string; tests: EcdsaTest[] };

test('C-22 ECDSA P-256（SHA-256、64バイトの署名）の Wycheproof のベクタで、valid は通り invalid は拒否される', async () => {
  const data = JSON.parse(
    readFileSync(new URL('../vectors/wycheproof/ecdsa_secp256r1_sha256_p1363_test.json', import.meta.url), 'utf8'),
  ) as { testGroups: EcdsaGroup[] };
  let valid = 0;
  let invalid = 0;
  for (const g of data.testGroups) {
    assert.equal(g.sha, 'SHA-256');
    const publicKey = await importSignPublicKey(fromHex(g.publicKey.uncompressed));
    for (const t of g.tests) {
      const ok = await verifySignature(publicKey, fromHex(t.sig), fromHex(t.msg));
      if (t.result === 'valid') {
        assert.equal(ok, true, `tcId ${t.tcId}: ${t.comment}`);
        valid += 1;
      } else {
        assert.equal(t.result, 'invalid');
        assert.equal(ok, false, `tcId ${t.tcId}: ${t.comment}`);
        invalid += 1;
      }
    }
  }
  assert.equal(valid, 169);
  assert.equal(invalid, 83);
});

// サーバーが管理者自身宛てのグラントを差し替えると、管理者は偽の Vault 鍵を自分の署名付きで全員に配ってしまう。
test('C-23 管理者自身宛てのグラントを別の鍵で署名したものに差し替えると、管理者の端末が開かずに拒否する', async () => {
  const evil = await createGrant({
    pins,
    signer: attackerSigner,
    memberId: ADMIN_ID,
    recipient: { keyId: admin.record.keyId, publicKey: admin.record.publicKey },
    vaultKeyVersion: 1,
    vaultKeyRaw: generateVaultKeyRaw(),
  });
  // 管理者の端末を初期化した後：ロック解除できた自分の行の署名用公開鍵を、自分の固定値として入れ直す
  const unlocked = await unlockAdminKey(ADMIN_PASSWORD, admin.record);
  const trust = newTrust(ADMIN_ID);
  await pinSigner(trust, adminPin, 1);
  const adminOwnUnlocked = { ...adminOwn(), privateKey: unlocked.privateKey };
  await assert.rejects(openGrantForAdmin(adminOwnUnlocked, trust, ...served(evil)), isCode('SIGNATURE_INVALID'));
  await assert.rejects(openGrant(adminOwnUnlocked, trust, ...served(evil)), isCode('SIGNATURE_INVALID'));

  // 本物の自分宛てのグラントは開け、管理操作で C さん宛てに包み直せる
  const raw = generateVaultKeyRaw();
  const real = await createGrant({
    pins,
    signer: adminSigner,
    memberId: ADMIN_ID,
    recipient: { keyId: admin.record.keyId, publicKey: admin.record.publicKey },
    vaultKeyVersion: 1,
    vaultKeyRaw: raw.slice(),
  });
  const reopened = await openGrantForAdmin(adminOwnUnlocked, trust, ...served(real));
  assert.deepEqual(reopened, raw);
  const toC = await grantToC({ ...adminSigner, privateKey: unlocked.signPrivateKey }, 1, reopened);
  reopened.fill(0);
  await openGrant(cOwn(), await trusted(), ...served(toC));
});

test('P-04 管理者の署名用公開鍵を固定する前は、本物のグラントでも開かず、照合を求める', async () => {
  const grant = await grantToC(adminSigner, 1);
  const trust = newTrust(C_ID);
  await assert.rejects(openGrant(cOwn(), trust, ...served(grant)), isCode('SIGNER_NOT_PINNED'));
  await assert.rejects(openGrantForAdmin(cOwn(), trust, ...served(grant)), isCode('SIGNER_NOT_PINNED'));
  // 照合して固定すれば開ける
  await pinSigner(trust, adminPin, 1);
  await openGrant(cOwn(), trust, ...served(grant));
});

test('P-05 固定した後に、サーバーが管理者の署名用公開鍵か鍵ID を差し替えると検知し、グラントを開かない', async () => {
  const trust = await trusted();
  // サーバーが /v1/me で返す管理者の鍵が、固定と違う
  await assert.rejects(
    assertSignerPinned(trust, { ...adminPin, publicKey: attacker.record.signPublicKey }),
    isCode('SIGNER_MISMATCH'),
  );
  await assert.rejects(assertSignerPinned(trust, { ...adminPin, keyId: 'key_attacker' }), isCode('SIGNER_MISMATCH'));
  await assert.rejects(assertSignerPinned(trust, { ...adminPin, memberId: 'member_attacker' }), isCode('SIGNER_MISMATCH'));
  await assertSignerPinned(trust, { ...adminPin, publicKey: adminPin.publicKey.slice() });
  await assert.rejects(assertSignerPinned(newTrust(C_ID), adminPin), isCode('SIGNER_NOT_PINNED'));

  // 攻撃者の鍵ID を名乗る、攻撃者の鍵で署名したグラント：鍵ID の時点で止まる
  const attackerTrust = newTrust('member_attacker');
  await pinSigner(attackerTrust, { memberId: ADMIN_ID, keyId: attacker.record.keyId, publicKey: attacker.record.signPublicKey }, 1);
  const evil = await grantToC({ ...attackerSigner, keyId: attacker.record.keyId, trust: attackerTrust }, 1);
  await assert.rejects(openGrant(cOwn(), trust, ...served(evil)), isCode('SIGNER_MISMATCH'));
  // 固定した後で呼び出し側の配列を書き換えても、固定値は変わらない
  const pin = { ...adminPin, publicKey: adminPin.publicKey.slice() };
  const store = newTrust(C_ID);
  await pinSigner(store, pin, 1);
  pin.publicKey[10]! ^= 1;
  await assertSignerPinned(store, adminPin);
});

test('固定できる管理者の署名用公開鍵は、曲線上の点で、ID の形が正しいものだけ', async () => {
  const bad = admin.record.signPublicKey.slice();
  bad[64]! ^= 1;
  await assert.rejects(pinSigner(newTrust(C_ID), { ...adminPin, publicKey: bad }, 1), isCode('INVALID_PUBLIC_KEY'));
  await assert.rejects(pinSigner(newTrust(C_ID), { ...adminPin, keyId: 'key|x' }, 1), isCode('INVALID_INPUT'));
  await assert.rejects(pinSigner(newTrust(C_ID), adminPin, 0), isCode('INVALID_INPUT'));
});

// 署名する中身の既知解テスト。期待値は src を使わず、設計案 3.1 の並びをここで組み立てる。
test('既知解 署名する中身は、ラベルと各フィールドを「長さ（2バイト）＋値」でつないだもの', () => {
  const field = (v: Uint8Array) => concat(fromHex(v.length.toString(16).padStart(4, '0')), v);
  const pkHash = fromHex('11'.repeat(32));
  const enc = fromHex('04' + '22'.repeat(64));
  const wrappedKey = fromHex('0102' + '33'.repeat(48));
  const expected = concat(
    field(utf8('teampw/v1/grant-signature')),
    field(new Uint8Array([0x01])),
    field(new Uint8Array([0x02])),
    field(utf8('member_admin')),
    field(utf8('key_A')),
    field(fromHex('0000000000000102')),
    field(utf8('member_c')),
    field(utf8('key_C')),
    field(pkHash),
    field(enc),
    field(wrappedKey),
  );
  const actual = grantSignedMessage({
    signerMemberId: 'member_admin',
    signerKeyId: 'key_A',
    vaultKeyVersion: 258,
    recipientMemberId: 'member_c',
    recipientKeyId: 'key_C',
    recipientPublicKeySha256: pkHash,
    ephemeralPublicKey: enc,
    wrappedKey,
  });
  assert.equal(toHex(actual), toHex(expected));
  assert.equal(toHex(actual).slice(0, 4 + 50), toHex(utf8('\u0000\u0019teampw/v1/grant-signature')));
  // 設計案 3.1 の例：鍵ID key_A（5文字）は 00 05 6b 65 79 5f 41
  assert.ok(toHex(actual).includes('00056b65795f41'));
  // 世代は8バイト
  assert.equal(toHex(i2osp(258, 8)), '0000000000000102');
});

test('既知解 グラントの署名は、src を使わずに node:crypto で、署名する中身と管理者の公開鍵から確かめられる', async () => {
  const grant = await grantToC(adminSigner, 7);
  const message = grantSignedMessage({
    signerMemberId: ADMIN_ID,
    signerKeyId: admin.record.keyId,
    vaultKeyVersion: 7,
    recipientMemberId: C_ID,
    recipientKeyId: memberC.record.keyId,
    recipientPublicKeySha256: new Uint8Array(await crypto.subtle.digest('SHA-256', memberC.record.publicKey)),
    ephemeralPublicKey: grant.ephemeralPublicKey,
    wrappedKey: grant.wrappedKey,
  });
  const pk = admin.record.signPublicKey;
  const key = createPublicKey({
    key: { kty: 'EC', crv: 'P-256', x: toBase64Url(pk.slice(1, 33)), y: toBase64Url(pk.slice(33, 65)) },
    format: 'jwk',
  });
  const verifier = createVerify('SHA256');
  verifier.update(message);
  assert.equal(verifier.verify({ key, dsaEncoding: 'ieee-p1363' }, grant.signature.slice(2)), true);
});

// DeepSeek #2：サーバーは /v1/vault で「今の世代は7」と答えつつ、グラントの行には古い世代5の本物のグラントを入れる。
// 利用者は最新を使っていると思い込み、新しいアイテムを古い鍵で暗号化してしまう。
test('C-24 サーバーが返す今の世代とグラントの世代が食い違うと、本物のグラントでも開かずに止める（DeepSeek #2）', async () => {
  const grant = await grantToC(adminSigner, 5);
  for (const current of [7, 4, 6]) {
    await assert.rejects(openGrant(cOwn(), await trusted(), grant, current), isCode('GENERATION_MISMATCH'), `今の世代 ${current}`);
    await assert.rejects(openGrantForAdmin(cOwn(), await trusted(), grant, current), isCode('GENERATION_MISMATCH'), `今の世代 ${current}`);
  }
  const trust = await trusted();
  await openGrant(cOwn(), trust, grant, 5);
  assert.equal(await trust.generations.get(), 5);
});
