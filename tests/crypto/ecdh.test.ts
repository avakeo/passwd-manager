import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { concat, fromHex, toHex } from '../../src/crypto/bytes.ts';
import { MemoryPinStore, importPublicKey, pinPublicKey } from '../../src/crypto/public-key.ts';
import { createGrant } from '../../src/crypto/grant.ts';
import { CryptoError } from '../../src/crypto/errors.ts';
import { generateVaultKeyRaw } from '../../src/crypto/vault-key.ts';
import { pinSigner } from '../../src/crypto/signer.ts';
import { newTrust } from '../helpers/trust.ts';

type WycheproofTest = { tcId: number; comment: string; public: string; private: string; shared: string; result: string };

const data = JSON.parse(
  readFileSync(new URL('../vectors/wycheproof/ecdh_secp256r1_ecpoint_test.json', import.meta.url), 'utf8'),
) as { testGroups: { tests: WycheproofTest[] }[] };
const cases = data.testGroups.flatMap((g) => g.tests);

// Wycheproof の秘密鍵（先頭に 00 が付いたり短かったりする整数）を、公開鍵なしの PKCS#8 にして読み込む。
// DER の組み立てはただのエンコードで、点の計算は WebCrypto が行う。
async function importWycheproofPrivate(hex: string): Promise<CryptoKey> {
  const d = fromHex(BigInt(`0x${hex || '0'}`).toString(16).padStart(64, '0'));
  const prefix = fromHex('3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420');
  return crypto.subtle.importKey('pkcs8', concat(prefix, d), { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
}

async function sharedSecret(t: WycheproofTest): Promise<string> {
  const publicKey = await importPublicKey(fromHex(t.public));
  const privateKey = await importWycheproofPrivate(t.private);
  return toHex(new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256)));
}

test('C-12 曲線上にない点などの不正な公開鍵（Wycheproof の invalid）は拒否される', async () => {
  const invalid = cases.filter((t) => t.result === 'invalid');
  assert.equal(invalid.length, 24);
  for (const t of invalid) {
    await assert.rejects(
      importPublicKey(fromHex(t.public)),
      (e: unknown) => e instanceof CryptoError && e.code === 'INVALID_PUBLIC_KEY',
      `tcId ${t.tcId}: ${t.comment}`,
    );
  }
});

test('C-12 Wycheproof の valid は受け入れられ、共有秘密が一致する', async () => {
  const valid = cases.filter((t) => t.result === 'valid');
  assert.equal(valid.length, 330);
  for (const t of valid) assert.equal(await sharedSecret(t), t.shared, `tcId ${t.tcId}: ${t.comment}`);
});

test('C-12 圧縮形式の公開鍵（Wycheproof の acceptable）は、非圧縮だけを受け付ける方針で拒否する', async () => {
  for (const t of cases.filter((x) => x.result === 'acceptable')) {
    await assert.rejects(importPublicKey(fromHex(t.public)), `tcId ${t.tcId}`);
  }
});

test('C-12 不正な公開鍵は固定できず、宛先にしたグラントも作らない', async () => {
  const notOnCurve = fromHex(cases.find((t) => t.result === 'invalid' && t.public.length === 130)!.public);
  const pins = new MemoryPinStore();
  const isInvalid = (e: unknown) => e instanceof CryptoError && e.code === 'INVALID_PUBLIC_KEY';
  await assert.rejects(pinPublicKey(pins, 'member_bad', { keyId: 'key_bad', publicKey: notOnCurve }), isInvalid);
  // 固定の保存先が壊れて不正な値が入っていても、包む前の読み込みで拒否する
  await pins.set('member_bad', { keyId: 'key_bad', publicKey: notOnCurve });
  const signPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const signKey = signPair.privateKey;
  const trust = newTrust('member_admin');
  await pinSigner(trust, { memberId: 'member_admin', keyId: 'key_admin', publicKey: new Uint8Array(await crypto.subtle.exportKey('raw', signPair.publicKey)) }, 1);
  await assert.rejects(
    createGrant({
      pins,
      signer: { memberId: 'member_admin', keyId: 'key_admin', privateKey: signKey, trust },
      memberId: 'member_bad',
      recipient: { keyId: 'key_bad', publicKey: notOnCurve },
      vaultKeyVersion: 1,
      vaultKeyRaw: generateVaultKeyRaw(),
    }),
    isInvalid,
  );
});
