import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { fromHex, toBase64Url, toHex, type Bytes } from '../../src/crypto/bytes.ts';
import { hkdfExpand, hkdfExtract } from '../../src/crypto/hkdf.ts';
import {
  AEAD_AES_128_GCM,
  AEAD_AES_256_GCM,
  encapWithEphemeral,
  keyScheduleBase,
  setupBaseR,
  setupBaseSWithEphemeral,
  type AeadId,
} from '../../src/crypto/hpke-core.ts';
import { openBase, sealBase } from '../../src/crypto/hpke.ts';

const subtle = crypto.subtle;
const ECDH_P256 = { name: 'ECDH', namedCurve: 'P-256' } as const;

// RFC 5869 付録 A.1、A.3。自前で組んだ Extract と Expand に当てる。
test('C-01 自前の HKDF Extract と Expand が RFC 5869 のテストベクタと一致する', async () => {
  const ikm = new Uint8Array(22).fill(0x0b);
  const prk1 = await hkdfExtract(fromHex('000102030405060708090a0b0c'), ikm);
  assert.equal(toHex(prk1), '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5');
  assert.equal(
    toHex(await hkdfExpand(prk1, fromHex('f0f1f2f3f4f5f6f7f8f9'), 42)),
    '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
  );
  // A.3：ソルトと info が空
  const prk3 = await hkdfExtract(new Uint8Array(0), ikm);
  assert.equal(toHex(prk3), '19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04');
  assert.equal(
    toHex(await hkdfExpand(prk3, new Uint8Array(0), 42)),
    '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8',
  );
});

type Vector = {
  info: string;
  skRm: string;
  skEm: string;
  pkRm: string;
  pkEm: string;
  enc: string;
  shared_secret: string;
  key_schedule_context: string;
  secret: string;
  key: string;
  base_nonce: string;
  encryptions: { aad: string; ct: string; nonce: string; pt: string }[];
};

function loadVector(name: string): Vector {
  const url = new URL(`../vectors/.cache/${name}`, import.meta.url);
  if (!existsSync(url)) {
    assert.fail(`HPKE のテストベクタがありません。先に npm run vectors:fetch を実行してください（tests/vectors/README.md）`);
  }
  return (JSON.parse(readFileSync(url, 'utf8')) as { vector: Vector }).vector;
}

// テストベクタの秘密鍵を、対応する公開鍵の x、y と一緒に JWK で WebCrypto に読み込む（点の計算はしない）
async function importPrivate(skHex: string, pkHex: string): Promise<CryptoKey> {
  const pk = fromHex(pkHex);
  return subtle.importKey(
    'jwk',
    {
      kty: 'EC',
      crv: 'P-256',
      d: toBase64Url(fromHex(skHex)),
      x: toBase64Url(pk.slice(1, 33)),
      y: toBase64Url(pk.slice(33, 65)),
    },
    ECDH_P256,
    false,
    ['deriveBits'],
  );
}

async function ephemeralFrom(v: Vector): Promise<CryptoKeyPair> {
  return {
    privateKey: await importPrivate(v.skEm, v.pkEm),
    publicKey: await subtle.importKey('raw', fromHex(v.pkEm), ECDH_P256, true, []),
  };
}

async function checkVector(name: string, aead: AeadId) {
  const v = loadVector(name);
  const pkRm = fromHex(v.pkRm);
  const info = fromHex(v.info);

  // KEM（Encap）
  const ephemeral = await ephemeralFrom(v);
  const { sharedSecret, enc } = await encapWithEphemeral(pkRm, ephemeral);
  assert.equal(toHex(enc), v.enc, 'enc');
  assert.equal(toHex(sharedSecret), v.shared_secret, 'shared_secret');

  // 鍵スケジュール
  const ks = await keyScheduleBase(aead, sharedSecret, info);
  assert.equal(toHex(ks.keyScheduleContext), v.key_schedule_context, 'key_schedule_context');
  assert.equal(toHex(ks.secret), v.secret, 'secret');
  assert.equal(toHex(ks.key), v.key, 'key');
  assert.equal(toHex(ks.baseNonce), v.base_nonce, 'base_nonce');

  // 送り手：シーケンス番号を進めながら、すべての暗号文が一致する
  const sender = await setupBaseSWithEphemeral(aead, pkRm, info, await ephemeralFrom(v));
  assert.equal(toHex(sender.enc), v.enc);
  for (const [i, e] of v.encryptions.entries()) {
    assert.equal(toHex(await sender.context.seal(fromHex(e.aad), fromHex(e.pt))), e.ct, `seal seq=${i}`);
  }

  // 受け手：同じ暗号文を順に開ける
  const skR = await importPrivate(v.skRm, v.pkRm);
  const receiver = await setupBaseR(aead, fromHex(v.enc), skR, pkRm, info);
  for (const [i, e] of v.encryptions.entries()) {
    assert.equal(toHex(await receiver.open(fromHex(e.aad), fromHex(e.ct))), e.pt, `open seq=${i}`);
  }
  return { v, skR, pkRm, info };
}

test('C-15 HPKE が RFC 9180 の公開テストベクタと一致する（Base、KEM 0x0010・KDF 0x0001・AEAD 0x0002）', async () => {
  const { v, skR, pkRm, info } = await checkVector('hpke-base-p256-sha256-aes256gcm.json', AEAD_AES_256_GCM);
  assert.ok(v.encryptions.length > 1);
  // 本番の入口（openBase）でも、シーケンス番号0の暗号文を開ける
  const e0 = v.encryptions[0]!;
  assert.equal(toHex(await openBase(skR, pkRm, fromHex(v.enc), info, fromHex(e0.aad), fromHex(e0.ct))), e0.pt);
});

test('C-15 HPKE が RFC 9180 付録 A.3 の組（AEAD 0x0001）のテストベクタと一致する', async () => {
  await checkVector('hpke-base-p256-sha256-aes128gcm.json', AEAD_AES_128_GCM);
});

test('本番の sealBase は毎回新しい使い捨て鍵ペアを作る', async () => {
  const r = await subtle.generateKey(ECDH_P256, false, ['deriveBits']);
  const pkRm = new Uint8Array(await subtle.exportKey('raw', r.publicKey)) as Bytes;
  const info = new Uint8Array([1, 2, 3]);
  const pt = new Uint8Array(32).fill(5);
  const a = await sealBase(pkRm, info, new Uint8Array(0), pt);
  const b = await sealBase(pkRm, info, new Uint8Array(0), pt);
  assert.notDeepEqual(a.enc, b.enc);
  assert.notDeepEqual(a.ct, b.ct);
  assert.deepEqual(await openBase(r.privateKey, pkRm, a.enc, info, new Uint8Array(0), a.ct), pt);
});
