// RFC 9180（HPKE）Base モードの中身。DHKEM(P-256, HKDF-SHA256)、HKDF-SHA256、AES-GCM。
//
// このファイルは、使い捨て鍵ペアを引数で受け取る関数（setupBaseSWithEphemeral）を持つ。
// テストベクタを確かめるために必要な口なので、本番の経路からは使わせない。
// src の中でこのファイルを import してよいのは src/crypto/hpke.ts だけ（tests/crypto/guard.test.ts で検査する）。
// hpke.ts は、使い捨て鍵ペアを必ず内部で生成してから、ここを呼ぶ。
// この口をテスト専用のファイルへ移すと、テストベクタで確かめる処理と本番の処理が別の関数になる。
// 同じ関数を通すことを優先して、ここに置いたままにする（攻撃者レビュー #4）。

import { concat, i2osp, utf8, wipe, type Bytes } from './bytes.ts';
import { hkdfExpand, hkdfExtract } from './hkdf.ts';
import { importPublicKey } from './public-key.ts';

export const KEM_P256_HKDF_SHA256 = 0x0010;
export const KDF_HKDF_SHA256 = 0x0001;
export const AEAD_AES_128_GCM = 0x0001;
export const AEAD_AES_256_GCM = 0x0002;
export type AeadId = typeof AEAD_AES_128_GCM | typeof AEAD_AES_256_GCM;

const NK: Record<AeadId, number> = { [AEAD_AES_128_GCM]: 16, [AEAD_AES_256_GCM]: 32 };
const NN = 12; // ノンスの長さ
const NH = 32; // HKDF-SHA256 の出力長
const N_SECRET = 32; // DHKEM(P-256) の共有秘密の長さ
const MODE_BASE = 0x00;

const HPKE_V1 = utf8('HPKE-v1');
const EMPTY: Bytes = new Uint8Array(0);

// suite_id。KEM の中では "KEM" || I2OSP(kem_id, 2)、鍵スケジュールでは "HPKE" || kem_id || kdf_id || aead_id
const KEM_SUITE_ID = concat(utf8('KEM'), i2osp(KEM_P256_HKDF_SHA256, 2));
function hpkeSuiteId(aead: AeadId): Bytes {
  return concat(utf8('HPKE'), i2osp(KEM_P256_HKDF_SHA256, 2), i2osp(KDF_HKDF_SHA256, 2), i2osp(aead, 2));
}

// LabeledExtract(salt, label, ikm) = Extract(salt, "HPKE-v1" || suite_id || label || ikm)
function labeledExtract(suiteId: Bytes, salt: Bytes, label: string, ikm: Bytes): Promise<Bytes> {
  return hkdfExtract(salt, concat(HPKE_V1, suiteId, utf8(label), ikm));
}

// LabeledExpand(prk, label, info, L) = Expand(prk, I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info, L)
function labeledExpand(suiteId: Bytes, prk: Bytes, label: string, info: Bytes, length: number): Promise<Bytes> {
  return hkdfExpand(prk, concat(i2osp(length, 2), HPKE_V1, suiteId, utf8(label), info), length);
}

// DH は WebCrypto の ECDH。結果は共有点の x 座標32バイト（RFC 9180 の P-256 の DH と同じ）。
async function dh(privateKey: CryptoKey, publicKeyRaw: Bytes): Promise<Bytes> {
  const publicKey = await importPublicKey(publicKeyRaw);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256));
}

async function extractAndExpand(dhValue: Bytes, kemContext: Bytes): Promise<Bytes> {
  const eaePrk = await labeledExtract(KEM_SUITE_ID, EMPTY, 'eae_prk', dhValue);
  try {
    return await labeledExpand(KEM_SUITE_ID, eaePrk, 'shared_secret', kemContext, N_SECRET);
  } finally {
    wipe(eaePrk);
  }
}

// Encap：使い捨て鍵ペア（skE, pkE）と受け手の公開鍵 pkR から、共有秘密と enc（= pkE の65バイト）を作る。
export async function encapWithEphemeral(
  pkRm: Bytes,
  ephemeral: CryptoKeyPair,
): Promise<{ sharedSecret: Bytes; enc: Bytes }> {
  const enc = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeral.publicKey));
  const dhValue = await dh(ephemeral.privateKey, pkRm);
  try {
    const sharedSecret = await extractAndExpand(dhValue, concat(enc, pkRm));
    return { sharedSecret, enc };
  } finally {
    wipe(dhValue);
  }
}

// Decap：受け手の秘密鍵 skR と enc から、同じ共有秘密を作る。kem_context には受け手自身の公開鍵 pkRm も入る。
export async function decap(enc: Bytes, skR: CryptoKey, pkRm: Bytes): Promise<Bytes> {
  const dhValue = await dh(skR, enc);
  try {
    return await extractAndExpand(dhValue, concat(enc, pkRm));
  } finally {
    wipe(dhValue);
  }
}

export type KeyScheduleOutput = {
  keyScheduleContext: Bytes;
  secret: Bytes;
  key: Bytes;
  baseNonce: Bytes;
};

// KeySchedule（Base モード：psk と psk_id は空）
export async function keyScheduleBase(aead: AeadId, sharedSecret: Bytes, info: Bytes): Promise<KeyScheduleOutput> {
  const suiteId = hpkeSuiteId(aead);
  const pskIdHash = await labeledExtract(suiteId, EMPTY, 'psk_id_hash', EMPTY);
  const infoHash = await labeledExtract(suiteId, EMPTY, 'info_hash', info);
  const keyScheduleContext = concat(new Uint8Array([MODE_BASE]), pskIdHash, infoHash);
  const secret = await labeledExtract(suiteId, sharedSecret, 'secret', EMPTY);
  const key = await labeledExpand(suiteId, secret, 'key', keyScheduleContext, NK[aead]);
  const baseNonce = await labeledExpand(suiteId, secret, 'base_nonce', keyScheduleContext, NN);
  return { keyScheduleContext, secret, key, baseNonce };
}

// 暗号化の文脈。ノンスは base_nonce XOR I2OSP(seq, Nn) で、シーケンス番号から作る（乱数のノンスは持たない）。
export class HpkeContext {
  readonly #key: CryptoKey;
  readonly #baseNonce: Bytes;
  #seq = 0;

  constructor(key: CryptoKey, baseNonce: Bytes) {
    this.#key = key;
    this.#baseNonce = baseNonce;
  }

  #nonce(): Bytes {
    const seq = i2osp(this.#seq, NN);
    const nonce = new Uint8Array(NN);
    for (let i = 0; i < NN; i++) nonce[i] = this.#baseNonce[i]! ^ seq[i]!;
    return nonce;
  }

  async seal(aad: Bytes, plaintext: Bytes): Promise<Bytes> {
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: this.#nonce(), additionalData: aad }, this.#key, plaintext);
    this.#seq += 1;
    return new Uint8Array(ct);
  }

  async open(aad: Bytes, ciphertext: Bytes): Promise<Bytes> {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: this.#nonce(), additionalData: aad }, this.#key, ciphertext);
    this.#seq += 1;
    return new Uint8Array(pt);
  }
}

async function contextFromSchedule(schedule: KeyScheduleOutput): Promise<HpkeContext> {
  try {
    const key = await crypto.subtle.importKey('raw', schedule.key, 'AES-GCM', false, ['encrypt', 'decrypt']);
    return new HpkeContext(key, schedule.baseNonce);
  } finally {
    wipe(schedule.key);
    wipe(schedule.secret);
  }
}

// SetupBaseS。使い捨て鍵ペアを引数で受け取る（テストベクタ用の口。本番は hpke.ts から、生成した鍵ペアでだけ呼ぶ）。
export async function setupBaseSWithEphemeral(
  aead: AeadId,
  pkRm: Bytes,
  info: Bytes,
  ephemeral: CryptoKeyPair,
): Promise<{ enc: Bytes; context: HpkeContext }> {
  const { sharedSecret, enc } = await encapWithEphemeral(pkRm, ephemeral);
  try {
    return { enc, context: await contextFromSchedule(await keyScheduleBase(aead, sharedSecret, info)) };
  } finally {
    wipe(sharedSecret);
  }
}

// SetupBaseR
export async function setupBaseR(aead: AeadId, enc: Bytes, skR: CryptoKey, pkRm: Bytes, info: Bytes): Promise<HpkeContext> {
  const sharedSecret = await decap(enc, skR, pkRm);
  try {
    return await contextFromSchedule(await keyScheduleBase(aead, sharedSecret, info));
  } finally {
    wipe(sharedSecret);
  }
}
