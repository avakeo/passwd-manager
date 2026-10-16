// 管理者署名の検証側：管理者の署名用公開鍵の固定、最後に見た世代の記録、ECDSA の署名と検証。
// 仕様書「暗号仕様 > 管理者の署名鍵ペア」、docs/設計案_グラントの送り手認証.md の4章。

import { equalBytes, type Bytes } from './bytes.ts';
import { CryptoError } from './errors.ts';
import { SIGNATURE_LENGTH, assertId, assertVersion } from './format.ts';
import { PUBLIC_KEY_LENGTH } from './public-key.ts';

const ECDSA_P256 = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const ECDSA_SHA256 = { name: 'ECDSA', hash: 'SHA-256' } as const;

// サーバーから来た管理者の署名用公開鍵を読み込む。受け付けるのは非圧縮形式の65バイトだけ。
// 曲線上にあるかの検査は WebCrypto に任せる。検証にしか使わないので取り出し不可にする。
export async function importSignPublicKey(raw: Bytes): Promise<CryptoKey> {
  if (!(raw instanceof Uint8Array) || raw.length !== PUBLIC_KEY_LENGTH || raw[0] !== 0x04) {
    throw new CryptoError('INVALID_PUBLIC_KEY');
  }
  try {
    return await crypto.subtle.importKey('raw', raw, ECDSA_P256, false, ['verify']);
  } catch {
    throw new CryptoError('INVALID_PUBLIC_KEY');
  }
}

// 署名は WebCrypto に任せる（ノンス k も WebCrypto の内部で作られる）。返すのは IEEE P1363 の64バイト。
export async function signMessage(privateKey: CryptoKey, message: Bytes): Promise<Bytes> {
  const signature = new Uint8Array(await crypto.subtle.sign(ECDSA_SHA256, privateKey, message));
  if (signature.length !== SIGNATURE_LENGTH) throw new CryptoError('INVALID_INPUT');
  return signature;
}

// 通るかどうかだけを返す。ECDSA の署名は一意でないので、署名を ID や重複の判定には使わない。
export async function verifySignature(publicKey: CryptoKey, signature: Bytes, message: Bytes): Promise<boolean> {
  if (signature.length !== SIGNATURE_LENGTH) return false;
  try {
    return await crypto.subtle.verify(ECDSA_SHA256, publicKey, signature, message);
  } catch {
    return false;
  }
}

// メンバーの端末が固定する、管理者の「メンバーID、鍵ID、署名用公開鍵」の組。
export type SignerPin = {
  memberId: string;
  keyId: string;
  publicKey: Bytes;
};

// 管理者は1人なので、固定するのは1組だけ。提出版と同じくインターフェースだけを置き、拡張機能で chrome.storage.local に差し替える。
export interface SignerPinStore {
  get(): Promise<SignerPin | undefined>;
  set(pin: SignerPin): Promise<void>;
}

function copyPin(pin: SignerPin): SignerPin {
  return { memberId: pin.memberId, keyId: pin.keyId, publicKey: pin.publicKey.slice() };
}

export class MemorySignerPinStore implements SignerPinStore {
  #pin: SignerPin | undefined;

  async get(): Promise<SignerPin | undefined> {
    return this.#pin && copyPin(this.#pin);
  }

  async set(pin: SignerPin): Promise<void> {
    this.#pin = copyPin(pin);
  }
}

// 承認のとき、Discord 以外の経路で管理者の画面と見比べて一致した組だけを固定する。
// 管理者自身の端末は、ロック解除できた自分の行の値を固定する（AAD に公開鍵の SHA-256 が入っているので、差し替えた行は開けない）。
export async function pinSigner(store: SignerPinStore, pin: SignerPin): Promise<void> {
  assertId(pin.memberId);
  assertId(pin.keyId);
  await importSignPublicKey(pin.publicKey);
  await store.set(copyPin(pin));
}

// サーバーが返した管理者の組が、固定した組と一致するかを確かめる（P-05）。公開鍵は65バイトそのもので比べる。
export async function assertSignerPinned(store: SignerPinStore, fromServer: SignerPin): Promise<SignerPin> {
  const pinned = await store.get();
  if (pinned === undefined) throw new CryptoError('SIGNER_NOT_PINNED');
  if (
    pinned.memberId !== fromServer.memberId ||
    pinned.keyId !== fromServer.keyId ||
    !equalBytes(pinned.publicKey, fromServer.publicKey)
  ) {
    throw new CryptoError('SIGNER_MISMATCH');
  }
  return pinned;
}

// 端末が最後に見た Vault 鍵の世代。これより古い世代のグラントは受け付けない（C-20）。
// 拡張機能で chrome.storage.local に差し替える。
export interface GenerationStore {
  get(): Promise<number | undefined>;
  set(vaultKeyVersion: number): Promise<void>;
}

export class MemoryGenerationStore implements GenerationStore {
  #version: number | undefined;

  async get(): Promise<number | undefined> {
    return this.#version;
  }

  async set(vaultKeyVersion: number): Promise<void> {
    assertVersion(vaultKeyVersion);
    this.#version = vaultKeyVersion;
  }
}
