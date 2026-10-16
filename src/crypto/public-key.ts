// 公開鍵の読み込み（手順5）と、フィンガープリント・固定（手順6）。
// 仕様書「暗号仕様 > メンバー鍵ペア」「鍵とメンバーのライフサイクル > メンバーの参加と承認」。

import { equalBytes, type Bytes } from './bytes.ts';
import { CryptoError } from './errors.ts';
import { assertId } from './format.ts';

export const PUBLIC_KEY_LENGTH = 65;

// サーバーから来た公開鍵を読み込む。受け付けるのは非圧縮形式（先頭 0x04、65バイト）だけ。
// 曲線上にあるかの検査は WebCrypto に任せる（点の計算は自前で書かない）。C-12。
export async function importPublicKey(raw: Bytes): Promise<CryptoKey> {
  if (!(raw instanceof Uint8Array) || raw.length !== PUBLIC_KEY_LENGTH || raw[0] !== 0x04) {
    throw new CryptoError('INVALID_PUBLIC_KEY');
  }
  try {
    return await crypto.subtle.importKey('raw', raw, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
  } catch {
    throw new CryptoError('INVALID_PUBLIC_KEY');
  }
}

// 人が読み上げて照合するための表示。保存はしない。
//   SHA-256 の先頭30バイトを5バイトずつ6つに分け、それぞれを整数として 100000 で割った余りを5桁にする（6組30桁、約100ビット）。
export async function fingerprint(publicKey: Bytes): Promise<string> {
  await importPublicKey(publicKey);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', publicKey));
  const groups: string[] = [];
  for (let i = 0; i < 6; i++) {
    let n = 0;
    for (const b of digest.subarray(i * 5, i * 5 + 5)) n = n * 256 + b; // 最大 2^40 なので Number で正確に計算できる
    groups.push(String(n % 100000).padStart(5, '0'));
  }
  return groups.join(' ');
}

// 承認のときに照合した鍵。鍵ID と公開鍵を組で固定する（公開鍵だけが同じで鍵ID が違う宛先にも、グラントを作らない）。
export type PinnedKey = {
  keyId: string;
  publicKey: Bytes;
};

// 管理者の端末に置く「照合済み公開鍵」の保存先。メンバーID ごとに、鍵ID と公開鍵の組を持つ。
// 提出版はインターフェースだけで、拡張機能で chrome.storage.local に差し替える。
export interface PinStore {
  get(memberId: string): Promise<PinnedKey | undefined>;
  set(memberId: string, key: PinnedKey): Promise<void>;
}

export class MemoryPinStore implements PinStore {
  readonly #pins = new Map<string, PinnedKey>();

  async get(memberId: string): Promise<PinnedKey | undefined> {
    const pinned = this.#pins.get(memberId);
    return pinned && { keyId: pinned.keyId, publicKey: pinned.publicKey.slice() };
  }

  async set(memberId: string, key: PinnedKey): Promise<void> {
    this.#pins.set(memberId, { keyId: key.keyId, publicKey: key.publicKey.slice() });
  }
}

// 承認のとき、Discord 以外の経路でフィンガープリントを照合できた公開鍵だけを、鍵ID と組にして固定する。
export async function pinPublicKey(store: PinStore, memberId: string, key: PinnedKey): Promise<void> {
  assertId(memberId);
  assertId(key.keyId);
  await importPublicKey(key.publicKey);
  await store.set(memberId, { keyId: key.keyId, publicKey: key.publicKey.slice() });
}

// グラントを作るたびに、サーバーから受け取った鍵ID と公開鍵が、固定した組と一致するかを確かめる。
// 公開鍵の比較は65バイトそのもので行う。
export async function assertPinned(store: PinStore, memberId: string, key: PinnedKey): Promise<void> {
  assertId(memberId);
  const pinned = await store.get(memberId);
  if (pinned === undefined) throw new CryptoError('PUBLIC_KEY_NOT_PINNED');
  if (pinned.keyId !== key.keyId || !equalBytes(pinned.publicKey, key.publicKey)) {
    throw new CryptoError('PUBLIC_KEY_MISMATCH');
  }
}
