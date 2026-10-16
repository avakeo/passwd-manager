// 管理者署名の検証側：管理者の署名用公開鍵の固定、最後に見た世代の記録、ECDSA の署名と検証。
// 仕様書「暗号仕様 > 管理者の署名鍵ペア」、docs/設計案_グラントの送り手認証.md の4章。

import { equalBytes, fromBase64Url, toBase64Url, type Bytes } from './bytes.ts';
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

// 管理者は1人なので、1つの組（接続先とメンバー）に固定するのは1組だけ。
export interface SignerPinStore {
  get(): Promise<SignerPin | undefined>;
  set(pin: SignerPin): Promise<void>;
}

// 端末が最後に見た Vault 鍵の世代。これより古い世代のグラントは受け付けない（C-20）。
// 書き込みは raise の1つだけ。今の値より大きいときだけ上げ、更新後の値を返す（下げる口は作らない）。
export interface GenerationStore {
  get(): Promise<number | undefined>;
  raise(vaultKeyVersion: number): Promise<number>;
}

// 端末の信頼の状態：固定した管理者の署名用公開鍵と、最後に見た世代
export type GrantTrust = {
  signerPins: SignerPinStore;
  generations: GenerationStore;
};

// 端末の保存先（拡張機能では chrome.storage.local）。キーと文字列の値だけを扱う。
export interface TrustStorage {
  get(key: string): Promise<string | undefined>;
  set(key: string, value: string): Promise<void>;
}

export class MemoryTrustStorage implements TrustStorage {
  readonly #values = new Map<string, string>();

  async get(key: string): Promise<string | undefined> {
    return this.#values.get(key);
  }

  async set(key: string, value: string): Promise<void> {
    this.#values.set(key, value);
  }
}

// 信頼の状態を分ける単位。API の接続先とメンバー ID の組ごとに、別の固定と世代を持つ（P-09）。
// 同じブラウザのプロファイルを別のメンバーが使っても、前のメンバーの値は効かない。
export type TrustScope = {
  apiOrigin: string; // https のオリジン（例 https://pw-api.example.com）
  memberId: string;
};

function assertApiOrigin(apiOrigin: string): void {
  let url: URL;
  try {
    url = new URL(apiOrigin);
  } catch {
    throw new CryptoError('INVALID_INPUT');
  }
  // パスや区切り文字を含まない、https のオリジンそのものだけ
  if (url.protocol !== 'https:' || url.origin !== apiOrigin || apiOrigin.includes('|')) throw new CryptoError('INVALID_INPUT');
}

// 保存先とキーごとに、読み書きを1つずつ順に行う。非同期の保存先で raise が同時に呼ばれても、
// 「読む → 比べる → 書く」の間に別の raise が割り込まない（Codex #1）。
const queues = new WeakMap<TrustStorage, Map<string, Promise<unknown>>>();

function serialized<T>(storage: TrustStorage, key: string, task: () => Promise<T>): Promise<T> {
  let byKey = queues.get(storage);
  if (byKey === undefined) {
    byKey = new Map();
    queues.set(storage, byKey);
  }
  const run = (byKey.get(key) ?? Promise.resolve()).then(task, task);
  byKey.set(key, run.catch(() => undefined));
  return run;
}

function trustKey(scope: TrustScope, name: 'signer' | 'generation'): string {
  return `teampw/v1/trust|${scope.apiOrigin}|${scope.memberId}|${name}`;
}

function copyPin(pin: SignerPin): SignerPin {
  return { memberId: pin.memberId, keyId: pin.keyId, publicKey: pin.publicKey.slice() };
}

// 保存した値は端末の中のものだが、形が崩れていれば使わない（固定がないのと同じ扱い）
function parsePin(value: string | undefined): SignerPin | undefined {
  if (value === undefined) return undefined;
  try {
    const v = JSON.parse(value) as { memberId: string; keyId: string; publicKey: string };
    assertId(v.memberId);
    assertId(v.keyId);
    const publicKey = fromBase64Url(v.publicKey);
    if (publicKey.length !== PUBLIC_KEY_LENGTH) return undefined;
    return { memberId: v.memberId, keyId: v.keyId, publicKey };
  } catch {
    return undefined;
  }
}

function parseVersion(value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  const n = Number(value);
  return Number.isSafeInteger(n) && n >= 1 ? n : undefined;
}

export function openTrust(storage: TrustStorage, scope: TrustScope): GrantTrust {
  assertApiOrigin(scope.apiOrigin);
  assertId(scope.memberId);
  const s = { apiOrigin: scope.apiOrigin, memberId: scope.memberId };
  return {
    signerPins: {
      get: async () => parsePin(await storage.get(trustKey(s, 'signer'))),
      set: async (pin) => {
        const p = copyPin(pin);
        await storage.set(trustKey(s, 'signer'), JSON.stringify({ memberId: p.memberId, keyId: p.keyId, publicKey: toBase64Url(p.publicKey) }));
      },
    },
    generations: {
      get: () => serialized(storage, trustKey(s, 'generation'), async () => parseVersion(await storage.get(trustKey(s, 'generation')))),
      raise: (vaultKeyVersion) => {
        assertVersion(vaultKeyVersion);
        const key = trustKey(s, 'generation');
        return serialized(storage, key, async () => {
          const current = parseVersion(await storage.get(key));
          if (current !== undefined && current >= vaultKeyVersion) return current;
          await storage.set(key, String(vaultKeyVersion));
          return vaultKeyVersion;
        });
      },
    },
  };
}

// 承認のとき、Discord 以外の経路で管理者の画面と見比べて一致した組だけを固定する。
// 管理者自身の端末は、ロック解除できた自分の行の値を固定する（AAD に公開鍵の SHA-256 が入っているので、差し替えた行は開けない）。
export async function pinSigner(trust: GrantTrust, pin: SignerPin): Promise<void> {
  assertId(pin.memberId);
  assertId(pin.keyId);
  await importSignPublicKey(pin.publicKey);
  await trust.signerPins.set(copyPin(pin));
}

// サーバーが返した管理者の組が、固定した組と一致するかを確かめる（P-05）。公開鍵は65バイトそのもので比べる。
export async function assertSignerPinned(trust: GrantTrust, fromServer: SignerPin): Promise<SignerPin> {
  const pinned = await trust.signerPins.get();
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
