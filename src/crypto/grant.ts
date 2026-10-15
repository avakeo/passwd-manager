// A-2 Vault 鍵の受け渡し（グラント）と、A-3 後半（自分宛てのグラントを開く）。
// 仕様書「暗号仕様 > Vault鍵の受け渡し」。
//   info = teampw/v1/vault-key-grant|<Vault鍵の世代>|<宛先の鍵ID>、aad は空。
//   wrapped_key は「形式、アルゴリズムID、暗号文と認証タグ」。ノンスは持たない。

import { utf8, wipe, type Bytes } from './bytes.ts';
import { CryptoError, decryptFailed } from './errors.ts';
import { assertId, assertVersion, encodeGrantEnvelope, parseGrantEnvelope } from './format.ts';
import { openBase, sealBase } from './hpke.ts';
import { assertPinned, importPublicKey, type PinStore } from './public-key.ts';
import { VAULT_KEY_LENGTH, importVaultKey } from './vault-key.ts';

const GRANT_INFO_LABEL = 'teampw/v1/vault-key-grant';
const EMPTY_AAD: Bytes = new Uint8Array(0);

export function grantInfo(vaultKeyVersion: number, recipientKeyId: string): Bytes {
  assertVersion(vaultKeyVersion);
  assertId(recipientKeyId);
  return utf8(`${GRANT_INFO_LABEL}|${vaultKeyVersion}|${recipientKeyId}`);
}

// D1 の vault_key_grants に保存するもの
export type Grant = {
  vaultKeyVersion: number;
  recipientKeyId: string;
  ephemeralPublicKey: Bytes; // enc（使い捨ての公開鍵、65バイト）
  wrappedKey: Bytes; // 形式、アルゴリズムID、暗号文と認証タグ
};

export type GrantRecipient = {
  keyId: string;
  publicKey: Bytes; // サーバーから受け取った公開鍵
};

// 固定値との照合なしで包む中身。export しない（照合を飛ばしてグラントを作る経路を作らない）。
async function sealGrant(recipient: GrantRecipient, vaultKeyVersion: number, vaultKeyRaw: Bytes): Promise<Grant> {
  if (vaultKeyRaw.length !== VAULT_KEY_LENGTH) throw new CryptoError('INVALID_INPUT');
  const info = grantInfo(vaultKeyVersion, recipient.keyId);
  await importPublicKey(recipient.publicKey); // 曲線上にない点などは、ここで拒否する
  const { enc, ct } = await sealBase(recipient.publicKey, info, EMPTY_AAD, vaultKeyRaw);
  return {
    vaultKeyVersion,
    recipientKeyId: recipient.keyId,
    ephemeralPublicKey: enc,
    wrappedKey: encodeGrantEnvelope(ct),
  };
}

// 管理者がグラントを作る唯一の入口。最初に、サーバーから受け取った公開鍵を、端末に固定した値と照合する（P-01）。
// 一致しなければ何も包まずに止める。
export async function createGrant(args: {
  pins: PinStore;
  memberId: string;
  recipient: GrantRecipient;
  vaultKeyVersion: number;
  vaultKeyRaw: Bytes;
}): Promise<Grant> {
  await assertPinned(args.pins, args.memberId, args.recipient.publicKey);
  return sealGrant(args.recipient, args.vaultKeyVersion, args.vaultKeyRaw);
}

export type OwnKey = {
  keyId: string;
  publicKey: Bytes; // 自分の公開鍵（HPKE の kem_context に入る）
  privateKey: CryptoKey; // ロック解除済み、取り出し不可
};

async function openGrantRaw(own: OwnKey, grant: Grant): Promise<Bytes> {
  if (grant.recipientKeyId !== own.keyId) throw decryptFailed();
  const ct = parseGrantEnvelope(grant.wrappedKey);
  // info は、グラントの行に書かれた値ではなく、自分の鍵IDと期待する世代から作る
  const info = grantInfo(grant.vaultKeyVersion, own.keyId);
  const raw = await openBase(own.privateKey, own.publicKey, grant.ephemeralPublicKey, info, EMPTY_AAD, ct);
  if (raw.length !== VAULT_KEY_LENGTH) {
    wipe(raw);
    throw decryptFailed();
  }
  return raw;
}

// 通常の利用：自分宛てのグラントを開き、Vault 鍵を取り出し不可で読み込む。
export async function openGrant(own: OwnKey, grant: Grant): Promise<CryptoKey> {
  const raw = await openGrantRaw(own, grant);
  try {
    return await importVaultKey(raw);
  } finally {
    wipe(raw);
  }
}

// 管理操作（承認、ローテーション）だけ：グラントを取り出し可として開き直し、生の Vault 鍵を返す。
// 呼び出し側は、全員分を包み終えたらすぐに wipe する（仕様書「鍵のライフサイクル」の Vault 鍵（管理操作））。
export function openGrantForAdmin(own: OwnKey, grant: Grant): Promise<Bytes> {
  return openGrantRaw(own, grant);
}
