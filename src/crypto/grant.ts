// A-2 Vault 鍵の受け渡し（グラント）と、A-3 後半（自分宛てのグラントを開く）。管理者署名を付ける。
// 仕様書「暗号仕様 > Vault鍵の受け渡し」、docs/設計案_グラントの送り手認証.md。
//   info = teampw/v1/vault-key-grant|<Vault鍵の世代>|<宛先の鍵ID>、aad は空。
//   wrapped_key は「形式、アルゴリズムID、暗号文と認証タグ」。ノンスは持たない。
//   signature は「形式、アルゴリズムID（0x03）、ECDSA P-256 の64バイト」。署名する中身は grantSignedMessage。

import { concat, i2osp, utf8, wipe, type Bytes } from './bytes.ts';
import { CryptoError, decryptFailed } from './errors.ts';
import {
  ALG_HPKE_BASE,
  FORMAT_V1,
  GRANT_ENVELOPE_LENGTH,
  assertId,
  assertVersion,
  encodeGrantEnvelope,
  encodeSignatureEnvelope,
  parseGrantEnvelope,
  parseSignatureEnvelope,
} from './format.ts';
import { openBase, sealBase } from './hpke.ts';
import { PUBLIC_KEY_LENGTH, assertPinned, importPublicKey, type PinnedKey, type PinStore } from './public-key.ts';
import { importSignPublicKey, pinnedSignerAndGeneration, signMessage, verifySignature, type GrantTrust } from './signer.ts';
import { VAULT_KEY_LENGTH, importVaultKey } from './vault-key.ts';

const GRANT_INFO_LABEL = 'teampw/v1/vault-key-grant';
const GRANT_SIGNATURE_LABEL = utf8('teampw/v1/grant-signature');
const EMPTY_AAD: Bytes = new Uint8Array(0);

export function grantInfo(vaultKeyVersion: number, recipientKeyId: string): Bytes {
  assertVersion(vaultKeyVersion);
  assertId(recipientKeyId);
  return utf8(`${GRANT_INFO_LABEL}|${vaultKeyVersion}|${recipientKeyId}`);
}

// 署名する中身のフィールド（設計案 3.1）
export type GrantSignedFields = {
  signerMemberId: string;
  signerKeyId: string;
  vaultKeyVersion: number;
  recipientMemberId: string;
  recipientKeyId: string;
  recipientPublicKeySha256: Bytes;
  ephemeralPublicKey: Bytes; // enc
  wrappedKey: Bytes; // ヘッダーを含む
};

// 各フィールドを「長さ（2バイト、ビッグエンディアン）＋値」にして順につなぐ。区切りが曖昧にならない。
function field(value: Uint8Array): Bytes {
  return concat(i2osp(value.length, 2), value);
}

export function grantSignedMessage(f: GrantSignedFields): Bytes {
  assertId(f.signerMemberId);
  assertId(f.signerKeyId);
  assertVersion(f.vaultKeyVersion);
  assertId(f.recipientMemberId);
  assertId(f.recipientKeyId);
  if (f.recipientPublicKeySha256.length !== 32) throw new CryptoError('INVALID_INPUT');
  return concat(
    field(GRANT_SIGNATURE_LABEL),
    field(new Uint8Array([FORMAT_V1])),
    field(new Uint8Array([ALG_HPKE_BASE])),
    field(utf8(f.signerMemberId)),
    field(utf8(f.signerKeyId)),
    field(i2osp(f.vaultKeyVersion, 8)),
    field(utf8(f.recipientMemberId)),
    field(utf8(f.recipientKeyId)),
    field(f.recipientPublicKeySha256),
    field(f.ephemeralPublicKey),
    field(f.wrappedKey),
  );
}

async function sha256(b: Bytes): Promise<Bytes> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', b));
}

// D1 の vault_key_grants に保存するもの
export type Grant = {
  vaultKeyVersion: number;
  recipientKeyId: string;
  ephemeralPublicKey: Bytes; // enc（使い捨ての公開鍵、65バイト）
  wrappedKey: Bytes; // 形式、アルゴリズムID、暗号文と認証タグ
  signerKeyId: string; // 署名した管理者の鍵ID
  signature: Bytes; // 形式、アルゴリズムID、署名
  formatVersion: number; // 行の format_version。知らない値なら開かない（C-10）
};

// サーバーから受け取った宛先の鍵ID と公開鍵
export type GrantRecipient = PinnedKey;

// 署名する管理者。署名用秘密鍵はロック解除済み、取り出し不可、用途は sign だけ。
// trust は管理者自身の端末の信頼の状態。世代を対面で初期化するまでは、グラントを作らない（DeepSeek #7）。
export type GrantSigner = {
  memberId: string;
  keyId: string;
  privateKey: CryptoKey;
  trust: GrantTrust;
};

// 固定値との照合なしで包む中身。export しない（照合を飛ばしてグラントを作る経路を作らない）。
async function sealGrant(recipient: GrantRecipient, vaultKeyVersion: number, vaultKeyRaw: Bytes) {
  if (vaultKeyRaw.length !== VAULT_KEY_LENGTH) throw new CryptoError('INVALID_INPUT');
  const info = grantInfo(vaultKeyVersion, recipient.keyId);
  await importPublicKey(recipient.publicKey); // 曲線上にない点などは、ここで拒否する
  const { enc, ct } = await sealBase(recipient.publicKey, info, EMPTY_AAD, vaultKeyRaw);
  return { ephemeralPublicKey: enc, wrappedKey: encodeGrantEnvelope(ct) };
}

// 管理者がグラントを作る唯一の入口。順番は、固定値との照合（P-01） → 包む → 署名。
// 照合が一致しなければ何も包まずに止める。
export async function createGrant(args: {
  pins: PinStore;
  signer: GrantSigner;
  memberId: string;
  recipient: GrantRecipient;
  vaultKeyVersion: number;
  vaultKeyRaw: Bytes;
}): Promise<Grant> {
  await assertPinned(args.pins, args.memberId, args.recipient);
  assertId(args.signer.memberId);
  assertId(args.signer.keyId);
  // 管理者の端末に、自分の組の固定と最後に見た世代がそろっていること。最後に見た世代より古い世代では作らない
  const { signer, lastSeen } = await pinnedSignerAndGeneration(args.signer.trust);
  if (signer.memberId !== args.signer.memberId || signer.keyId !== args.signer.keyId) throw new CryptoError('SIGNER_MISMATCH');
  assertVersion(args.vaultKeyVersion);
  if (args.vaultKeyVersion < lastSeen) throw new CryptoError('STALE_GENERATION');
  const { ephemeralPublicKey, wrappedKey } = await sealGrant(args.recipient, args.vaultKeyVersion, args.vaultKeyRaw);
  const message = grantSignedMessage({
    signerMemberId: args.signer.memberId,
    signerKeyId: args.signer.keyId,
    vaultKeyVersion: args.vaultKeyVersion,
    recipientMemberId: args.memberId,
    recipientKeyId: args.recipient.keyId,
    recipientPublicKeySha256: await sha256(args.recipient.publicKey),
    ephemeralPublicKey,
    wrappedKey,
  });
  return {
    vaultKeyVersion: args.vaultKeyVersion,
    recipientKeyId: args.recipient.keyId,
    ephemeralPublicKey,
    wrappedKey,
    signerKeyId: args.signer.keyId,
    signature: encodeSignatureEnvelope(await signMessage(args.signer.privateKey, message)),
    formatVersion: FORMAT_V1,
  };
}

// 自分の鍵。keyId と publicKey は、ロック解除できた自分の行の値（AAD に公開鍵の SHA-256 が入っているので差し替えられない）。
export type OwnKey = {
  memberId: string;
  keyId: string;
  publicKey: Bytes; // 自分の公開鍵（HPKE の kem_context と、署名する中身に入る）
  privateKey: CryptoKey; // ロック解除済み、取り出し不可
};

// 端末の信頼の状態（固定した管理者の署名用公開鍵と、最後に見た世代）。接続先とメンバーの組ごとに signer.ts の openTrust で作る。
export type { GrantTrust };

// 開く前に、設計案 4.3 の順で確かめる。1つでも違えば開かない。
// サーバーから来たグラントの形を、ほかの確認より先に確かめる（DeepSeek #11）。
// 長さの決まったバイト列が違う長さなら MALFORMED。長さの欄（2バイト）に収まらない値で署名する中身を組み立てない。
function assertGrantShape(grant: Grant): void {
  if (typeof grant !== 'object' || grant === null) throw new CryptoError('MALFORMED');
  const { ephemeralPublicKey, wrappedKey, recipientKeyId, signerKeyId } = grant;
  if (!(ephemeralPublicKey instanceof Uint8Array) || ephemeralPublicKey.length !== PUBLIC_KEY_LENGTH) throw new CryptoError('MALFORMED');
  if (!(wrappedKey instanceof Uint8Array) || wrappedKey.length !== GRANT_ENVELOPE_LENGTH) throw new CryptoError('MALFORMED');
  if (typeof recipientKeyId !== 'string' || typeof signerKeyId !== 'string') throw new CryptoError('MALFORMED');
  assertVersion(grant.vaultKeyVersion);
  // 行の format_version も、署名する中身の形式（v1）と一致しなければならない（DeepSeek #12）
  if (grant.formatVersion !== FORMAT_V1) throw new CryptoError('UNSUPPORTED_FORMAT');
}

// currentVaultKeyVersion は、サーバーが /v1/vault で「今の世代」として返した値。
async function verifyGrant(own: OwnKey, trust: GrantTrust, grant: Grant, currentVaultKeyVersion: number): Promise<void> {
  // 0. 形と長さ
  assertGrantShape(grant);
  // 1. 管理者の署名用公開鍵を固定し、最後に見た世代も初期化してある（未設定なら、固定していないのと同じ扱い）
  const { signer, lastSeen } = await pinnedSignerAndGeneration(trust);
  // 2. 署名者の鍵ID が、固定した鍵ID と一致する
  if (grant.signerKeyId !== signer.keyId) throw new CryptoError('SIGNER_MISMATCH');
  // 3. 署名の長さ、形式、アルゴリズムID
  const signature = parseSignatureEnvelope(grant.signature);
  // 4. 最後に見た世代より古くない（C-20）
  assertVersion(grant.vaultKeyVersion);
  if (grant.vaultKeyVersion < lastSeen) throw new CryptoError('STALE_GENERATION');
  // サーバーが示す今の世代と食い違うグラントは開かない（DeepSeek #2）。古い本物のグラントを今のものと思わせない
  assertVersion(currentVaultKeyVersion);
  if (grant.vaultKeyVersion !== currentVaultKeyVersion) throw new CryptoError('GENERATION_MISMATCH');
  // 5. 宛先の鍵ID が自分の鍵ID と一致する
  if (grant.recipientKeyId !== own.keyId) throw decryptFailed();
  // 6. 署名する中身は、グラントの行の値ではなく、固定した署名者と自分の値から組み立てる
  if (own.publicKey.length !== PUBLIC_KEY_LENGTH) throw new CryptoError('INVALID_INPUT');
  const message = grantSignedMessage({
    signerMemberId: signer.memberId,
    signerKeyId: signer.keyId,
    vaultKeyVersion: grant.vaultKeyVersion,
    recipientMemberId: own.memberId,
    recipientKeyId: own.keyId,
    recipientPublicKeySha256: await sha256(own.publicKey),
    ephemeralPublicKey: grant.ephemeralPublicKey,
    wrappedKey: grant.wrappedKey,
  });
  const publicKey = await importSignPublicKey(signer.publicKey);
  if (!(await verifySignature(publicKey, signature, message))) throw new CryptoError('SIGNATURE_INVALID');
}

async function openGrantRaw(own: OwnKey, trust: GrantTrust, grant: Grant, currentVaultKeyVersion: number): Promise<Bytes> {
  await verifyGrant(own, trust, grant, currentVaultKeyVersion);
  const ct = parseGrantEnvelope(grant.wrappedKey);
  // info は、グラントの行に書かれた値ではなく、自分の鍵IDと期待する世代から作る
  const info = grantInfo(grant.vaultKeyVersion, own.keyId);
  // 7. HPKE で開く
  const raw = await openBase(own.privateKey, own.publicKey, grant.ephemeralPublicKey, info, EMPTY_AAD, ct);
  if (raw.length !== VAULT_KEY_LENGTH) {
    wipe(raw);
    throw decryptFailed();
  }
  // 8. 開けたら、最後に見た世代を進める（保存先の1つの操作で、今の値より大きいときだけ上げる）
  await trust.generations.raise(grant.vaultKeyVersion);
  return raw;
}

// 通常の利用：自分宛てのグラントの署名を確かめて開き、Vault 鍵を取り出し不可で読み込む。
export async function openGrant(own: OwnKey, trust: GrantTrust, grant: Grant, currentVaultKeyVersion: number): Promise<CryptoKey> {
  const raw = await openGrantRaw(own, trust, grant, currentVaultKeyVersion);
  try {
    return await importVaultKey(raw);
  } finally {
    wipe(raw);
  }
}

// 管理操作（承認、ローテーション）だけ：署名を確かめたうえで、グラントを取り出し可として開き直し、生の Vault 鍵を返す。
// 管理者自身宛てのグラントも、ここで署名を確かめる（C-23）。
// 呼び出し側は、全員分を包み終えたらすぐに wipe する（仕様書「鍵のライフサイクル」の Vault 鍵（管理操作））。
export function openGrantForAdmin(own: OwnKey, trust: GrantTrust, grant: Grant, currentVaultKeyVersion: number): Promise<Bytes> {
  return openGrantRaw(own, trust, grant, currentVaultKeyVersion);
}
