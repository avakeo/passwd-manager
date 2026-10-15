// A-4 アイテムの暗号化と復号。
// 仕様書「暗号仕様 > アイテムの暗号化」。
//   JSON → 先頭4バイトに長さ → パディング（512B〜64KB）→ AES-256-GCM（ノンスは毎回乱数、AAD は v1|item|ID|世代）

import { fromUtf8, utf8, wipe, type Bytes } from './bytes.ts';
import { aesGcmDecrypt, aesGcmEncrypt } from './aead.ts';
import { CryptoError, decryptFailed } from './errors.ts';
import { encodeAeadEnvelope, itemAad, parseAeadEnvelope, type ItemContext } from './format.ts';

export const PADDING_BUCKETS = [512, 1024, 4096, 16384, 65536];
const LENGTH_PREFIX = 4;
export const MAX_ITEM_JSON_BYTES = PADDING_BUCKETS[PADDING_BUCKETS.length - 1]! - LENGTH_PREFIX; // 65,532

export type ItemContent = { type: 'login' | 'note' } & Record<string, unknown>;

function pad(body: Bytes): Bytes {
  const bucket = PADDING_BUCKETS.find((b) => b >= body.length + LENGTH_PREFIX);
  // 上限を超える場合は、暗号化の前にクライアントで拒否する（API 側は別に 413 で拒否する）。
  if (bucket === undefined) throw new CryptoError('ITEM_TOO_LARGE');
  const padded = new Uint8Array(bucket);
  new DataView(padded.buffer).setUint32(0, body.length);
  padded.set(body, LENGTH_PREFIX);
  return padded;
}

function unpad(padded: Bytes): Bytes {
  if (!PADDING_BUCKETS.includes(padded.length)) throw decryptFailed();
  const length = new DataView(padded.buffer, padded.byteOffset).getUint32(0);
  if (length > padded.length - LENGTH_PREFIX) throw decryptFailed();
  return padded.slice(LENGTH_PREFIX, LENGTH_PREFIX + length);
}

export async function encryptItem(vaultKey: CryptoKey, ctx: ItemContext, content: ItemContent): Promise<Bytes> {
  const aad = itemAad(ctx);
  const body = utf8(JSON.stringify(content));
  const padded = pad(body);
  try {
    const { nonce, ciphertext } = await aesGcmEncrypt(vaultKey, aad, padded);
    return encodeAeadEnvelope('item', nonce, ciphertext);
  } finally {
    wipe(body);
    wipe(padded);
  }
}

export async function decryptItem(vaultKey: CryptoKey, ctx: ItemContext, envelope: Uint8Array): Promise<ItemContent> {
  const aad = itemAad(ctx);
  const { nonce, ciphertext } = parseAeadEnvelope('item', envelope);
  const padded = await aesGcmDecrypt(vaultKey, nonce, aad, ciphertext);
  try {
    const body = unpad(padded);
    let content: unknown;
    try {
      content = JSON.parse(fromUtf8(body));
    } catch {
      throw decryptFailed();
    } finally {
      wipe(body);
    }
    if (typeof content !== 'object' || content === null || !('type' in content)) throw decryptFailed();
    const type = (content as { type: unknown }).type;
    if (type !== 'login' && type !== 'note') throw decryptFailed();
    return content as ItemContent;
  } finally {
    wipe(padded);
  }
}
