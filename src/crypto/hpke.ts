// HPKE Base モードの本番の入口（KEM 0x0010・KDF 0x0001・AEAD 0x0002）。
// 使い捨て鍵ペアは必ずここで生成する。秘密側は取り出し不可で作り、使い終われば参照を捨てる。
// 1つの文脈で暗号化するのは1回だけ（シーケンス番号0）。

import type { Bytes } from './bytes.ts';
import { decryptFailed } from './errors.ts';
import { AEAD_AES_256_GCM, setupBaseR, setupBaseSWithEphemeral } from './hpke-core.ts';

export async function sealBase(pkRm: Bytes, info: Bytes, aad: Bytes, plaintext: Bytes): Promise<{ enc: Bytes; ct: Bytes }> {
  const ephemeral = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const { enc, context } = await setupBaseSWithEphemeral(AEAD_AES_256_GCM, pkRm, info, ephemeral);
  return { enc, ct: await context.seal(aad, plaintext) };
}

export async function openBase(
  skR: CryptoKey,
  pkRm: Bytes,
  enc: Bytes,
  info: Bytes,
  aad: Bytes,
  ct: Bytes,
): Promise<Bytes> {
  try {
    const context = await setupBaseR(AEAD_AES_256_GCM, enc, skR, pkRm, info);
    return await context.open(aad, ct);
  } catch {
    // 不正な enc、別の宛先、改ざんのどれも同じ失敗にする
    throw decryptFailed();
  }
}
