// アイテムの ID と暗号文の形（中身は読めないし、読まない）。app.ts と rotate-routes.ts で使う。

import { HttpProblem } from './problem.ts';
import { fromBase64Url } from '../crypto/bytes.ts';
import { ALG_AES_256_GCM, FORMAT_V2 } from '../crypto/format.ts';

// アイテムの暗号文の長さ（パディング単位 ＋ 形式1 ＋ アルゴリズムID1 ＋ ノンス12 ＋ 認証タグ16）
const ITEM_ENVELOPE_LENGTHS = [512, 1024, 4096, 16384, 65536].map((b) => b + 30);
export const MAX_ITEM_ENVELOPE = ITEM_ENVELOPE_LENGTHS[ITEM_ENVELOPE_LENGTHS.length - 1]!;
export const ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
const BASE64URL = /^[A-Za-z0-9_-]*$/;

// アイテムの暗号文の形だけを確かめる（中身は読めないし、読まない）
export function checkItemCiphertext(ciphertext: unknown): string {
  if (typeof ciphertext !== 'string' || !BASE64URL.test(ciphertext) || ciphertext.length % 4 === 1) throw new HttpProblem(400);
  if (Math.floor((ciphertext.length * 3) / 4) > MAX_ITEM_ENVELOPE) throw new HttpProblem(413);
  const bytes = fromBase64Url(ciphertext);
  if (!ITEM_ENVELOPE_LENGTHS.includes(bytes.length)) throw new HttpProblem(400);
  // 先頭2バイトが 0x02 0x01（アイテムの形式 v2、AES-256-GCM）
  if (bytes[0] !== FORMAT_V2 || bytes[1] !== ALG_AES_256_GCM) throw new HttpProblem(400);
  return ciphertext;
}
