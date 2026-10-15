// HPKE（RFC 9180）の公開テストベクタを取得し、C-15 で使う組だけを tests/vectors/.cache に書き出す。
// 再配布してよいかを確認できていないため、リポジトリにはコミットしない（docs/判断待ち.md）。
// 取得元のコミットと SHA-256 を固定し、中身が変わっていれば止まる。
//
//   npm run vectors:fetch

import { mkdirSync, writeFileSync } from 'node:fs';

const SOURCE =
  'https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json';
const SHA256 = '61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6';

type Vector = { mode: number; kem_id: number; kdf_id: number; aead_id: number } & Record<string, unknown>;

// 本番の組（KEM 0x0010・KDF 0x0001・AEAD 0x0002）と、RFC 9180 付録 A.3 の組（AEAD 0x0001）。どちらも Base モード。
const WANTED = [
  { name: 'hpke-base-p256-sha256-aes256gcm.json', kem_id: 0x0010, kdf_id: 0x0001, aead_id: 0x0002 },
  { name: 'hpke-base-p256-sha256-aes128gcm.json', kem_id: 0x0010, kdf_id: 0x0001, aead_id: 0x0001 },
];

const res = await fetch(SOURCE);
if (!res.ok) throw new Error(`取得に失敗しました: ${res.status}`);
const body = new Uint8Array(await res.arrayBuffer());
const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', body))]
  .map((b) => b.toString(16).padStart(2, '0'))
  .join('');
if (digest !== SHA256) throw new Error(`SHA-256 が一致しません: ${digest}`);

const all = JSON.parse(new TextDecoder().decode(body)) as Vector[];
const dir = new URL('../tests/vectors/.cache/', import.meta.url);
mkdirSync(dir, { recursive: true });
for (const w of WANTED) {
  const v = all.find((x) => x.mode === 0 && x.kem_id === w.kem_id && x.kdf_id === w.kdf_id && x.aead_id === w.aead_id);
  if (!v) throw new Error(`組が見つかりません: ${w.name}`);
  writeFileSync(new URL(w.name, dir), JSON.stringify({ source: SOURCE, sha256: SHA256, vector: v }, null, 2));
  console.log(`書き出しました: tests/vectors/.cache/${w.name}`);
}
