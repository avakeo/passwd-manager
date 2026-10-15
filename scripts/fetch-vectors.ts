// tests/vectors/hpke に置いた HPKE（RFC 9180）のテストベクタを、出典から作り直して照合するための道具。
// テストの実行には不要（ベクタはリポジトリに置いてある）。出典とライセンスの扱いは tests/vectors/README.md。
// 取得元のコミットと SHA-256 を固定し、中身が変わっていれば止まる。
//
//   npm run vectors:fetch

import { mkdirSync, writeFileSync } from 'node:fs';

const SOURCE =
  'https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json';
const SHA256 = '61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6';

type Vector = { mode: number; kem_id: number; kdf_id: number; aead_id: number } & Record<string, unknown>;

const res = await fetch(SOURCE);
if (!res.ok) throw new Error(`取得に失敗しました: ${res.status}`);
const body = new Uint8Array(await res.arrayBuffer());
const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', body))]
  .map((b) => b.toString(16).padStart(2, '0'))
  .join('');
if (digest !== SHA256) throw new Error(`SHA-256 が一致しません: ${digest}`);

// 本番の組（Base モード、KEM 0x0010・KDF 0x0001・AEAD 0x0002）の1件だけ
const all = JSON.parse(new TextDecoder().decode(body)) as Vector[];
const v = all.find((x) => x.mode === 0 && x.kem_id === 0x0010 && x.kdf_id === 0x0001 && x.aead_id === 0x0002);
if (!v) throw new Error('組が見つかりません');
const dir = new URL('../tests/vectors/hpke/', import.meta.url);
mkdirSync(dir, { recursive: true });
writeFileSync(
  new URL('hpke-base-p256-sha256-aes256gcm.json', dir),
  JSON.stringify({ source: SOURCE, source_sha256: SHA256, vector: v }, null, 2) + '\n',
);
console.log('書き出しました: tests/vectors/hpke/hpke-base-p256-sha256-aes256gcm.json');
