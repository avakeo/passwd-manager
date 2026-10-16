// 観点表（docs/暗号コア実装計画.md の3章）のうち、ソースを読めば機械的に確かめられるものを検査する。
//
// これは補助の検査。正規表現でソースを読むだけなので、書き方次第で外れる（攻撃者レビュー #4）。
// 守りたい動作そのものは、動作のテストで確かめる：
//   公開鍵の固定は P-01（tests/crypto/pin.test.ts）、取り出し不可は C-16、使い捨て鍵ペアの生成は hpke.test.ts。
// ここでは、動作のテストでは見つけにくい「危ない書き方が増えていないか」だけを見る。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';

type Source = { path: string; text: string };

const srcRoot = new URL('../../src/', import.meta.url);
const sources: Source[] = readdirSync(srcRoot, { recursive: true })
  .map((p) => p.replace(/\\/g, '/'))
  .filter((p) => p.endsWith('.ts'))
  .map((path) => ({ path, text: readFileSync(new URL(path, srcRoot), 'utf8') }));

// コメントを除いたコード
function code(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
}

// hpke-core.ts を読み込むファイル。静的な import、再 export（export ... from）、動的な import() を数える。
function hpkeCoreImporters(files: Source[]): string[] {
  return files.filter((s) => /\bfrom\s*['"][^'"]*hpke-core(\.ts)?['"]|\bimport\s*\(\s*['"][^'"]*hpke-core(\.ts)?['"]/.test(code(s.text))).map((s) => s.path);
}

test('観点表（補助） src のファイルを読めている', () => {
  assert.ok(sources.length >= 10);
  assert.ok(sources.some((s) => s.path === 'crypto/hpke-core.ts'));
});

test('観点表（補助） 乱数：Math.random を使わない', () => {
  for (const s of sources) assert.ok(!/Math\.random/.test(code(s.text)), s.path);
});

test('観点表（補助） 乱数：getRandomValues を呼ぶのは src/crypto/random.ts だけ', () => {
  const users = sources.filter((s) => /getRandomValues/.test(code(s.text))).map((s) => s.path);
  assert.deepEqual(users, ['crypto/random.ts']);
});

test('観点表（補助） テスト用の口：使い捨て鍵ペアを受け取る hpke-core.ts を import するのは hpke.ts だけ', () => {
  assert.deepEqual(hpkeCoreImporters(sources), ['crypto/hpke.ts']);
});

test('観点表（補助） テスト用の口の検査は、動的な import と再 export も見つける', () => {
  const samples: Source[] = [
    { path: 'static', text: "import { setupBaseSWithEphemeral } from './hpke-core.ts';" },
    { path: 'dynamic', text: "const core = await import('./hpke-core.ts');" },
    { path: 'dynamic-spaced', text: 'const core = await import (\n  "../crypto/hpke-core.ts"\n);' },
    { path: 're-export', text: "export { setupBaseSWithEphemeral as setup } from './hpke-core.ts';" },
    { path: 're-export-all', text: "export * from './crypto/hpke-core.ts';" },
    { path: 'comment-only', text: "// import('./hpke-core.ts') はしない" },
  ];
  assert.deepEqual(hpkeCoreImporters(samples), ['static', 'dynamic', 'dynamic-spaced', 're-export', 're-export-all']);
});

test('観点表（補助） 取り出し不可：extractable を true にするのは、鍵ペアの生成と公開鍵の読み込みだけ', () => {
  const users = sources.filter((s) => /,\s*true,\s*\[/.test(code(s.text))).map((s) => s.path).sort();
  assert.deepEqual(users, ['crypto/member-key.ts', 'crypto/public-key.ts']);
  const memberKey = code(sources.find((s) => s.path === 'crypto/member-key.ts')!.text);
  assert.equal(memberKey.match(/,\s*true,\s*\[/g)!.length, 1);
  assert.match(memberKey, /generateKey\(ECDH_P256, true, \['deriveBits'\]\)/);
});

test('観点表（補助） ログ：src から console に出力しない（トークン、Authorization ヘッダー、本文をログに出さない）', () => {
  for (const s of sources) assert.ok(!/\bconsole\./.test(code(s.text)), s.path);
});

test('観点表（補助） テスト用の認証：本番の入口（worker.ts）は createApp だけを使い、認証の差し込み口を持たない', () => {
  const worker = code(sources.find((s) => s.path === 'api/worker.ts')!.text);
  assert.match(worker, /export default createApp\(\);/);
  const app = code(sources.find((s) => s.path === 'api/app.ts')!.text);
  assert.match(app, /export function createApp\(\)/); // 引数を取らない
});
