// 観点表（docs/暗号コア実装計画.md の3章）のうち、ソースを読めば機械的に確かめられるものを検査する。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';

const srcRoot = new URL('../../src/', import.meta.url);
const sources = readdirSync(srcRoot, { recursive: true })
  .map((p) => p.replace(/\\/g, '/'))
  .filter((p) => p.endsWith('.ts'))
  .map((path) => ({ path, text: readFileSync(new URL(path, srcRoot), 'utf8') }));

// コメントを除いたコード
function code(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
}

test('観点表 src のファイルを読めている', () => {
  assert.ok(sources.length >= 10);
  assert.ok(sources.some((s) => s.path === 'crypto/hpke-core.ts'));
});

test('観点表 乱数：Math.random を使わない', () => {
  for (const s of sources) assert.ok(!/Math\.random/.test(code(s.text)), s.path);
});

test('観点表 乱数：getRandomValues を呼ぶのは src/crypto/random.ts だけ', () => {
  const users = sources.filter((s) => /getRandomValues/.test(code(s.text))).map((s) => s.path);
  assert.deepEqual(users, ['crypto/random.ts']);
});

test('観点表 テスト用の口：使い捨て鍵ペアを受け取る hpke-core.ts を import するのは hpke.ts だけ', () => {
  const users = sources.filter((s) => /from '\.\/hpke-core\.ts'|from '[./]*crypto\/hpke-core\.ts'/.test(s.text)).map((s) => s.path);
  assert.deepEqual(users, ['crypto/hpke.ts']);
});

test('観点表 公開鍵の固定：照合なしでグラントを包む関数は export しない', () => {
  const grant = sources.find((s) => s.path === 'crypto/grant.ts')!;
  assert.ok(!/export\s+(async\s+)?function\s+sealGrant/.test(grant.text));
  assert.match(grant.text, /export async function createGrant[\s\S]*?await assertPinned\(/);
});

test('観点表 取り出し不可：extractable を true にするのは、鍵ペアの生成と公開鍵の読み込みだけ', () => {
  const users = sources.filter((s) => /,\s*true,\s*\[/.test(code(s.text))).map((s) => s.path).sort();
  assert.deepEqual(users, ['crypto/member-key.ts', 'crypto/public-key.ts']);
  const memberKey = code(sources.find((s) => s.path === 'crypto/member-key.ts')!.text);
  assert.equal(memberKey.match(/,\s*true,\s*\[/g)!.length, 1);
  assert.match(memberKey, /generateKey\(ECDH_P256, true, \['deriveBits'\]\)/);
});
