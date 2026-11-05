// Web ページのビルド（2026-11-01 追記、判断待ち10）と、画面で HTML として解釈しないことの検査。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { buildWeb, checkWebConfig } from '../../scripts/build-web.ts';

const CONFIG = { apiOrigin: 'https://pw-api.example.com', discordClientId: '100000000000000001', webOrigin: 'https://pw.example.com' };

test('設定：API と Web ページの接続先は https のオリジンだけ。パス付き・http・ワイルドカードは断る', () => {
  checkWebConfig(CONFIG); // 正しい設定は通る（投げればテストが落ちる）
  for (const key of ['apiOrigin', 'webOrigin'] as const) {
    for (const bad of ['http://pw.example.com', 'https://pw.example.com/x', 'https://*.example.com', 'pw.example.com']) {
      assert.throws(() => checkWebConfig({ ...CONFIG, [key]: bad }), new RegExp(key), `${key} ${bad}`);
    }
  }
  assert.throws(() => checkWebConfig({ ...CONFIG, discordClientId: 'x' }), /discordClientId/);
});

test('ビルド：index.html と、TypeScript から作った JS・CSS・設定ができる。API と拡張機能のコードは入れない', async () => {
  const out = new URL('../../dist/test-web/', import.meta.url);
  await buildWeb({ outDir: out, config: CONFIG });
  for (const f of ['index.html', 'web/page/app.js', 'web/page/web-client.js', 'web/page/style.css', 'web/config.js', 'client/discord-login.js']) {
    assert.ok(existsSync(new URL(f, out)), f);
  }
  const app = readFileSync(new URL('web/page/app.js', out), 'utf8');
  assert.ok(!/from\s+['"][^'"]+\.ts['"]/.test(app), '.ts の import が残っていない');
  const config = readFileSync(new URL('web/config.js', out), 'utf8');
  assert.match(config, /https:\/\/pw-api\.example\.com/);
  assert.match(config, /100000000000000001/);
  for (const dir of ['api', 'extension']) assert.equal(existsSync(new URL(`${dir}/`, out)), false, dir);
  assert.equal(existsSync(new URL('web/worker.js', out)), false, '配る Worker のコードはアセットに入れない');
});

test('HTML として解釈しない：Web ページのコードに innerHTML・outerHTML・insertAdjacentHTML・document.write・eval がない。HTML にインラインのスクリプトとスタイルがない', () => {
  const root = new URL('../../src/web/', import.meta.url);
  const files = readdirSync(root, { recursive: true }).map((p) => p.replace(/\\/g, '/')).filter((p) => /\.(ts|html)$/.test(p));
  assert.ok(files.includes('page/app.ts') && files.includes('page/index.html'));
  for (const f of files) {
    const text = readFileSync(new URL(f, root), 'utf8');
    assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function/.test(text), f);
  }
  const html = readFileSync(new URL('page/index.html', root), 'utf8');
  assert.ok(!/<script(?![^>]*\bsrc=)/.test(html) && !/<style|\sstyle=|\son[a-z]+=/i.test(html));
});

test('設定の置き場所：例の設定は config/web.example.json にあり、設定の確認に通る。手元の config/web.local.json は Git の管理外', () => {
  const example = JSON.parse(readFileSync(new URL('../../config/web.example.json', import.meta.url), 'utf8')) as typeof CONFIG;
  checkWebConfig(example);
  assert.match(readFileSync(new URL('../../.gitignore', import.meta.url), 'utf8'), /^config\/\*\.local\.json$/m);
});
