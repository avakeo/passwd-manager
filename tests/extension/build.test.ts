// 拡張機能のビルドと manifest の検査（E-16 の manifest の部分）と、画面で HTML として解釈しないことの検査（DeepSeek #2）。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { buildExtension, buildManifest } from '../../scripts/build-extension.ts';

const CONFIG = { apiOrigin: 'https://pw-api.example.com', discordClientId: '100000000000000001', manifestKey: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtest' };
const template = JSON.parse(readFileSync(new URL('../../src/extension/manifest.json', import.meta.url), 'utf8')) as Record<string, unknown>;

test('E-16 manifest：権限は storage と identity と API の接続先だけ。content_scripts・externally_connectable・web_accessible_resources を持たない', () => {
  const m = buildManifest(template, CONFIG) as Record<string, unknown>;
  assert.equal(m.manifest_version, 3);
  assert.deepEqual(m.permissions, ['storage', 'identity']);
  assert.deepEqual(m.host_permissions, ['https://pw-api.example.com/*']);
  for (const k of ['content_scripts', 'externally_connectable', 'web_accessible_resources', 'optional_permissions', 'optional_host_permissions']) assert.equal(k in m, false, k);
  assert.equal(m.key, CONFIG.manifestKey);
  assert.deepEqual(m.background, { service_worker: 'extension/background/service-worker.js', type: 'module' });
  assert.match(String((m.content_security_policy as Record<string, string>).extension_pages), /^script-src 'self'; object-src 'none'/);
});

test('manifest：API の接続先は https のオリジンだけ。パス付き・http・ワイルドカードは断る', () => {
  for (const apiOrigin of ['http://pw-api.example.com', 'https://pw-api.example.com/v1', 'https://*.example.com', 'pw-api.example.com']) {
    assert.throws(() => buildManifest(template, { ...CONFIG, apiOrigin }), /apiOrigin/, apiOrigin);
  }
  assert.throws(() => buildManifest(template, { ...CONFIG, discordClientId: 'x' }), /discordClientId/);
});

test('ビルド：TypeScript から拡張機能を作り、import の .ts は .js に書き換わる。設定の値が入る', async () => {
  const out = new URL('../../dist/test-extension/', import.meta.url);
  await buildExtension({ outDir: out, config: CONFIG });
  for (const f of ['manifest.json', 'extension/background/service-worker.js', 'extension/popup/popup.html', 'extension/popup/popup.js', 'extension/page/app.html', 'extension/page/app.js', 'extension/config.js', 'crypto/grant.js']) {
    assert.ok(existsSync(new URL(f, out)), f);
  }
  const sw = readFileSync(new URL('extension/background/service-worker.js', out), 'utf8');
  assert.ok(!/from\s+['"][^'"]+\.ts['"]/.test(sw), '.ts の import が残っていない');
  assert.ok(/from\s+['"]\.\/background\.js['"]/.test(sw));
  assert.match(readFileSync(new URL('extension/config.js', out), 'utf8'), /https:\/\/pw-api\.example\.com/);
  // src/api（Workers）は入れない
  assert.equal(existsSync(new URL('api/app.js', out)), false);
});

test('HTML として解釈しない：拡張機能の画面のコードに innerHTML・outerHTML・insertAdjacentHTML・document.write がない（DeepSeek #2）', () => {
  const root = new URL('../../src/extension/', import.meta.url);
  const files = readdirSync(root, { recursive: true }).map((p) => p.replace(/\\/g, '/')).filter((p) => /\.(ts|html)$/.test(p));
  assert.ok(files.some((f) => f.endsWith('page/app.ts')) && files.some((f) => f.endsWith('page/items.ts')) && files.some((f) => f.endsWith('popup/popup.ts')));
  for (const f of files) {
    const text = readFileSync(new URL(f, root), 'utf8');
    assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function/.test(text), f);
    // アイテムの中身（URL など）をリンクや画像の行き先にしない。イベント属性を後から付けない（フェーズ2b）
    assert.ok(!/\.(href|src)\s*=|setAttribute\(\s*['"](on|href|src)/i.test(text), `${f}：href・src・イベント属性に値を入れない`);
    if (f.endsWith('.html')) assert.ok(!/<script(?![^>]*\bsrc=)/.test(text) && !/\son[a-z]+=/i.test(text), `${f}：インラインのスクリプトとイベント属性を書かない`);
  }
});

test('E-16 storage.session は既定の設定（信頼されたページだけ）のまま使う：拡張機能のコードに setAccessLevel がない', () => {
  const root = new URL('../../src/extension/', import.meta.url);
  const files = readdirSync(root, { recursive: true }).map((p) => p.replace(/\\/g, '/')).filter((p) => /\.(ts|html)$/.test(p));
  assert.ok(files.some((f) => f.endsWith('background/background.ts')));
  for (const f of files) assert.ok(!/setAccessLevel/.test(readFileSync(new URL(f, root), 'utf8')), f);
});
