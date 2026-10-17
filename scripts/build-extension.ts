// 拡張機能のビルド。依存は足さず、入っている TypeScript（tsc）で JS にし、HTML・CSS・manifest を写す。
//   npm run build:extension   → dist/extension（Chrome の「パッケージ化されていない拡張機能を読み込む」で選ぶ）
// 設定は Git の管理外の extension.config.local.json（例：extension.config.example.json）。
//   apiOrigin：API の接続先（https のオリジン）。manifest の host_permissions と、出力の config.js に入る
//   discordClientId：Discord のアプリの Client ID（秘密ではない）
//   manifestKey：拡張機能 ID を固定する公開鍵（scripts/extension-key.ts が表示する。秘密鍵はリポジトリの外）

import { execFileSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export type ExtensionConfig = { apiOrigin: string; discordClientId: string; manifestKey: string };

const ROOT = new URL('../', import.meta.url);

export function buildManifest(template: Record<string, unknown>, config: ExtensionConfig): Record<string, unknown> {
  let url: URL;
  try {
    url = new URL(config.apiOrigin);
  } catch {
    throw new Error('apiOrigin が URL ではない');
  }
  if (url.protocol !== 'https:' || url.origin !== config.apiOrigin || config.apiOrigin.includes('*')) throw new Error('apiOrigin は https のオリジンだけ（パスもワイルドカードも付けない）');
  if (!/^\d{17,20}$/.test(config.discordClientId)) throw new Error('discordClientId は Discord のアプリの Client ID（数字）');
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(config.manifestKey)) throw new Error('manifestKey は base64 の公開鍵');
  return { ...template, key: config.manifestKey, host_permissions: [`${config.apiOrigin}/*`] };
}

export async function buildExtension(opts: { outDir: URL; config: ExtensionConfig }): Promise<void> {
  const template = JSON.parse(readFileSync(new URL('src/extension/manifest.json', ROOT), 'utf8')) as Record<string, unknown>;
  const manifest = buildManifest(template, opts.config);
  rmSync(opts.outDir, { recursive: true, force: true });
  execFileSync(process.execPath, [fileURLToPath(new URL('node_modules/typescript/bin/tsc', ROOT)), '-p', fileURLToPath(new URL('tsconfig.extension.json', ROOT)), '--outDir', fileURLToPath(opts.outDir)], {
    stdio: 'inherit',
  });
  const srcExt = new URL('src/extension/', ROOT);
  for (const f of readdirSync(srcExt, { recursive: true }).map((p) => p.replace(/\\/g, '/')).filter((p) => /\.(html|css)$/.test(p))) {
    const dest = new URL(`extension/${f}`, opts.outDir);
    mkdirSync(new URL('./', dest), { recursive: true });
    copyFileSync(new URL(f, srcExt), dest);
  }
  writeFileSync(new URL('manifest.json', opts.outDir), `${JSON.stringify(manifest, null, 2)}\n`);
  writeFileSync(
    new URL('extension/config.js', opts.outDir),
    `export const CONFIG = ${JSON.stringify({ apiOrigin: opts.config.apiOrigin, discordClientId: opts.config.discordClientId })};\n`,
  );
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1]) {
  const path = new URL('extension.config.local.json', ROOT);
  if (!existsSync(path)) {
    process.stderr.write('extension.config.local.json がない。extension.config.example.json を写して値を書く\n');
    process.exitCode = 1;
  } else {
    const config = JSON.parse(readFileSync(path, 'utf8')) as ExtensionConfig;
    await buildExtension({ outDir: new URL('dist/extension/', ROOT), config });
    process.stdout.write('dist/extension を作った\n');
  }
}
