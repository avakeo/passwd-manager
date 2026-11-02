// Web ページのビルド（2026-11-01 追記、判断待ち10）。依存は足さず、入っている TypeScript（tsc）で JS にし、HTML・CSS を写す。
//   npm run build:web   → dist/web（wrangler.web.toml の [assets] がここを配る）
// 設定は Git の管理外の web.config.local.json（例：web.config.example.json）。
//   apiOrigin：API の接続先（https のオリジン）
//   discordClientId：Discord のアプリの Client ID（秘密ではない）
//   webOrigin：このページのオリジン。Discord から戻る先は <webOrigin>/callback

import { execFileSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export type WebBuildConfig = { apiOrigin: string; discordClientId: string; webOrigin: string };

const ROOT = new URL('../', import.meta.url);

function checkOrigin(name: string, value: unknown): void {
  let url: URL;
  try {
    url = new URL(String(value));
  } catch {
    throw new Error(`${name} が URL ではない`);
  }
  if (url.protocol !== 'https:' || url.origin !== value || String(value).includes('*')) throw new Error(`${name} は https のオリジンだけ（パスもワイルドカードも付けない）`);
}

export function checkWebConfig(config: WebBuildConfig): void {
  checkOrigin('apiOrigin', config.apiOrigin);
  checkOrigin('webOrigin', config.webOrigin);
  if (!/^\d{17,20}$/.test(config.discordClientId)) throw new Error('discordClientId は Discord のアプリの Client ID（数字）');
}

export async function buildWeb(opts: { outDir: URL; config: WebBuildConfig }): Promise<void> {
  checkWebConfig(opts.config);
  rmSync(opts.outDir, { recursive: true, force: true });
  execFileSync(process.execPath, [fileURLToPath(new URL('node_modules/typescript/bin/tsc', ROOT)), '-p', fileURLToPath(new URL('tsconfig.web.json', ROOT)), '--outDir', fileURLToPath(opts.outDir)], {
    stdio: 'inherit',
  });
  copyFileSync(new URL('src/web/page/index.html', ROOT), new URL('index.html', opts.outDir));
  mkdirSync(new URL('web/page/', opts.outDir), { recursive: true });
  copyFileSync(new URL('src/web/page/style.css', ROOT), new URL('web/page/style.css', opts.outDir));
  const { apiOrigin, discordClientId, webOrigin } = opts.config;
  writeFileSync(new URL('web/config.js', opts.outDir), `export const CONFIG = ${JSON.stringify({ apiOrigin, discordClientId, webOrigin })};\n`);
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1]) {
  const path = new URL('web.config.local.json', ROOT);
  if (!existsSync(path)) {
    process.stderr.write('web.config.local.json がない。web.config.example.json を写して値を書く\n');
    process.exitCode = 1;
  } else {
    const config = JSON.parse(readFileSync(path, 'utf8')) as WebBuildConfig;
    await buildWeb({ outDir: new URL('dist/web/', ROOT), config });
    process.stdout.write('dist/web を作った\n');
  }
}
