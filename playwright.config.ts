// 拡張機能を本物のブラウザ（Playwright の Chromium）で読み込んで動かすテスト。npm run test:browser。
// いつもの npm test（node:test）とは分ける。ブラウザは `npx playwright install chromium` で取る。
import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: 'tests/browser',
  testMatch: '**/*.spec.ts',
  workers: 1,
  timeout: 60_000,
  reporter: 'list',
});
