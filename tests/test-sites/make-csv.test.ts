// test-sites/make-csv.ts が作る CSV が、プレビューで決めたとおりに読めること（M-01・M-03、重複、対応しない列の警告）

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { importCsvPreview } from '../../src/client/csv-import.ts';

function make(): string {
  return String(execFileSync(process.execPath, ['--experimental-strip-types', '--no-warnings', 'test-sites/make-csv.ts', 'example']));
}

test('テスト用の CSV：6行が読め、http の行はエラー、TOTP の列に値がある行は警告、最後の行は重複', () => {
  const csv = make();
  const p = importCsvPreview(csv, 'chrome');
  assert.deepEqual(p.items.map((i) => i.row), [2, 3, 4, 5, 7, 9]);
  assert.deepEqual(p.errors, [{ row: 8, reason: 'invalid item' }]);
  assert.deepEqual(p.warnings, [{ row: 7, reason: 'unsupported columns have values' }]);
  assert.deepEqual(p.items.map((i) => i.duplicate), [false, false, false, false, false, true]);
  assert.equal(p.items[3]!.item.notes, 'カンマ, "引用符" と\n改行を含むメモ（M-01）');
  assert.equal(p.items[0]!.item.urls[0], 'https://teampw-site-a.example.workers.dev/');
  // パスワードは毎回作り直す
  assert.notEqual(importCsvPreview(make(), 'chrome').items[0]!.item.password, p.items[0]!.item.password);
  assert.ok(p.items.every((i) => i.item.username.endsWith('@example.com') && i.item.password.length === 20));
});
