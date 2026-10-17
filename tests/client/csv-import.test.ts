import { test } from 'node:test';
import assert from 'node:assert/strict';
import { importCsvPreview, MAX_CSV_BYTES, MAX_CSV_ROWS } from '../../src/client/csv-import.ts';

test('M-01 CSV Chrome: 引用符・カンマ・改行・二重引用符を解析し、HTTPS URLをそのまま残す', () => {
  const csv = 'name,url,username,password,note\r\n"社内,Wiki",https://wiki.example.com/login?a=1,team@example.com,"a""b","first\nsecond"\r\n';
  const result = importCsvPreview(csv, 'chrome');
  assert.deepEqual(result.errors, []);
  assert.equal(result.items.length, 1);
  assert.deepEqual(result.items[0]!.item, { type: 'login', title: '社内,Wiki', username: 'team@example.com', password: 'a"b', urls: ['https://wiki.example.com/login?a=1'], notes: 'first\nsecond', customFields: [] });
  assert.equal(result.items[0]!.row, 2);
});
test('M-02 CSV Proton Passと1Passwordの列名を変換し、未対応のTOTPは取り込まない', () => {
  const proton = importCsvPreview('name,url,username,password,note,totp\nProton,https://p.example/a,u,p,n,123\n', 'proton');
  const one = importCsvPreview('Title,Website,Username,Password,Notes\nOne,https://one.example/path,u,p,n\n', '1password');
  assert.equal(proton.items[0]!.item.title, 'Proton');
  assert.deepEqual(proton.warnings.map((w) => w.row), [2]);
  assert.equal(proton.items[0]!.item.urls[0], 'https://p.example/a');
  assert.equal(one.items[0]!.item.title, 'One');
  assert.equal(one.items[0]!.item.urls[0], 'https://one.example/path');
});
test('M-03 壊れた行だけを報告して後続を読み、重複をプレビューに出す', () => {
  const csv = 'name,url,username,password\nA,https://a.example,u,p\n"broken"x,https://b.example,u,p\nA,https://a.example,u,p2\nB,http://b.example,u,p\nC,https://c.example,u,p\n';
  const result = importCsvPreview(csv, 'chrome');
  assert.deepEqual(result.items.map((x) => x.item.title), ['A', 'A', 'C']);
  assert.equal(result.items[1]!.duplicate, true);
  assert.deepEqual(result.errors.map((x) => x.row), [3, 5]);
});
test('M-03 CSVの大きな1アイテムはエラーにして次の行を続ける', () => {
  const csv = `name,url,username,password\nHuge,https://a.example,u,${'あ'.repeat(22000)}\nOK,https://b.example,u,p\n`;
  const result = importCsvPreview(csv, 'chrome');
  assert.equal(result.errors.length, 1);
  assert.equal(result.items[0]!.item.title, 'OK');
});

test('M-03 閉じ忘れの引用符を報告し、次の物理行の正常な行を残す', () => {
  const result = importCsvPreview('name,url,username,password\n"Broken,https://bad.example,u,p\nGood,https://good.example,u,p\n', 'chrome');
  assert.deepEqual(result.errors.map((e) => e.row), [2]);
  assert.deepEqual(result.items.map((x) => x.item.title), ['Good']);
});

test('M-02 既存アイテムとの重複でパスワード変更の有無を返す', () => {
  const existing = [{ type: 'login' as const, title: 'Wiki', username: 'team', password: 'old', urls: ['https://wiki.example.com/login'], notes: '', customFields: [] }];
  const csv = 'name,url,username,password\nWiki,https://wiki.example.com/login,team,old\nWiki,https://wiki.example.com/login,team,new\nOther,https://other.example.com,team,new\n';
  const result = importCsvPreview(csv, 'chrome', existing);
  assert.deepEqual(result.items.map(({ duplicate, passwordChangedFromExisting }) => ({ duplicate, passwordChangedFromExisting })), [
    { duplicate: true, passwordChangedFromExisting: false },
    { duplicate: true, passwordChangedFromExisting: true },
    { duplicate: false, passwordChangedFromExisting: false },
  ]);
});

test('M-02 使わない見出しの重複は無視し、使う見出しの重複は結果で報告する', () => {
  const allowed = importCsvPreview('name,url,username,password,tag,tag\nWiki,https://wiki.example.com,u,p,a,b\n', 'chrome');
  assert.equal(allowed.items.length, 1);
  assert.deepEqual(allowed.errors, []);
  for (const header of ['name,name,url,username,password', 'name,url,username,email,password', 'name,url,username,password,password']) {
    assert.deepEqual(importCsvPreview(`${header}\nWiki,https://wiki.example.com,u,p,p\n`, 'chrome').errors, [{ row: 1, reason: 'invalid CSV header' }]);
  }
});

test('M-03 空・見出し不足・壊れたCSVも例外で止まらず結果で報告する', () => {
  for (const source of ['', 'name,username,password\nA,u,p', 'name,url,username,password\n"bad"x,https://a.example,u,p']) {
    const result = importCsvPreview(source, 'chrome');
    assert.ok(result.errors.length > 0);
  }
});

test('M-03 CSV全体のUTF-8サイズと物理行数の上限を超えたら解析せず結果で報告する', () => {
  const header = 'name,url,username,password\n';
  const tooLarge = header + 'A,https://a.example,u,' + 'x'.repeat(MAX_CSV_BYTES);
  assert.deepEqual(importCsvPreview(tooLarge, 'chrome').errors, [{ row: 1, reason: 'CSV too large' }]);
  const tooManyRows = header + 'A,https://a.example,u,p\n'.repeat(MAX_CSV_ROWS);
  assert.deepEqual(importCsvPreview(tooManyRows, 'chrome').errors, [{ row: 1, reason: 'too many CSV rows' }]);
  const atRowLimit = header + 'A,https://a.example,u,p\n'.repeat(MAX_CSV_ROWS - 1);
  assert.equal(importCsvPreview(atRowLimit, 'chrome').items.length, MAX_CSV_ROWS - 1);
  const multibyte = header + 'A,https://a.example,u,' + 'あ'.repeat(Math.ceil(MAX_CSV_BYTES / 3));
  assert.deepEqual(importCsvPreview(multibyte, 'chrome').errors, [{ row: 1, reason: 'CSV too large' }]);
  const manyUnclosedRows = header + '"broken\n'.repeat(2_000);
  assert.ok(importCsvPreview(manyUnclosedRows, 'chrome').errors.length > 0);
});

