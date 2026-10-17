import { test } from 'node:test';
import assert from 'node:assert/strict';
import { importCsvPreview } from '../../src/client/csv-import.ts';

test('I-02 CSV Chrome: 引用符・カンマ・改行・二重引用符を解析し、HTTPS URLをそのまま残す', () => {
  const csv = 'name,url,username,password,note\r\n"社内,Wiki",https://wiki.example.com/login?a=1,team@example.com,"a""b","first\nsecond"\r\n';
  const result = importCsvPreview(csv, 'chrome');
  assert.deepEqual(result.errors, []);
  assert.equal(result.items.length, 1);
  assert.deepEqual(result.items[0]!.item, { type: 'login', title: '社内,Wiki', username: 'team@example.com', password: 'a"b', urls: ['https://wiki.example.com/login?a=1'], notes: 'first\nsecond', customFields: [] });
  assert.equal(result.items[0]!.row, 2);
});
test('I-02 CSV Proton Passと1Passwordの列名を変換し、未対応のTOTPは取り込まない', () => {
  const proton = importCsvPreview('name,url,username,password,note,totp\nProton,https://p.example/a,u,p,n,123\n', 'proton');
  const one = importCsvPreview('Title,Website,Username,Password,Notes\nOne,https://one.example/path,u,p,n\n', '1password');
  assert.equal(proton.items[0]!.item.title, 'Proton');
  assert.deepEqual(proton.warnings.map((w) => w.row), [2]);
  assert.equal(proton.items[0]!.item.urls[0], 'https://p.example/a');
  assert.equal(one.items[0]!.item.title, 'One');
  assert.equal(one.items[0]!.item.urls[0], 'https://one.example/path');
});
test('I-02 壊れた行だけを報告して後続を読み、重複をプレビューに出す', () => {
  const csv = 'name,url,username,password\nA,https://a.example,u,p\n"broken"x,https://b.example,u,p\nA,https://a.example,u,p2\nB,http://b.example,u,p\nC,https://c.example,u,p\n';
  const result = importCsvPreview(csv, 'chrome');
  assert.deepEqual(result.items.map((x) => x.item.title), ['A', 'A', 'C']);
  assert.equal(result.items[1]!.duplicate, true);
  assert.deepEqual(result.errors.map((x) => x.row), [3, 5]);
});
test('I-01 CSVの大きな1アイテムはエラーにして次の行を続ける', () => {
  const csv = `name,url,username,password\nHuge,https://a.example,u,${'あ'.repeat(22000)}\nOK,https://b.example,u,p\n`;
  const result = importCsvPreview(csv, 'chrome');
  assert.equal(result.errors.length, 1);
  assert.equal(result.items[0]!.item.title, 'OK');
});

test('I-02 閉じ忘れの引用符を報告し、次の物理行の正常な行を残す', () => {
  const result = importCsvPreview('name,url,username,password\n"Broken,https://bad.example,u,p\nGood,https://good.example,u,p\n', 'chrome');
  assert.deepEqual(result.errors.map((e) => e.row), [2]);
  assert.deepEqual(result.items.map((x) => x.item.title), ['Good']);
});

