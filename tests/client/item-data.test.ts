import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateItem, type LoginItem } from '../../src/client/item-data.ts';

const login: LoginItem = { type: 'login', title: 'Wiki', username: 'a@b.test', password: 'pw', urls: ['https://wiki.example.com'], notes: '', customFields: [
  { type: 'text', label: '担当', value: 'A' },
  { type: 'hidden', label: 'PIN', value: '1234' },
  { type: 'date', label: '期限', value: '2028-02-29' },
] };

test('I-02 E-12 テキスト・非表示・日付の項目を持つログインとメモを受け付ける', () => {
  assert.deepEqual(validateItem(login), login);
  assert.deepEqual(validateItem({ type: 'note', title: 'memo', body: 'hello' }), { type: 'note', title: 'memo', body: 'hello' });
});
test('I-02 項目の型、未知のプロパティ、日付の厳密さを検査', () => {
  assert.throws(() => validateItem({ ...login, customFields: [{ type: 'date', label: 'x', value: '2027-02-29' }] }));
  assert.throws(() => validateItem({ ...login, customFields: [{ type: 'password', label: 'x', value: 'abc' }] }));
  assert.throws(() => validateItem({ ...login, customFields: [{ type: 'hidden', label: 'x', value: 123 }] }));
  assert.throws(() => validateItem({ ...login, surprise: true }));
  assert.throws(() => validateItem({ ...login, customFields: [...login.customFields, ...Array(20).fill(login.customFields[0])] }));
  assert.deepEqual(validateItem({ ...login, urls: ['https://wiki.example.com/path'] }), { ...login, urls: ['https://wiki.example.com/path'] });
  for (const url of ['http://wiki.example.com', 'javascript:alert(1)', 'data:text/html,hi']) {
    assert.throws(() => validateItem({ ...login, urls: [url] }));
  }
});
test('I-01 UTF-8のJSONを最大65532バイトで制限', () => {
  assert.throws(() => validateItem({ type: 'note', title: '長い', body: 'あ'.repeat(22_000) }), /too large/i);
  assert.equal(validateItem({ type: 'note', title: '短い', body: 'あ'.repeat(1000) }).type, 'note');
});

test('I-02 検査した値だけを新しいオブジェクトと配列へ写す', () => {
  const input = structuredClone(login);
  const checked = validateItem(input) as LoginItem;
  assert.deepEqual(checked, input);
  assert.ok(checked !== input);
  assert.ok(checked.urls !== input.urls);
  assert.ok(checked.customFields !== input.customFields);
  assert.ok(checked.customFields[0] !== input.customFields[0]);
  const note = { type: 'note', title: 'Memo', body: 'text' };
  assert.ok(validateItem(note) !== note);
});

test('I-02 Stringオブジェクトなど文字列以外のカスタム項目の種類は拒否する', () => {
  assert.throws(() => validateItem({ ...login, customFields: [{ type: new String('hidden'), label: 'PIN', value: '1234' }] }));
  assert.throws(() => validateItem({ ...login, customFields: [{ type: 'hidden', label: new String('PIN'), value: '1234' }] }));
});

