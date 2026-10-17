// E-08 ポップアップ・全画面ページから Service Worker へのメッセージの入口。
// 送り元が自分の拡張機能のページでなければ、どんな中身でも処理しない。受け付ける種類と項目は表で固定する。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MESSAGE_SCHEMAS, acceptedSender, parseMessage } from '../../src/extension/background/messages.ts';
import { EXTENSION_ID } from '../helpers/fake-chrome.ts';

const runtime = { id: EXTENSION_ID, getURL: (p: string) => `chrome-extension://${EXTENSION_ID}/${p}` };
const POPUP = `chrome-extension://${EXTENSION_ID}/extension/popup/popup.html`;
const PAGE = `chrome-extension://${EXTENSION_ID}/extension/page/app.html`;

test('E-08 送り元：自分の拡張機能のポップアップと全画面ページだけを受け付ける', () => {
  assert.equal(acceptedSender(runtime, { id: EXTENSION_ID, url: POPUP }), true);
  assert.equal(acceptedSender(runtime, { id: EXTENSION_ID, url: `${PAGE}#sessions` }), true, '全画面ページの中の移動（ハッシュ）は同じページ');
  const rejected = [
    { id: EXTENSION_ID, url: 'https://evil.example.com/' }, // ページに注入したスクリプトやコンテンツスクリプト
    { id: EXTENSION_ID, url: 'https://pw-api.example.com/extension/popup/popup.html' },
    { id: 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz', url: POPUP.replace(EXTENSION_ID, 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz') }, // 別の拡張機能
    { id: 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz', url: POPUP },
    { id: EXTENSION_ID, url: `${POPUP}?type=unlock` }, // 自分のページでもクエリ付きは受け付けない
    { id: EXTENSION_ID, url: `chrome-extension://${EXTENSION_ID}/extension/other.html` },
    { id: EXTENSION_ID, url: 'not a url' },
    { id: EXTENSION_ID },
    { url: POPUP },
    {},
  ];
  for (const s of rejected) assert.equal(acceptedSender(runtime, s), false, JSON.stringify(s));
});

test('E-08 種類：表にある種類だけを、決めた項目と型で受け付ける', () => {
  assert.deepEqual(parseMessage({ type: 'status' }), { type: 'status' });
  assert.deepEqual(parseMessage({ type: 'unlock', masterPassword: 'x'.repeat(20) }), { type: 'unlock', masterPassword: 'x'.repeat(20) });
  assert.deepEqual(parseMessage({ type: 'loginTotp', code: '123456' }), { type: 'loginTotp', code: '123456' });
  assert.deepEqual(parseMessage({ type: 'loginTotp', recoveryCode: 'ABCD-EFGH-IJKL-MNOP' }), { type: 'loginTotp', recoveryCode: 'ABCD-EFGH-IJKL-MNOP' });
  const bad: unknown[] = [
    null,
    'status',
    [],
    { type: 'readSecrets' }, // 表にない種類
    { type: 'status', extra: 1 }, // 余分な項目
    { type: 'unlock' }, // 足りない
    { type: 'unlock', masterPassword: 1 }, // 型違い
    { type: 'unlock', masterPassword: 'x'.repeat(5000) }, // 長すぎる
    { type: 'loginTotp', code: '12345' },
    { type: 'loginTotp', code: '123456', recoveryCode: 'ABCD' }, // どちらか一方だけ
    { type: 'createKey', masterPassword: 'x'.repeat(20), replace: 'yes' },
    { type: 'revokeSession', sessionId: '../x' },
    { type: '__proto__' },
    { type: 'constructor' },
  ];
  for (const m of bad) assert.equal(parseMessage(m), null, JSON.stringify(m));
});

test('E-08 種類の表に、鍵やトークンを返す種類がない', () => {
  const names = Object.keys(MESSAGE_SCHEMAS).sort();
  assert.ok(names.every((n) => !/key|token|secret|export/i.test(n) || n === 'createKey'), names.join(','));
});
