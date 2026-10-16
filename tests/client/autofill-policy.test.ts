import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canAutofill, originForSavedUrl } from '../../src/client/autofill-policy.ts';

const ok = { popupInitiated: true, unlocked: true, topFrame: true, tabId: 7, expectedTabId: 7, documentId: 'doc1', expectedDocumentId: 'doc1', pageUrl: 'https://wiki.example.com/login', livePageUrl: 'https://wiki.example.com/next', savedOrigins: ['https://wiki.example.com'] };
test('E-01 E-04 URLはパスとクエリを捨て、HTTPSのオリジンとポートだけを比較', () => {
  assert.equal(originForSavedUrl('https://wiki.example.com:443/login?q=1'), 'https://wiki.example.com');
  assert.equal(canAutofill(ok), true);
  assert.equal(canAutofill({ ...ok, savedOrigins: ['https://other.example.com', 'https://wiki.example.com'] }), true);
  assert.equal(canAutofill({ ...ok, savedOrigins: ['https://wiki.example.com:8443'] }), false);
  assert.equal(canAutofill({ ...ok, pageUrl: 'https://wiki.example.com:8443/login', livePageUrl: 'https://wiki.example.com:8443/login' }), false);
  assert.equal(canAutofill({ ...ok, pageUrl: 'https://wiki.example.com.evil.test', livePageUrl: 'https://wiki.example.com.evil.test' }), false);
});
test('E-02 E-03 E-05 iframe・HTTP・wwwの違いは拒否', () => {
  assert.equal(canAutofill({ ...ok, topFrame: false }), false);
  assert.equal(canAutofill({ ...ok, pageUrl: 'http://wiki.example.com', livePageUrl: 'http://wiki.example.com' }), false);
  assert.equal(canAutofill({ ...ok, pageUrl: 'https://www.wiki.example.com', livePageUrl: 'https://www.wiki.example.com' }), false);
  assert.throws(() => originForSavedUrl('http://wiki.example.com'));
  assert.throws(() => originForSavedUrl('https://user:pass@wiki.example.com'));
});
test('E-07 E-11 E-13 操作・ロック・タブと文書の固定・入力直前の再確認', () => {
  assert.equal(canAutofill({ ...ok, popupInitiated: false }), false);
  assert.equal(canAutofill({ ...ok, unlocked: false }), false);
  assert.equal(canAutofill({ ...ok, tabId: 8 }), false);
  assert.equal(canAutofill({ ...ok, documentId: 'doc2' }), false);
  assert.equal(canAutofill({ ...ok, livePageUrl: 'https://evil.test' }), false);
  assert.equal(canAutofill({ ...ok, livePageUrl: 'https://wiki.example.com.evil.test' }), false);
});
