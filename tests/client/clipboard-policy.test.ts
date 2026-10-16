import { test } from 'node:test';
import assert from 'node:assert/strict';
import { shouldClearClipboard } from '../../src/client/clipboard-policy.ts';

test('E-10 E-12 コピー後1分以上で中身が同じ場合だけ消す', () => {
  const args = { copiedText: 'secret', currentText: 'secret', copiedAt: 1000, now: 61000 };
  assert.equal(shouldClearClipboard(args), true);
  assert.equal(shouldClearClipboard({ ...args, now: 60999 }), false);
  assert.equal(shouldClearClipboard({ ...args, currentText: 'another copy' }), false);
  assert.equal(shouldClearClipboard({ ...args, currentText: '' }), false);
  assert.equal(shouldClearClipboard({ ...args, copiedText: '' }), false);
  assert.equal(shouldClearClipboard({ ...args, copiedAt: Number.NaN }), false);
  assert.equal(shouldClearClipboard({ ...args, now: 999 }), false);
});
