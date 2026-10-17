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

test('E-10 E-12 改行コードと末尾改行の違いだけなら同じコピーと判定する', () => {
  const args = { copiedText: 'first\nsecond', currentText: 'first\r\nsecond\r\n', copiedAt: 0, now: 60_000 };
  assert.equal(shouldClearClipboard(args), true);
  assert.equal(shouldClearClipboard({ ...args, currentText: 'first\r\nchanged\r\n' }), false);
  assert.equal(shouldClearClipboard({ ...args, copiedText: '\n', currentText: '' }), false);
});
