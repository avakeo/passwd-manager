import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generatePassword, passwordAlphabetSize, passwordEntropyBits } from '../../src/client/password.ts';

test('C-11 既定の20文字と指定長・文字種・紛らわしい文字の除外', () => {
  assert.equal(generatePassword().length, 20);
  const value = generatePassword({ length: 96, lower: true, upper: false, digits: false, symbols: false, excludeAmbiguous: true });
  assert.match(value, /^[a-km-z]{96}$/);
  const mixed = generatePassword({ length: 80, lower: true, upper: true, digits: true, symbols: true });
  assert.match(mixed, /[a-z]/);
  assert.match(mixed, /[A-Z]/);
  assert.match(mixed, /[0-9]/);
  assert.match(mixed, /[^a-zA-Z0-9]/);
  assert.equal(mixed.length, 80);
});

test('C-11 棄却サンプリングの偏り検査：3文字集合で各頻度が妥当な範囲', () => {
  const counts = new Map([['a', 0], ['b', 0], ['c', 0]]);
  // 指定した集合だけを使う入口を通す。256 は3で割り切れないため余りを捨てる必要がある。
  const output = generatePassword({ length: 60_000, alphabet: 'abc' });
  for (const ch of output) counts.set(ch, counts.get(ch)! + 1);
  for (const count of counts.values()) assert.ok(count > 19_300 && count < 20_700, `count=${count}`);
});

test('C-11 指定の失敗条件とエントロピー表示用の値', () => {
  assert.throws(() => generatePassword({ length: 0 }));
  assert.throws(() => generatePassword({ length: 1.2 }));
  assert.throws(() => generatePassword({ lower: false, upper: false, digits: false, symbols: false }));
  assert.throws(() => generatePassword({ alphabet: 'aa' }));
  assert.equal(passwordEntropyBits(20, 2), 20);
  assert.ok(passwordEntropyBits(20, 62) > 119);
});

test('C-11 有効な文字種は短いパスワードでも各1文字以上含む', () => {
  for (let i = 0; i < 100; i++) {
    const value = generatePassword({ length: 4 });
    assert.match(value, /[a-z]/);
    assert.match(value, /[A-Z]/);
    assert.match(value, /[0-9]/);
    assert.match(value, /[^a-zA-Z0-9]/);
  }
  assert.throws(() => generatePassword({ length: 3 }));
});

test('C-11 作り直し後も有効な文字列の並びに偏りがない', () => {
  let lowerFirst = 0;
  const samples = 8_000;
  for (let i = 0; i < samples; i++) {
    const value = generatePassword({ length: 2, lower: true, upper: true, digits: false, symbols: false });
    assert.match(value, /[a-z]/);
    assert.match(value, /[A-Z]/);
    if (/^[a-z]/.test(value)) lowerFirst++;
  }
  assert.ok(lowerFirst > 3_800 && lowerFirst < 4_200, `lowerFirst=${lowerFirst}`);
});



test('C-11 強度の表示に使う、使える文字の数（生成と同じ文字の集合から数える）', () => {
  assert.equal(passwordAlphabetSize({}), 26 + 26 + 10 + 22);
  assert.equal(passwordAlphabetSize({ excludeAmbiguous: true }), 26 + 26 + 10 + 22 - 5);
  assert.equal(passwordAlphabetSize({ lower: false, upper: false, symbols: false }), 10);
  assert.equal(passwordAlphabetSize({ lower: false, upper: false, digits: false, symbols: false }), 0);
  for (const options of [{}, { excludeAmbiguous: true }, { symbols: false, length: 12 }]) {
    const p = generatePassword(options);
    assert.ok(new Set(p).size <= passwordAlphabetSize(options));
  }
});
