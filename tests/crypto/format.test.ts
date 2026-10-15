import { test } from 'node:test';
import assert from 'node:assert/strict';
import { concat, fromBase64Url, fromHex, i2osp, toBase64Url, toHex, utf8 } from '../../src/crypto/bytes.ts';
import { newId } from '../../src/crypto/random.ts';
import {
  ALG_AES_256_GCM,
  ALG_HPKE_BASE,
  FORMAT_V1,
  assertId,
  encodeAeadEnvelope,
  encodeGrantEnvelope,
  itemAad,
  memberKeyAad,
  parseAeadEnvelope,
  parseGrantEnvelope,
} from '../../src/crypto/format.ts';
import { CryptoError } from '../../src/crypto/errors.ts';

const nonce = new Uint8Array(12).fill(7);
const body = new Uint8Array(32).fill(9);

function isCode(code: string) {
  return (e: unknown) => e instanceof CryptoError && e.code === code;
}

test('バイト列の変換が往復する', () => {
  const b = fromHex('00ff10');
  assert.equal(toHex(b), '00ff10');
  assert.deepEqual(fromBase64Url(toBase64Url(b)), b);
  assert.deepEqual(concat(utf8('ab'), utf8('c')), utf8('abc'));
  assert.deepEqual(i2osp(0x0010, 2), fromHex('0010'));
});

test('ID は乱数16バイトの base64url（22文字）に接頭辞を付けたもの', () => {
  const a = newId('item');
  const b = newId('key');
  assert.match(a, /^item_[A-Za-z0-9_-]{22}$/);
  assert.match(b, /^key_[A-Za-z0-9_-]{22}$/);
  assert.notEqual(newId('item'), a);
});

test('ID に区切り文字などが入ると拒否する', () => {
  assert.throws(() => assertId('item_a|b'), isCode('INVALID_INPUT'));
  assert.throws(() => assertId(''), isCode('INVALID_INPUT'));
  assert.throws(() => assertId('a'.repeat(65)), isCode('INVALID_INPUT'));
  assertId('key_7f3a');
});

test('AAD は v1|item|ID|世代 と v1|member-key|鍵ID', () => {
  assert.deepEqual(itemAad({ itemId: 'item_3c9a', vaultKeyVersion: 1 }), utf8('v1|item|item_3c9a|1'));
  assert.deepEqual(memberKeyAad({ keyId: 'key_7f3a' }), utf8('v1|member-key|key_7f3a'));
  assert.throws(() => itemAad({ itemId: 'item_3c9a', vaultKeyVersion: 0 }), isCode('INVALID_INPUT'));
  assert.throws(() => itemAad({ itemId: 'item_3c9a', vaultKeyVersion: 1.5 }), isCode('INVALID_INPUT'));
});

test('保存形式は 形式・アルゴリズムID・ノンス・暗号文 の順で往復する', () => {
  const env = encodeAeadEnvelope('item', nonce, body);
  assert.equal(env[0], FORMAT_V1);
  assert.equal(env[1], ALG_AES_256_GCM);
  assert.equal(env.length, 2 + 12 + 32);
  const parsed = parseAeadEnvelope('item', env);
  assert.deepEqual(parsed.nonce, nonce);
  assert.deepEqual(parsed.ciphertext, body);
});

test('グラントの保存形式はノンスを持たない', () => {
  const env = encodeGrantEnvelope(body);
  assert.equal(env[0], FORMAT_V1);
  assert.equal(env[1], ALG_HPKE_BASE);
  assert.equal(env.length, 2 + 32);
  assert.deepEqual(parseGrantEnvelope(env), body);
});

test('C-10 未知の形式バージョンは拒否される', () => {
  const env = encodeAeadEnvelope('item', nonce, body);
  env[0] = 0x02;
  assert.throws(() => parseAeadEnvelope('item', env), isCode('UNSUPPORTED_FORMAT'));
  const grant = encodeGrantEnvelope(body);
  grant[0] = 0x00;
  assert.throws(() => parseGrantEnvelope(grant), isCode('UNSUPPORTED_FORMAT'));
});

test('C-10 未知のアルゴリズムIDは拒否される', () => {
  const env = encodeAeadEnvelope('member-key', nonce, body);
  env[1] = 0x7f;
  assert.throws(() => parseAeadEnvelope('member-key', env), isCode('UNSUPPORTED_FORMAT'));
});

test('C-10 使う所が違うアルゴリズムID（アイテムに HPKE の 0x02、グラントに 0x01）は拒否される', () => {
  const env = encodeAeadEnvelope('item', nonce, body);
  env[1] = ALG_HPKE_BASE;
  assert.throws(() => parseAeadEnvelope('item', env), isCode('UNSUPPORTED_FORMAT'));
  const grant = encodeGrantEnvelope(body);
  grant[1] = ALG_AES_256_GCM;
  assert.throws(() => parseGrantEnvelope(grant), isCode('UNSUPPORTED_FORMAT'));
});

test('C-10 短すぎる保存形式は拒否される', () => {
  assert.throws(() => parseAeadEnvelope('item', new Uint8Array([FORMAT_V1, ALG_AES_256_GCM, 1, 2])), isCode('MALFORMED'));
  assert.throws(() => parseGrantEnvelope(new Uint8Array([FORMAT_V1])), isCode('MALFORMED'));
});
