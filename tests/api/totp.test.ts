// TOTP の中身（RFC 6238）、シークレットの暗号化、回復コード、ステップアップの判定。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  RECOVERY_CODE_BYTES,
  base32Decode,
  base32Encode,
  decryptTotpSecret,
  encryptTotpSecret,
  hashRecoveryCode,
  newRecoveryCodes,
  newTotpSecret,
  otpauthUri,
  totpCode,
  verifyTotp,
} from '../../src/api/totp.ts';
import { requireRecentTotp, STEP_UP_WINDOW_MS } from '../../src/api/auth.ts';
import { HttpProblem } from '../../src/api/problem.ts';
import { fromBase64Url, toBase64Url, utf8 } from '../../src/crypto/bytes.ts';
import { CryptoError } from '../../src/crypto/errors.ts';
import { base32ToBytes, referenceTotp } from '../helpers/totp-reference.ts';

const KEY = toBase64Url(new Uint8Array(32).fill(7));

// RFC 6238 付録 B（SHA-1）。シークレットは ASCII の "12345678901234567890"
const RFC_SECRET = utf8('12345678901234567890');
const RFC_VECTORS: [number, string][] = [
  [59, '94287082'],
  [1111111109, '07081804'],
  [1111111111, '14050471'],
  [1234567890, '89005924'],
  [2000000000, '69279037'],
  [20000000000, '65353130'],
];

test('TOTP の計算が RFC 6238 付録 B のテストベクタ（SHA-1、8桁）と一致し、6桁はその下6桁になる', async () => {
  for (const [t, code] of RFC_VECTORS) {
    const step = Math.floor(t / 30);
    assert.equal(await totpCode(RFC_SECRET, step, 8), code, `T=${t}`);
    assert.equal(await totpCode(RFC_SECRET, step), code.slice(2), `T=${t}（6桁）`);
  }
});

test('TOTP の検証は前後1ステップまで許し、最後に使ったステップ以前は拒否する（A-09 の中身）', async () => {
  const secret = newTotpSecret();
  const now = 1_800_000_000_000;
  const step = Math.floor(now / 30000);
  for (const d of [-1, 0, 1]) assert.equal(await verifyTotp(secret, referenceTotp(secret, step + d), now, null), step + d, `ずれ ${d}`);
  for (const d of [-2, 2]) assert.equal(await verifyTotp(secret, referenceTotp(secret, step + d), now, null), null, `ずれ ${d}`);
  // 最後に使ったステップと同じ・それより前のコードは拒否
  assert.equal(await verifyTotp(secret, referenceTotp(secret, step), now, step), null);
  assert.equal(await verifyTotp(secret, referenceTotp(secret, step - 1), now, step), null);
  assert.equal(await verifyTotp(secret, referenceTotp(secret, step + 1), now, step), step + 1);
  // 形の違うコード
  for (const bad of ['', '12345', '1234567', 'abcdef', ' 123456', '12345６']) assert.equal(await verifyTotp(secret, bad, now, null), null, bad);
});

test('TOTP のシークレットは乱数20バイトで、base32 と otpauth の URI で渡す', () => {
  const a = newTotpSecret();
  assert.equal(a.length, 20);
  assert.notDeepEqual(newTotpSecret(), a);
  assert.deepEqual(base32Decode(base32Encode(a)), a);
  assert.deepEqual(base32ToBytes(base32Encode(a)), a); // テスト側の読み方とも一致
  assert.equal(base32Encode(utf8('12345678901234567890')), 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
  const uri = new URL(otpauthUri(a, 'メンバー1'));
  assert.equal(uri.protocol, 'otpauth:');
  assert.equal(uri.searchParams.get('secret'), base32Encode(a));
  assert.equal(uri.searchParams.get('algorithm'), 'SHA1');
  assert.equal(uri.searchParams.get('digits'), '6');
  assert.equal(uri.searchParams.get('period'), '30');
  assert.equal(uri.searchParams.get('issuer'), 'teampw');
});

test('TOTP のシークレットの暗号文は、先頭に形式（0x01）とアルゴリズムID（0x01 AES-256-GCM）を持ち、AAD にメンバーID が入る', async () => {
  const secret = newTotpSecret();
  const env = await encryptTotpSecret(KEY, 'member_1', secret, 'totp-secret');
  const bytes = fromBase64Url(env);
  assert.equal(bytes[0], 0x01, '形式');
  assert.equal(bytes[1], 0x01, 'アルゴリズムID');
  assert.equal(bytes.length, 2 + 12 + 20 + 16, '形式、アルゴリズムID、ノンス、20バイトの暗号文、認証タグ');
  assert.deepEqual(await decryptTotpSecret(KEY, 'member_1', env, 'totp-secret'), secret);
  // 同じシークレットでも、ノンスは毎回乱数なので暗号文は変わる
  assert.notEqual(await encryptTotpSecret(KEY, 'member_1', secret, 'totp-secret'), env);

  const isCode = (code: string) => (e: unknown) => e instanceof CryptoError && e.code === code;
  // 別のメンバーの行へ移す、登録途中の列へ移す、鍵が違う → 復号に失敗
  await assert.rejects(decryptTotpSecret(KEY, 'member_2', env, 'totp-secret'), isCode('DECRYPT_FAILED'));
  await assert.rejects(decryptTotpSecret(KEY, 'member_1', env, 'totp-pending-secret'), isCode('DECRYPT_FAILED'));
  await assert.rejects(decryptTotpSecret(toBase64Url(new Uint8Array(32).fill(8)), 'member_1', env, 'totp-secret'), isCode('DECRYPT_FAILED'));
  // 知らない形式・アルゴリズムID は、復号を試さずに拒否
  for (const i of [0, 1]) {
    const b = bytes.slice();
    b[i] = 0x02;
    await assert.rejects(decryptTotpSecret(KEY, 'member_1', toBase64Url(b), 'totp-secret'), isCode('UNSUPPORTED_FORMAT'), `先頭${i}`);
  }
  // 鍵の長さが32バイトでなければ、暗号化も復号もしない
  await assert.rejects(encryptTotpSecret(toBase64Url(new Uint8Array(16)), 'member_1', secret, 'totp-secret'), isCode('INVALID_INPUT'));
});

test('回復コードは10個で、それぞれ80ビット以上の乱数から作り、ハッシュは区切りと大文字小文字によらない', async () => {
  assert.ok(RECOVERY_CODE_BYTES * 8 >= 80);
  const codes = newRecoveryCodes();
  assert.equal(codes.length, 10);
  assert.equal(new Set(codes).size, 10);
  for (const c of codes) {
    assert.match(c, /^[A-Z2-7]{4}(-[A-Z2-7]{4})+$/);
    assert.ok(base32ToBytes(c.replace(/-/g, '')).length >= 10, `${c} は80ビット以上`);
  }
  // たくさん作っても重ならない
  const many = new Set<string>();
  for (let i = 0; i < 200; i++) for (const c of newRecoveryCodes()) many.add(c);
  assert.equal(many.size, 2000);
  assert.equal(await hashRecoveryCode(codes[0]!), await hashRecoveryCode(codes[0]!.toLowerCase().replace(/-/g, '')));
  assert.notEqual(await hashRecoveryCode(codes[0]!), await hashRecoveryCode(codes[1]!));
  assert.match(await hashRecoveryCode(codes[0]!), /^[0-9a-f]{64}$/);
});

test('A-10 管理操作の直前の TOTP の再確認：5分以内に確かめたセッションだけを通す（判定の単体テスト）', () => {
  const now = 1_800_000_000_000;
  assert.equal(STEP_UP_WINDOW_MS, 5 * 60 * 1000);
  const isForbidden = (e: unknown) => e instanceof HttpProblem && e.status === 403;
  assert.throws(() => requireRecentTotp({ totpVerifiedAt: null }, now), isForbidden, '一度も確かめていない');
  assert.throws(() => requireRecentTotp({ totpVerifiedAt: now - STEP_UP_WINDOW_MS - 1 }, now), isForbidden, '5分より前');
  assert.throws(() => requireRecentTotp({ totpVerifiedAt: now + 60_000 }, now), isForbidden, '未来の時刻');
  requireRecentTotp({ totpVerifiedAt: now - STEP_UP_WINDOW_MS }, now);
  requireRecentTotp({ totpVerifiedAt: now }, now);
});
