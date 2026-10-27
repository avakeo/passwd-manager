// A-5 クイックロック解除の暗号（src/crypto/quick-unlock.ts）。拡張機能の通しのテストは tests/extension/quick-unlock.test.ts。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { openQuickUnlock, sealQuickUnlock, QUICK_UNLOCK_ITERATIONS } from '../../src/crypto/quick-unlock.ts';
import { encryptItem, decryptItem } from '../../src/crypto/item.ts';
import { importVaultKey } from '../../src/crypto/vault-key.ts';
import { CryptoError } from '../../src/crypto/errors.ts';

const ctx = { apiOrigin: 'https://pw-api.example.com', memberId: 'member_a', vaultKeyVersion: 3 };
const raw = new Uint8Array(32).fill(5);
const record = await sealQuickUnlock('2580', raw.slice(), ctx);

function code(e: unknown): string {
  return e instanceof CryptoError ? e.code : String(e);
}

test('A-5 パスコードで包んだ Vault 鍵は、同じパスコードで開くと、取り出し不可の同じ鍵になる', async () => {
  assert.equal(record.iterations, QUICK_UNLOCK_ITERATIONS);
  assert.equal(record.vaultKeyVersion, 3);
  const key = await openQuickUnlock('2580', record, ctx);
  assert.equal(key.extractable, false);
  // 元の鍵で暗号化したアイテムを、戻った鍵で開ける
  const original = await importVaultKey(raw.slice());
  const ct = await encryptItem(original, { itemId: 'item_x', vaultKeyVersion: 3, revision: 1 }, { type: 'note', title: 't', body: 'b' });
  assert.deepEqual(await decryptItem(key, { itemId: 'item_x', vaultKeyVersion: 3, revision: 1 }, ct), { type: 'note', title: 't', body: 'b' });
});

test('A-5 違うパスコード、別のメンバー・接続先の組では開けない（AAD）。世代を書き換えても開けない', async () => {
  for (const [name, p, c, r] of [
    ['パスコード', '0000', ctx, record],
    ['メンバー', '2580', { ...ctx, memberId: 'member_b' }, record],
    ['接続先', '2580', { ...ctx, apiOrigin: 'https://other.example.com' }, record],
    ['世代', '2580', ctx, { ...record, vaultKeyVersion: 4 }],
  ] as const) {
    await assert.rejects(openQuickUnlock(p, r, c), (e: unknown) => code(e) === 'DECRYPT_FAILED', name);
  }
});

test('A-5 反復回数やソルトを書き換えた保存は、重い計算の前に断る。パスコードは4桁の数字だけ', async () => {
  await assert.rejects(openQuickUnlock('2580', { ...record, iterations: 1000 }, ctx), (e: unknown) => code(e) === 'KDF_PARAMS_REJECTED');
  await assert.rejects(openQuickUnlock('2580', { ...record, salt: 'AAAA' }, ctx), (e: unknown) => code(e) === 'KDF_PARAMS_REJECTED');
  await assert.rejects(sealQuickUnlock('12345', raw.slice(), ctx), (e: unknown) => code(e) === 'INVALID_INPUT');
  await assert.rejects(sealQuickUnlock('12a4', raw.slice(), ctx), (e: unknown) => code(e) === 'INVALID_INPUT');
});
