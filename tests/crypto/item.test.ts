import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decryptItem, encryptItem, MAX_ITEM_JSON_BYTES, PADDING_BUCKETS, type ItemContent } from '../../src/crypto/item.ts';
import { generateVaultKeyRaw, importVaultKey } from '../../src/crypto/vault-key.ts';
import { CryptoError } from '../../src/crypto/errors.ts';
import { encodeAeadEnvelope, itemAad, parseAeadEnvelope } from '../../src/crypto/format.ts';
import { toHex, utf8 } from '../../src/crypto/bytes.ts';

const ctx = { itemId: 'item_3c9a', vaultKeyVersion: 1, revision: 1 };
const login: ItemContent = {
  type: 'login',
  title: '社内Wiki',
  username: 'team@example.com',
  password: 'Tr7#qLm2!vX9pK',
  urls: ['https://wiki.example.com'],
  notes: '',
};
const OVERHEAD = 1 + 1 + 12 + 16; // 形式、アルゴリズムID、ノンス、認証タグ

async function newVaultKey() {
  return importVaultKey(generateVaultKeyRaw());
}

function isDecryptFailed(e: unknown) {
  return e instanceof CryptoError && e.code === 'DECRYPT_FAILED';
}

// 長さ n バイトの JSON になるアイテム
function itemOfJsonLength(n: number): ItemContent {
  const base = JSON.stringify({ type: 'note', title: '', body: '' }).length;
  return { type: 'note', title: '', body: 'x'.repeat(n - base) };
}

test('C-02 アイテムの暗号化と復号の往復で元に戻る', async () => {
  const key = await newVaultKey();
  const env = await encryptItem(key, ctx, login);
  assert.deepEqual(await decryptItem(key, ctx, env), login);
});

test('C-03 暗号文の本体を1ビット改ざんすると復号に失敗する', async () => {
  const key = await newVaultKey();
  const env = await encryptItem(key, ctx, login);
  env[2 + 12 + 100]! ^= 0x01;
  await assert.rejects(decryptItem(key, ctx, env), isDecryptFailed);
});

test('C-03 ノンスを1ビット改ざんすると復号に失敗する', async () => {
  const key = await newVaultKey();
  const env = await encryptItem(key, ctx, login);
  env[2]! ^= 0x80;
  await assert.rejects(decryptItem(key, ctx, env), isDecryptFailed);
});

test('C-03 認証タグを1ビット改ざんすると復号に失敗する', async () => {
  const key = await newVaultKey();
  const env = await encryptItem(key, ctx, login);
  env[env.length - 1]! ^= 0x01;
  await assert.rejects(decryptItem(key, ctx, env), isDecryptFailed);
});

test('C-03 どのバイトの1ビットを改ざんしても復号に失敗する（ヘッダー以外の全バイト）', async () => {
  const key = await newVaultKey();
  const env = await encryptItem(key, ctx, { type: 'note', title: 'a', body: '' });
  for (let i = 2; i < env.length; i++) {
    const tampered = env.slice();
    tampered[i]! ^= 1 << i % 8;
    await assert.rejects(decryptItem(key, ctx, tampered), isDecryptFailed, `byte ${i}`);
  }
});

test('C-04 暗号文を別のアイテムIDの場所に移すと復号に失敗する（AAD 不一致）', async () => {
  const key = await newVaultKey();
  const env = await encryptItem(key, ctx, login);
  await assert.rejects(decryptItem(key, { ...ctx, itemId: 'item_8e21' }, env), isDecryptFailed);
});

test('C-05 鍵の世代を書き換えると復号に失敗する', async () => {
  const key = await newVaultKey();
  const env = await encryptItem(key, ctx, login);
  await assert.rejects(decryptItem(key, { ...ctx, vaultKeyVersion: 2 }, env), isDecryptFailed);
});

test('C-26 AAD に入れたのと違うリビジョンで復号すると失敗する（古い暗号文の書き戻し。DeepSeek #1）', async () => {
  const key = await newVaultKey();
  const env = await encryptItem(key, { ...ctx, revision: 1 }, login);
  // 控えた revision 1 の暗号文を、サーバーが revision 3 の行として返す
  await assert.rejects(decryptItem(key, { ...ctx, revision: 3 }, env), isDecryptFailed);
  await assert.rejects(decryptItem(key, { ...ctx, revision: 2 }, env), isDecryptFailed);
  assert.deepEqual(await decryptItem(key, { ...ctx, revision: 1 }, env), login);
});

test('C-10 形式が v1（0x01）のアイテムは、復号を試さずに拒否する', async () => {
  const key = await newVaultKey();
  const env = await encryptItem(key, ctx, login);
  assert.equal(env[0], 0x02);
  env[0] = 0x01;
  await assert.rejects(decryptItem(key, ctx, env), (e: unknown) => e instanceof CryptoError && e.code === 'UNSUPPORTED_FORMAT');
});

test('別の Vault 鍵では復号に失敗する', async () => {
  const env = await encryptItem(await newVaultKey(), ctx, login);
  await assert.rejects(decryptItem(await newVaultKey(), ctx, env), isDecryptFailed);
});

test('C-08 大量に暗号化したときのノンスがすべて異なる', async () => {
  const key = await newVaultKey();
  const seen = new Set<string>();
  const N = 5000;
  for (let i = 0; i < N; i++) {
    const env = await encryptItem(key, ctx, login);
    seen.add(toHex(parseAeadEnvelope('item', env).nonce));
  }
  assert.equal(seen.size, N);
});

test('C-08 同じ内容を2回暗号化しても暗号文が異なる', async () => {
  const key = await newVaultKey();
  const a = await encryptItem(key, ctx, login);
  const b = await encryptItem(key, ctx, login);
  assert.notDeepEqual(a, b);
});

test('C-09 暗号文の長さはパディング単位のどれかにしかならない', async () => {
  const key = await newVaultKey();
  const allowed = new Set(PADDING_BUCKETS.map((b) => b + OVERHEAD));
  const lengths = [40, 100, 508, 509, 1020, 1021, 4092, 4093, 16380, 16381, 65532];
  const seen = new Set<number>();
  for (const n of lengths) {
    const env = await encryptItem(key, ctx, itemOfJsonLength(n));
    assert.ok(allowed.has(env.length), `JSON ${n}B -> ${env.length}B`);
    seen.add(env.length);
  }
  assert.deepEqual([...seen].sort((a, b) => a - b), PADDING_BUCKETS.map((b) => b + OVERHEAD));
});

test('C-09 短いメモと普通のログインは同じ長さ（512 段）になる', async () => {
  const key = await newVaultKey();
  const a = await encryptItem(key, ctx, { type: 'note', title: 'a', body: '' });
  const b = await encryptItem(key, ctx, login);
  assert.equal(a.length, 512 + OVERHEAD);
  assert.equal(b.length, 512 + OVERHEAD);
});

test('上限（JSON 65,532 バイト）を超えるアイテムは暗号化の前に拒否する', async () => {
  const key = await newVaultKey();
  assert.equal(MAX_ITEM_JSON_BYTES, 65532);
  await assert.rejects(
    encryptItem(key, ctx, itemOfJsonLength(65533)),
    (e: unknown) => e instanceof CryptoError && e.code === 'ITEM_TOO_LARGE',
  );
});

test('復号後の長さの値が範囲外なら失敗にする', async () => {
  // 正しい鍵と AAD で暗号化された、長さの値だけが壊れた平文を用意する
  const raw = generateVaultKeyRaw();
  const key = await importVaultKey(raw);
  const encKey = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']);
  for (const badLength of [509, 0xffffffff]) {
    const padded = new Uint8Array(512);
    new DataView(padded.buffer).setUint32(0, badLength);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: itemAad(ctx) }, encKey, padded),
    );
    await assert.rejects(decryptItem(key, ctx, encodeAeadEnvelope('item', nonce, ct)), isDecryptFailed);
  }
});

test('パディング単位でない大きさの平文は失敗にする', async () => {
  const raw = generateVaultKeyRaw();
  const key = await importVaultKey(raw);
  const encKey = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']);
  const body = utf8(JSON.stringify(login));
  const padded = new Uint8Array(4 + body.length); // 詰め物なし
  new DataView(padded.buffer).setUint32(0, body.length);
  padded.set(body, 4);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: itemAad(ctx) }, encKey, padded),
  );
  await assert.rejects(decryptItem(key, ctx, encodeAeadEnvelope('item', nonce, ct)), isDecryptFailed);
});

test('Vault 鍵は取り出し不可で読み込まれる', async () => {
  const key = await newVaultKey();
  assert.equal(key.extractable, false);
  await assert.rejects(crypto.subtle.exportKey('raw', key));
});
