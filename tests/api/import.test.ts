// フェーズ5：CSV インポートの一括作成（POST /v1/items/import）。仕様書「CSVインポート」「JSONによる一括処理」。
// 1回の送信は500件・1.5MB まで。1つのバッチなので、全部入るか全部入らないかのどちらか。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fakeCiphertext, setup } from '../helpers/api.ts';
import { toBase64Url } from '../../src/crypto/bytes.ts';

function ids(n: number, prefix = 'A'): string[] {
  return Array.from({ length: n }, (_, i) => `item_${prefix}${String(i).padStart(21, '0')}`);
}

function body(list: string[], cipher = fakeCiphertext()) {
  return { vault_key_version: 1, items: list.map((id) => ({ id, ciphertext: cipher })) };
}

function count(t: ReturnType<typeof setup>): number {
  return Number(t.db.db.prepare('SELECT COUNT(*) AS n FROM items').get()!.n);
}

async function status(res: Response, expected: number) {
  assert.equal(res.status, expected);
  if (expected >= 400) assert.match(res.headers.get('content-type') ?? '', /^application\/problem\+json/);
}

test('M-04 500件を1回の送信で作る。Vault リビジョンは1だけ増え、全部が同じ change_seq とリビジョン1で入る', async () => {
  const t = setup();
  const alice = await t.addMember('active');
  const before = t.vaultRevision();
  const res = await t.request('POST', '/v1/items/import', alice.token, body(ids(500)));
  await status(res, 201);
  assert.deepEqual(await res.json(), { count: 500, revision: 1 });
  assert.equal(count(t), 500);
  assert.equal(t.vaultRevision(), before + 1);
  const rows = t.db.db.prepare('SELECT DISTINCT revision, change_seq, created_by, vault_key_version FROM items').all();
  assert.deepEqual(rows.map((r) => ({ ...r })), [{ revision: 1, change_seq: before + 1, created_by: alice.id, vault_key_version: 1 }]);
  // 監査ログは1件ずつ
  assert.equal(Number(t.db.db.prepare(`SELECT COUNT(*) AS n FROM audit_logs WHERE action = 'item.import'`).get()!.n), 500);
  // 差分同期で、ほかの人にも全部見える
  const sync = (await (await t.request('GET', '/v1/items?after=0', (await t.addMember('active')).token)).json()) as { items: unknown[] };
  assert.equal(sync.items.length, 500);
});

test('M-04 501件、または1.5MB を超える送信は 413 で、1件も入らない', async () => {
  const t = setup();
  const alice = await t.addMember('active');
  await status(await t.request('POST', '/v1/items/import', alice.token, body(ids(501))), 413);
  // 64KB 段の暗号文（約 87KB）を18件で 1.5MB を超える
  const big = new Uint8Array(65536 + 30).fill(0x44);
  big[0] = 0x02;
  big[1] = 0x01;
  const cipher = toBase64Url(big);
  await status(await t.request('POST', '/v1/items/import', alice.token, body(ids(18), cipher)), 413);
  assert.equal(count(t), 0);
  // 17件（約 1.48MB）なら入る。ほかの入口の上限（約 96KB）より大きい本文を、この入口だけで受ける
  await status(await t.request('POST', '/v1/items/import', alice.token, body(ids(17), cipher)), 201);
  assert.equal(count(t), 17);
});

test('I-03 既存の ID が1つでも混ざれば 409 で、ほかの行も入らない（1つのバッチ）', async () => {
  const t = setup();
  const alice = await t.addMember('active');
  const [first] = ids(1, 'Z');
  await status(await t.request('POST', '/v1/items', alice.token, { id: first, vault_key_version: 1, ciphertext: fakeCiphertext() }), 201);
  const before = t.vaultRevision();
  await status(await t.request('POST', '/v1/items/import', alice.token, body([...ids(10), first!])), 409);
  assert.equal(count(t), 1);
  assert.equal(t.vaultRevision(), before);
  assert.equal(Number(t.db.db.prepare(`SELECT COUNT(*) AS n FROM audit_logs WHERE action = 'item.import'`).get()!.n), 0);
});

test('I-02 送信の中で ID が重なる、暗号文の形が違う、想定外の項目がある、空の配列は 400 で、1件も入らない', async () => {
  const t = setup();
  const alice = await t.addMember('active');
  const [a, b] = ids(2);
  const bad = [
    body([a!, a!]),
    { vault_key_version: 1, items: [{ id: a, ciphertext: fakeCiphertext() }, { id: b, ciphertext: 'AAAA' }] },
    { vault_key_version: 1, items: [{ id: a, ciphertext: fakeCiphertext(), revision: 1 }] },
    { vault_key_version: 1, items: [{ id: 'bad id', ciphertext: fakeCiphertext() }] },
    { vault_key_version: 1, items: [] },
    { vault_key_version: 1, items: 'x' },
    { items: [{ id: a, ciphertext: fakeCiphertext() }] },
  ];
  for (const b of bad) await status(await t.request('POST', '/v1/items/import', alice.token, b), 400);
  assert.equal(count(t), 0);
});

test('鍵の世代が今のものと違えば 409（ローテーションの後の古い世代では入れない）', async () => {
  const t = setup();
  const alice = await t.addMember('active');
  await status(await t.request('POST', '/v1/items/import', alice.token, { ...body(ids(2)), vault_key_version: 2 }), 409);
  assert.equal(count(t), 0);
});

test('I-01 ほかの入口の本文の上限は、今までどおり（POST /v1/items に 1.5MB 近い本文は 413）', async () => {
  const t = setup();
  const alice = await t.addMember('active');
  const res = await t.request('POST', '/v1/items', alice.token, { id: ids(1)[0], vault_key_version: 1, ciphertext: 'A'.repeat(1_000_000) });
  await status(res, 413);
});
