import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fakeCiphertext, setup } from '../helpers/api.ts';

const ITEM_ID = 'item_AAAAAAAAAAAAAAAAAAAAAA';

async function json(res: Response) {
  return (await res.json()) as Record<string, unknown>;
}

async function expectProblem(res: Response, status: number) {
  assert.equal(res.status, status);
  assert.match(res.headers.get('content-type') ?? '', /^application\/problem\+json/);
  const body = await json(res);
  assert.equal(body.status, status);
  assert.equal(typeof body.title, 'string');
  return body;
}

async function createItem(t: ReturnType<typeof setup>, token: string, id = ITEM_ID) {
  const res = await t.request('POST', '/v1/items', token, { id, vault_key_version: 1, ciphertext: fakeCiphertext() });
  assert.equal(res.status, 201);
  return json(res);
}

// ---- S-01 楽観的ロック ----

test('S-01 古いリビジョンでの更新は 409 になり、書き換わらない', async () => {
  const t = setup();
  const alice = await t.addMember('active');
  const bob = await t.addMember('active');
  await createItem(t, alice.token);

  // 2人とも revision 1 を元に編集する。先に保存した alice が勝つ
  const first = await t.request('PUT', `/v1/items/${ITEM_ID}`, alice.token, {
    revision: 1,
    vault_key_version: 1,
    ciphertext: fakeCiphertext(0x11),
  });
  assert.equal(first.status, 200);
  assert.equal((await json(first)).revision, 2);
  const revisionAfterFirst = t.vaultRevision();

  const stale = await t.request('PUT', `/v1/items/${ITEM_ID}`, bob.token, {
    revision: 1,
    vault_key_version: 1,
    ciphertext: fakeCiphertext(0x22),
  });
  await expectProblem(stale, 409);

  // alice の内容のまま。Vault リビジョンも増えていない
  const row = t.db.db.prepare('SELECT revision, ciphertext FROM items WHERE id = ?').get(ITEM_ID)!;
  assert.equal(row.revision, 2);
  assert.equal(row.ciphertext, fakeCiphertext(0x11));
  assert.equal(t.vaultRevision(), revisionAfterFirst);
});

test('S-01 古いリビジョンでの削除は 409 になり、消えない', async () => {
  const t = setup();
  const alice = await t.addMember('active');
  await createItem(t, alice.token);
  await t.request('PUT', `/v1/items/${ITEM_ID}`, alice.token, { revision: 1, vault_key_version: 1, ciphertext: fakeCiphertext(0x11) });

  await expectProblem(await t.request('DELETE', `/v1/items/${ITEM_ID}`, alice.token, { revision: 1 }), 409);
  const row = t.db.db.prepare('SELECT deleted_at, ciphertext FROM items WHERE id = ?').get(ITEM_ID)!;
  assert.equal(row.deleted_at, null);
  assert.equal(row.ciphertext, fakeCiphertext(0x11));
});

test('S-01 正しいリビジョンなら更新でき、Vault リビジョンが1増える', async () => {
  const t = setup();
  const alice = await t.addMember('active');
  await createItem(t, alice.token);
  const before = t.vaultRevision();
  const res = await t.request('PUT', `/v1/items/${ITEM_ID}`, alice.token, { revision: 1, vault_key_version: 1, ciphertext: fakeCiphertext(0x33) });
  assert.equal(res.status, 200);
  assert.equal(t.vaultRevision(), before + 1);
});

test('存在しないアイテムの更新は 404', async () => {
  const t = setup();
  const alice = await t.addMember('active');
  await expectProblem(
    await t.request('PUT', `/v1/items/${ITEM_ID}`, alice.token, { revision: 1, vault_key_version: 1, ciphertext: fakeCiphertext() }),
    404,
  );
});

test('S-02 S-10 削除すると暗号文が消え、差分同期に削除が含まれる', async () => {
  const t = setup();
  const alice = await t.addMember('active');
  await createItem(t, alice.token);
  const del = await t.request('DELETE', `/v1/items/${ITEM_ID}`, alice.token, { revision: 1 });
  assert.equal(del.status, 200);
  const row = t.db.db.prepare('SELECT ciphertext, deleted_at FROM items WHERE id = ?').get(ITEM_ID)!;
  assert.equal(row.ciphertext, null);
  assert.notEqual(row.deleted_at, null);
  const list = await json(await t.request('GET', '/v1/items?after=0', alice.token));
  const items = list.items as { id: string; deleted: boolean; ciphertext: string | null }[];
  assert.deepEqual(items.map((i) => [i.id, i.deleted, i.ciphertext]), [[ITEM_ID, true, null]]);
});

test('S-02 差分同期は change_seq（書いたときの Vault リビジョン）で取り、同じミリ秒に書かれたものも取りこぼさない', async () => {
  const t = setup();
  const alice = await t.addMember('active');
  const realNow = Date.now;
  const frozen = realNow();
  Date.now = () => frozen; // 2つの書き込みも、間の読み出しも、同じミリ秒
  try {
    await createItem(t, alice.token, 'item_AAAAAAAAAAAAAAAAAAAAAA');
    const first = await json(await t.request('GET', '/v1/items?after=0', alice.token));
    const firstItems = first.items as { id: string; change_seq: number }[];
    assert.deepEqual(firstItems.map((i) => i.id), ['item_AAAAAAAAAAAAAAAAAAAAAA']);
    const cursor = firstItems[0]!.change_seq;
    assert.equal(cursor, first.vault_revision);
    await createItem(t, alice.token, 'item_BBBBBBBBBBBBBBBBBBBBBB');
    const second = await json(await t.request('GET', `/v1/items?after=${cursor}`, alice.token));
    assert.deepEqual((second.items as { id: string }[]).map((i) => i.id), ['item_BBBBBBBBBBBBBBBBBBBBBB'], '同じミリ秒の2件目も取れる');
    // 削除も change_seq が進み、次の差分に入る
    await t.request('DELETE', '/v1/items/item_AAAAAAAAAAAAAAAAAAAAAA', alice.token, { revision: 1 });
    const third = await json(await t.request('GET', `/v1/items?after=${(second.items as { change_seq: number }[])[0]!.change_seq}`, alice.token));
    assert.deepEqual((third.items as { id: string; deleted: boolean }[]).map((i) => [i.id, i.deleted]), [['item_AAAAAAAAAAAAAAAAAAAAAA', true]]);
  } finally {
    Date.now = realNow;
  }
  assert.equal((await t.request('GET', '/v1/items?after=x', alice.token)).status, 400);
});

test('I-03 既存のアイテムIDで新規作成すると 409', async () => {
  const t = setup();
  const alice = await t.addMember('active');
  await createItem(t, alice.token);
  const before = t.vaultRevision();
  await expectProblem(
    await t.request('POST', '/v1/items', alice.token, { id: ITEM_ID, vault_key_version: 1, ciphertext: fakeCiphertext() }),
    409,
  );
  assert.equal(t.vaultRevision(), before);
});

test('I-01 サイズ上限を超える本文は 413', async () => {
  const t = setup();
  const alice = await t.addMember('active');
  const huge = 'A'.repeat(200_000);
  await expectProblem(await t.request('POST', '/v1/items', alice.token, { id: ITEM_ID, vault_key_version: 1, ciphertext: huge }), 413);
});

test('I-02 I-05 不正な JSON、型違い、不正な ID は 400 で、内部の情報を含まない', async () => {
  const t = setup();
  const alice = await t.addMember('active');
  const bad = [
    '{"id":',
    { id: ITEM_ID, vault_key_version: '1', ciphertext: fakeCiphertext() },
    { id: 'item_a|b', vault_key_version: 1, ciphertext: fakeCiphertext() },
    { id: ITEM_ID, vault_key_version: 1, ciphertext: 'not base64url!' },
    { id: ITEM_ID, vault_key_version: 1, ciphertext: fakeCiphertext(), extra: 1 },
    { id: ITEM_ID, vault_key_version: 1, ciphertext: 'AQE' }, // パディング単位でない長さ
  ];
  for (const body of bad) {
    const problem = await expectProblem(await t.request('POST', '/v1/items', alice.token, body), 400);
    assert.ok(!/sqlite|SQL|stack|at \w+ \(/i.test(JSON.stringify(problem)), JSON.stringify(problem));
  }
});

test('現在の世代でない Vault 鍵で暗号化したアイテムは 409', async () => {
  const t = setup();
  const alice = await t.addMember('active');
  await expectProblem(
    await t.request('POST', '/v1/items', alice.token, { id: ITEM_ID, vault_key_version: 2, ciphertext: fakeCiphertext() }),
    409,
  );
});

// ---- Z-01 認可 ----

test('Z-01 承認待ちのメンバーがアイテムや Vault を取得すると 403', async () => {
  const t = setup();
  const active = await t.addMember('active');
  await createItem(t, active.token);
  const pending = await t.addMember('pending');
  await expectProblem(await t.request('GET', '/v1/items?after=0', pending.token), 403);
  await expectProblem(await t.request('GET', '/v1/vault', pending.token), 403);
  await expectProblem(
    await t.request('POST', '/v1/items', pending.token, { id: 'item_BBBBBBBBBBBBBBBBBBBBBB', vault_key_version: 1, ciphertext: fakeCiphertext() }),
    403,
  );
  await expectProblem(
    await t.request('PUT', `/v1/items/${ITEM_ID}`, pending.token, { revision: 1, vault_key_version: 1, ciphertext: fakeCiphertext() }),
    403,
  );
  await expectProblem(await t.request('DELETE', `/v1/items/${ITEM_ID}`, pending.token, { revision: 1 }), 403);
  // 承認済みのメンバーは取得できる
  assert.equal((await t.request('GET', '/v1/items?after=0', active.token)).status, 200);
});

test('Z-06 削除済みのメンバーの操作は 403', async () => {
  const t = setup();
  const removed = await t.addMember('removed');
  await expectProblem(await t.request('GET', '/v1/items?after=0', removed.token), 403);
  await expectProblem(await t.request('GET', '/v1/vault', removed.token), 403);
});

test('Z-07 Web ページ用（読み取り専用）のトークンで書き込むと 403', async () => {
  const t = setup();
  const web = await t.addMember('active', { scope: 'web' });
  assert.equal((await t.request('GET', '/v1/items?after=0', web.token)).status, 200);
  await expectProblem(
    await t.request('POST', '/v1/items', web.token, { id: ITEM_ID, vault_key_version: 1, ciphertext: fakeCiphertext() }),
    403,
  );
});

test('A-05 A-06 トークンなし、知らないトークン、期限切れ、無効化されたセッションは 401', async () => {
  const t = setup();
  const alice = await t.addMember('active');
  const bob = await t.addMember('active');
  const carol = await t.addMember('active');
  t.db.db.prepare('UPDATE sessions SET expires_at = 1 WHERE member_id = ?').run(bob.id);
  t.db.db.prepare('UPDATE sessions SET revoked_at = 1 WHERE member_id = ?').run(carol.id);
  await expectProblem(await t.request('GET', '/v1/items?after=0'), 401);
  await expectProblem(await t.request('GET', '/v1/items?after=0', 'unknown-token'), 401);
  await expectProblem(await t.request('GET', '/v1/items?after=0', bob.token), 401);
  await expectProblem(await t.request('GET', '/v1/items?after=0', carol.token), 401);
  assert.equal((await t.request('GET', '/v1/items?after=0', alice.token)).status, 200);
});

test('W-01 W-02 CORS は https://pw.example.com だけを許可する', async () => {
  const t = setup();
  const pre = (origin: string) =>
    t.app.request(
      '/v1/items',
      { method: 'OPTIONS', headers: { Origin: origin, 'Access-Control-Request-Method': 'GET', 'Access-Control-Request-Headers': 'authorization' } },
      { DB: t.db },
    );
  assert.equal((await pre('https://pw.example.com')).headers.get('access-control-allow-origin'), 'https://pw.example.com');
  for (const origin of ['https://evil.example.com', 'https://pw.example.com.evil.test', 'http://pw.example.com']) {
    assert.equal((await pre(origin)).headers.get('access-control-allow-origin'), null, origin);
  }
});
