// フェーズ4b：ローテーション（POST /v1/vault/rotate）。仕様書「メンバーの削除とローテーション」「ローテーションの1リクエスト化」。
// 1回のリクエスト・1つのバッチ。先頭の rotation_guard で、Vault リビジョン、アイテムの集合（リビジョン込み）、グラントの宛先の集合を確かめる。
// テスト S-03〜S-08、A-10、Z-02。サーバーは暗号文を読まないので、アイテムの暗号文は形だけ正しいもので足りる。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createAdminKey, createMemberKey } from '../../src/crypto/member-key.ts';
import { createGrant, type GrantSigner } from '../../src/crypto/grant.ts';
import { MemoryPinStore, pinPublicKey } from '../../src/crypto/public-key.ts';
import { pinSigner } from '../../src/crypto/signer.ts';
import { generateVaultKeyRaw } from '../../src/crypto/vault-key.ts';
import { newTrust } from '../helpers/trust.ts';
import { fakeCiphertext, setup } from '../helpers/api.ts';
import { grantBody, insertKey } from '../helpers/vault-admin.ts';

const adminKey = await createAdminKey('admin-hoshi-sora-umi-42');
const cKey = await createMemberKey('c-san-kawa-mori-yama-18');
const dKey = await createMemberKey('d-san-kawa-mori-yama-19');
const v1 = generateVaultKeyRaw();
const v2 = generateVaultKeyRaw();

type Setup = ReturnType<typeof setup>;
const ITEMS = ['item_AAAAAAAAAAAAAAAAAAAAAA', 'item_BBBBBBBBBBBBBBBBBBBBBB', 'item_CCCCCCCCCCCCCCCCCCCCCC'];

// 管理者と C さん（承認済み）、D さん（承認待ち）。アイテム3件（1件は2回更新）と、削除済み1件
async function world() {
  const t = setup();
  const admin = await t.addMember('active', { role: 'admin', totpVerifiedAt: Date.now() });
  const c = await t.addMember('active');
  const d = await t.addMember('pending');
  insertKey(t, admin.id, adminKey.record);
  insertKey(t, c.id, cKey.record);
  insertKey(t, d.id, dKey.record);
  const trust = newTrust(admin.id);
  await pinSigner(trust, { memberId: admin.id, keyId: adminKey.record.keyId, publicKey: adminKey.record.signPublicKey }, 1);
  const signer: GrantSigner = { memberId: admin.id, keyId: adminKey.record.keyId, privateKey: adminKey.signPrivateKey, trust };
  const pins = new MemoryPinStore();
  const people = { [admin.id]: adminKey.record, [c.id]: cKey.record, [d.id]: dKey.record };
  for (const [id, rec] of Object.entries(people)) await pinPublicKey(pins, id, { keyId: rec.keyId, publicKey: rec.publicKey });
  const grantFor = async (memberId: string, version: number, raw: Uint8Array) => {
    const rec = people[memberId]!;
    return grantBody(await createGrant({ pins, signer, memberId, recipient: { keyId: rec.keyId, publicKey: rec.publicKey }, vaultKeyVersion: version, vaultKeyRaw: raw as never }));
  };
  for (const id of [admin.id, c.id]) {
    const b = await grantFor(id, 1, v1);
    t.db.db
      .prepare(`INSERT INTO vault_key_grants (vault_key_version, recipient_key_id, ephemeral_public_key, wrapped_key, signer_key_id, signature, format_version, created_at) VALUES (1, ?, ?, ?, ?, ?, 1, 0)`)
      .run(b.recipient_key_id, b.ephemeral_public_key, b.wrapped_key, b.signer_key_id, b.signature);
  }
  for (const id of ITEMS) assert.equal((await t.request('POST', '/v1/items', admin.token, { id, vault_key_version: 1, ciphertext: fakeCiphertext() })).status, 201);
  await t.request('PUT', `/v1/items/${ITEMS[1]}`, admin.token, { revision: 1, vault_key_version: 1, ciphertext: fakeCiphertext(0x11) });
  await t.request('POST', '/v1/items', admin.token, { id: 'item_DDDDDDDDDDDDDDDDDDDDDD', vault_key_version: 1, ciphertext: fakeCiphertext() });
  await t.request('DELETE', '/v1/items/item_DDDDDDDDDDDDDDDDDDDDDD', admin.token, { revision: 1 });
  // 管理者が取得した状態から作る、正しいローテーションの中身
  const body = async (overrides: Record<string, unknown> = {}) => {
    const rows = t.db.db.prepare('SELECT id, revision FROM items WHERE deleted_at IS NULL ORDER BY id').all() as { id: string; revision: number }[];
    return {
      from_vault_revision: t.vaultRevision(),
      vault_key_version: 2,
      items: rows.map((r) => ({ id: r.id, revision: r.revision + 1, ciphertext: fakeCiphertext(0x77) })),
      grants: [await grantFor(admin.id, 2, v2), await grantFor(c.id, 2, v2)],
      ...overrides,
    };
  };
  return { t, admin, c, d, body, grantFor };
}

function snapshot(t: Setup) {
  return JSON.stringify({
    items: t.db.db.prepare('SELECT * FROM items ORDER BY id').all(),
    grants: t.db.db.prepare('SELECT * FROM vault_key_grants ORDER BY vault_key_version, recipient_key_id').all(),
    meta: t.db.db.prepare('SELECT * FROM vault_meta').all(),
    versions: t.db.db.prepare('SELECT * FROM vault_key_versions').all(),
  });
}

const rotate = (t: Setup, token: string, b: unknown) => t.request('POST', '/v1/vault/rotate', token, b);

test('ローテーション：新しい世代を登録し、全アイテムをリビジョン+1で書き換え、全員分のグラントを置き、古い世代のグラントを消す', async () => {
  const { t, admin, c, body } = await world();
  const before = t.vaultRevision();
  const res = await rotate(t, admin.token, await body());
  assert.equal(res.status, 200, await res.clone().text());
  assert.deepEqual(await res.json(), { vault_key_version: 2, vault_revision: before + 1 });
  const meta = t.db.db.prepare('SELECT current_vault_key_version, vault_revision FROM vault_meta').get()!;
  assert.deepEqual({ ...meta }, { current_vault_key_version: 2, vault_revision: before + 1 });
  const items = t.db.db.prepare('SELECT id, revision, vault_key_version, ciphertext, change_seq, deleted_at FROM items ORDER BY id').all() as Record<string, unknown>[];
  for (const it of items.filter((i) => i.deleted_at === null)) {
    assert.deepEqual([it.vault_key_version, it.ciphertext, it.change_seq], [2, fakeCiphertext(0x77), before + 1], String(it.id));
  }
  assert.deepEqual(items.map((i) => i.revision), [2, 3, 2, 2], 'B は2回目の更新で2、削除済みの D はそのまま');
  assert.equal(items.find((i) => i.deleted_at !== null)!.vault_key_version, 1, '削除済みは書き換えない');
  assert.deepEqual(t.db.db.prepare('SELECT DISTINCT vault_key_version AS v FROM vault_key_grants').all().map((r) => r.v), [2], 'S-06 古い世代のグラントは残らない');
  assert.deepEqual(t.db.db.prepare('SELECT version, status FROM vault_key_versions ORDER BY version').all().map((r) => ({ ...r })), [{ version: 1, status: 'retired' }, { version: 2, status: 'current' }]);
  // C さんは新しい世代のグラントを受け取る。差分同期で書き換えたアイテムも届く
  const vault = (await (await t.request('GET', '/v1/vault', c.token)).json()) as { current_vault_key_version: number; grant: { vault_key_version: number } };
  assert.deepEqual([vault.current_vault_key_version, vault.grant.vault_key_version], [2, 2]);
  const sync = (await (await t.request('GET', `/v1/items?after=${before}`, c.token)).json()) as { items: unknown[] };
  assert.equal(sync.items.length, 3);
  assert.equal(Number(t.db.db.prepare(`SELECT COUNT(*) AS n FROM audit_logs WHERE action = 'vault.rotate'`).get()!.n), 1);
  // 古い世代では、もう書けない
  assert.equal((await t.request('POST', '/v1/items', c.token, { id: 'item_EEEEEEEEEEEEEEEEEEEEEE', vault_key_version: 1, ciphertext: fakeCiphertext() })).status, 409);
});

test('S-04 アイテムのリビジョンが1件でも食い違えば、1行も更新せず 409', async () => {
  const { t, admin, body } = await world();
  const b = await body();
  b.items[1] = { ...b.items[1]!, revision: b.items[1]!.revision - 1 };
  const before = snapshot(t);
  assert.equal((await rotate(t, admin.token, b)).status, 409);
  assert.equal(snapshot(t), before);
});

test('S-07 管理者が取得した後に、アイテムが足された・消された・更新されたら 409', async () => {
  for (const change of ['add', 'delete', 'update'] as const) {
    const { t, admin, body } = await world();
    const b = await body();
    if (change === 'add') await t.request('POST', '/v1/items', admin.token, { id: 'item_FFFFFFFFFFFFFFFFFFFFFF', vault_key_version: 1, ciphertext: fakeCiphertext() });
    if (change === 'delete') await t.request('DELETE', `/v1/items/${ITEMS[0]}`, admin.token, { revision: 1 });
    if (change === 'update') await t.request('PUT', `/v1/items/${ITEMS[2]}`, admin.token, { revision: 1, vault_key_version: 1, ciphertext: fakeCiphertext(0x12) });
    const before = snapshot(t);
    assert.equal((await rotate(t, admin.token, b)).status, 409, change);
    assert.equal(snapshot(t), before, change);
  }
});

test('S-07 Vault リビジョンが取得したときと違えば、アイテムの集合が同じでも 409。アイテムを抜く・足すのも 409', async () => {
  const { t, admin, body } = await world();
  const b = await body();
  assert.equal((await rotate(t, admin.token, { ...b, from_vault_revision: b.from_vault_revision - 1 })).status, 409);
  assert.equal((await rotate(t, admin.token, { ...b, items: b.items.slice(1) })).status, 409);
  assert.equal((await rotate(t, admin.token, { ...b, items: [...b.items, { id: 'item_DDDDDDDDDDDDDDDDDDDDDD', revision: 3, ciphertext: fakeCiphertext(0x77) }] })).status, 409, '削除済みを含める');
});

test('S-08 グラントの宛先の集合が、有効なメンバーの鍵の集合と違えば 409（取得の後の承認・削除、抜け、余分）', async () => {
  const { t, admin, c, d, body, grantFor } = await world();
  const b = await body();
  assert.equal((await rotate(t, admin.token, { ...b, grants: b.grants.slice(0, 1) })).status, 409, 'C さんの分がない');
  assert.equal((await rotate(t, admin.token, { ...b, grants: [...b.grants, await grantFor(d.id, 2, v2)] })).status, 409, '承認待ちの D さんの分がある');
  // 取得の後に D さんが承認された
  t.db.db.prepare(`UPDATE members SET status = 'active' WHERE id = ?`).run(d.id);
  const before = snapshot(t);
  assert.equal((await rotate(t, admin.token, b)).status, 409);
  assert.equal(snapshot(t), before);
  // 取得の後に C さんが削除された
  t.db.db.prepare(`UPDATE members SET status = 'pending' WHERE id = ?`).run(d.id);
  t.db.db.prepare(`UPDATE members SET status = 'removed' WHERE id = ?`).run(c.id);
  assert.equal((await rotate(t, admin.token, b)).status, 409);
  // C さんが削除され、D さんが承認されて、数だけは同じ（宛先の中身で比べる）
  t.db.db.prepare(`UPDATE members SET status = 'active' WHERE id = ?`).run(d.id);
  assert.equal((await rotate(t, admin.token, b)).status, 409);
});

test('S-03 バッチの途中でエラーが起きたら、全体が元に戻る', async () => {
  const { t, admin, body } = await world();
  const b = await body();
  t.db.db.exec(`CREATE TRIGGER fail_grants BEFORE INSERT ON vault_key_grants WHEN NEW.vault_key_version = 2 BEGIN SELECT RAISE(ABORT, 'わざと'); END`);
  const before = snapshot(t);
  assert.equal((await rotate(t, admin.token, b)).status, 500);
  assert.equal(snapshot(t), before);
});

test('S-05 送信が 1.5MB を超えたら 413', async () => {
  const { t, admin, body } = await world();
  const b = await body();
  const big = 'A'.repeat(1_600_000);
  assert.equal((await rotate(t, admin.token, { ...b, padding: big })).status, 413);
});

test('グラントの形と署名を確かめる。署名が違う、世代が違う、世代を飛ばす、ID の重なりは断る', async () => {
  const { t, admin, c, body, grantFor } = await world();
  const b = await body();
  const g0 = b.grants[0]!;
  const badSig = { ...g0, signature: g0.signature.slice(0, 10) + (g0.signature[10] === 'A' ? 'B' : 'A') + g0.signature.slice(11) };
  assert.equal((await rotate(t, admin.token, { ...b, grants: [badSig, b.grants[1]] })).status, 400, '署名が違う（DeepSeek #2）');
  assert.equal((await rotate(t, admin.token, { ...b, grants: [{ ...g0, signature: 'AAAA' }, b.grants[1]] })).status, 400, '署名の長さとヘッダー（DeepSeek #9）');
  assert.equal((await rotate(t, admin.token, { ...b, vault_key_version: 3 })).status, 400, 'グラントの世代と違う');
  const skip = [await grantFor(admin.id, 3, v2), await grantFor(c.id, 3, v2)];
  assert.equal((await rotate(t, admin.token, { ...b, vault_key_version: 3, grants: skip })).status, 409, '世代を飛ばす');
  assert.equal((await rotate(t, admin.token, { ...b, grants: [b.grants[0], b.grants[0]] })).status, 400, '同じ宛先が2つ');
  assert.equal((await rotate(t, admin.token, { ...b, items: [b.items[0], b.items[0], b.items[2]] })).status, 400, '同じアイテムが2つ');
  assert.equal((await rotate(t, admin.token, { ...b, extra: 1 })).status, 400);
  assert.equal(t.vaultRevision(), b.from_vault_revision);
});

test('A-10 Z-02 ローテーションは、5分以内に TOTP を確かめた管理者だけ', async () => {
  const { t, c, body } = await world();
  const stale = await t.addMember('active', { role: 'admin', totpVerifiedAt: Date.now() - 6 * 60 * 1000 });
  const b = await body();
  assert.equal((await rotate(t, c.token, b)).status, 403);
  assert.equal((await rotate(t, stale.token, b)).status, 403);
});
