// フェーズ2b：アイテムの一覧・作成・編集・削除、同期と 409（docs/実装状況.md の10章）。
// 偽の chrome と本物の API（app.request ＋ SQLite）をつなぐ。2つの端末は、同じサーバーにつないだ2つの偽の chrome。

import { after, beforeEach, mock, test } from 'node:test';
import assert from 'node:assert/strict';
import { IDLE_LOCK_MS } from '../../src/extension/background/background.ts';
import { POPUP, adminReady, newDiscord, secondDevice, send, world, type World } from '../helpers/extension-world.ts';
import { fakeCiphertext } from '../helpers/api.ts';
import { API_ORIGIN, newDiscordUser } from '../helpers/extension-world.ts';
import { referenceTotp, stepAt, base32ToBytes } from '../helpers/totp-reference.ts';
import { chromeTrustStorage } from '../../src/extension/background/storage.ts';
import { fromBase64Url, toBase64Url } from '../../src/crypto/bytes.ts';
import { createAdminKey } from '../../src/crypto/member-key.ts';
import { createGrant } from '../../src/crypto/grant.ts';
import { encryptItem } from '../../src/crypto/item.ts';
import { MemoryPinStore, pinPublicKey } from '../../src/crypto/public-key.ts';
import { openTrust, pinSigner } from '../../src/crypto/signer.ts';
import { generateVaultKeyRaw, importVaultKey } from '../../src/crypto/vault-key.ts';
import { newTrust } from '../helpers/trust.ts';

const T0 = 1_800_000_000_000;
mock.timers.enable({ apis: ['Date'], now: T0 });
after(() => mock.timers.reset());
beforeEach(() => mock.timers.setTime(T0));
const MIN = 60 * 1000;

const discord = newDiscord();
after(discord.install());

const LOGIN = {
  type: 'login',
  title: '社内 Wiki',
  username: 'team@example.com',
  password: 'correct-horse-battery-staple',
  urls: ['https://wiki.example.com/login?next=/'],
  notes: 'メモ',
  customFields: [{ type: 'hidden', label: 'PIN', value: '0420' }],
};

type Summary = { id: string; type: string; title: string; username?: string; urls?: string[]; unreadable: boolean; revision: number };

async function list(w: World): Promise<Summary[]> {
  const r = await send(w, { type: 'listItems' });
  assert.equal(r.ok, true, JSON.stringify(r));
  return r.items as Summary[];
}

async function create(w: World, item: Record<string, unknown> = LOGIN): Promise<string> {
  const r = await send(w, { type: 'saveItem', item });
  assert.equal(r.ok, true, JSON.stringify(r));
  return String(r.id);
}

test('I-01 I-02 アイテムを作ると、一覧にはパスワードを出さず、1件を開いたときだけ中身を返す。D1 と storage.local には暗号文だけ', async () => {
  const w = world(discord);
  await adminReady(w, discord);
  const id = await create(w);
  assert.match(id, /^item_[A-Za-z0-9_-]{22}$/, 'ID は Service Worker が作る');
  const items = await list(w);
  assert.deepEqual(items.map((i) => [i.id, i.title, i.username, i.unreadable]), [[id, '社内 Wiki', 'team@example.com', false]]);
  assert.ok(!JSON.stringify(items).includes(LOGIN.password) && !JSON.stringify(items).includes('0420'), '一覧にパスワードと非表示の項目がない');
  const one = await send(w, { type: 'getItem', id });
  assert.deepEqual(one.item, LOGIN);
  assert.equal(one.revision, 1);
  // サーバーと端末の保存には、平文がない
  const stored = JSON.stringify(w.t.db.db.prepare('SELECT * FROM items').all()) + w.chrome.storage.local.dump() + w.chrome.storage.session.dump();
  for (const plain of [LOGIN.title, LOGIN.username, LOGIN.password, 'wiki.example.com', '0420']) assert.ok(!stored.includes(plain), plain);
});

test('I-01 I-02 形の違うアイテム、https 以外の URL、大きすぎるアイテムは、送る前に断る', async () => {
  const w = world(discord);
  await adminReady(w, discord);
  w.calls.length = 0;
  const bad: Record<string, unknown>[] = [
    { ...LOGIN, extra: 1 },
    { ...LOGIN, urls: ['http://wiki.example.com/'] },
    { ...LOGIN, urls: ['javascript:alert(1)'] },
    { ...LOGIN, title: '' },
    { ...LOGIN, customFields: [{ type: 'date', label: '期限', value: '2026-02-30' }] },
    { ...LOGIN, notes: 'x'.repeat(70_000) }, // 65,532バイトを超える
    { type: 'note', title: 'メモ', body: 1 },
  ];
  for (const [i, item] of bad.entries()) assert.equal((await send(w, { type: 'saveItem', item })).error, 'BAD_REQUEST', `${i}`);
  assert.deepEqual(w.calls.filter((c) => c.includes('/v1/items')), [], 'API には送っていない');
});

test('HTML として解釈しない：タグを含む中身は、そのままの文字列で保存して読み戻す', async () => {
  const w = world(discord);
  await adminReady(w, discord);
  const tricky = { type: 'note', title: '<img src=x onerror=alert(1)>', body: '<script>alert(1)</script>&amp;' };
  const id = await create(w, tricky);
  assert.equal((await list(w))[0]!.title, tricky.title);
  assert.deepEqual((await send(w, { type: 'getItem', id })).item, tricky);
});

test('S-02 S-10 もう一方の端末の削除は、次の同期で一覧から消え、手元のキャッシュからも暗号文が消える', async () => {
  const a = world(discord);
  const admin = await adminReady(a, discord);
  const id = await create(a);
  const cached = () => [...a.chrome.storage.local.values.entries()].filter(([k]) => k.startsWith('teampw/v1/sync|')).map(([, v]) => JSON.stringify(v)).join('');
  assert.ok(cached().includes(id));
  const b = await secondDevice(a, discord, admin.userId, admin.secret);
  assert.equal((await send(b, { type: 'sync' })).ok, true);
  assert.deepEqual((await list(b)).map((i) => i.id), [id]);
  assert.equal((await send(b, { type: 'deleteItem', id, revision: 1 })).ok, true);
  assert.equal((await send(a, { type: 'sync' })).ok, true);
  assert.deepEqual(await list(a), []);
  assert.ok(!cached().includes(id), 'キャッシュに暗号文が残らない');
});

test('S-01 2つの端末で同じアイテムを編集すると、後の方は 409 で上書きせず、今の版を返す。利用者が選んだときだけ上書きする', async () => {
  const a = world(discord);
  const admin = await adminReady(a, discord);
  const id = await create(a);
  const b = await secondDevice(a, discord, admin.userId, admin.secret);
  await send(b, { type: 'sync' });
  assert.equal((await send(a, { type: 'saveItem', id, revision: 1, item: { ...LOGIN, title: 'A の変更' } })).ok, true);
  const conflict = await send(b, { type: 'saveItem', id, revision: 1, item: { ...LOGIN, title: 'B の変更' } });
  assert.deepEqual([conflict.ok, conflict.error], [false, 'CONFLICT']);
  assert.equal((conflict.current as { title: string }).title, 'A の変更', '今の版を返す');
  assert.equal(conflict.currentRevision, 2);
  // 上書きされていない
  await send(a, { type: 'sync' });
  assert.equal(((await send(a, { type: 'getItem', id })).item as { title: string }).title, 'A の変更');
  // B の利用者が「自分の内容で上書きする」を選んだ
  assert.equal((await send(b, { type: 'saveItem', id, revision: 2, item: { ...LOGIN, title: 'B の変更' } })).ok, true);
  await send(a, { type: 'sync' });
  assert.equal(((await send(a, { type: 'getItem', id })).item as { title: string }).title, 'B の変更');
  // B の上書きでリビジョンは3。今のリビジョンでなら削除できる
  const del = await send(a, { type: 'deleteItem', id, revision: 3 });
  assert.equal(del.ok, true, JSON.stringify(del));
});

test('S-01 古いリビジョンでの削除は 409 で、今の版を返し、消さない', async () => {
  const a = world(discord);
  const admin = await adminReady(a, discord);
  const id = await create(a);
  const b = await secondDevice(a, discord, admin.userId, admin.secret);
  await send(b, { type: 'sync' });
  assert.equal((await send(a, { type: 'saveItem', id, revision: 1, item: { ...LOGIN, title: '新しい' } })).ok, true);
  const del = await send(b, { type: 'deleteItem', id, revision: 1 });
  assert.deepEqual([del.ok, del.error, del.currentRevision], [false, 'CONFLICT', 2]);
  assert.equal(Number(a.t.db.db.prepare('SELECT COUNT(*) AS n FROM items WHERE deleted_at IS NULL').get()!.n), 1);
});

test('S-09 サーバーが、最後に見たものより古い Vault リビジョンを返したら、同期を止めて警告し、キャッシュを書き換えない', async () => {
  const w = world(discord);
  await adminReady(w, discord);
  await create(w);
  await create(w, { type: 'note', title: '2件目', body: '' });
  assert.equal((await send(w, { type: 'sync' })).ok, true);
  const before = w.chrome.storage.local.dump();
  // 巻き戻した応答（古い Vault リビジョンで、アイテムが1件消えている）
  w.rewrite = async (call, res) => {
    if (call !== 'GET /v1/items') return null;
    const body = (await res.json()) as Record<string, unknown>;
    return Response.json({ ...body, vault_revision: 1, items: [] });
  };
  const r = await send(w, { type: 'sync' });
  assert.deepEqual([r.ok, r.error], [false, 'ROLLBACK_DETECTED']);
  assert.equal(w.chrome.storage.local.dump(), before);
  assert.equal((await list(w)).length, 2);
});

test('同期は放置のロックを延ばさない：sync と listItems だけを送り続けても、最後の操作から15分でロックされる', async () => {
  const w = world(discord);
  await adminReady(w, discord);
  let lockedAt: number | null = null;
  for (let ms = IDLE_LOCK_MS - 1000; ms <= 60 * MIN; ms += IDLE_LOCK_MS - 1000) {
    mock.timers.setTime(T0 + ms);
    await send(w, { type: 'sync' });
    await send(w, { type: 'listItems' });
    if ((await send(w, { type: 'status' }, POPUP)).locked === true) {
      lockedAt = ms;
      break;
    }
  }
  assert.equal(lockedAt, 2 * (IDLE_LOCK_MS - 1000));
  // 1件を開く（getItem）は利用者の操作なので延ばす
  const v = world(discord);
  await adminReady(v, discord);
  const id = await create(v);
  mock.timers.setTime(T0 + IDLE_LOCK_MS - 1000);
  await send(v, { type: 'getItem', id });
  mock.timers.setTime(T0 + 2 * (IDLE_LOCK_MS - 1000));
  assert.equal((await send(v, { type: 'status' }, POPUP)).locked, false);
});

test('E-11 ロック中は、アイテムの一覧・取得・保存・削除・同期を断る', async () => {
  const w = world(discord);
  await adminReady(w, discord);
  const id = await create(w);
  await send(w, { type: 'lock' }, POPUP);
  for (const m of [{ type: 'listItems' }, { type: 'getItem', id }, { type: 'saveItem', item: LOGIN }, { type: 'deleteItem', id, revision: 1 }, { type: 'sync' }]) {
    assert.equal((await send(w, m)).error, 'LOCKED', m.type);
  }
});

test('I-02 復号できない、または形の合わないアイテムは「読めないアイテム」として ID だけを出す', async () => {
  const w = world(discord);
  await adminReady(w, discord);
  // サーバーに、形だけ正しい別物の暗号文が入っていた
  w.t.db.db
    .prepare(`INSERT INTO items (id, revision, vault_key_version, ciphertext, created_by, created_at, updated_by, updated_at, change_seq)
              VALUES ('item_ZZZZZZZZZZZZZZZZZZZZZZ', 1, 1, ?, 'x', 0, 'x', 0, 99)`)
    .run(fakeCiphertext());
  assert.equal((await send(w, { type: 'sync' })).ok, true);
  const items = await list(w);
  assert.deepEqual(items.map((i) => [i.id, i.unreadable, i.title]), [['item_ZZZZZZZZZZZZZZZZZZZZZZ', true, '']]);
  assert.equal((await send(w, { type: 'getItem', id: 'item_ZZZZZZZZZZZZZZZZZZZZZZ' })).error, 'UNREADABLE');
});

test('I-02 正しく復号できても、中身の形が合わないアイテム（知らない項目、http の URL）は「読めないアイテム」にする', async () => {
  // Vault 鍵をテストの側で持つため、管理者と最初の Vault をテストの中で作り、メンバーの端末を承認済みにする
  const w = world(discord);
  const admin = await w.t.addMember('active', { role: 'admin' });
  const adminKey = await createAdminKey('admin-hoshi-sora-umi-42');
  w.t.db.db
    .prepare(`INSERT INTO member_keys (id, member_id, ecdh_public_key, encrypted_private_key, ecdsa_public_key, encrypted_sign_private_key,
                                       kdf_algorithm, kdf_params, kdf_salt, format_version, status, created_at)
              VALUES (?, ?, ?, ?, ?, ?, 'PBKDF2-HMAC-SHA256', '{"iterations":600000,"normalization":"NFC"}', ?, 1, 'active', 0)`)
    .run(adminKey.record.keyId, admin.id, toBase64Url(adminKey.record.publicKey), toBase64Url(adminKey.record.encryptedPrivateKey),
      toBase64Url(adminKey.record.signPublicKey), toBase64Url(adminKey.record.encryptedSignPrivateKey), toBase64Url(adminKey.record.kdf.salt));
  w.t.db.db.exec(`INSERT INTO vault_meta (id, current_vault_key_version, vault_revision, schema_version) VALUES (1, 1, 0, 1);
                  INSERT INTO vault_key_versions (version, status, created_by, created_at) VALUES (1, 'current', NULL, 0)`);
  const userId = newDiscordUser(discord);
  w.chrome.loginAs = userId;
  await send(w, { type: 'login', deviceLabel: 'テスト端末' }, POPUP);
  const start = await send(w, { type: 'totpSetupStart' });
  await send(w, { type: 'totpSetupConfirm', code: referenceTotp(base32ToBytes(String(start.secret).replace(/ /g, '')), stepAt(Date.now())) });
  const MEMBER_PASSWORD = 'member-kawa-mori-yama-18';
  await send(w, { type: 'createKey', masterPassword: MEMBER_PASSWORD, replace: false });
  const memberId = String(w.t.db.db.prepare('SELECT id FROM members WHERE discord_user_id = ?').get(userId)!.id);
  const row = w.t.db.db.prepare(`SELECT id, ecdh_public_key AS pk FROM member_keys WHERE member_id = ? AND status = 'active'`).get(memberId)!;
  const raw = generateVaultKeyRaw();
  const vaultKey = await importVaultKey(raw.slice());
  const adminTrust = newTrust(admin.id);
  await pinSigner(adminTrust, { memberId: admin.id, keyId: adminKey.record.keyId, publicKey: adminKey.record.signPublicKey }, 1);
  const pins = new MemoryPinStore();
  const recipient = { keyId: String(row.id), publicKey: fromBase64Url(String(row.pk)) };
  await pinPublicKey(pins, memberId, recipient);
  const grant = await createGrant({ pins, signer: { memberId: admin.id, keyId: adminKey.record.keyId, privateKey: adminKey.signPrivateKey, trust: adminTrust }, memberId, recipient, vaultKeyVersion: 1, vaultKeyRaw: raw });
  w.t.db.db
    .prepare(`INSERT INTO vault_key_grants (vault_key_version, recipient_key_id, ephemeral_public_key, wrapped_key, signer_key_id, signature, format_version, created_at) VALUES (1, ?, ?, ?, ?, ?, 1, 0)`)
    .run(grant.recipientKeyId, toBase64Url(grant.ephemeralPublicKey), toBase64Url(grant.wrappedKey), grant.signerKeyId, toBase64Url(grant.signature));
  w.t.db.db.prepare(`UPDATE members SET status = 'active' WHERE id = ?`).run(memberId);
  await pinSigner(openTrust(chromeTrustStorage(w.chrome.storage.local), { apiOrigin: API_ORIGIN, memberId }), { memberId: admin.id, keyId: adminKey.record.keyId, publicKey: adminKey.record.signPublicKey }, 1);
  await send(w, { type: 'lock' }, POPUP);
  assert.equal((await send(w, { type: 'unlock', masterPassword: MEMBER_PASSWORD }, POPUP)).vault, 'ready');
  // 本物の Vault 鍵で暗号化したが、形の合わない中身（知らない項目、http の URL）
  const bad: [string, Record<string, unknown>][] = [
    ['item_SSSSSSSSSSSSSSSSSSSSSS', { type: 'note', title: '形が違う', body: '', script: '<img onerror=x>' }],
    ['item_TTTTTTTTTTTTTTTTTTTTTT', { type: 'login', title: 'http', username: '', password: 'p', urls: ['http://evil.example.com/'], notes: '', customFields: [] }],
  ];
  for (const [i, [id, content]] of bad.entries()) {
    const ct = await encryptItem(vaultKey, { itemId: id, vaultKeyVersion: 1 }, content as { type: 'note' });
    w.t.db.db
      .prepare(`INSERT INTO items (id, revision, vault_key_version, ciphertext, created_by, created_at, updated_by, updated_at, change_seq) VALUES (?, 1, 1, ?, 'x', 0, 'x', 0, ?)`)
      .run(id, toBase64Url(ct), 50 + i);
  }
  assert.equal((await send(w, { type: 'sync' })).ok, true);
  const items = await list(w);
  assert.deepEqual(items.map((i) => [i.id, i.unreadable]).sort(), bad.map(([id]) => [id, true]).sort());
  for (const [id] of bad) assert.equal((await send(w, { type: 'getItem', id })).error, 'UNREADABLE');
});
