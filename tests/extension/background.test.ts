// 拡張機能の Service Worker の処理を、偽の chrome（tests/helpers/fake-chrome.ts）と、本物の API（app.request ＋ SQLite）、
// 偽の Discord でつないで確かめる。ブラウザは使わない（ブラウザでの確認は docs/review/phase-2a.md の手で確かめる項目）。
// 時刻は mock.timers で固定する。TOTP の期待するコードは src を使わずに計算する。

import { after, beforeEach, mock, test } from 'node:test';
import assert from 'node:assert/strict';
import { createBackground, IDLE_LOCK_MS, type Background } from '../../src/extension/background/background.ts';
import { FakeDiscord } from '../helpers/fake-discord.ts';
import { FakeChrome } from '../helpers/fake-chrome.ts';
import { TEST_ENV, setup } from '../helpers/api.ts';
import { base32ToBytes, referenceTotp, stepAt } from '../helpers/totp-reference.ts';
import { chromeTrustStorage } from '../../src/extension/background/storage.ts';
import { fromBase64Url, toBase64Url } from '../../src/crypto/bytes.ts';
import { createAdminKey } from '../../src/crypto/member-key.ts';
import { createGrant } from '../../src/crypto/grant.ts';
import { MemoryPinStore, pinPublicKey } from '../../src/crypto/public-key.ts';
import { openTrust, pinSigner } from '../../src/crypto/signer.ts';
import { generateVaultKeyRaw } from '../../src/crypto/vault-key.ts';
import { newTrust } from '../helpers/trust.ts';

const T0 = 1_800_000_000_000;
mock.timers.enable({ apis: ['Date'], now: T0 });
after(() => mock.timers.reset());
beforeEach(() => mock.timers.setTime(T0));
const at = (ms: number) => mock.timers.setTime(T0 + ms);
const MIN = 60 * 1000;

const discord = new FakeDiscord({
  clientId: TEST_ENV.DISCORD_CLIENT_ID,
  clientSecret: TEST_ENV.DISCORD_CLIENT_SECRET,
  botToken: TEST_ENV.DISCORD_BOT_TOKEN,
  guildId: TEST_ENV.DISCORD_GUILD_ID,
});
after(discord.install());

const API_ORIGIN = 'https://pw-api.example.com';
const POPUP = 'extension/popup/popup.html';
const PAGE = 'extension/page/app.html';
const ADMIN_PASSWORD = 'admin-hoshi-sora-umi-42';
const MEMBER_PASSWORD = 'member-kawa-mori-yama-18';
let nextUser = 700000000000000000n;

type Gate = { arrived: Promise<void>; release: () => void };
type World = {
  t: ReturnType<typeof setup>;
  chrome: FakeChrome;
  bg: Background;
  responses: string[];
  calls: string[]; // 拡張機能が API に送った「メソッド パス」
  gates: Map<string, { arrive: () => void; released: Promise<void> }>;
  rewrite: ((call: string, res: Response) => Promise<Response | null>) | null;
};
type Reply = { ok: boolean; error?: string } & Record<string, unknown>;

function world(): World {
  const t = setup();
  // 本番と同じく、vault_meta の行は最初の Vault を作るときにできる
  t.db.db.exec('DELETE FROM vault_meta; DELETE FROM vault_key_versions');
  const chrome = new FakeChrome(discord);
  const w: World = { t, chrome, bg: null as unknown as Background, responses: [], calls: [], gates: new Map(), rewrite: null };
  w.bg = newBackground(w);
  return w;
}

// Service Worker を起動し直す（メモリは消え、chrome.storage は残る）
function newBackground(w: World): Background {
  return createBackground({
    chrome: w.chrome,
    apiOrigin: API_ORIGIN,
    discordClientId: TEST_ENV.DISCORD_CLIENT_ID,
    fetch: async (input, init) => {
      const url = new URL(String(input));
      assert.equal(url.origin, API_ORIGIN, 'API の接続先にだけ送る');
      const call = `${init.method ?? 'GET'} ${url.pathname}`;
      // 止めておく呼び出し（同時に起きることを、決まった順で作る）
      const gate = w.gates.get(call);
      if (gate) {
        w.gates.delete(call);
        gate.arrive();
        await gate.released;
      }
      w.calls.push(call);
      const res = await w.t.app.request(url.pathname + url.search, init, w.t.env);
      return (w.rewrite && (await w.rewrite(call, res))) || res;
    },
  });
}

// 次の call（例 'POST /v1/auth/refresh'）を、release を呼ぶまで API に届けない
function hold(w: World, call: string): Gate {
  let arrive!: () => void;
  let release!: () => void;
  const arrived = new Promise<void>((r) => (arrive = r));
  const released = new Promise<void>((r) => (release = r));
  w.gates.set(call, { arrive, released });
  return { arrived, release };
}

async function send(w: World, message: Record<string, unknown>, from = PAGE): Promise<Reply> {
  const reply = (await w.bg.handleMessage(message, w.chrome.senderFrom(from))) as Reply;
  w.responses.push(JSON.stringify(reply));
  return reply;
}

function newDiscordUser(): string {
  nextUser += 1n;
  const id = String(nextUser);
  discord.addUser(id, { roles: [TEST_ENV.DISCORD_ROLE_ID], globalName: 'チームの人' });
  return id;
}

// 初めてログインして TOTP を登録するまで。登録したシークレットを返す
async function loginAndRegisterTotp(w: World, userId: string, makeAdmin: boolean) {
  w.chrome.loginAs = userId;
  const first = await send(w, { type: 'login', deviceLabel: 'テスト端末' }, POPUP);
  assert.deepEqual([first.ok, first.status], [true, 'totp_setup_required']);
  if (makeAdmin) w.t.db.db.prepare(`UPDATE members SET role = 'admin', status = 'active' WHERE discord_user_id = ?`).run(userId);
  const start = await send(w, { type: 'totpSetupStart' });
  assert.equal(start.ok, true);
  assert.match(String(start.otpauthUri), /^otpauth:\/\/totp\//);
  const secret = base32ToBytes(String(start.secret).replace(/ /g, ''));
  const confirm = await send(w, { type: 'totpSetupConfirm', code: referenceTotp(secret, stepAt(Date.now())) });
  assert.equal(confirm.ok, true);
  assert.equal((confirm.recoveryCodes as string[]).length, 10);
  return secret;
}

// 管理者：ログイン → TOTP の登録 → 鍵の作成 → 最初の Vault
async function adminReady(w: World) {
  const userId = newDiscordUser();
  const secret = await loginAndRegisterTotp(w, userId, true);
  const key = await send(w, { type: 'createKey', masterPassword: ADMIN_PASSWORD, replace: false });
  assert.deepEqual([key.ok, key.vault], [true, 'needs-init'], JSON.stringify(key));
  const init = await send(w, { type: 'initVault' });
  assert.deepEqual([init.ok, init.vault], [true, 'ready'], JSON.stringify(init));
  return { userId, secret };
}

function sessionTokens(w: World): string[] {
  return [...w.chrome.storage.session.values.values()].flatMap((v) => (typeof v === 'object' && v !== null ? Object.values(v).filter((x): x is string => typeof x === 'string' && x.length === 43) : []));
}

test('管理者：ログイン、TOTP の登録、鍵の作成、最初の Vault まで。Vault 鍵はメモリにだけあり、応答にもストレージにも出ない', async () => {
  const w = world();
  await adminReady(w);
  const status = await send(w, { type: 'status' }, POPUP);
  assert.deepEqual([status.loggedIn, status.locked, status.vault, (status.member as { role: string }).role], [true, false, 'ready', 'admin']);
  assert.equal(status.recoveryCodesRemaining, 10);
  // D1 には自分宛てのグラントが1つ
  assert.equal(Number(w.t.db.db.prepare('SELECT COUNT(*) AS n FROM vault_key_grants').get()!.n), 1);
  // 署名鍵の固定と最後に見た世代は、接続先とメンバー ID の組ごとのキーで storage.local に（P-09）
  const memberId = (status.member as { id: string }).id;
  const localKeys = [...w.chrome.storage.local.values.keys()].sort();
  assert.ok(localKeys.includes(`teampw/v1/trust|${API_ORIGIN}|${memberId}|signer`), localKeys.join(' '));
  assert.equal(w.chrome.storage.local.values.get(`teampw/v1/trust|${API_ORIGIN}|${memberId}|generation`), '1');
  // トークンは storage.session にだけ置き、storage.local にも応答にも出さない
  const tokens = sessionTokens(w);
  assert.equal(tokens.length >= 2, true);
  for (const token of tokens) {
    assert.ok(!w.chrome.storage.local.dump().includes(token), 'storage.local にトークンがない');
    assert.ok(w.responses.every((r) => !r.includes(token)), '応答にトークンがない');
  }
  // マスターパスワードはどこにも残らない
  assert.ok(!w.chrome.storage.local.dump().includes(ADMIN_PASSWORD) && !w.chrome.storage.session.dump().includes(ADMIN_PASSWORD));
});

test('E-14 Service Worker が止まると鍵が消えてロック状態から始まる。ログインは続き、マスターパスワードで Vault まで開ける', async () => {
  const w = world();
  await adminReady(w);
  w.bg = newBackground(w); // 起動し直し
  await w.bg.onStartup();
  const status = await send(w, { type: 'status' }, POPUP);
  assert.deepEqual([status.loggedIn, status.locked, status.vault], [true, true, 'locked']);
  // ロック中は鍵を使う指示を断る（E-11）
  assert.equal((await send(w, { type: 'initVault' })).error, 'LOCKED');
  // 間違ったマスターパスワード
  const wrong = await send(w, { type: 'unlock', masterPassword: 'wrong-password-zzzz-11' }, POPUP);
  assert.deepEqual([wrong.ok, wrong.error], [false, 'BAD_PASSWORD']);
  const ok = await send(w, { type: 'unlock', masterPassword: ADMIN_PASSWORD }, POPUP);
  assert.deepEqual([ok.ok, ok.vault], [true, 'ready'], JSON.stringify(ok));
});

test('放置のロックは45分（2026-10-29 に15分から延ばした）', () => {
  assert.equal(IDLE_LOCK_MS, 45 * MIN);
});

test('放置のロック：45分を過ぎてから来たメッセージは、処理の前にロックする。45分以内なら続く', async () => {
  const w = world();
  await adminReady(w);
  at(IDLE_LOCK_MS - 1000);
  assert.equal((await send(w, { type: 'status' }, POPUP)).locked, false, '45分以内');
  // 最後の操作から45分と1ミリ秒
  at(IDLE_LOCK_MS - 1000 + IDLE_LOCK_MS + 1);
  const status = await send(w, { type: 'status' }, POPUP);
  assert.deepEqual([status.locked, status.vault], [true, 'locked']);
  assert.equal((await send(w, { type: 'initVault' })).error, 'LOCKED');
});

test('DeepSeek #4 status のような確認だけのメッセージを送り続けても、利用者の操作がなければ45分でロックされる', async () => {
  const w = world();
  await adminReady(w);
  // 45分より少し短い間隔で、180分まで status だけを送り続ける（同期のポーリングの代わり）
  let lockedAt: number | null = null;
  for (let ms = IDLE_LOCK_MS - 1000; ms <= 4 * IDLE_LOCK_MS; ms += IDLE_LOCK_MS - 1000) {
    at(ms);
    if ((await send(w, { type: 'status' }, POPUP)).locked === true) {
      lockedAt = ms;
      break;
    }
  }
  assert.equal(lockedAt, 2 * (IDLE_LOCK_MS - 1000), '最初の操作（最初の Vault）から45分を過ぎた最初の status でロック');
  assert.deepEqual(w.bg.memoryState(), { unlocked: false, vaultKey: false });
});

test('DeepSeek #4 画面を開く（opened）、ロック解除などの利用者の操作は、放置の時刻を新しくする', async () => {
  const w = world();
  await adminReady(w);
  at(IDLE_LOCK_MS - 1000);
  assert.equal((await send(w, { type: 'opened' }, POPUP)).ok, true);
  at(2 * (IDLE_LOCK_MS - 1000));
  assert.equal((await send(w, { type: 'status' }, POPUP)).locked, false, '画面を開いてから45分以内');
  at(2 * (IDLE_LOCK_MS - 1000) + IDLE_LOCK_MS);
  assert.equal((await send(w, { type: 'status' }, POPUP)).locked, true);
});

test('放置のロック：Service Worker が起きたときにも確かめ、45分を過ぎていればロックの後始末（解除用の保存を消す）をする', async () => {
  const w = world();
  await adminReady(w);
  // 2b のクイックロック解除の保存の場所（ロックで消すもの）を置いておく
  await w.chrome.storage.session.set({ 'teampw/v1/unlock|quick': 'x' });
  at(30 * MIN);
  w.bg = newBackground(w);
  await w.bg.onStartup();
  assert.equal(w.chrome.storage.session.values.has('teampw/v1/unlock|quick'), true, '45分以内なら消さない');
  at(46 * MIN);
  w.bg = newBackground(w);
  await w.bg.onStartup();
  assert.equal(w.chrome.storage.session.values.has('teampw/v1/unlock|quick'), false, '45分を過ぎたら消す');
  assert.equal((await send(w, { type: 'status' }, POPUP)).loggedIn, true, 'ログインは続く');
});

test('E-18 ブラウザを閉じると storage.session が消え、ログインからやり直す。storage.local の固定は残る', async () => {
  const w = world();
  const { userId, secret } = await adminReady(w);
  w.chrome.storage.session.clear();
  w.bg = newBackground(w);
  await w.bg.onStartup();
  assert.equal((await send(w, { type: 'status' }, POPUP)).loggedIn, false);
  // もう一度ログイン（TOTP 登録済みなのでコードを求められる）
  at(MIN);
  w.chrome.loginAs = userId;
  assert.equal((await send(w, { type: 'login', deviceLabel: 'テスト端末' }, POPUP)).status, 'totp_required');
  assert.equal((await send(w, { type: 'loginTotp', code: '000000' }, POPUP)).error, 'BAD_CODE');
  const ok = await send(w, { type: 'loginTotp', code: referenceTotp(secret, stepAt(Date.now())) }, POPUP);
  assert.deepEqual([ok.ok, ok.status], [true, 'ok']);
  assert.equal((await send(w, { type: 'unlock', masterPassword: ADMIN_PASSWORD }, POPUP)).vault, 'ready');
});

test('アクセストークンが切れていても、リフレッシュトークンで更新して続ける。更新できなければログアウトの状態になる', async () => {
  const w = world();
  await adminReady(w);
  at(16 * MIN);
  const list = await send(w, { type: 'listSessions' });
  assert.equal(list.ok, true, JSON.stringify(list));
  // サーバーでセッションを無効にされた
  w.t.db.db.exec('UPDATE sessions SET revoked_at = 1');
  at(32 * MIN);
  assert.equal((await send(w, { type: 'listSessions' })).error, 'NOT_LOGGED_IN');
  assert.equal((await send(w, { type: 'status' }, POPUP)).loggedIn, false);
});

test('Codex #1 トークンが切れた状態で3つの API 呼び出しが同時に走っても、更新は1回で、ログアウトにならない', async () => {
  const w = world();
  await adminReady(w);
  at(16 * MIN); // アクセストークンは15分
  w.calls.length = 0;
  const replies = await Promise.all([send(w, { type: 'listSessions' }), send(w, { type: 'listSessions' }), send(w, { type: 'listSessions' })]);
  assert.deepEqual(replies.map((r) => r.ok), [true, true, true], JSON.stringify(replies));
  assert.equal(w.calls.filter((c) => c === 'POST /v1/auth/refresh').length, 1, '更新は1回');
  assert.equal(Number(w.t.db.db.prepare('SELECT COUNT(*) AS n FROM sessions WHERE revoked_at IS NOT NULL').get()!.n), 0, '使い回しの検知でセッションが無効になっていない');
  assert.equal((await send(w, { type: 'status' }, POPUP)).loggedIn, true);
});

test('Codex #1 更新の途中でログアウトすると、遅れて終わった更新はトークンを書き戻さない。サーバーのセッションも無効になる', async () => {
  const w = world();
  await adminReady(w);
  at(16 * MIN);
  const gate = hold(w, 'POST /v1/auth/refresh');
  const pending = send(w, { type: 'listSessions' });
  await gate.arrived;
  assert.equal((await send(w, { type: 'logout' }, POPUP)).ok, true);
  gate.release();
  assert.equal((await pending).error, 'NOT_LOGGED_IN');
  assert.equal(w.chrome.storage.session.values.has('teampw/v1/session'), false, 'トークンが書き戻されていない');
  assert.equal(Number(w.t.db.db.prepare('SELECT COUNT(*) AS n FROM sessions WHERE revoked_at IS NULL').get()!.n), 0, 'サーバーのセッションも無効');
});

test('Codex #1 更新の途中で別の人がログインしても、遅れて終わった前の人の更新で上書きしない', async () => {
  const w = world();
  await adminReady(w);
  at(16 * MIN);
  const gate = hold(w, 'POST /v1/auth/refresh');
  const pending = send(w, { type: 'listSessions' });
  await gate.arrived;
  const other = newDiscordUser();
  w.chrome.loginAs = other;
  assert.equal((await send(w, { type: 'login', deviceLabel: 'テスト端末' }, POPUP)).status, 'totp_setup_required');
  const otherId = String(w.t.db.db.prepare('SELECT id FROM members WHERE discord_user_id = ?').get(other)!.id);
  gate.release();
  await pending;
  const stored = w.chrome.storage.session.values.get('teampw/v1/session') as { memberId: string };
  assert.equal(stored.memberId, otherId, '後からログインした人のトークンのまま');
});

// ロック解除の途中（鍵を開けた後、自分宛てのグラントを取りに行っている間）に、ロック・ログアウト・15分の経過が起きる
for (const [name, interrupt] of [
  ['ロック', async (w: World) => void (await send(w, { type: 'lock' }, POPUP))],
  ['ログアウト', async (w: World) => void (await send(w, { type: 'logout' }, POPUP))],
  ['15分の経過', async () => at(16 * MIN)],
] as const) {
  test(`Codex #3 ロック解除の途中で${name}が起きても、終わった後に鍵がメモリに残らない`, async () => {
    const w = world();
    await adminReady(w);
    await send(w, { type: 'lock' }, POPUP);
    const gate = hold(w, 'GET /v1/vault');
    const pending = send(w, { type: 'unlock', masterPassword: ADMIN_PASSWORD }, POPUP);
    await gate.arrived;
    await interrupt(w);
    gate.release();
    const reply = await pending;
    assert.deepEqual([reply.ok, reply.error], [false, 'LOCKED'], JSON.stringify(reply));
    assert.deepEqual(w.bg.memoryState(), { unlocked: false, vaultKey: false });
  });
}

test('Codex #3 鍵の作成と最初の Vault の途中でロックしても、終わった後に鍵がメモリに残らない', async () => {
  const w = world();
  const userId = newDiscordUser();
  await loginAndRegisterTotp(w, userId, true);
  const keyGate = hold(w, 'PUT /v1/me/keys');
  const creating = send(w, { type: 'createKey', masterPassword: ADMIN_PASSWORD, replace: false });
  await keyGate.arrived;
  await send(w, { type: 'lock' }, POPUP);
  keyGate.release();
  assert.equal((await creating).error, 'LOCKED');
  assert.deepEqual(w.bg.memoryState(), { unlocked: false, vaultKey: false });
  // 鍵はサーバーに登録済み。ロック解除してから最初の Vault を作り、その途中でロックする
  assert.equal((await send(w, { type: 'unlock', masterPassword: ADMIN_PASSWORD }, POPUP)).vault, 'needs-init');
  const initGate = hold(w, 'POST /v1/vault/init');
  const initializing = send(w, { type: 'initVault' });
  await initGate.arrived;
  await send(w, { type: 'lock' }, POPUP);
  initGate.release();
  assert.equal((await initializing).error, 'LOCKED');
  assert.deepEqual(w.bg.memoryState(), { unlocked: false, vaultKey: false });
});

test('Codex #4 ログインの応答のメンバー ID と GET /v1/me の id が食い違ったら、止めて何も送らず何も保存しない', async () => {
  const w = world();
  await loginAndRegisterTotp(w, newDiscordUser(), true);
  // サーバー（または途中の誰か）が、別のメンバーの id を返す
  w.rewrite = async (call, res) => {
    if (call !== 'GET /v1/me' || res.status !== 200) return null;
    const body = (await res.json()) as Record<string, unknown>;
    return Response.json({ ...body, id: 'member_someone_else' });
  };
  const before = w.chrome.storage.local.dump();
  w.calls.length = 0;
  assert.equal((await send(w, { type: 'createKey', masterPassword: ADMIN_PASSWORD, replace: false })).error, 'MEMBER_MISMATCH');
  assert.equal((await send(w, { type: 'unlock', masterPassword: ADMIN_PASSWORD }, POPUP)).error, 'MEMBER_MISMATCH');
  assert.equal((await send(w, { type: 'status' }, POPUP)).error, 'MEMBER_MISMATCH');
  assert.deepEqual(w.calls.filter((c) => c !== 'GET /v1/me'), [], '鍵の登録などは送らない');
  assert.equal(w.chrome.storage.local.dump(), before, '固定も世代も書かない');
  assert.equal(Number(w.t.db.db.prepare('SELECT COUNT(*) AS n FROM member_keys').get()!.n), 0);
  assert.deepEqual(w.bg.memoryState(), { unlocked: false, vaultKey: false });
});

test('Codex #5 P-04 P-07 固定と最後に見た世代が未設定の端末（storage.local が空）は、サーバーが本物のグラントを返しても開かない', async () => {
  const w = world();
  // 管理者は、テストの中で暗号コアを使って作る（鍵とグラントは本物）
  const admin = await w.t.addMember('active', { role: 'admin' });
  const adminKey = await createAdminKey(ADMIN_PASSWORD);
  w.t.db.db
    .prepare(`INSERT INTO member_keys (id, member_id, ecdh_public_key, encrypted_private_key, ecdsa_public_key, encrypted_sign_private_key,
                                       kdf_algorithm, kdf_params, kdf_salt, format_version, status, created_at)
              VALUES (?, ?, ?, ?, ?, ?, 'PBKDF2-HMAC-SHA256', '{"iterations":600000,"normalization":"NFC"}', ?, 1, 'active', 0)`)
    .run(adminKey.record.keyId, admin.id, toBase64Url(adminKey.record.publicKey), toBase64Url(adminKey.record.encryptedPrivateKey),
      toBase64Url(adminKey.record.signPublicKey), toBase64Url(adminKey.record.encryptedSignPrivateKey), toBase64Url(adminKey.record.kdf.salt));
  w.t.db.db.exec(`INSERT INTO vault_meta (id, current_vault_key_version, vault_revision, schema_version) VALUES (1, 1, 0, 1);
                  INSERT INTO vault_key_versions (version, status, created_by, created_at) VALUES (1, 'current', NULL, 0)`);
  // メンバー：拡張機能でログインし、鍵を作る
  await loginAndRegisterTotp(w, newDiscordUser(), false);
  assert.equal((await send(w, { type: 'createKey', masterPassword: MEMBER_PASSWORD, replace: false })).vault, 'awaiting-approval');
  const memberId = String(((await send(w, { type: 'status' }, POPUP)) as unknown as { member: { id: string } }).member.id);
  const row = w.t.db.db.prepare(`SELECT id, ecdh_public_key AS pk FROM member_keys WHERE member_id = ? AND status = 'active'`).get(memberId)!;
  // 管理者がメンバーを承認し、本物の署名付きグラントを置いた（承認の API はフェーズ4なので D1 に直接入れる）
  const adminTrust = newTrust(admin.id);
  await pinSigner(adminTrust, { memberId: admin.id, keyId: adminKey.record.keyId, publicKey: adminKey.record.signPublicKey }, 1);
  const pins = new MemoryPinStore();
  const recipient = { keyId: String(row.id), publicKey: fromBase64Url(String(row.pk)) };
  await pinPublicKey(pins, memberId, recipient);
  const grant = await createGrant({
    pins,
    signer: { memberId: admin.id, keyId: adminKey.record.keyId, privateKey: adminKey.signPrivateKey, trust: adminTrust },
    memberId,
    recipient,
    vaultKeyVersion: 1,
    vaultKeyRaw: generateVaultKeyRaw(),
  });
  w.t.db.db
    .prepare(`INSERT INTO vault_key_grants (vault_key_version, recipient_key_id, ephemeral_public_key, wrapped_key, signer_key_id, signature, format_version, created_at)
              VALUES (1, ?, ?, ?, ?, ?, 1, 0)`)
    .run(grant.recipientKeyId, toBase64Url(grant.ephemeralPublicKey), toBase64Url(grant.wrappedKey), grant.signerKeyId, toBase64Url(grant.signature));
  w.t.db.db.prepare(`UPDATE members SET status = 'active' WHERE id = ?`).run(memberId);
  // 端末は照合をしていない（storage.local に固定も世代もない）ので、本物のグラントでも開かない
  assert.equal([...w.chrome.storage.local.values.keys()].filter((k) => k.includes(memberId)).length, 0);
  await send(w, { type: 'lock' }, POPUP);
  assert.equal((await send(w, { type: 'unlock', masterPassword: MEMBER_PASSWORD }, POPUP)).vault, 'awaiting-approval');
  assert.equal(w.bg.memoryState().vaultKey, false);
  // 対照：照合して固定と世代を storage.local に入れれば、同じグラントを開ける（グラントが本物であることの確認）
  await pinSigner(openTrust(chromeTrustStorage(w.chrome.storage.local), { apiOrigin: API_ORIGIN, memberId }), { memberId: admin.id, keyId: adminKey.record.keyId, publicKey: adminKey.record.signPublicKey }, 1);
  await send(w, { type: 'lock' }, POPUP);
  assert.equal((await send(w, { type: 'unlock', masterPassword: MEMBER_PASSWORD }, POPUP)).vault, 'ready');
  assert.equal(w.bg.memoryState().vaultKey, true);
});

test('DeepSeek #5 ロックでも、ログインの途中の一時トークンを消す（ログアウトと同じ）', async () => {
  const w = world();
  const { userId, secret } = await adminReady(w);
  w.chrome.storage.session.clear(); // ブラウザを閉じた
  w.bg = newBackground(w);
  at(MIN);
  w.chrome.loginAs = userId;
  assert.equal((await send(w, { type: 'login', deviceLabel: 'テスト端末' }, POPUP)).status, 'totp_required');
  assert.equal((await send(w, { type: 'status' }, POPUP)).loginInProgress, true);
  await send(w, { type: 'lock' }, POPUP);
  assert.equal((await send(w, { type: 'status' }, POPUP)).loginInProgress, false);
  assert.equal((await send(w, { type: 'loginTotp', code: referenceTotp(secret, stepAt(Date.now())) }, POPUP)).error, 'NO_LOGIN_IN_PROGRESS');
});

test('メンバー：鍵を作っても、照合と承認（フェーズ4）が済むまでグラントを開かない（P-04）', async () => {
  const w = world();
  await adminReady(w);
  const m = world();
  m.t = w.t; // 同じサーバー
  m.bg = newBackground(m);
  await loginAndRegisterTotp(m, newDiscordUser(), false);
  const key = await send(m, { type: 'createKey', masterPassword: MEMBER_PASSWORD, replace: false });
  assert.deepEqual([key.ok, key.vault], [true, 'awaiting-approval'], JSON.stringify(key));
  // メンバーは最初の Vault を作れない
  assert.equal((await send(m, { type: 'initVault' })).error, 'NOT_ADMIN');
  // 短いマスターパスワードは断る
  assert.equal((await send(m, { type: 'createKey', masterPassword: 'short-pass-1', replace: true })).error, 'BAD_REQUEST');
});

test('鍵の作り直しは、明示したときだけ。5分を過ぎていれば TOTP の再確認を求める', async () => {
  const w = world();
  const { secret } = await adminReady(w);
  assert.equal((await send(w, { type: 'createKey', masterPassword: ADMIN_PASSWORD, replace: false })).error, 'KEY_EXISTS');
  at(6 * MIN);
  // グラントがある管理者の登録し直しはサーバーが 409 にするが、その前に再確認を求める
  assert.equal((await send(w, { type: 'createKey', masterPassword: 'admin-new-pass-word-77', replace: true })).error, 'STEP_UP_REQUIRED');
  assert.equal((await send(w, { type: 'stepUp', code: referenceTotp(secret, stepAt(Date.now())) })).ok, true);
  assert.equal((await send(w, { type: 'createKey', masterPassword: 'admin-new-pass-word-77', replace: true })).error, 'CONFLICT');
});

test('E-08 ページに注入したスクリプトや別の拡張機能からのメッセージは、ログイン・ロック解除・ロックを含め、何も処理しない', async () => {
  const w = world();
  await adminReady(w);
  const before = w.chrome.storage.session.dump() + w.chrome.storage.local.dump();
  for (const sender of [{ id: w.chrome.runtime.id, url: 'https://evil.example.com/' }, { id: 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz', url: 'chrome-extension://zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz/x.html' }]) {
    for (const message of [{ type: 'lock' }, { type: 'logout' }, { type: 'status' }, { type: 'unlock', masterPassword: ADMIN_PASSWORD }]) {
      const reply = (await w.bg.handleMessage(message, sender)) as Reply;
      assert.deepEqual(reply, { ok: false, error: 'BAD_REQUEST' });
    }
  }
  assert.equal(w.chrome.storage.session.dump() + w.chrome.storage.local.dump(), before);
  assert.equal((await send(w, { type: 'status' }, POPUP)).locked, false, '偽のロックは効いていない');
});

test('セッションの一覧の端末名は、送られたとおりの文字列で返す（画面は文字として表示する。DeepSeek #2）', async () => {
  const w = world();
  const userId = newDiscordUser();
  w.chrome.loginAs = userId;
  await send(w, { type: 'login', deviceLabel: '<img src=x onerror=alert(1)>' }, POPUP);
  const list = await send(w, { type: 'listSessions' });
  // TOTP の登録前は使えない（A-11）
  assert.equal(list.error, 'TOTP_SETUP_REQUIRED');
  const start = await send(w, { type: 'totpSetupStart' });
  const secret = base32ToBytes(String(start.secret).replace(/ /g, ''));
  await send(w, { type: 'totpSetupConfirm', code: referenceTotp(secret, stepAt(Date.now())) });
  const after = await send(w, { type: 'listSessions' });
  assert.deepEqual((after.sessions as { deviceLabel: string }[]).map((s) => s.deviceLabel), ['<img src=x onerror=alert(1)>']);
});
