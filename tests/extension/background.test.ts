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

type World = { t: ReturnType<typeof setup>; chrome: FakeChrome; bg: Background; responses: string[] };
type Reply = { ok: boolean; error?: string } & Record<string, unknown>;

function world(): World {
  const t = setup();
  // 本番と同じく、vault_meta の行は最初の Vault を作るときにできる
  t.db.db.exec('DELETE FROM vault_meta; DELETE FROM vault_key_versions');
  const chrome = new FakeChrome(discord);
  const w: World = { t, chrome, bg: null as unknown as Background, responses: [] };
  w.bg = newBackground(w);
  return w;
}

// Service Worker を起動し直す（メモリは消え、chrome.storage は残る）
function newBackground(w: World): Background {
  return createBackground({
    chrome: w.chrome,
    apiOrigin: API_ORIGIN,
    discordClientId: TEST_ENV.DISCORD_CLIENT_ID,
    fetch: (input, init) => {
      const url = new URL(String(input));
      assert.equal(url.origin, API_ORIGIN, 'API の接続先にだけ送る');
      return Promise.resolve(w.t.app.request(url.pathname + url.search, init, w.t.env));
    },
  });
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

test('放置のロック：15分を過ぎてから来たメッセージは、処理の前にロックする。15分以内なら続く', async () => {
  const w = world();
  await adminReady(w);
  at(IDLE_LOCK_MS - 1000);
  assert.equal((await send(w, { type: 'status' }, POPUP)).locked, false, '15分以内');
  // 最後の操作から15分と1ミリ秒
  at(IDLE_LOCK_MS - 1000 + IDLE_LOCK_MS + 1);
  const status = await send(w, { type: 'status' }, POPUP);
  assert.deepEqual([status.locked, status.vault], [true, 'locked']);
  assert.equal((await send(w, { type: 'initVault' })).error, 'LOCKED');
});

test('放置のロック：Service Worker が起きたときにも確かめ、15分を過ぎていればロックの後始末（解除用の保存を消す）をする', async () => {
  const w = world();
  await adminReady(w);
  // 2b のクイックロック解除の保存の場所（ロックで消すもの）を置いておく
  await w.chrome.storage.session.set({ 'teampw/v1/unlock|quick': 'x' });
  at(10 * MIN);
  w.bg = newBackground(w);
  await w.bg.onStartup();
  assert.equal(w.chrome.storage.session.values.has('teampw/v1/unlock|quick'), true, '15分以内なら消さない');
  at(16 * MIN);
  w.bg = newBackground(w);
  await w.bg.onStartup();
  assert.equal(w.chrome.storage.session.values.has('teampw/v1/unlock|quick'), false, '15分を過ぎたら消す');
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
