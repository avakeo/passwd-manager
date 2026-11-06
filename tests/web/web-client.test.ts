// Web ページのログインと API の呼び出し（2026-11-01 追記、判断待ち10）。画面から切り離した src/web/page/web-client.ts を、
// 本物の API（app.request ＋ SQLite）と偽の Discord で確かめる。仕様書「Webページの配信」。

import { after, beforeEach, mock, test } from 'node:test';
import assert from 'node:assert/strict';
import { FakeDiscord } from '../helpers/fake-discord.ts';
import { TEST_ENV, WEB_ORIGIN, setup } from '../helpers/api.ts';
import { referenceTotp, stepAt } from '../helpers/totp-reference.ts';
import { SESSION_KEY, WebError, WebSession, finishLogin, handoffCode, startLogin, type WebConfig } from '../../src/web/page/web-client.ts';

const T0 = 1_800_000_000_000;
mock.timers.enable({ apis: ['Date'], now: T0 });
after(() => mock.timers.reset());
beforeEach(() => mock.timers.setTime(T0));

const fake = new FakeDiscord({ clientId: TEST_ENV.DISCORD_CLIENT_ID, clientSecret: TEST_ENV.DISCORD_CLIENT_SECRET, botToken: TEST_ENV.DISCORD_BOT_TOKEN, guildId: TEST_ENV.DISCORD_GUILD_ID });
after(fake.install());

const API_ORIGIN = 'https://pw-api.example.com';
const CONFIG: WebConfig = { apiOrigin: API_ORIGIN, discordClientId: TEST_ENV.DISCORD_CLIENT_ID, webOrigin: WEB_ORIGIN };

let nextUser = 800000000000000000n;
function newDiscordUser(): string {
  nextUser += 1n;
  const id = String(nextUser);
  fake.addUser(id, { roles: [TEST_ENV.DISCORD_ROLE_ID], globalName: 'チームの人' });
  return id;
}

class MemoryStorage {
  readonly values = new Map<string, string>();
  getItem(k: string) {
    return this.values.get(k) ?? null;
  }
  setItem(k: string, v: string) {
    this.values.set(k, v);
  }
  removeItem(k: string) {
    this.values.delete(k);
  }
}

// API のオリジンへの fetch だけを、本物の API（app.request）に回す。呼ばれた先を控える
function apiFetch(t: ReturnType<typeof setup>, calls: string[] = []): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input, init);
    const url = new URL(req.url);
    assert.equal(url.origin, API_ORIGIN, 'API のオリジン以外には送らない');
    calls.push(`${req.method} ${url.pathname}`);
    return t.app.request(url.pathname + url.search, { method: req.method, headers: req.headers, body: req.method === 'GET' ? undefined : await req.text() }, { DB: t.db, ...TEST_ENV });
  }) as typeof fetch;
}

// Discord の認可画面でログインした後に、戻ってくる URL を作る
async function discordRedirect(storage: MemoryStorage, userId: string): Promise<string> {
  const url = new URL(await startLogin(CONFIG, storage));
  assert.equal(url.origin + url.pathname, 'https://discord.com/oauth2/authorize');
  assert.equal(url.searchParams.get('redirect_uri'), `${WEB_ORIGIN}/callback`);
  const code = fake.issueCode({ userId, redirectUri: `${WEB_ORIGIN}/callback`, codeChallenge: url.searchParams.get('code_challenge')! });
  return `${WEB_ORIGIN}/callback?code=${code}&state=${url.searchParams.get('state')}`;
}

async function member(t: ReturnType<typeof setup>, role: 'admin' | 'member' = 'member') {
  const userId = newDiscordUser();
  const secret = crypto.getRandomValues(new Uint8Array(20));
  const m = await t.addMember('active', { role, discordUserId: userId, totpSecret: secret });
  return { userId, secret, id: m.id };
}

async function loggedIn(t: ReturnType<typeof setup>, role: 'admin' | 'member' = 'member', calls: string[] = [], storage = new MemoryStorage()) {
  const m = await member(t, role);
  const href = await discordRedirect(storage, m.userId);
  const { challengeToken } = await finishLogin(href, CONFIG, storage, apiFetch(t, calls));
  return WebSession.verifyTotp(CONFIG, apiFetch(t, calls), storage, challengeToken, referenceTotp(m.secret, stepAt(Date.now())));
}

async function rejects(p: Promise<unknown>, code: string) {
  await assert.rejects(p, (e: unknown) => e instanceof WebError && e.code === code);
}

test('W-06 Web ページのログイン：state と PKCE を確かめ、TOTP の後に Web 用のセッションで読める', async () => {
  const t = setup();
  const session = await loggedIn(t);
  const sessions = (await session.get('/v1/me/sessions')).sessions as { scope: string; current: boolean }[];
  assert.deepEqual(sessions.filter((s) => s.current).map((s) => s.scope), ['web']);
  assert.equal(((await session.get('/v1/members')).members as unknown[]).length, 1);
});

test('W-06 state と検証値は sessionStorage に1回だけ置き、戻ったら消す', async () => {
  const t = setup();
  const m = await member(t);
  const storage = new MemoryStorage();
  const href = await discordRedirect(storage, m.userId);
  assert.equal(storage.values.size, 1);
  const { challengeToken } = await finishLogin(href, CONFIG, storage, apiFetch(t));
  assert.equal(storage.values.size, 0);
  // 同じ戻り先をもう一度使っても、通らない
  await rejects(finishLogin(href, CONFIG, storage, apiFetch(t)), 'NO_PENDING');
  await WebSession.verifyTotp(CONFIG, apiFetch(t), storage, challengeToken, referenceTotp(m.secret, stepAt(Date.now())));
  assert.deepEqual([...storage.values.keys()], [SESSION_KEY], 'TOTP の後は、セッションの1件だけ');
});

test('W-06 state が違う戻り先は、API に送らずに断る（A-01）', async () => {
  const t = setup();
  const m = await member(t);
  const storage = new MemoryStorage();
  const href = new URL(await discordRedirect(storage, m.userId));
  href.searchParams.set('state', 'x'.repeat(43));
  const calls: string[] = [];
  await rejects(finishLogin(href.toString(), CONFIG, storage, apiFetch(t, calls)), 'STATE_MISMATCH');
  assert.deepEqual(calls, []);
  assert.equal(storage.values.size, 0, '失敗しても、置いた値は消す');
});

test('W-07 TOTP を登録していない人は、Web ページではログインできない', async () => {
  const t = setup();
  const userId = newDiscordUser();
  const storage = new MemoryStorage();
  await rejects(finishLogin(await discordRedirect(storage, userId), CONFIG, storage, apiFetch(t)), 'FORBIDDEN');
});

test('TOTP のコードが違えば BAD_CODE', async () => {
  const t = setup();
  const m = await member(t);
  const storage = new MemoryStorage();
  const { challengeToken } = await finishLogin(await discordRedirect(storage, m.userId), CONFIG, storage, apiFetch(t));
  await rejects(WebSession.verifyTotp(CONFIG, apiFetch(t), storage, challengeToken, '000000'), 'BAD_CODE');
  assert.equal(storage.values.size, 0);
});

test('アクセストークンの期限が切れたら、メモリのリフレッシュトークンで1回だけ更新して読み直す', async () => {
  const t = setup();
  const calls: string[] = [];
  const session = await loggedIn(t, 'member', calls);
  mock.timers.setTime(T0 + 16 * 60 * 1000);
  assert.ok(Array.isArray((await session.get('/v1/me/sessions')).sessions));
  assert.deepEqual(calls.slice(-3), ['GET /v1/me/sessions', 'POST /v1/auth/refresh', 'GET /v1/me/sessions']);
});

test('監査ログは、管理者がログインしてから5分の間だけ。過ぎたら FORBIDDEN（画面はログインし直すよう伝える）', async () => {
  const t = setup();
  const admin = await loggedIn(t, 'admin');
  assert.ok(Array.isArray((await admin.get('/v1/audit-logs')).logs));
  mock.timers.setTime(T0 + 6 * 60 * 1000);
  await rejects(admin.get('/v1/audit-logs'), 'FORBIDDEN');
  const memberSession = await loggedIn(t);
  await rejects(memberSession.get('/v1/audit-logs'), 'FORBIDDEN');
});

test('Web ページから呼べるのは、決めた GET の入口だけ', async () => {
  const t = setup();
  const session = await loggedIn(t);
  await rejects(session.get('/v1/items?after=0'), 'NOT_ALLOWED');
  await rejects(session.get('https://evil.example.com/v1/me'), 'NOT_ALLOWED');
});

// 再読み込みで戻る（2026-11-05 追記）。リフレッシュトークンと自分の ID・役割を sessionStorage に置き、開き直したら更新して使う
function stored(storage: MemoryStorage): Record<string, unknown> {
  return JSON.parse(storage.values.get(SESSION_KEY)!) as Record<string, unknown>;
}

test('W-08 sessionStorage に置くのは、リフレッシュトークンと、画面に出す自分の ID と役割だけ。アクセストークンは置かない', async () => {
  const t = setup();
  const storage = new MemoryStorage();
  const session = await loggedIn(t, 'member', [], storage);
  assert.deepEqual(Object.keys(stored(storage)), ['refresh', 'member']);
  assert.equal(typeof stored(storage).refresh, 'string');
  assert.deepEqual(stored(storage).member, session.member);
});

test('W-08 再読み込みしたら、置いたリフレッシュトークンで同じセッションに戻る。セッションは増えない', async () => {
  const t = setup();
  const storage = new MemoryStorage();
  const first = await loggedIn(t, 'admin', [], storage);
  const count = ((await first.get('/v1/me/sessions')).sessions as unknown[]).length;
  const before = stored(storage).refresh;
  const calls: string[] = [];
  const again = await WebSession.resume(CONFIG, apiFetch(t, calls), storage);
  assert.ok(again);
  assert.deepEqual(calls, ['POST /v1/auth/refresh']);
  assert.notEqual(stored(storage).refresh, before, '使ったリフレッシュトークンは、新しいものに置き換える');
  assert.deepEqual(again.member, first.member);
  const sessions = (await again.get('/v1/me/sessions')).sessions as { current: boolean }[];
  assert.equal(sessions.length, count, '再読み込みで、新しいセッションを作らない');
  assert.equal(sessions.filter((x) => x.current).length, 1);
  // ログインから5分の間なら、管理者は監査ログも見られる（TOTP を確かめた時刻はセッションに残る）
  assert.ok(Array.isArray((await again.get('/v1/audit-logs')).logs));
});

test('W-08 何も置いていない、または中身が壊れていれば、API を呼ばずにログインの画面へ。壊れた値は消す', async () => {
  const t = setup();
  const calls: string[] = [];
  const storage = new MemoryStorage();
  assert.equal(await WebSession.resume(CONFIG, apiFetch(t, calls), storage), null);
  storage.setItem(SESSION_KEY, '{"refresh":1}');
  assert.equal(await WebSession.resume(CONFIG, apiFetch(t, calls), storage), null);
  storage.setItem(SESSION_KEY, '{"refresh":"r"}');
  assert.equal(await WebSession.resume(CONFIG, apiFetch(t, calls), storage), null);
  storage.setItem(SESSION_KEY, 'x');
  assert.equal(await WebSession.resume(CONFIG, apiFetch(t, calls), storage), null);
  assert.deepEqual(calls, []);
  assert.equal(storage.values.size, 0);
});

test('W-08 期限（7日）が切れた、または無効にされたセッションでは戻らず、置いた値を消す', async () => {
  const t = setup();
  const storage = new MemoryStorage();
  await loggedIn(t, 'member', [], storage);
  mock.timers.setTime(T0 + 8 * 24 * 60 * 60 * 1000);
  assert.equal(await WebSession.resume(CONFIG, apiFetch(t), storage), null);
  assert.equal(storage.values.size, 0);

  mock.timers.setTime(T0);
  const storage2 = new MemoryStorage();
  await loggedIn(t, 'member', [], storage2);
  await t.db.prepare('UPDATE sessions SET revoked_at = ?').bind(Date.now()).run();
  assert.equal(await WebSession.resume(CONFIG, apiFetch(t), storage2), null);
  assert.equal(storage2.values.size, 0);
});

test('W-08 ページを開いたまま更新したら、置いた値も新しいリフレッシュトークンにする。その後の再読み込みでも戻れる', async () => {
  const t = setup();
  const storage = new MemoryStorage();
  const session = await loggedIn(t, 'member', [], storage);
  const before = stored(storage).refresh;
  mock.timers.setTime(T0 + 16 * 60 * 1000);
  await session.get('/v1/me/sessions');
  assert.notEqual(stored(storage).refresh, before);
  assert.ok(await WebSession.resume(CONFIG, apiFetch(t), storage));
});

test('W-08 更新に失敗したら、置いた値を消す', async () => {
  const t = setup();
  const storage = new MemoryStorage();
  const session = await loggedIn(t, 'member', [], storage);
  await t.db.prepare('UPDATE sessions SET revoked_at = ?').bind(Date.now()).run();
  await rejects(session.get('/v1/me/sessions'), 'EXPIRED');
  assert.equal(storage.values.size, 0);
});

test('W-08 「このタブのログインを消す」で、置いた値を消す。その後の再読み込みではログインの画面になる', async () => {
  const t = setup();
  const storage = new MemoryStorage();
  const session = await loggedIn(t, 'member', [], storage);
  session.forget();
  assert.equal(storage.values.size, 0);
  assert.equal(await WebSession.resume(CONFIG, apiFetch(t), storage), null);
});

// 拡張機能から開く（2026-11-05 追記、W-09）。拡張機能が作った使い捨てのコードを、URL の # の後ろで受け取る
async function extensionCode(t: ReturnType<typeof setup>, role: 'admin' | 'member' = 'member') {
  const m = await member(t, role);
  // 拡張機能でログインして TOTP を確かめたセッション
  const ext = await t.addSession(m.id, { totpVerifiedAt: Date.now() });
  const res = await t.request('POST', '/v1/me/web-handoff', ext.token, {});
  assert.equal(res.status, 201);
  return String(((await res.json()) as Record<string, unknown>).code);
}

test('W-09 URL の #handoff= からコードを取り出す。形が違えば null', () => {
  const code = 'A'.repeat(43);
  assert.equal(handoffCode(`#handoff=${code}`), code);
  for (const bad of ['', '#', '#handoff=', `#handoff=${'A'.repeat(42)}`, `#handoff=${code}&x=1`, `#other=${code}`, `#handoff=${'A'.repeat(42)}+`]) assert.equal(handoffCode(bad), null, bad);
});

test('W-09 拡張機能のコードで Web 用のセッションを受け取り、sessionStorage に置く。再読み込みでも戻れる', async () => {
  const t = setup();
  const storage = new MemoryStorage();
  const calls: string[] = [];
  const session = await WebSession.fromHandoff(CONFIG, apiFetch(t, calls), storage, await extensionCode(t, 'admin'));
  assert.deepEqual(calls, ['POST /v1/auth/web-handoff']);
  assert.equal(session.member.role, 'admin');
  assert.ok(Array.isArray((await session.get('/v1/audit-logs')).logs));
  assert.deepEqual(Object.keys(stored(storage)), ['refresh', 'member']);
  assert.ok(await WebSession.resume(CONFIG, apiFetch(t), storage));
});

test('W-09 使い終わった・期限切れのコードは HANDOFF。前に置いた値は消す', async () => {
  const t = setup();
  const code = await extensionCode(t);
  await WebSession.fromHandoff(CONFIG, apiFetch(t), new MemoryStorage(), code);
  const storage = new MemoryStorage();
  storage.setItem(SESSION_KEY, '{"refresh":"old","member":{"id":"member_x","role":"member"}}');
  await rejects(WebSession.fromHandoff(CONFIG, apiFetch(t), storage, code), 'HANDOFF');
  assert.equal(storage.values.size, 0);
});
