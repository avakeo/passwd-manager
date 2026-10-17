// Discord ログイン、Bot によるロールの確認、セッションの発行・更新・ログアウト、TOTP。
// 本物の Discord は呼ばない。globalThis.fetch を偽の Discord（tests/helpers/fake-discord.ts）に置き換え、本番と同じコードを通す。
// 時刻は node:test の mock.timers で固定し、TOTP の期待するコードは src を使わずに計算する（tests/helpers/totp-reference.ts）。

import { after, mock, test } from 'node:test';
import assert from 'node:assert/strict';
import { createLoginRequest } from '../../src/client/discord-login.ts';
import { fromBase64Url } from '../../src/crypto/bytes.ts';
import { sha256Hex } from '../../src/api/auth.ts';
import { DISCORD_API, FakeDiscord } from '../helpers/fake-discord.ts';
import { EXTENSION_REDIRECT_URI, LOCAL_REDIRECT_URI, TEST_ENV, setup } from '../helpers/api.ts';
import { base32ToBytes, referenceTotp, stepAt } from '../helpers/totp-reference.ts';

const T0 = 1_800_000_000_000; // 30秒の区切りのちょうど始まり
mock.timers.enable({ apis: ['Date'], now: T0 });
after(() => mock.timers.reset());

const fake = new FakeDiscord({
  clientId: TEST_ENV.DISCORD_CLIENT_ID,
  clientSecret: TEST_ENV.DISCORD_CLIENT_SECRET,
  botToken: TEST_ENV.DISCORD_BOT_TOKEN,
  guildId: TEST_ENV.DISCORD_GUILD_ID,
});
const restore = fake.install();
after(restore);

const ROLE = TEST_ENV.DISCORD_ROLE_ID;
let nextUser = 500000000000000000n;
function newDiscordUser(roles: string[] | null = [ROLE], globalName: string | null = 'チームの人') {
  nextUser += 1n;
  const id = String(nextUser);
  fake.addUser(id, { roles, globalName });
  return id;
}

type Setup = ReturnType<typeof setup>;
type LoginBody = {
  status?: 'ok' | 'totp_required' | 'totp_setup_required';
  access_token?: string;
  refresh_token?: string;
  challenge_token?: string;
  member?: { id: string; role: string; status: string };
};

// 拡張機能と同じ道筋：クライアント側の関数で state と PKCE を作り、偽の Discord が認可コードを出し、API に渡す
async function login(t: Setup, userId: string, opts: { redirectUri?: string; registered?: string; verifier?: string } = {}) {
  const redirectUri = opts.redirectUri ?? EXTENSION_REDIRECT_URI;
  const req = await createLoginRequest({ clientId: TEST_ENV.DISCORD_CLIENT_ID, redirectUri });
  const challenge = new URL(req.url).searchParams.get('code_challenge')!;
  const code = fake.issueCode({ userId, redirectUri: opts.registered ?? redirectUri, codeChallenge: challenge });
  const res = await t.request('POST', '/v1/auth/discord', undefined, {
    code,
    code_verifier: opts.verifier ?? req.codeVerifier,
    redirect_uri: redirectUri,
    device_label: 'テスト端末',
  });
  return { res, body: (await res.clone().json()) as LoginBody };
}

function count(t: Setup, table: string): number {
  return Number(t.db.db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get()!.n);
}

function dump(t: Setup): string {
  const tables = t.db.db.prepare(`SELECT name FROM sqlite_master WHERE type = 'table'`).all().map((r) => String(r.name));
  return JSON.stringify(tables.map((name) => t.db.db.prepare(`SELECT * FROM ${name}`).all()));
}

test('初めてのログインで、承認待ちのメンバーができ、セッションが発行される（承認待ちは /v1/me だけを使える）', async () => {
  const t = setup();
  const userId = newDiscordUser([ROLE, '999']);
  const { res, body } = await login(t, userId);
  assert.equal(res.status, 200);
  assert.equal(body.status, 'ok');
  assert.match(body.access_token!, /^[A-Za-z0-9_-]{43}$/);
  assert.match(body.refresh_token!, /^[A-Za-z0-9_-]{43}$/);
  assert.deepEqual({ role: body.member!.role, status: body.member!.status }, { role: 'member', status: 'pending' });
  const row = t.db.db.prepare('SELECT discord_user_id, display_name, role, status FROM members WHERE id = ?').get(body.member!.id)!;
  assert.deepEqual({ ...row }, { discord_user_id: userId, display_name: 'チームの人', role: 'member', status: 'pending' });
  // 2回目のログインでは、行を増やさない
  await login(t, userId);
  assert.equal(count(t, 'members'), 1);
  // 承認待ち：/v1/me は使えるが、Vault とアイテムは 403（Z-01）
  assert.notEqual((await t.request('GET', '/v1/me', body.access_token)).status, 403);
  assert.equal((await t.request('GET', '/v1/vault', body.access_token)).status, 403);
  assert.equal((await t.request('GET', '/v1/items?since=0', body.access_token)).status, 403);
  // D1 に生のトークンは置かない
  assert.ok(!dump(t).includes(body.access_token!) && !dump(t).includes(body.refresh_token!));
});

test('承認済みのメンバーのログインでは、Vault もアイテムも使えるセッションが発行される', async () => {
  const t = setup();
  const userId = newDiscordUser();
  const first = await login(t, userId);
  t.db.db.prepare(`UPDATE members SET status = 'active' WHERE id = ?`).run(first.body.member!.id);
  const { body } = await login(t, userId);
  assert.equal(body.member!.status, 'active');
  assert.equal((await t.request('GET', '/v1/items?since=0', body.access_token)).status, 200);
});

test('A-02 PKCE の検証値が違うと、Discord が拒否し、ログインも 400 で拒否される（検証値は Discord に渡している）', async () => {
  const t = setup();
  const userId = newDiscordUser();
  const before = fake.requests.length;
  const { res, body } = await login(t, userId, { verifier: 'x'.repeat(43) });
  assert.equal(res.status, 400);
  assert.equal(body.access_token, undefined);
  const tokenRequest = fake.requests.slice(before).find((r) => r.url === `${DISCORD_API}/oauth2/token`)!;
  assert.equal(new URLSearchParams(tokenRequest.body).get('code_verifier'), 'x'.repeat(43));
  assert.equal(count(t, 'members'), 0);
  assert.equal(count(t, 'sessions'), 0);
});

test('A-02 認可コードは1回だけ。同じコードでもう一度ログインすると 400', async () => {
  const t = setup();
  const userId = newDiscordUser();
  const req = await createLoginRequest({ clientId: TEST_ENV.DISCORD_CLIENT_ID, redirectUri: EXTENSION_REDIRECT_URI });
  const code = fake.issueCode({ userId, redirectUri: EXTENSION_REDIRECT_URI, codeChallenge: new URL(req.url).searchParams.get('code_challenge')! });
  const body = { code, code_verifier: req.codeVerifier, redirect_uri: EXTENSION_REDIRECT_URI, device_label: 'テスト端末' };
  assert.equal((await t.request('POST', '/v1/auth/discord', undefined, body)).status, 200);
  assert.equal((await t.request('POST', '/v1/auth/discord', undefined, body)).status, 400);
});

test('A-03 ロールを持たない Discord ユーザー、サーバーにいないユーザーは 403 で、メンバーの行もセッションも作らない', async () => {
  const t = setup();
  for (const roles of [['999'], [], null]) {
    const { res, body } = await login(t, newDiscordUser(roles));
    assert.equal(res.status, 403, JSON.stringify(roles));
    assert.equal(body.access_token, undefined);
  }
  assert.equal(count(t, 'members'), 0);
  assert.equal(count(t, 'sessions'), 0);
});

test('A-13 許可していない redirect_uri でのログインは 400 で、Discord に問い合わせもしない', async () => {
  const t = setup();
  const userId = newDiscordUser();
  const before = fake.requests.length;
  for (const redirectUri of ['https://evil.example.com/', 'https://abcdefghijklmnopabcdefghijklmnop.chromiumapp.org/x', `${EXTENSION_REDIRECT_URI}?a=1`]) {
    const { res } = await login(t, userId, { redirectUri });
    assert.equal(res.status, 400, redirectUri);
  }
  assert.equal(fake.requests.length, before);
  // 許可したものは通る（手動確認用の localhost も設定に書いたので通る）
  assert.equal((await login(t, userId, { redirectUri: LOCAL_REDIRECT_URI })).res.status, 200);
});

test('A-14 ログインの応答、D1、ログに、Discord のトークンとクライアントシークレット、Bot のトークンが残らない', async () => {
  const t = setup();
  const userId = newDiscordUser();
  const logged: string[] = [];
  const original = { log: console.log, error: console.error, warn: console.warn, info: console.info, debug: console.debug };
  for (const k of Object.keys(original) as (keyof typeof original)[]) console[k] = (...args: unknown[]) => void logged.push(args.map(String).join(' '));
  const before = fake.requests.length;
  let text: string;
  try {
    const { res } = await login(t, userId);
    text = await res.text();
  } finally {
    Object.assign(console, original);
  }
  const discordAccessToken = fake.issuedAccessTokens.at(-1)!;
  for (const secret of [discordAccessToken, TEST_ENV.DISCORD_CLIENT_SECRET, TEST_ENV.DISCORD_BOT_TOKEN]) {
    assert.ok(!text.includes(secret), '応答に含まれない');
    assert.ok(!dump(t).includes(secret), 'D1 に残らない');
  }
  assert.deepEqual(logged, [], 'ログに何も出さない');
  // クライアントシークレットはトークンの交換だけに、Bot のトークンはメンバーの取得だけに使い、どちらも discord.com だけに送る
  const sent = fake.requests.slice(before);
  assert.ok(sent.every((r) => r.url.startsWith(`${DISCORD_API}/`)));
  const withSecret = sent.filter((r) => r.body.includes(TEST_ENV.DISCORD_CLIENT_SECRET) || JSON.stringify(r.headers).includes(TEST_ENV.DISCORD_CLIENT_SECRET));
  assert.deepEqual(withSecret.map((r) => r.url), [`${DISCORD_API}/oauth2/token`]);
  const withBot = sent.filter((r) => JSON.stringify(r.headers).includes(TEST_ENV.DISCORD_BOT_TOKEN));
  assert.deepEqual(withBot.map((r) => new URL(r.url).pathname), [`/api/v10/guilds/${TEST_ENV.DISCORD_GUILD_ID}/members/${userId}`]);
  assert.deepEqual(fake.unexpected, []);
});

test('Discord の障害（500）のときは 502 で、セッションを作らない', async () => {
  const t = setup();
  for (const where of ['token', 'user', 'member'] as const) {
    fake.failNext = where;
    const { res } = await login(t, newDiscordUser());
    assert.equal(res.status, 502, where);
  }
  assert.equal(count(t, 'sessions'), 0);
});

test('削除済みのメンバーは、ロールを持っていてもログインできない（403）', async () => {
  const t = setup();
  const userId = newDiscordUser();
  const first = await login(t, userId);
  t.db.db.prepare(`UPDATE members SET status = 'removed' WHERE id = ?`).run(first.body.member!.id);
  assert.equal((await login(t, userId)).res.status, 403);
});

async function refresh(t: Setup, refreshToken: string) {
  const res = await t.request('POST', '/v1/auth/refresh', undefined, { refresh_token: refreshToken });
  return { res, body: (await res.clone().json()) as LoginBody };
}

test('更新：アクセストークンとリフレッシュトークンが新しくなり、古いアクセストークンは 401', async () => {
  const t = setup();
  const { body } = await login(t, newDiscordUser());
  const r = await refresh(t, body.refresh_token!);
  assert.equal(r.res.status, 200);
  assert.notEqual(r.body.access_token, body.access_token);
  assert.notEqual(r.body.refresh_token, body.refresh_token);
  assert.equal((await t.request('GET', '/v1/me/sessions', body.access_token)).status, 401);
  assert.equal((await t.request('GET', '/v1/me/sessions', r.body.access_token)).status, 200);
});

test('A-04 ロールを外された後のセッションの更新は 403 で、そのセッションは無効になる', async () => {
  const t = setup();
  const userId = newDiscordUser();
  const { body } = await login(t, userId);
  fake.setRoles(userId, ['999']);
  assert.equal((await refresh(t, body.refresh_token!)).res.status, 403);
  assert.equal((await t.request('GET', '/v1/me/sessions', body.access_token)).status, 401, 'アクセストークンも使えない');
  // ロールを戻しても、無効にしたセッションは戻らない
  fake.setRoles(userId, [ROLE]);
  assert.equal((await refresh(t, body.refresh_token!)).res.status, 401);
  // サーバーから抜けた場合も同じ
  const other = newDiscordUser();
  const o = await login(t, other);
  fake.setRoles(other, null);
  assert.equal((await refresh(t, o.body.refresh_token!)).res.status, 403);
});

test('A-12 使用済みのリフレッシュトークンをもう一度使うと 401 で、セッションごと無効になる', async () => {
  const t = setup();
  const { body } = await login(t, newDiscordUser());
  const first = await refresh(t, body.refresh_token!);
  assert.equal(first.res.status, 200);
  // 盗まれた古いリフレッシュトークンが使われた
  assert.equal((await refresh(t, body.refresh_token!)).res.status, 401);
  // 正規の利用者の新しいトークンも使えなくなる（盗まれたかもしれないセッションを丸ごと止める）
  assert.equal((await t.request('GET', '/v1/me/sessions', first.body.access_token)).status, 401);
  assert.equal((await refresh(t, first.body.refresh_token!)).res.status, 401);
});

test('A-12 2回以上更新した後に、最初のリフレッシュトークンを送っても、セッションごと無効になる', async () => {
  const t = setup();
  const { body } = await login(t, newDiscordUser());
  const r1 = await refresh(t, body.refresh_token!);
  const r2 = await refresh(t, r1.body.refresh_token!);
  const r3 = await refresh(t, r2.body.refresh_token!);
  assert.equal(r3.res.status, 200);
  // 2世代以上前のトークン（盗まれたもの）が使われた
  assert.equal((await refresh(t, body.refresh_token!)).res.status, 401);
  assert.equal((await t.request('GET', '/v1/me/sessions', r3.body.access_token)).status, 401);
  assert.equal((await refresh(t, r3.body.refresh_token!)).res.status, 401);
  // 別の人のセッションは巻き込まない
  const other = await login(t, newDiscordUser());
  assert.equal((await t.request('GET', '/v1/me/sessions', other.body.access_token)).status, 200);
});

test('使い終わったリフレッシュトークンの記録は、セッションの期限が切れたら、次のログインのときに消す', async () => {
  const t = setup();
  const { body } = await login(t, newDiscordUser());
  await refresh(t, body.refresh_token!);
  assert.equal(count(t, 'used_refresh_tokens'), 1);
  mock.timers.setTime(T0 + 7 * 24 * 60 * 60 * 1000);
  await login(t, newDiscordUser());
  assert.equal(count(t, 'used_refresh_tokens'), 0);
  mock.timers.setTime(T0);
});

test('A-12 同じリフレッシュトークンで同時に更新すると、条件付きの更新に負けた側も使い回しとみなし、セッションごと無効になる', async () => {
  const t = setup();
  const { body } = await login(t, newDiscordUser());
  // 2つの更新が、どちらも古いトークンでセッションを読んだ後、ロールの確認の位置で並ぶ
  fake.holdMemberRequests(2);
  const results = await Promise.all([refresh(t, body.refresh_token!), refresh(t, body.refresh_token!)]);
  assert.deepEqual(results.map((r) => r.res.status).sort(), [200, 401]);
  const winner = results.find((r) => r.res.status === 200)!;
  // 勝った側の新しいトークンも使えない
  assert.equal((await t.request('GET', '/v1/me/sessions', winner.body.access_token)).status, 401);
  assert.equal((await refresh(t, winner.body.refresh_token!)).res.status, 401);
  assert.notEqual(t.db.db.prepare('SELECT revoked_at AS r FROM sessions').get()!.r, null);
});

test('A-05 A-06 期限切れのアクセストークン・リフレッシュトークン、無効化されたセッションは 401', async () => {
  const t = setup();
  const { body } = await login(t, newDiscordUser());
  mock.timers.setTime(T0 + 15 * 60 * 1000 + 1);
  assert.equal((await t.request('GET', '/v1/me/sessions', body.access_token)).status, 401, 'アクセストークンの期限切れ');
  const r = await refresh(t, body.refresh_token!);
  assert.equal(r.res.status, 200, 'リフレッシュトークンはまだ使える');
  mock.timers.setTime(T0 + 7 * 24 * 60 * 60 * 1000 + 1);
  assert.equal((await refresh(t, r.body.refresh_token!)).res.status, 401, 'リフレッシュトークンの期限切れ（更新しても延びない）');
  mock.timers.setTime(T0);
  const s = await login(t, newDiscordUser());
  t.db.db.prepare(`UPDATE sessions SET revoked_at = ? WHERE refresh_token_hash IS NOT NULL`).run(T0);
  assert.equal((await t.request('GET', '/v1/me/sessions', s.body.access_token)).status, 401, '無効化');
  assert.equal((await refresh(t, s.body.refresh_token!)).res.status, 401, '無効化');
});

test('A-07 ログアウトした後は、アクセストークンもリフレッシュトークンも 401', async () => {
  const t = setup();
  const { body } = await login(t, newDiscordUser());
  assert.equal((await t.request('POST', '/v1/auth/logout', body.access_token)).status, 204);
  assert.equal((await t.request('GET', '/v1/me/sessions', body.access_token)).status, 401);
  assert.equal((await refresh(t, body.refresh_token!)).res.status, 401);
  assert.equal((await t.request('POST', '/v1/auth/logout', body.access_token)).status, 401);
});

test('Z-03 他人のセッションは一覧に出ず、無効化しようとしても 404。自分の別のセッションは無効化できる', async () => {
  const t = setup();
  const a = await t.addMember('active');
  const aOther = await t.addSession(a.id);
  const b = await t.addMember('active');
  const list = (await (await t.request('GET', '/v1/me/sessions', a.token)).json()) as { sessions: Record<string, unknown>[] };
  assert.deepEqual(list.sessions.map((s) => s.id).sort(), [a.sessionId, aOther.sessionId].sort());
  assert.ok(list.sessions.every((s) => !('access_token_hash' in s) && !('refresh_token_hash' in s)), 'ハッシュは返さない');
  assert.deepEqual(list.sessions.filter((s) => s.current).map((s) => s.id), [a.sessionId]);
  // B さんのセッションを A さんが無効化しようとする（IDOR）
  assert.equal((await t.request('DELETE', `/v1/me/sessions/${b.sessionId}`, a.token)).status, 404);
  assert.equal((await t.request('GET', '/v1/me/sessions', b.token)).status, 200, 'B さんのセッションは生きている');
  assert.equal((await t.request('DELETE', '/v1/me/sessions/session_nonexistent', a.token)).status, 404);
  // 自分の別のセッションは無効化できる
  assert.equal((await t.request('DELETE', `/v1/me/sessions/${aOther.sessionId}`, a.token)).status, 204);
  assert.equal((await t.request('GET', '/v1/me/sessions', aOther.token)).status, 401);
});

// ---- TOTP ----

// アクセストークンから、そのセッションの TOTP を確かめた時刻を引く
async function verifiedAt(t: Setup, accessToken: string): Promise<number | null> {
  const v = t.db.db.prepare('SELECT totp_verified_at AS v FROM sessions WHERE access_token_hash = ?').get(await sha256Hex(accessToken))!.v;
  return v === null ? null : Number(v);
}

async function totpLogin(t: Setup, userId: string, code: string | { recovery: string }) {
  const { body } = await login(t, userId);
  assert.equal(body.status, 'totp_required');
  const payload = typeof code === 'string' ? { challenge_token: body.challenge_token, code } : { challenge_token: body.challenge_token, recovery_code: code.recovery };
  const res = await t.request('POST', '/v1/auth/totp', undefined, payload);
  return { res, body: (await res.clone().json()) as LoginBody, challenge: body.challenge_token! };
}

async function memberWithTotp(t: Setup, role: 'admin' | 'member' = 'member') {
  const userId = newDiscordUser();
  const secret = crypto.getRandomValues(new Uint8Array(20));
  const m = await t.addMember('active', { role, discordUserId: userId, totpSecret: secret });
  return { userId, secret, ...m };
}

test('TOTP を登録した人のログインは、一時トークンだけを返し、コードを確かめてからセッションを発行する', async () => {
  const t = setup();
  const m = await memberWithTotp(t);
  const { body } = await login(t, m.userId);
  assert.equal(body.status, 'totp_required');
  assert.equal(body.access_token, undefined);
  assert.match(body.challenge_token!, /^[A-Za-z0-9_-]{43}$/);
  // 一時トークンはセッションとしては使えない
  assert.equal((await t.request('GET', '/v1/me', body.challenge_token)).status, 401);
  const res = await t.request('POST', '/v1/auth/totp', undefined, { challenge_token: body.challenge_token, code: referenceTotp(m.secret, stepAt(T0)) });
  assert.equal(res.status, 200);
  const s = (await res.json()) as LoginBody;
  assert.equal((await t.request('GET', '/v1/items?since=0', s.access_token)).status, 200);
  // 確かめた時刻がセッションに入る（管理操作の再確認に使う）
  assert.equal(await verifiedAt(t, s.access_token!), T0);
  // 使った一時トークンはもう使えない
  const again = await t.request('POST', '/v1/auth/totp', undefined, { challenge_token: body.challenge_token, code: referenceTotp(m.secret, stepAt(T0) + 1) });
  assert.equal(again.status, 401);
});

test('TOTP の一時トークンは5分で切れる', async () => {
  const t = setup();
  const m = await memberWithTotp(t);
  const { body } = await login(t, m.userId);
  mock.timers.setTime(T0 + 5 * 60 * 1000 + 1);
  const res = await t.request('POST', '/v1/auth/totp', undefined, { challenge_token: body.challenge_token, code: referenceTotp(m.secret, stepAt(T0 + 5 * 60 * 1000 + 1)) });
  assert.equal(res.status, 401);
  mock.timers.setTime(T0);
});

test('期限切れの一時トークンは、新しく作るときに消す', async () => {
  const t = setup();
  const m = await memberWithTotp(t);
  for (let i = 0; i < 3; i++) await login(t, m.userId);
  assert.equal(count(t, 'auth_challenges'), 3);
  mock.timers.setTime(T0 + 5 * 60 * 1000);
  await login(t, m.userId);
  assert.equal(count(t, 'auth_challenges'), 1, '期限切れの3つは消え、新しい1つだけ');
  mock.timers.setTime(T0);
});

test('A-09 一度使った TOTP コードをもう一度送ると拒否される（それより前のステップのコードも拒否）', async () => {
  const t = setup();
  const m = await memberWithTotp(t);
  const code = referenceTotp(m.secret, stepAt(T0));
  assert.equal((await totpLogin(t, m.userId, code)).res.status, 200);
  assert.equal((await totpLogin(t, m.userId, code)).res.status, 401, '同じコード');
  assert.equal((await totpLogin(t, m.userId, referenceTotp(m.secret, stepAt(T0) - 1))).res.status, 401, '前のステップ');
  assert.equal((await totpLogin(t, m.userId, referenceTotp(m.secret, stepAt(T0) + 1))).res.status, 200, '次のステップ（前後1ステップまで）');
});

test('A-08 間違った TOTP コードを繰り返すと、5回で 15分間 429 になり、正しいコードも受け付けない', async () => {
  const t = setup();
  const m = await memberWithTotp(t);
  for (let i = 0; i < 5; i++) assert.equal((await totpLogin(t, m.userId, '000000')).res.status, 401, `${i + 1}回目`);
  const right = referenceTotp(m.secret, stepAt(T0));
  assert.equal((await totpLogin(t, m.userId, right)).res.status, 429);
  // ログインした後の再確認（ステップアップ）でも同じ数え方
  const s = await t.addSession(m.id);
  assert.equal((await t.request('POST', '/v1/auth/totp', s.token, { code: right })).status, 429);
  // 15分たてば受け付ける
  mock.timers.setTime(T0 + 15 * 60 * 1000);
  assert.equal((await totpLogin(t, m.userId, referenceTotp(m.secret, stepAt(T0 + 15 * 60 * 1000)))).res.status, 200);
  mock.timers.setTime(T0);
});

test('A-08 間違った TOTP コードを同時に20個送っても、試せるのは5回までで、残りは確かめずに 429', async () => {
  const t = setup();
  const m = await memberWithTotp(t);
  const challenges: string[] = [];
  for (let i = 0; i < 20; i++) challenges.push((await login(t, m.userId)).body.challenge_token!);
  const results = await Promise.all(challenges.map((ch) => t.request('POST', '/v1/auth/totp', undefined, { challenge_token: ch, code: '000000' })));
  const statuses = results.map((r) => r.status);
  assert.equal(statuses.filter((s) => s === 401).length, 5, '確かめたのは5回');
  assert.equal(statuses.filter((s) => s === 429).length, 15);
  // 回復コードでも同じ数え方
  assert.equal((await totpLogin(t, m.userId, { recovery: 'AAAA-AAAA-AAAA-AAAA' })).res.status, 429);
});

test('A-08 時間をおいて失敗を重ねても、5回目の失敗の時刻から15分締め出される', async () => {
  const t = setup();
  const m = await memberWithTotp(t);
  const at = (ms: number) => mock.timers.setTime(T0 + ms);
  const MIN = 60 * 1000;
  for (const [i, ms] of [0, 4 * MIN, 8 * MIN, 12 * MIN, 14 * MIN + 59_000].entries()) {
    at(ms);
    assert.equal((await totpLogin(t, m.userId, '000000')).res.status, 401, `${i + 1}回目`);
  }
  const fifth = 14 * MIN + 59_000;
  // 最初の失敗から15分を過ぎても、5回目から15分たつまでは、正しいコードも 429
  for (const ms of [15 * MIN + 1000, fifth + 15 * MIN - 1]) {
    at(ms);
    assert.equal((await totpLogin(t, m.userId, referenceTotp(m.secret, stepAt(T0 + ms)))).res.status, 429, `${ms}`);
  }
  at(fifth + 15 * MIN);
  assert.equal((await totpLogin(t, m.userId, referenceTotp(m.secret, stepAt(T0 + fifth + 15 * MIN)))).res.status, 200);
  mock.timers.setTime(T0);
});

test('A-08 成功したら失敗の回数を戻す（4回失敗して成功した後は、また5回まで試せる）', async () => {
  const t = setup();
  const m = await memberWithTotp(t);
  for (let i = 0; i < 4; i++) assert.equal((await totpLogin(t, m.userId, '000000')).res.status, 401);
  assert.equal((await totpLogin(t, m.userId, referenceTotp(m.secret, stepAt(T0)))).res.status, 200);
  for (let i = 0; i < 4; i++) assert.equal((await totpLogin(t, m.userId, '000000')).res.status, 401, `戻した後の${i + 1}回目`);
  mock.timers.setTime(T0 + 30_000);
  assert.equal((await totpLogin(t, m.userId, referenceTotp(m.secret, stepAt(T0 + 30_000)))).res.status, 200);
  mock.timers.setTime(T0);
});

test('A-08 TOTP の登録の確定でも、同時に送ったコードは5回までしか試せない', async () => {
  const t = setup();
  const m = await t.addMember('active');
  await t.request('POST', '/v1/me/totp', m.token);
  const results = await Promise.all(Array.from({ length: 20 }, () => t.request('POST', '/v1/me/totp/confirm', m.token, { code: '000000' })));
  const statuses = results.map((r) => r.status);
  assert.equal(statuses.filter((s) => s === 403).length, 5);
  assert.equal(statuses.filter((s) => s === 429).length, 15);
});

test('回復コードは1回だけ使える', async () => {
  const t = setup();
  // 拡張機能から登録して、回復コードを受け取る
  const userId = newDiscordUser();
  const m = await t.addMember('active', { discordUserId: userId });
  const reg = (await (await t.request('POST', '/v1/me/totp', m.token)).json()) as { secret: string };
  const secret = base32ToBytes(reg.secret);
  const confirm = await t.request('POST', '/v1/me/totp/confirm', m.token, { code: referenceTotp(secret, stepAt(T0)) });
  const { recovery_codes } = (await confirm.json()) as { recovery_codes: string[] };
  assert.equal((await totpLogin(t, userId, { recovery: recovery_codes[0]! })).res.status, 200);
  assert.equal((await totpLogin(t, userId, { recovery: recovery_codes[0]! })).res.status, 401, '2回目');
  assert.equal((await totpLogin(t, userId, { recovery: recovery_codes[1]!.toLowerCase() })).res.status, 200, '別のコードは使える');
  assert.equal((await totpLogin(t, userId, { recovery: 'AAAA-AAAA-AAAA-AAAA' })).res.status, 401);
  // D1 には回復コードそのものを置かない
  const row = String(t.db.db.prepare('SELECT recovery_code_hashes AS h FROM members WHERE id = ?').get(m.id)!.h);
  assert.ok(recovery_codes.every((c) => !row.includes(c) && !row.includes(c.replace(/-/g, ''))));
  assert.equal((JSON.parse(row) as string[]).length, 8);
});

test('TOTP の登録：登録途中のシークレットはコードで確定するまで使わない。D1 の暗号文は先頭に形式とアルゴリズムID を持つ', async () => {
  const t = setup();
  const m = await t.addMember('active');
  const r1 = await t.request('POST', '/v1/me/totp', m.token);
  assert.equal(r1.status, 200);
  const reg = (await r1.json()) as { secret: string; otpauth_uri: string };
  assert.ok(reg.otpauth_uri.startsWith('otpauth://totp/'));
  const secret = base32ToBytes(reg.secret);
  assert.equal(secret.length, 20);
  const pending = String(t.db.db.prepare('SELECT totp_pending_secret_encrypted AS s FROM members WHERE id = ?').get(m.id)!.s);
  const bytes = fromBase64Url(pending);
  assert.deepEqual([bytes[0], bytes[1]], [0x01, 0x01]);
  assert.ok(!pending.includes(reg.secret));
  assert.equal(t.db.db.prepare('SELECT totp_secret_encrypted AS s FROM members WHERE id = ?').get(m.id)!.s, null);
  // 間違ったコードでは確定しない
  assert.equal((await t.request('POST', '/v1/me/totp/confirm', m.token, { code: '000000' })).status, 403);
  const ok = await t.request('POST', '/v1/me/totp/confirm', m.token, { code: referenceTotp(secret, stepAt(T0)) });
  assert.equal(ok.status, 200);
  assert.equal(((await ok.json()) as { recovery_codes: string[] }).recovery_codes.length, 10);
  const active = fromBase64Url(String(t.db.db.prepare('SELECT totp_secret_encrypted AS s FROM members WHERE id = ?').get(m.id)!.s));
  assert.deepEqual([active[0], active[1]], [0x01, 0x01]);
  // 登録済みならもう一度は始められない
  assert.equal((await t.request('POST', '/v1/me/totp', m.token)).status, 409);
  // メンバーは解除できる（今のコードが要る）。管理者は解除できない
  assert.equal((await t.request('DELETE', '/v1/me/totp', m.token, { code: '000000' })).status, 403);
  mock.timers.setTime(T0 + 30_000);
  assert.equal((await t.request('DELETE', '/v1/me/totp', m.token, { code: referenceTotp(secret, stepAt(T0 + 30_000)) })).status, 204);
  mock.timers.setTime(T0);
  assert.equal(t.db.db.prepare('SELECT totp_secret_encrypted AS s FROM members WHERE id = ?').get(m.id)!.s, null);
  const admin = await memberWithTotp(t, 'admin');
  assert.equal((await t.request('DELETE', '/v1/me/totp', admin.token, { code: referenceTotp(admin.secret, stepAt(T0)) })).status, 403);
});

test('A-11 TOTP を登録していない管理者は、ログインで登録を求められ、登録するまで管理操作も読み書きもできない', async () => {
  const t = setup();
  const userId = newDiscordUser();
  const first = await login(t, userId);
  t.db.db.prepare(`UPDATE members SET role = 'admin', status = 'active' WHERE id = ?`).run(first.body.member!.id);
  const { body } = await login(t, userId);
  assert.equal(body.status, 'totp_setup_required');
  const token = body.access_token!;
  for (const [method, path] of [
    ['GET', '/v1/me'],
    ['GET', '/v1/vault'],
    ['GET', '/v1/items?since=0'],
    ['GET', '/v1/me/sessions'],
  ] as const) {
    assert.equal((await t.request(method, path, token)).status, 403, `${method} ${path}`);
  }
  assert.equal((await t.request('POST', '/v1/items', token, { id: 'item_AAAAAAAAAAAAAAAAAAAAAA', vault_key_version: 1, ciphertext: 'AQE' })).status, 403);
  // 登録はできる
  const reg = (await (await t.request('POST', '/v1/me/totp', token)).json()) as { secret: string };
  const secret = base32ToBytes(reg.secret);
  assert.equal((await t.request('POST', '/v1/me/totp/confirm', token, { code: referenceTotp(secret, stepAt(T0)) })).status, 200);
  // 登録した後は使える。登録したセッションは TOTP を確かめた扱い
  assert.equal((await t.request('GET', '/v1/items?since=0', token)).status, 200);
  assert.equal(await verifiedAt(t, token), T0);
});

test('ログインした後の TOTP の再確認（ステップアップ）で、セッションの確かめた時刻が新しくなる', async () => {
  const t = setup();
  const m = await memberWithTotp(t);
  const s = await t.addSession(m.id);
  mock.timers.setTime(T0 + 60_000);
  assert.equal((await t.request('POST', '/v1/auth/totp', s.token, { code: '000000' })).status, 403);
  assert.equal((await t.request('POST', '/v1/auth/totp', s.token, { code: referenceTotp(m.secret, stepAt(T0 + 60_000)) })).status, 204);
  assert.equal(Number(t.db.db.prepare('SELECT totp_verified_at AS v FROM sessions WHERE id = ?').get(s.sessionId)!.v), T0 + 60_000);
  mock.timers.setTime(T0);
  // TOTP を登録していないメンバーの再確認は 409
  const plain = await t.addMember('active');
  assert.equal((await t.request('POST', '/v1/auth/totp', plain.token, { code: '000000' })).status, 409);
});
