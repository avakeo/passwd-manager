// Web ページ（2026-11-01 追記、判断待ち10）の API 側：Web 用のログインと CORS。
// Web ページは鍵を使わず、トークンは読み取り専用（Z-07・Z-08）。redirect_uri が Web ページのオリジンなら、Web 用のセッションを発行する。

import { after, beforeEach, mock, test } from 'node:test';
import assert from 'node:assert/strict';
import { createLoginRequest } from '../../src/client/discord-login.ts';
import { FakeDiscord } from '../helpers/fake-discord.ts';
import { EXTENSION_REDIRECT_URI, TEST_ENV, WEB_ORIGIN, WEB_REDIRECT_URI, setup } from '../helpers/api.ts';
import { referenceTotp, stepAt } from '../helpers/totp-reference.ts';

const T0 = 1_800_000_000_000;
mock.timers.enable({ apis: ['Date'], now: T0 });
after(() => mock.timers.reset());
beforeEach(() => mock.timers.setTime(T0));

const fake = new FakeDiscord({ clientId: TEST_ENV.DISCORD_CLIENT_ID, clientSecret: TEST_ENV.DISCORD_CLIENT_SECRET, botToken: TEST_ENV.DISCORD_BOT_TOKEN, guildId: TEST_ENV.DISCORD_GUILD_ID });
after(fake.install());

let nextUser = 700000000000000000n;
function newDiscordUser(): string {
  nextUser += 1n;
  const id = String(nextUser);
  fake.addUser(id, { roles: [TEST_ENV.DISCORD_ROLE_ID], globalName: 'チームの人' });
  return id;
}

type Setup = ReturnType<typeof setup>;

async function login(t: Setup, userId: string, redirectUri: string) {
  const req = await createLoginRequest({ clientId: TEST_ENV.DISCORD_CLIENT_ID, redirectUri });
  const code = fake.issueCode({ userId, redirectUri, codeChallenge: new URL(req.url).searchParams.get('code_challenge')! });
  const res = await t.request('POST', '/v1/auth/discord', undefined, { code, code_verifier: req.codeVerifier, redirect_uri: redirectUri, device_label: 'Web ページ' });
  return { res, body: (await res.clone().json()) as Record<string, unknown> };
}

async function webSession(t: Setup, role: 'admin' | 'member' = 'member') {
  const userId = newDiscordUser();
  const secret = crypto.getRandomValues(new Uint8Array(20));
  await t.addMember('active', { role, discordUserId: userId, totpSecret: secret });
  const { body } = await login(t, userId, WEB_REDIRECT_URI);
  assert.equal(body.status, 'totp_required');
  const res = await t.request('POST', '/v1/auth/totp', undefined, { challenge_token: body.challenge_token, code: referenceTotp(secret, stepAt(T0)) });
  assert.equal(res.status, 200);
  return (await res.json()) as { access_token: string; refresh_token: string };
}

// ログインで発行したセッションの用途（addMember が作るセッションは数えない）
function scopeOf(t: Setup): string[] {
  return t.db.db.prepare(`SELECT scope FROM sessions WHERE device_label = 'Web ページ' ORDER BY created_at, id`).all().map((r) => String(r.scope));
}

test('W-06 redirect_uri が Web ページのオリジンなら、TOTP を確かめてから Web 用（読み取り専用）のセッションを発行する', async () => {
  const t = setup();
  const s = await webSession(t);
  assert.deepEqual(scopeOf(t), ['web']);
  assert.equal((await t.request('GET', '/v1/me/sessions', s.access_token)).status, 200);
  assert.equal((await t.request('GET', '/v1/members', s.access_token)).status, 200);
  // 書き込みは 403（Z-07）
  assert.equal((await t.request('POST', '/v1/items', s.access_token, {})).status, 403);
  assert.equal((await t.request('PUT', '/v1/me/keys', s.access_token, {})).status, 403);
  // 秘密鍵の暗号文と KDF の設定は返さない（Z-08）
  const me = JSON.stringify(await (await t.request('GET', '/v1/me', s.access_token)).json());
  assert.ok(!me.includes('encrypted_private_key') && !me.includes('kdf_params'));
});

test('W-06 拡張機能の redirect_uri なら、今までどおり拡張機能用のセッション', async () => {
  const t = setup();
  const userId = newDiscordUser();
  const secret = crypto.getRandomValues(new Uint8Array(20));
  await t.addMember('active', { discordUserId: userId, totpSecret: secret });
  const { body } = await login(t, userId, EXTENSION_REDIRECT_URI);
  await t.request('POST', '/v1/auth/totp', undefined, { challenge_token: body.challenge_token, code: referenceTotp(secret, stepAt(T0)) });
  assert.deepEqual(scopeOf(t), ['extension']);
});

test('W-07 TOTP をまだ登録していない人は、Web ページではログインできない（登録は拡張機能で行う）', async () => {
  const t = setup();
  const userId = newDiscordUser();
  const { res } = await login(t, userId, WEB_REDIRECT_URI);
  assert.equal(res.status, 403);
  assert.deepEqual(scopeOf(t), []);
});

test('W-07 Web 用のセッションのリフレッシュも Web 用のまま', async () => {
  const t = setup();
  const s = await webSession(t);
  const res = await t.request('POST', '/v1/auth/refresh', undefined, { refresh_token: s.refresh_token });
  assert.equal(res.status, 200);
  const next = (await res.json()) as { access_token: string };
  assert.equal((await t.request('POST', '/v1/items', next.access_token, {})).status, 403);
  assert.ok(scopeOf(t).every((x) => x === 'web'));
});

test('W-01 W-02 CORS は、設定した Web ページのオリジン1つだけを許可する', async () => {
  const t = setup();
  const pre = (origin: string, env: Record<string, unknown> = {}) =>
    t.app.request('/v1/me', { method: 'OPTIONS', headers: { Origin: origin, 'Access-Control-Request-Method': 'GET', 'Access-Control-Request-Headers': 'authorization' } }, { DB: t.db, ...TEST_ENV, ...env });
  assert.equal((await pre(WEB_ORIGIN)).headers.get('access-control-allow-origin'), WEB_ORIGIN);
  // 設定を変えれば、そのオリジンだけになる（実際のドメインはリポジトリに書かず、Workers の設定に置く）
  const other = 'https://teampw-web.example.workers.dev';
  assert.equal((await pre(other, { WEB_ORIGIN: other })).headers.get('access-control-allow-origin'), other);
  assert.equal((await pre(WEB_ORIGIN, { WEB_ORIGIN: other })).headers.get('access-control-allow-origin'), null);
  // 設定がなければ、どこも許可しない
  assert.equal((await pre(WEB_ORIGIN, { WEB_ORIGIN: undefined })).headers.get('access-control-allow-origin'), null);
  for (const origin of ['https://evil.example.com', `${WEB_ORIGIN}.evil.test`, WEB_ORIGIN.replace('https:', 'http:'), 'null']) {
    assert.equal((await pre(origin)).headers.get('access-control-allow-origin'), null, origin);
  }
});
