// 拡張機能から Web ページを開く（2026-11-05 追記、W-09）。仕様書「Webページの配信」。
//   POST /v1/me/web-handoff：拡張機能のセッションで、1分だけ使える使い捨てのコードを作る
//   POST /v1/auth/web-handoff（公開）：コードを Web 用（読み取り専用）のセッションに替える
// TOTP を確かめた時刻と、リフレッシュの期限は、元の拡張機能のセッションから引き継ぐ（コードを通して延ばせない）。

import { after, beforeEach, mock, test } from 'node:test';
import assert from 'node:assert/strict';
import { sha256Hex } from '../../src/api/auth.ts';
import { FakeDiscord } from '../helpers/fake-discord.ts';
import { TEST_ENV, setup } from '../helpers/api.ts';

const T0 = 1_800_000_000_000;
mock.timers.enable({ apis: ['Date'], now: T0 });
after(() => mock.timers.reset());
beforeEach(() => mock.timers.setTime(T0));

const fake = new FakeDiscord({ clientId: TEST_ENV.DISCORD_CLIENT_ID, clientSecret: TEST_ENV.DISCORD_CLIENT_SECRET, botToken: TEST_ENV.DISCORD_BOT_TOKEN, guildId: TEST_ENV.DISCORD_GUILD_ID });
after(fake.install());

let nextUser = 710000000000000000n;
function newDiscordUser(): string {
  nextUser += 1n;
  const id = String(nextUser);
  fake.addUser(id, { roles: [TEST_ENV.DISCORD_ROLE_ID], globalName: 'チームの人' });
  return id;
}

type Setup = ReturnType<typeof setup>;
type Json = Record<string, unknown>;

async function extensionMember(t: Setup, role: 'admin' | 'member' = 'member', totpVerifiedAt: number | null = T0) {
  const userId = newDiscordUser();
  const m = await t.addMember('active', { role, discordUserId: userId, totpVerifiedAt });
  return { ...m, userId };
}

async function newCode(t: Setup, token: string): Promise<string> {
  const res = await t.request('POST', '/v1/me/web-handoff', token, {});
  assert.equal(res.status, 201);
  const body = (await res.json()) as Json;
  assert.match(String(body.code), /^[A-Za-z0-9_-]{43}$/);
  return String(body.code);
}

async function exchange(t: Setup, code: string) {
  const res = await t.request('POST', '/v1/auth/web-handoff', undefined, { code });
  return { res, body: res.ok ? ((await res.json()) as Json) : {} };
}

test('W-09 拡張機能のセッションで作ったコードを、Web 用（読み取り専用）のセッションに替えられる', async () => {
  const t = setup();
  const m = await extensionMember(t);
  const { res, body } = await exchange(t, await newCode(t, m.token));
  assert.equal(res.status, 200);
  assert.deepEqual(body.member, { id: m.id, role: 'member', status: 'active' });
  const web = String(body.access_token);
  assert.equal((await t.request('GET', '/v1/members', web)).status, 200);
  assert.equal((await t.request('GET', '/v1/items?after=0', web)).status, 403, '読み取り専用。アイテムは読めない');
  const row = t.db.db.prepare('SELECT scope, device_label FROM sessions WHERE access_token_hash = ?').get(await sha256Hex(web))!;
  assert.deepEqual({ ...row }, { scope: 'web', device_label: 'Web ページ' });
  // 元の拡張機能のセッションはそのまま使える
  assert.equal((await t.request('GET', '/v1/me/sessions', m.token)).status, 200);
});

test('W-09 コードは1回だけ。2回目は 401', async () => {
  const t = setup();
  const m = await extensionMember(t);
  const code = await newCode(t, m.token);
  assert.equal((await exchange(t, code)).res.status, 200);
  assert.equal((await exchange(t, code)).res.status, 401);
});

test('W-09 コードの期限は1分。過ぎたら 401', async () => {
  const t = setup();
  const m = await extensionMember(t);
  const code = await newCode(t, m.token);
  mock.timers.setTime(T0 + 61 * 1000);
  assert.equal((await exchange(t, code)).res.status, 401);
});

test('W-09 知らないコード、形の違うコードは断る', async () => {
  const t = setup();
  assert.equal((await exchange(t, 'a'.repeat(43))).res.status, 401);
  assert.equal((await exchange(t, 'short')).res.status, 400);
  assert.equal((await t.request('POST', '/v1/auth/web-handoff', undefined, {})).status, 400);
});

test('W-09 D1 にはコードの SHA-256 だけを置く', async () => {
  const t = setup();
  const m = await extensionMember(t);
  const code = await newCode(t, m.token);
  const rows = t.db.db.prepare('SELECT * FROM web_handoffs').all();
  assert.equal(rows.length, 1);
  assert.equal(rows[0]!.code_hash, await sha256Hex(code));
  assert.ok(!JSON.stringify(rows).includes(code));
});

test('W-09 TOTP を確かめた時刻は元のセッションから引き継ぐ。監査ログは、拡張機能で確かめてから5分の間だけ', async () => {
  const t = setup();
  const admin = await extensionMember(t, 'admin', T0);
  mock.timers.setTime(T0 + 4 * 60 * 1000);
  const fresh = await exchange(t, await newCode(t, admin.token));
  assert.equal((await t.request('GET', '/v1/audit-logs', String(fresh.body.access_token))).status, 200);
  mock.timers.setTime(T0 + 6 * 60 * 1000);
  const late = await exchange(t, await newCode(t, admin.token));
  assert.equal((await t.request('GET', '/v1/audit-logs', String(late.body.access_token))).status, 403, 'コードを通して5分を延ばせない');

  // TOTP を確かめた扱いでないセッション（端末を覚えた戻り）からは、確かめていない Web のセッションになる
  const resumed = await extensionMember(t, 'admin', null);
  const web = await exchange(t, await newCode(t, resumed.token));
  assert.equal(web.res.status, 200);
  const row = t.db.db.prepare('SELECT totp_verified_at FROM sessions WHERE access_token_hash = ?').get(await sha256Hex(String(web.body.access_token)))!;
  assert.equal(row.totp_verified_at, null);
});

test('W-09 Web のセッションの期限は、元の拡張機能のセッションより後にならない', async () => {
  const t = setup();
  const m = await extensionMember(t);
  // 3日後も拡張機能はセッションを更新して使っている（アクセストークンの期限だけを延ばして表す。リフレッシュの期限はログインから7日のまま）
  t.db.db.prepare('UPDATE sessions SET expires_at = ? WHERE id = ?').run(T0 + 4 * 24 * 60 * 60 * 1000, m.sessionId);
  mock.timers.setTime(T0 + 3 * 24 * 60 * 60 * 1000);
  const { body } = await exchange(t, await newCode(t, m.token));
  assert.equal(body.refresh_expires_at, T0 + 7 * 24 * 60 * 60 * 1000);
  const row = t.db.db.prepare('SELECT refresh_expires_at FROM sessions WHERE access_token_hash = ?').get(await sha256Hex(String(body.access_token)))!;
  assert.equal(row.refresh_expires_at, T0 + 7 * 24 * 60 * 60 * 1000);
});

test('W-09 Web 用のトークンでは、コードを作れない（403）', async () => {
  const t = setup();
  const m = await extensionMember(t);
  const { body } = await exchange(t, await newCode(t, m.token));
  assert.equal((await t.request('POST', '/v1/me/web-handoff', String(body.access_token), {})).status, 403);
});

test('W-09 コードを作った後に削除された、またはロールを外された人は、替えられない（403）', async () => {
  const t = setup();
  const removed = await extensionMember(t);
  const code1 = await newCode(t, removed.token);
  t.db.db.prepare(`UPDATE members SET status = 'removed' WHERE id = ?`).run(removed.id);
  assert.equal((await exchange(t, code1)).res.status, 403);

  const noRole = await extensionMember(t);
  const code2 = await newCode(t, noRole.token);
  fake.addUser(noRole.userId, { roles: [], globalName: 'チームの人' });
  assert.equal((await exchange(t, code2)).res.status, 403);
});

test('W-09 元の拡張機能のセッションを無効にした後は、作ってあったコードも使えない（401）', async () => {
  const t = setup();
  const m = await extensionMember(t);
  const code = await newCode(t, m.token);
  t.db.db.prepare('UPDATE sessions SET revoked_at = ? WHERE id = ?').run(T0, m.sessionId);
  assert.equal((await exchange(t, code)).res.status, 401);
});

test('W-09 替えたら監査ログに残す', async () => {
  const t = setup();
  const m = await extensionMember(t);
  await exchange(t, await newCode(t, m.token));
  const log = t.db.db.prepare(`SELECT actor_member_id, target_id FROM audit_logs WHERE action = 'auth.web_handoff'`).all();
  assert.deepEqual(log.map((r) => ({ ...r })), [{ actor_member_id: m.id, target_id: m.id }]);
});

test('W-09 Web ページのオリジンが設定されていなければ、コードを作らない（404）', async () => {
  const t = setup();
  const m = await extensionMember(t);
  const res = await t.app.request('/v1/me/web-handoff', { method: 'POST', headers: { Authorization: `Bearer ${m.token}`, 'Content-Type': 'application/json' }, body: '{}' }, { ...t.env, WEB_ORIGIN: '' });
  assert.equal(res.status, 404);
});
