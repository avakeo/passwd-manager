// 認可の表：「利用者の状態」×「エンドポイント」の全マスを自動テストにする（仕様書「テスト項目 > 認可（Z）」）。
// 許可のマスは 401・403 にならないこと、拒否のマスは決めた番号になることを確かめる。
// 表そのものは docs/review/phase-1.md にも載せる。

import { after, mock, test } from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULT_TOTP_SECRET, fakeCiphertext, setup } from '../helpers/api.ts';
import { FakeDiscord } from '../helpers/fake-discord.ts';
import { TEST_ENV } from '../helpers/api.ts';
import { referenceTotp, stepAt } from '../helpers/totp-reference.ts';

const T0 = 1_800_000_000_000;
mock.timers.enable({ apis: ['Date'], now: T0 });
after(() => mock.timers.reset());
// 公開の入口（ログイン）で Discord に出ても、本物には出ない
const restore = new FakeDiscord({
  clientId: TEST_ENV.DISCORD_CLIENT_ID,
  clientSecret: TEST_ENV.DISCORD_CLIENT_SECRET,
  botToken: TEST_ENV.DISCORD_BOT_TOKEN,
  guildId: TEST_ENV.DISCORD_GUILD_ID,
}).install();
after(restore);

// TOTP は全員必須。「TOTP 未登録」の3つは、登録するまで TOTP の登録とログアウトしかできない（A-11）
export const STATES = [
  '未ログイン',
  'TOTP 待ち',
  'TOTP 未登録（承認待ち）',
  'TOTP 未登録（メンバー）',
  'TOTP 未登録（管理者）',
  '承認待ち',
  'メンバー',
  '管理者',
  '削除済み',
  'Web 用（メンバー）',
] as const;
type State = (typeof STATES)[number];

// ok：許可（401・403 にならない）。数字：その番号で拒否
type Cell = 'ok' | 400 | 401 | 403;
type Ctx = { sessionId: string; itemId: string; code: string; registered: boolean };
type Row = { name: string; method: string; path: (ctx: Ctx) => string; body?: (ctx: Ctx) => unknown; expect: Record<State, Cell> };

// マスは STATES の順に並べる
function cells(...values: Cell[]): Record<State, Cell> {
  assert.equal(values.length, STATES.length);
  return Object.fromEntries(STATES.map((s, i) => [s, values[i]!])) as Record<State, Cell>;
}

//                                 未ログイン TOTP待ち 未登録:承認待ち メンバー 管理者  承認待ち  メンバー 管理者 削除済み Web用
export const ROWS: Row[] = [
  { name: 'POST /v1/auth/logout', method: 'POST', path: () => '/v1/auth/logout', expect: cells(401, 401, 'ok', 'ok', 'ok', 'ok', 'ok', 'ok', 403, 403) },
  { name: 'GET /v1/me', method: 'GET', path: () => '/v1/me', expect: cells(401, 401, 403, 403, 403, 'ok', 'ok', 'ok', 403, 'ok') },
  { name: 'GET /v1/me/sessions', method: 'GET', path: () => '/v1/me/sessions', expect: cells(401, 401, 403, 403, 403, 'ok', 'ok', 'ok', 403, 'ok') },
  {
    name: 'DELETE /v1/me/sessions/{id}',
    method: 'DELETE',
    path: (c) => `/v1/me/sessions/${c.sessionId}`,
    expect: cells(401, 401, 403, 403, 403, 'ok', 'ok', 'ok', 403, 403),
  },
  {
    // この端末を覚える（2026-10-29 追記）。承認待ちでも使える。Web 用は読み取りだけなので 403
    name: 'POST /v1/me/devices',
    method: 'POST',
    path: () => '/v1/me/devices',
    body: () => ({ pin_proof: 'A'.repeat(43) }),
    expect: cells(401, 401, 403, 403, 403, 'ok', 'ok', 'ok', 403, 403),
  },
  {
    // 登録済みの人は作り直し（今のコードを付ける）
    name: 'POST /v1/me/totp（登録、登録済みなら作り直し）',
    method: 'POST',
    path: () => '/v1/me/totp',
    body: (c) => (c.registered ? { code: c.code } : undefined),
    expect: cells(401, 401, 'ok', 'ok', 'ok', 'ok', 'ok', 'ok', 403, 403),
  },
  {
    name: 'POST /v1/me/totp/confirm',
    method: 'POST',
    path: () => '/v1/me/totp/confirm',
    body: () => ({ code: '000000' }),
    expect: cells(401, 401, 'ok', 'ok', 'ok', 'ok', 'ok', 'ok', 403, 403),
  },
  {
    // 未ログインは Bearer がないので一時トークンの形として読み、challenge_token がないので 400
    name: 'POST /v1/auth/totp（再確認、Bearer 付き）',
    method: 'POST',
    path: () => '/v1/auth/totp',
    body: (c) => ({ code: c.code }),
    expect: cells(400, 401, 403, 403, 403, 'ok', 'ok', 'ok', 403, 403),
  },
  // 中身は空（400）。許可のマスでは 401・403 にならないことだけを見る
  { name: 'PUT /v1/me/keys', method: 'PUT', path: () => '/v1/me/keys', body: () => ({}), expect: cells(401, 401, 403, 403, 403, 'ok', 'ok', 'ok', 403, 403) },
  { name: 'POST /v1/vault/init', method: 'POST', path: () => '/v1/vault/init', body: () => ({}), expect: cells(401, 401, 403, 403, 403, 403, 403, 'ok', 403, 403) },
  { name: 'GET /v1/vault', method: 'GET', path: () => '/v1/vault', expect: cells(401, 401, 403, 403, 403, 403, 'ok', 'ok', 403, 'ok') },
  { name: 'GET /v1/items', method: 'GET', path: () => '/v1/items?after=0', expect: cells(401, 401, 403, 403, 403, 403, 'ok', 'ok', 403, 'ok') },
  {
    name: 'POST /v1/items',
    method: 'POST',
    path: () => '/v1/items',
    body: () => ({ id: `item_${'B'.repeat(22)}`, vault_key_version: 1, ciphertext: fakeCiphertext() }),
    expect: cells(401, 401, 403, 403, 403, 403, 'ok', 'ok', 403, 403),
  },
  {
    name: 'POST /v1/items/import',
    method: 'POST',
    path: () => '/v1/items/import',
    body: () => ({ vault_key_version: 1, items: [{ id: `item_${'C'.repeat(22)}`, ciphertext: fakeCiphertext() }] }),
    expect: cells(401, 401, 403, 403, 403, 403, 'ok', 'ok', 403, 403),
  },
  {
    name: 'PUT /v1/items/{id}',
    method: 'PUT',
    path: (c) => `/v1/items/${c.itemId}`,
    body: () => ({ revision: 1, vault_key_version: 1, ciphertext: fakeCiphertext() }),
    expect: cells(401, 401, 403, 403, 403, 403, 'ok', 'ok', 403, 403),
  },
  {
    name: 'DELETE /v1/items/{id}',
    method: 'DELETE',
    path: (c) => `/v1/items/${c.itemId}`,
    body: () => ({ revision: 1 }),
    expect: cells(401, 401, 403, 403, 403, 403, 'ok', 'ok', 403, 403),
  },
];

// 公開の入口（Bearer を使わない）。どの状態の人でも、トークンなしで呼ぶ。
test('Z（表） 公開の入口：ログイン・更新・TOTP の一時トークンは、Bearer なしで呼べ、不正な中身は 400・401 で拒否する', async () => {
  const t = setup();
  assert.equal((await t.request('POST', '/v1/auth/discord', undefined, { code: 'x', code_verifier: 'y'.repeat(43), redirect_uri: 'https://evil.example.com/', device_label: 'x' })).status, 400);
  assert.equal((await t.request('POST', '/v1/auth/discord', undefined, '{')).status, 400);
  assert.equal((await t.request('POST', '/v1/auth/refresh', undefined, { refresh_token: 'A'.repeat(43) })).status, 401);
  assert.equal((await t.request('POST', '/v1/auth/refresh', undefined, { refresh_token: 1 })).status, 400);
  assert.equal((await t.request('POST', '/v1/auth/totp', undefined, { challenge_token: 'A'.repeat(43), code: '000000' })).status, 401);
  assert.equal((await t.request('POST', '/v1/auth/totp', undefined, { challenge_token: 'A'.repeat(43), code: '000000', extra: 1 })).status, 400);
  // この端末を覚えた後の復帰（2026-10-29 追記）。知らない端末のトークンは 403、形の違う値は 400
  assert.equal((await t.request('POST', '/v1/auth/resume', undefined, { device_token: 'A'.repeat(43), pin_proof: 'A'.repeat(43) })).status, 403);
  assert.equal((await t.request('POST', '/v1/auth/resume', undefined, { device_token: 'A'.repeat(43) })).status, 400);
});

// 1マスを1つのテストにする（結果の一覧で、マスごとに成功・失敗が分かる）
for (const row of ROWS) {
  for (const state of STATES) {
    test(`Z（表） ${row.name} × ${state} → ${row.expect[state]}`, async () => {
      // マスごとに作り直す（前のマスの操作の影響を受けない）
      const t = setup();
      const owner = await t.addMember('active');
      const itemId = `item_${'A'.repeat(22)}`;
      await t.request('POST', '/v1/items', owner.token, { id: itemId, vault_key_version: 1, ciphertext: fakeCiphertext() });
      const registered = !state.startsWith('TOTP 未登録');
      let token: string | undefined;
      let sessionId = 'session_none';
      if (state === 'TOTP 待ち') {
        // ログインの途中の一時トークンを、Bearer として使おうとする
        const m = await t.addMember('active');
        token = 'challenge_' + m.token.slice(10); // セッションの表にないトークン
        t.db.db
          .prepare(`INSERT INTO auth_challenges (id, member_id, challenge_hash, scope, device_label, created_at, expires_at) VALUES ('ch_1', ?, 'h', 'extension', 'x', ?, ?)`)
          .run(m.id, T0, T0 + 300000);
      } else if (state !== '未ログイン') {
        const pending = state === '承認待ち' || state === 'TOTP 未登録（承認待ち）';
        const m = await t.addMember(pending ? 'pending' : state === '削除済み' ? 'removed' : 'active', {
          role: state === '管理者' || state === 'TOTP 未登録（管理者）' ? 'admin' : 'member',
          scope: state === 'Web 用（メンバー）' ? 'web' : 'extension',
          totpSecret: registered ? DEFAULT_TOTP_SECRET : null,
          totpVerifiedAt: T0, // 自分の別のセッションの無効化には、5分以内の TOTP の確認が要る（A-15）
        });
        token = m.token;
        const other = await t.addSession(m.id, { scope: state === 'Web 用（メンバー）' ? 'web' : 'extension' });
        sessionId = other.sessionId;
      }
      // TOTP の行は、中身によって 409 などになることがあるが、許可のマスでは 401・403 にはならない
      const ctx: Ctx = { sessionId, itemId, code: referenceTotp(DEFAULT_TOTP_SECRET, stepAt(T0)), registered };
      const res = await t.request(row.method, row.path(ctx), token, row.body?.(ctx));
      const expected = row.expect[state];
      if (expected === 'ok') assert.ok(res.status !== 401 && res.status !== 403, `${state}：許可のはずが ${res.status}`);
      else assert.equal(res.status, expected, `${state}`);
    });
  }
}
