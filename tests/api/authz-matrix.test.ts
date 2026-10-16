// 認可の表：「利用者の状態」×「エンドポイント」の全マスを自動テストにする（仕様書「テスト項目 > 認可（Z）」）。
// 許可のマスは 401・403 にならないこと、拒否のマスは決めた番号になることを確かめる。
// 表そのものは docs/review/phase-1.md にも載せる。

import { after, mock, test } from 'node:test';
import assert from 'node:assert/strict';
import { fakeCiphertext, setup } from '../helpers/api.ts';
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

export const STATES = ['未ログイン', 'TOTP 待ち', '承認待ち', 'メンバー', '管理者（TOTP 未登録）', '管理者', '削除済み', 'Web 用（メンバー）'] as const;
type State = (typeof STATES)[number];

// ok：許可（401・403 にならない）。数字：その番号で拒否
type Cell = 'ok' | 400 | 401 | 403;
type Row = { name: string; method: string; path: (ctx: Ctx) => string; body?: (ctx: Ctx) => unknown; expect: Record<State, Cell> };
type Ctx = { sessionId: string; itemId: string; code: string };

const ALL_OK_MEMBER: Pick<Record<State, Cell>, 'メンバー' | '管理者'> = { メンバー: 'ok', 管理者: 'ok' };

export const ROWS: Row[] = [
  {
    name: 'POST /v1/auth/logout',
    method: 'POST',
    path: () => '/v1/auth/logout',
    expect: { 未ログイン: 401, 'TOTP 待ち': 401, 承認待ち: 'ok', ...ALL_OK_MEMBER, '管理者（TOTP 未登録）': 'ok', 削除済み: 403, 'Web 用（メンバー）': 403 },
  },
  {
    name: 'GET /v1/me',
    method: 'GET',
    path: () => '/v1/me',
    expect: { 未ログイン: 401, 'TOTP 待ち': 401, 承認待ち: 'ok', ...ALL_OK_MEMBER, '管理者（TOTP 未登録）': 403, 削除済み: 403, 'Web 用（メンバー）': 'ok' },
  },
  {
    name: 'GET /v1/me/sessions',
    method: 'GET',
    path: () => '/v1/me/sessions',
    expect: { 未ログイン: 401, 'TOTP 待ち': 401, 承認待ち: 'ok', ...ALL_OK_MEMBER, '管理者（TOTP 未登録）': 403, 削除済み: 403, 'Web 用（メンバー）': 'ok' },
  },
  {
    name: 'DELETE /v1/me/sessions/{id}',
    method: 'DELETE',
    path: (c) => `/v1/me/sessions/${c.sessionId}`,
    expect: { 未ログイン: 401, 'TOTP 待ち': 401, 承認待ち: 'ok', ...ALL_OK_MEMBER, '管理者（TOTP 未登録）': 403, 削除済み: 403, 'Web 用（メンバー）': 403 },
  },
  {
    name: 'POST /v1/me/totp',
    method: 'POST',
    path: () => '/v1/me/totp',
    expect: { 未ログイン: 401, 'TOTP 待ち': 401, 承認待ち: 'ok', ...ALL_OK_MEMBER, '管理者（TOTP 未登録）': 'ok', 削除済み: 403, 'Web 用（メンバー）': 403 },
  },
  {
    name: 'POST /v1/me/totp/confirm',
    method: 'POST',
    path: () => '/v1/me/totp/confirm',
    body: () => ({ code: '000000' }),
    expect: { 未ログイン: 401, 'TOTP 待ち': 401, 承認待ち: 'ok', ...ALL_OK_MEMBER, '管理者（TOTP 未登録）': 'ok', 削除済み: 403, 'Web 用（メンバー）': 403 },
  },
  {
    name: 'DELETE /v1/me/totp',
    method: 'DELETE',
    path: () => '/v1/me/totp',
    body: (c) => ({ code: c.code }),
    expect: { 未ログイン: 401, 'TOTP 待ち': 401, 承認待ち: 'ok', メンバー: 'ok', '管理者（TOTP 未登録）': 403, 管理者: 403, 削除済み: 403, 'Web 用（メンバー）': 403 },
  },
  {
    name: 'POST /v1/auth/totp（再確認、Bearer 付き）',
    method: 'POST',
    path: () => '/v1/auth/totp',
    body: (c) => ({ code: c.code }),
    // 未ログインは Bearer がないので一時トークンの形として読み、challenge_token がないので 400
    expect: { 未ログイン: 400, 'TOTP 待ち': 401, 承認待ち: 'ok', ...ALL_OK_MEMBER, '管理者（TOTP 未登録）': 403, 削除済み: 403, 'Web 用（メンバー）': 403 },
  },
  {
    name: 'GET /v1/vault',
    method: 'GET',
    path: () => '/v1/vault',
    expect: { 未ログイン: 401, 'TOTP 待ち': 401, 承認待ち: 403, ...ALL_OK_MEMBER, '管理者（TOTP 未登録）': 403, 削除済み: 403, 'Web 用（メンバー）': 'ok' },
  },
  {
    name: 'GET /v1/items',
    method: 'GET',
    path: () => '/v1/items?since=0',
    expect: { 未ログイン: 401, 'TOTP 待ち': 401, 承認待ち: 403, ...ALL_OK_MEMBER, '管理者（TOTP 未登録）': 403, 削除済み: 403, 'Web 用（メンバー）': 'ok' },
  },
  {
    name: 'POST /v1/items',
    method: 'POST',
    path: () => '/v1/items',
    body: () => ({ id: `item_${'B'.repeat(22)}`, vault_key_version: 1, ciphertext: fakeCiphertext() }),
    expect: { 未ログイン: 401, 'TOTP 待ち': 401, 承認待ち: 403, ...ALL_OK_MEMBER, '管理者（TOTP 未登録）': 403, 削除済み: 403, 'Web 用（メンバー）': 403 },
  },
  {
    name: 'PUT /v1/items/{id}',
    method: 'PUT',
    path: (c) => `/v1/items/${c.itemId}`,
    body: () => ({ revision: 1, vault_key_version: 1, ciphertext: fakeCiphertext() }),
    expect: { 未ログイン: 401, 'TOTP 待ち': 401, 承認待ち: 403, ...ALL_OK_MEMBER, '管理者（TOTP 未登録）': 403, 削除済み: 403, 'Web 用（メンバー）': 403 },
  },
  {
    name: 'DELETE /v1/items/{id}',
    method: 'DELETE',
    path: (c) => `/v1/items/${c.itemId}`,
    body: () => ({ revision: 1 }),
    expect: { 未ログイン: 401, 'TOTP 待ち': 401, 承認待ち: 403, ...ALL_OK_MEMBER, '管理者（TOTP 未登録）': 403, 削除済み: 403, 'Web 用（メンバー）': 403 },
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
      const secret = new Uint8Array(20).fill(9);
      let token: string | undefined;
      let sessionId = 'session_none';
      if (state === 'TOTP 待ち') {
        // ログインの途中の一時トークンを、Bearer として使おうとする
        const m = await t.addMember('active', { totpSecret: secret });
        token = 'challenge_' + m.token.slice(10); // セッションの表にないトークン
        t.db.db
          .prepare(`INSERT INTO auth_challenges (id, member_id, challenge_hash, scope, device_label, created_at, expires_at) VALUES ('ch_1', ?, 'h', 'extension', 'x', ?, ?)`)
          .run(m.id, T0, T0 + 300000);
      } else if (state !== '未ログイン') {
        const m = await t.addMember(state === '承認待ち' ? 'pending' : state === '削除済み' ? 'removed' : 'active', {
          role: state.startsWith('管理者') ? 'admin' : 'member',
          scope: state === 'Web 用（メンバー）' ? 'web' : 'extension',
          totpSecret: state === '管理者（TOTP 未登録）' || state === '承認待ち' ? undefined : secret,
        });
        token = m.token;
        const other = await t.addSession(m.id, { scope: state === 'Web 用（メンバー）' ? 'web' : 'extension' });
        sessionId = other.sessionId;
      }
      // 承認待ちの人は TOTP を持たないので、TOTP の行は「登録していない」応答（409 など）になるが、401・403 にはならない
      const ctx: Ctx = { sessionId, itemId, code: referenceTotp(secret, stepAt(T0)) };
      const res = await t.request(row.method, row.path(ctx), token, row.body?.(ctx));
      const expected = row.expect[state];
      if (expected === 'ok') assert.ok(res.status !== 401 && res.status !== 403, `${state}：許可のはずが ${res.status}`);
      else assert.equal(res.status, expected, `${state}`);
    });
  }
}
