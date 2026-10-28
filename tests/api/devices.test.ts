// この端末を覚える（2026-10-29 追記。仕様書「この端末を覚える」）。
// ブラウザを閉じた後は、Discord と TOTP の代わりに、端末のトークンと4桁のパスコードで同じセッションに戻る。
// パスコードの間違いはサーバーが数え、3回で端末のトークンを無効にする。期限はセッションと同じ（ログインから7日）。

import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import { TEST_ENV, setup } from '../helpers/api.ts';
import { FakeDiscord } from '../helpers/fake-discord.ts';
import { toBase64Url } from '../../src/crypto/bytes.ts';

// 戻るときも、セッションの更新と同じく Bot でロールを確かめる（A-04）
const discord = new FakeDiscord({
  clientId: TEST_ENV.DISCORD_CLIENT_ID,
  clientSecret: TEST_ENV.DISCORD_CLIENT_SECRET,
  botToken: TEST_ENV.DISCORD_BOT_TOKEN,
  guildId: TEST_ENV.DISCORD_GUILD_ID,
});
after(discord.install());
let nextUser = 700000000000000000n;
function discordUser(): string {
  nextUser += 1n;
  discord.addUser(String(nextUser), { roles: [TEST_ENV.DISCORD_ROLE_ID] });
  return String(nextUser);
}

async function proof(pin: string): Promise<string> {
  return toBase64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`test|${pin}`))));
}

async function json(res: Response) {
  return (await res.json()) as Record<string, unknown>;
}

// TOTP を確かめた直後のセッションで、端末を覚える
async function remembered(t: ReturnType<typeof setup>, pin = '2580') {
  const discordUserId = discordUser();
  const m = { ...(await t.addMember('active', { totpVerifiedAt: Date.now(), discordUserId })), discordUserId };
  const res = await t.request('POST', '/v1/me/devices', m.token, { pin_proof: await proof(pin) });
  assert.equal(res.status, 201);
  const body = await json(res);
  return { m, deviceToken: String(body.device_token), body };
}

function resume(t: ReturnType<typeof setup>, deviceToken: string, pinProof: string) {
  return t.request('POST', '/v1/auth/resume', undefined, { device_token: deviceToken, pin_proof: pinProof });
}

test('A-16 端末を覚えられるのは、直近5分以内に TOTP を確かめたセッションだけ。トークンは D1 にハッシュだけ', async () => {
  const t = setup();
  const old = await t.addMember('active', { totpVerifiedAt: Date.now() - 6 * 60 * 1000 });
  assert.equal((await t.request('POST', '/v1/me/devices', old.token, { pin_proof: await proof('2580') })).status, 403);
  const { m, deviceToken, body } = await remembered(t);
  assert.match(deviceToken, /^[A-Za-z0-9_-]{43}$/);
  const session = t.db.db.prepare('SELECT refresh_expires_at FROM sessions WHERE id = ?').get(m.sessionId)!;
  assert.equal(body.expires_at, session.refresh_expires_at, '期限はセッションと同じ（ログインから7日）');
  const stored = JSON.stringify(t.db.db.prepare('SELECT * FROM remembered_devices').all());
  assert.ok(!stored.includes(deviceToken), '生のトークンは置かない');
  assert.ok(!stored.includes(await proof('2580')), 'パスコードの値もそのまま置かない');
  // 形の違う値は 400、Web 用のトークンでは 403
  assert.equal((await t.request('POST', '/v1/me/devices', m.token, { pin_proof: '1234' })).status, 400);
  const web = await t.addMember('active', { scope: 'web', totpVerifiedAt: Date.now() });
  assert.equal((await t.request('POST', '/v1/me/devices', web.token, { pin_proof: await proof('2580') })).status, 403);
});

test('A-17 端末のトークンとパスコードで、同じセッションに戻る。新しいトークンを返し、端末のトークンも替える。TOTP を確かめた扱いにはしない', async () => {
  const t = setup();
  const { m, deviceToken } = await remembered(t);
  const res = await resume(t, deviceToken, await proof('2580'));
  assert.equal(res.status, 200);
  const body = await json(res);
  assert.equal((body.member as { id: string }).id, m.id);
  assert.notEqual(body.device_token, deviceToken);
  // 新しいアクセストークンで API を使える
  assert.equal((await t.request('GET', '/v1/me/sessions', String(body.access_token))).status, 200);
  // 同じセッションのまま（一覧に増えない）。管理操作の前の TOTP の確認は、やり直しが要る
  const rows = t.db.db.prepare('SELECT id, totp_verified_at FROM sessions WHERE member_id = ? AND revoked_at IS NULL').all(m.id);
  assert.deepEqual(rows.map((r) => ({ ...r })), [{ id: m.sessionId, totp_verified_at: null }]);
  // 前の端末のトークンでは、もう戻れない
  assert.equal((await resume(t, deviceToken, await proof('2580'))).status, 403);
  const again = await json(await resume(t, String(body.device_token), await proof('2580')));
  assert.equal(again.status, 'ok');
  // 前のアクセストークンは使えない。ブラウザを閉じて消えたはずの前のリフレッシュトークンが使われたら、
  // 盗まれたものとみなしてセッションごと無効にする（A-12 と同じ）。その後は端末のトークンでも戻れない
  assert.equal((await t.request('GET', '/v1/me/sessions', m.token)).status, 401);
  assert.equal((await t.request('POST', '/v1/auth/refresh', undefined, { refresh_token: m.refreshToken })).status, 401);
  assert.notEqual(t.db.db.prepare('SELECT revoked_at FROM sessions WHERE id = ?').get(m.sessionId)!.revoked_at, null);
  assert.equal((await resume(t, String(again.device_token), await proof('2580'))).status, 403);
});

test('A-18 パスコードを3回間違えると、端末のトークンを無効にする。その後は正しいパスコードでも戻れない。成功すると回数を戻す', async () => {
  const t = setup();
  const { deviceToken } = await remembered(t);
  const wrong = await proof('0000');
  let r = await resume(t, deviceToken, wrong);
  assert.equal(r.status, 401);
  assert.equal((await json(r)).attempts_left, 2);
  r = await resume(t, deviceToken, wrong);
  assert.equal((await json(r)).attempts_left, 1);
  // 2回間違えた後に成功すると、回数は0に戻る
  const ok = await json(await resume(t, deviceToken, await proof('2580')));
  const next = String(ok.device_token);
  for (const left of [2, 1]) assert.equal((await json(await resume(t, next, wrong))).attempts_left, left);
  r = await resume(t, next, wrong);
  assert.equal(r.status, 403, '3回目で無効');
  assert.equal((await resume(t, next, await proof('2580'))).status, 403);
});

test('A-18 回数が3に達した行は、確かめる前に断る（同時に送られて、無効にする前に3回目が数えられた場合）', async () => {
  const t = setup();
  const { deviceToken } = await remembered(t);
  t.db.db.prepare('UPDATE remembered_devices SET failed_count = 3').run();
  assert.equal((await resume(t, deviceToken, await proof('2580'))).status, 403, '正しいパスコードでも');
});

test('A-18 同時に送っても、試せるのは3回まで', async () => {
  const t = setup();
  const { deviceToken } = await remembered(t);
  const results = await Promise.all(['0001', '0002', '0003', '0004', '0005', '2580'].map(async (pin) => (await resume(t, deviceToken, await proof(pin))).status));
  assert.equal(results.filter((s) => s === 200).length <= 1, true);
  assert.equal(results.filter((s) => s === 401).length + results.filter((s) => s === 200).length <= 3, true, JSON.stringify(results));
});

test('A-19 ログアウト、セッションの無効化、7日の期限、削除済みの人、ロールを外された人は戻れない', async () => {
  const t = setup();
  // ログアウト
  const a = await remembered(t);
  assert.equal((await t.request('POST', '/v1/auth/logout', a.m.token)).status, 204);
  assert.notEqual(t.db.db.prepare('SELECT revoked_at FROM remembered_devices WHERE session_id = ?').get(a.m.sessionId)!.revoked_at, null, '端末の行も無効にする');
  assert.equal((await resume(t, a.deviceToken, await proof('2580'))).status, 403);
  // 別のセッションから無効にされた
  const b = await remembered(t);
  t.db.db.prepare('UPDATE sessions SET revoked_at = ? WHERE id = ?').run(Date.now(), b.m.sessionId);
  assert.equal((await resume(t, b.deviceToken, await proof('2580'))).status, 403);
  // 期限切れ
  const c = await remembered(t);
  t.db.db.prepare('UPDATE remembered_devices SET expires_at = ? WHERE session_id = ?').run(Date.now() - 1, c.m.sessionId);
  assert.equal((await resume(t, c.deviceToken, await proof('2580'))).status, 403);
  // 削除済み
  const d = await remembered(t);
  t.db.db.prepare(`UPDATE members SET status = 'removed' WHERE id = ?`).run(d.m.id);
  assert.equal((await resume(t, d.deviceToken, await proof('2580'))).status, 403);
  // ロールを外された（セッションも無効にする）
  const e = await remembered(t);
  discord.setRoles(e.m.discordUserId, []);
  assert.equal((await resume(t, e.deviceToken, await proof('2580'))).status, 403);
  assert.notEqual(t.db.db.prepare('SELECT revoked_at FROM sessions WHERE id = ?').get(e.m.sessionId)!.revoked_at, null);
  // 知らないトークン、形の違う値
  assert.equal((await resume(t, 'A'.repeat(43), await proof('2580'))).status, 403);
  assert.equal((await t.request('POST', '/v1/auth/resume', undefined, { device_token: 'x', pin_proof: await proof('2580') })).status, 400);
});
