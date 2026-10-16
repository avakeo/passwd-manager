// ログイン、セッションの更新・ログアウト・一覧・無効化、TOTP。仕様書「認証・認可フロー」「エンドポイント」。
//   POST /v1/auth/discord、POST /v1/auth/refresh、POST /v1/auth/totp、POST /v1/auth/logout、
//   GET /v1/me/sessions、DELETE /v1/me/sessions/{id}、POST /v1/me/totp、POST /v1/me/totp/confirm、DELETE /v1/me/totp
// トークンは乱数32バイト。D1 には SHA-256 だけを置き、応答で一度だけ生の値を返す。ログは出さない。

import type { Hono } from 'hono';
import { sha256Hex } from './auth.ts';
import type { D1Database } from './d1.ts';
import { exchangeCodeForUser, hasTeamRole } from './discord.ts';
import type { Bindings, Env } from './env.ts';
import { readJson, readJsonOneOf } from './json.ts';
import { HttpProblem } from './problem.ts';
import {
  base32Encode,
  decryptTotpSecret,
  encryptTotpSecret,
  hashRecoveryCode,
  newRecoveryCodes,
  newTotpSecret,
  otpauthUri,
  verifyTotp,
} from './totp.ts';
import { wipe } from '../crypto/bytes.ts';
import { newId, newToken } from '../crypto/random.ts';

export const ACCESS_TOKEN_TTL_MS = 15 * 60 * 1000;
export const REFRESH_TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const CHALLENGE_TTL_MS = 5 * 60 * 1000;
export const TOTP_MAX_FAILURES = 5;
export const TOTP_FAILURE_WINDOW_MS = 15 * 60 * 1000;

const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const VERIFIER_PATTERN = /^[A-Za-z0-9._~-]{43,128}$/; // RFC 7636
const CODE_PATTERN = /^[\x21-\x7e]{1,512}$/;

type MemberRow = { id: string; role: 'admin' | 'member'; status: 'pending' | 'active' | 'removed'; has_totp: number };

function isString(v: unknown, pattern: RegExp): v is string {
  return typeof v === 'string' && pattern.test(v);
}

function deviceLabel(v: unknown): string {
  if (typeof v !== 'string' || v.length === 0 || [...v].length > 64) throw new HttpProblem(400);
  return v;
}

async function issueSession(db: D1Database, memberId: string, scope: 'extension' | 'web', label: string | null, totpVerifiedAt: number | null) {
  const now = Date.now();
  const accessToken = newToken();
  const refreshToken = newToken();
  await db
    .prepare(
      `INSERT INTO sessions (id, member_id, access_token_hash, refresh_token_hash, device_label, created_at, expires_at,
                             refresh_expires_at, totp_verified_at, scope)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(newId('session'), memberId, await sha256Hex(accessToken), await sha256Hex(refreshToken), label, now, now + ACCESS_TOKEN_TTL_MS, now + REFRESH_TOKEN_TTL_MS, totpVerifiedAt, scope)
    .run();
  return { access_token: accessToken, refresh_token: refreshToken, access_expires_at: now + ACCESS_TOKEN_TTL_MS, refresh_expires_at: now + REFRESH_TOKEN_TTL_MS };
}

function memberView(m: MemberRow) {
  return { id: m.id, role: m.role, status: m.status };
}

async function audit(db: D1Database, memberId: string, action: string): Promise<void> {
  await db.prepare(`INSERT INTO audit_logs (actor_member_id, action, target_type, target_id, created_at) VALUES (?, ?, 'member', ?, ?)`).bind(memberId, action, memberId, Date.now()).run();
}

// ---- TOTP の失敗の制限（メンバーごとに15分で5回まで：A-08） ----

async function assertNotLocked(db: D1Database, memberId: string, now: number): Promise<void> {
  const row = await db.prepare('SELECT totp_failed_count AS n, totp_failed_window_start AS start FROM members WHERE id = ?').bind(memberId).first<{ n: number; start: number | null }>();
  if (row && Number(row.n) >= TOTP_MAX_FAILURES && row.start !== null && now - Number(row.start) < TOTP_FAILURE_WINDOW_MS) throw new HttpProblem(429);
}

async function recordFailure(db: D1Database, memberId: string, now: number): Promise<void> {
  // SET の式は、どれも更新前の値で計算される
  await db
    .prepare(
      `UPDATE members SET
         totp_failed_count = CASE WHEN totp_failed_window_start IS NULL OR ? - totp_failed_window_start >= ? THEN 1 ELSE totp_failed_count + 1 END,
         totp_failed_window_start = CASE WHEN totp_failed_window_start IS NULL OR ? - totp_failed_window_start >= ? THEN ? ELSE totp_failed_window_start END
       WHERE id = ?`,
    )
    .bind(now, TOTP_FAILURE_WINDOW_MS, now, TOTP_FAILURE_WINDOW_MS, now, memberId)
    .run();
}

async function recordSuccess(db: D1Database, memberId: string): Promise<void> {
  await db.prepare('UPDATE members SET totp_failed_count = 0, totp_failed_window_start = NULL WHERE id = ?').bind(memberId).run();
}

// 登録済みの TOTP でコードを確かめる。登録していなければ null（呼び出し側が 409 などにする）。
// 合ったステップを「最後に使った」として、それより前のときだけ書き込む（同じコードの同時の再利用も防ぐ：A-09）。
async function checkMemberCode(env: Bindings, memberId: string, code: unknown): Promise<boolean | null> {
  const db = env.DB;
  const now = Date.now();
  const row = await db.prepare('SELECT totp_secret_encrypted AS s, totp_last_step AS last FROM members WHERE id = ?').bind(memberId).first<{ s: string | null; last: number | null }>();
  if (!row || row.s === null) return null;
  await assertNotLocked(db, memberId, now);
  const secret = await decryptTotpSecret(env.TOTP_ENCRYPTION_KEY, memberId, row.s, 'totp-secret');
  let step: number | null;
  try {
    step = await verifyTotp(secret, typeof code === 'string' ? code : '', now, row.last === null ? null : Number(row.last));
  } finally {
    wipe(secret);
  }
  if (step !== null) {
    const res = await db.prepare('UPDATE members SET totp_last_step = ? WHERE id = ? AND (totp_last_step IS NULL OR totp_last_step < ?)').bind(step, memberId, step).run();
    if (res.meta.changes === 1) {
      await recordSuccess(db, memberId);
      return true;
    }
  }
  await recordFailure(db, memberId, now);
  return false;
}

async function checkRecoveryCode(db: D1Database, memberId: string, code: unknown): Promise<boolean> {
  const now = Date.now();
  await assertNotLocked(db, memberId, now);
  const row = await db.prepare('SELECT recovery_code_hashes AS h FROM members WHERE id = ?').bind(memberId).first<{ h: string | null }>();
  const hashes = row?.h ? (JSON.parse(row.h) as string[]) : [];
  const hash = typeof code === 'string' && code.length <= 64 ? await hashRecoveryCode(code) : '';
  if (hash !== '' && hashes.includes(hash)) {
    // 使ったものを消す。同時に同じコードが使われたら、片方だけが通る
    const res = await db.prepare('UPDATE members SET recovery_code_hashes = ? WHERE id = ? AND recovery_code_hashes = ?').bind(JSON.stringify(hashes.filter((h) => h !== hash)), memberId, row!.h).run();
    if (res.meta.changes === 1) {
      await recordSuccess(db, memberId);
      return true;
    }
  }
  await recordFailure(db, memberId, now);
  return false;
}

export function registerAuthRoutes(app: Hono<Env>): void {
  // ログイン（公開）。Discord の認可コードと PKCE の検証値を受け取り、ロールを確かめてセッションを発行する。
  app.post('/v1/auth/discord', async (c) => {
    const body = await readJson(c.req.raw, ['code', 'code_verifier', 'redirect_uri', 'device_label']);
    if (!isString(body.code, CODE_PATTERN) || !isString(body.code_verifier, VERIFIER_PATTERN) || typeof body.redirect_uri !== 'string') throw new HttpProblem(400);
    const label = deviceLabel(body.device_label);
    // 受け付ける redirect_uri は設定に書いたものだけ。違えば Discord に問い合わせもしない（A-13）
    const allowed = c.env.DISCORD_REDIRECT_URIS.split(',').map((s) => s.trim()).filter((s) => s !== '');
    if (!allowed.includes(body.redirect_uri)) throw new HttpProblem(400);

    const user = await exchangeCodeForUser(c.env, { code: body.code, codeVerifier: body.code_verifier, redirectUri: body.redirect_uri });
    if (!(await hasTeamRole(c.env, user.id))) throw new HttpProblem(403); // A-03

    const db = c.env.DB;
    // 初めてのログインなら、承認待ちのメンバーとして作る
    await db
      .prepare(`INSERT OR IGNORE INTO members (id, discord_user_id, display_name, role, status, created_at) VALUES (?, ?, ?, 'member', 'pending', ?)`)
      .bind(newId('member'), user.id, user.displayName, Date.now())
      .run();
    const m = await db
      .prepare(`SELECT id, role, status, totp_secret_encrypted IS NOT NULL AS has_totp FROM members WHERE discord_user_id = ?`)
      .bind(user.id)
      .first<MemberRow>();
    if (!m) throw new HttpProblem(500);
    if (m.status === 'removed') throw new HttpProblem(403);
    await audit(db, m.id, 'auth.login');

    // TOTP を登録している人には、TOTP の確認にしか使えない5分の一時トークンだけを返す
    if (Number(m.has_totp) === 1) {
      const challenge = newToken();
      const now = Date.now();
      await db
        .prepare(`INSERT INTO auth_challenges (id, member_id, challenge_hash, scope, device_label, created_at, expires_at) VALUES (?, ?, ?, 'extension', ?, ?, ?)`)
        .bind(newId('challenge'), m.id, await sha256Hex(challenge), label, now, now + CHALLENGE_TTL_MS)
        .run();
      return c.json({ status: 'totp_required', challenge_token: challenge, challenge_expires_at: now + CHALLENGE_TTL_MS, member: memberView(m) });
    }
    const session = await issueSession(db, m.id, 'extension', label, null);
    // 管理者は TOTP が必須。登録するまでは、TOTP の登録とログアウトしかできない（A-11）
    return c.json({ status: m.role === 'admin' ? 'totp_setup_required' : 'ok', ...session, member: memberView(m) });
  });

  // セッションの更新（公開。リフレッシュトークンを本文で受け取る）
  app.post('/v1/auth/refresh', async (c) => {
    const body = await readJson(c.req.raw, ['refresh_token']);
    if (!isString(body.refresh_token, TOKEN_PATTERN)) throw new HttpProblem(400);
    const db = c.env.DB;
    const now = Date.now();
    const hash = await sha256Hex(body.refresh_token);
    const row = await db
      .prepare(
        `SELECT s.id, s.revoked_at, s.refresh_expires_at, m.discord_user_id, m.status
           FROM sessions s JOIN members m ON m.id = s.member_id WHERE s.refresh_token_hash = ?`,
      )
      .bind(hash)
      .first<{ id: string; revoked_at: number | null; refresh_expires_at: number | null; discord_user_id: string; status: string }>();
    if (!row) {
      // 使用済みのリフレッシュトークン：盗まれた可能性があるので、そのセッションごと無効にする（A-12）
      await db.prepare('UPDATE sessions SET revoked_at = ? WHERE prev_refresh_token_hash = ? AND revoked_at IS NULL').bind(now, hash).run();
      throw new HttpProblem(401);
    }
    if (row.revoked_at !== null || row.refresh_expires_at === null || Number(row.refresh_expires_at) <= now) throw new HttpProblem(401);
    const revoke = () => db.prepare('UPDATE sessions SET revoked_at = ? WHERE id = ?').bind(now, row.id).run();
    // 削除済み、またはロールを外された人は、ここで止めてセッションを無効にする（A-04）
    if (row.status === 'removed' || !(await hasTeamRole(c.env, row.discord_user_id))) {
      await revoke();
      throw new HttpProblem(403);
    }
    const accessToken = newToken();
    const refreshToken = newToken();
    const res = await db
      .prepare(
        `UPDATE sessions SET access_token_hash = ?, refresh_token_hash = ?, prev_refresh_token_hash = ?, expires_at = ?, last_used_at = ?
          WHERE id = ? AND refresh_token_hash = ? AND revoked_at IS NULL`,
      )
      .bind(await sha256Hex(accessToken), await sha256Hex(refreshToken), hash, now + ACCESS_TOKEN_TTL_MS, now, row.id, hash)
      .run();
    if (res.meta.changes !== 1) throw new HttpProblem(401); // 同時に更新された
    // リフレッシュトークンの期限は、ログインから7日のまま延ばさない
    return c.json({ access_token: accessToken, refresh_token: refreshToken, access_expires_at: now + ACCESS_TOKEN_TTL_MS, refresh_expires_at: Number(row.refresh_expires_at) });
  });

  // TOTP のコード。Bearer がなければログインの途中（一時トークン）、あれば管理操作の前の再確認（ステップアップ）
  app.post('/v1/auth/totp', async (c) => {
    const db = c.env.DB;
    if (c.req.header('Authorization') !== undefined) {
      const p = c.get('principal');
      const body = await readJson(c.req.raw, ['code']);
      const ok = await checkMemberCode(c.env, p.memberId, body.code);
      if (ok === null) throw new HttpProblem(409);
      if (!ok) throw new HttpProblem(403);
      await db.prepare('UPDATE sessions SET totp_verified_at = ? WHERE id = ?').bind(Date.now(), p.sessionId).run();
      return c.body(null, 204);
    }
    const body = await readJsonOneOf(c.req.raw, [
      ['challenge_token', 'code'],
      ['challenge_token', 'recovery_code'],
    ]);
    if (!isString(body.challenge_token, TOKEN_PATTERN)) throw new HttpProblem(401);
    const now = Date.now();
    const ch = await db
      .prepare(
        `SELECT c.id, c.member_id, c.scope, c.device_label, m.role, m.status, 1 AS has_totp
           FROM auth_challenges c JOIN members m ON m.id = c.member_id
          WHERE c.challenge_hash = ? AND c.expires_at > ?`,
      )
      .bind(await sha256Hex(body.challenge_token), now)
      .first<{ id: string; member_id: string; scope: 'extension' | 'web'; device_label: string | null; role: 'admin' | 'member'; status: 'pending' | 'active' | 'removed'; has_totp: number }>();
    if (!ch) throw new HttpProblem(401);
    if (ch.status === 'removed') throw new HttpProblem(403);
    const ok = 'code' in body ? await checkMemberCode(c.env, ch.member_id, body.code) : await checkRecoveryCode(db, ch.member_id, body.recovery_code);
    if (ok !== true) throw new HttpProblem(401);
    // 一時トークンは1回だけ
    const used = await db.prepare('DELETE FROM auth_challenges WHERE id = ?').bind(ch.id).run();
    if (used.meta.changes !== 1) throw new HttpProblem(401);
    const session = await issueSession(db, ch.member_id, ch.scope, ch.device_label, now);
    return c.json({ status: 'ok', ...session, member: memberView({ id: ch.member_id, role: ch.role, status: ch.status, has_totp: 1 }) });
  });

  app.post('/v1/auth/logout', async (c) => {
    const p = c.get('principal');
    await c.env.DB.prepare('UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL').bind(Date.now(), p.sessionId).run();
    return c.body(null, 204);
  });

  // 自分のセッションだけ。トークンのハッシュは返さない
  app.get('/v1/me/sessions', async (c) => {
    const p = c.get('principal');
    const rows = await c.env.DB.prepare(
      `SELECT id, device_label, scope, created_at, last_used_at FROM sessions
        WHERE member_id = ? AND revoked_at IS NULL AND (refresh_expires_at IS NULL OR refresh_expires_at > ?) ORDER BY created_at, id`,
    )
      .bind(p.memberId, Date.now())
      .all<{ id: string; device_label: string | null; scope: string; created_at: number; last_used_at: number | null }>();
    return c.json({ sessions: rows.results.map((r) => ({ ...r, current: r.id === p.sessionId })) });
  });

  // 他人のセッションは、あってもなくても同じ 404（Z-03）
  app.delete('/v1/me/sessions/:id', async (c) => {
    const p = c.get('principal');
    const id = c.req.param('id');
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(id)) throw new HttpProblem(404);
    const res = await c.env.DB.prepare('UPDATE sessions SET revoked_at = ? WHERE id = ? AND member_id = ? AND revoked_at IS NULL').bind(Date.now(), id, p.memberId).run();
    if (res.meta.changes !== 1) throw new HttpProblem(404);
    return c.body(null, 204);
  });

  // TOTP の登録の開始。シークレットは、コードで確定するまで登録途中の列に置く
  app.post('/v1/me/totp', async (c) => {
    const p = c.get('principal');
    const db = c.env.DB;
    const m = await db.prepare('SELECT display_name, totp_secret_encrypted AS s FROM members WHERE id = ?').bind(p.memberId).first<{ display_name: string; s: string | null }>();
    if (!m) throw new HttpProblem(404);
    if (m.s !== null) throw new HttpProblem(409);
    const secret = newTotpSecret();
    try {
      await db.prepare('UPDATE members SET totp_pending_secret_encrypted = ? WHERE id = ?').bind(await encryptTotpSecret(c.env.TOTP_ENCRYPTION_KEY, p.memberId, secret, 'totp-pending-secret'), p.memberId).run();
      return c.json({ secret: base32Encode(secret), otpauth_uri: otpauthUri(secret, m.display_name) });
    } finally {
      wipe(secret);
    }
  });

  // TOTP の登録の確定。回復コードは、ここで一度だけ返す
  app.post('/v1/me/totp/confirm', async (c) => {
    const p = c.get('principal');
    const db = c.env.DB;
    const body = await readJson(c.req.raw, ['code']);
    const m = await db.prepare('SELECT totp_secret_encrypted AS s, totp_pending_secret_encrypted AS pending FROM members WHERE id = ?').bind(p.memberId).first<{ s: string | null; pending: string | null }>();
    if (!m || m.s !== null || m.pending === null) throw new HttpProblem(409);
    const now = Date.now();
    await assertNotLocked(db, p.memberId, now);
    const secret = await decryptTotpSecret(c.env.TOTP_ENCRYPTION_KEY, p.memberId, m.pending, 'totp-pending-secret');
    try {
      const step = await verifyTotp(secret, typeof body.code === 'string' ? body.code : '', now, null);
      if (step === null) {
        await recordFailure(db, p.memberId, now);
        throw new HttpProblem(403);
      }
      const codes = newRecoveryCodes();
      const hashes = await Promise.all(codes.map(hashRecoveryCode));
      const encrypted = await encryptTotpSecret(c.env.TOTP_ENCRYPTION_KEY, p.memberId, secret, 'totp-secret');
      const results = await db.batch([
        db
          .prepare(
            `UPDATE members SET totp_secret_encrypted = ?, totp_pending_secret_encrypted = NULL, totp_last_step = ?, recovery_code_hashes = ?,
                    totp_failed_count = 0, totp_failed_window_start = NULL
              WHERE id = ? AND totp_secret_encrypted IS NULL AND totp_pending_secret_encrypted = ?`,
          )
          .bind(encrypted, step, JSON.stringify(hashes), p.memberId, m.pending),
        // 登録したセッションは、TOTP を確かめた扱い
        db.prepare('UPDATE sessions SET totp_verified_at = ? WHERE id = ? AND changes() = 1').bind(now, p.sessionId),
      ]);
      if (results[0]!.meta.changes !== 1) throw new HttpProblem(409);
      await audit(db, p.memberId, 'totp.register');
      return c.json({ recovery_codes: codes });
    } finally {
      wipe(secret);
    }
  });

  // TOTP の解除。管理者はできない。今のコードが要る
  app.delete('/v1/me/totp', async (c) => {
    const p = c.get('principal');
    if (p.role === 'admin') throw new HttpProblem(403);
    const body = await readJson(c.req.raw, ['code']);
    const ok = await checkMemberCode(c.env, p.memberId, body.code);
    if (ok === null) throw new HttpProblem(409);
    if (!ok) throw new HttpProblem(403);
    await c.env.DB.prepare(
      `UPDATE members SET totp_secret_encrypted = NULL, totp_pending_secret_encrypted = NULL, totp_last_step = NULL, recovery_code_hashes = NULL WHERE id = ?`,
    )
      .bind(p.memberId)
      .run();
    await audit(c.env.DB, p.memberId, 'totp.remove');
    return c.body(null, 204);
  });
}
