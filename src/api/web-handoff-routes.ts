// 拡張機能から Web ページを開く（2026-11-05 追記、W-09）。仕様書「Webページの配信」。
//   POST /v1/me/web-handoff：拡張機能のセッションで、1分だけ使える使い捨てのコードを作る。D1 にはコードの SHA-256 だけを置く
//   POST /v1/auth/web-handoff（公開）：コードを Web 用（読み取り専用）のセッションに替える。1回だけ
// Web のセッションは元の拡張機能のセッションと別に作る。TOTP を確かめた時刻とリフレッシュの期限は、元のセッションから引き継ぐ
// （コードを通して、監査ログを見られる5分や、7日の期限を延ばせない）。Web 用のトークンではコードを作れない（auth.ts の WEB_ROUTES）。

import type { Hono } from 'hono';
import { sha256Hex } from './auth.ts';
import { hasTeamRole } from './discord.ts';
import type { Env } from './env.ts';
import { readJson } from './json.ts';
import { HttpProblem } from './problem.ts';
import { issueSession } from './session.ts';
import { newToken } from '../crypto/random.ts';

export const WEB_HANDOFF_TTL_MS = 60 * 1000;
const CODE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export function registerWebHandoffRoutes(app: Hono<Env>): void {
  app.post('/v1/me/web-handoff', async (c) => {
    // Web ページのオリジンを設定していなければ、開く先がない
    if (typeof c.env.WEB_ORIGIN !== 'string' || c.env.WEB_ORIGIN === '') throw new HttpProblem(404);
    const p = c.get('principal');
    const db = c.env.DB;
    const now = Date.now();
    const code = newToken();
    await db.batch([
      db.prepare('DELETE FROM web_handoffs WHERE expires_at <= ?').bind(now),
      db
        .prepare('INSERT INTO web_handoffs (code_hash, member_id, session_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)')
        .bind(await sha256Hex(code), p.memberId, p.sessionId, now, now + WEB_HANDOFF_TTL_MS),
    ]);
    return c.json({ code, expires_at: now + WEB_HANDOFF_TTL_MS }, 201);
  });

  app.post('/v1/auth/web-handoff', async (c) => {
    const body = await readJson(c.req.raw, ['code']);
    if (typeof body.code !== 'string' || !CODE_PATTERN.test(body.code)) throw new HttpProblem(400);
    const db = c.env.DB;
    const now = Date.now();
    const codeHash = await sha256Hex(body.code);
    // 1回だけ。期限内で、まだ使っていないものを使用済みにできたときだけ進む
    const taken = await db.prepare('UPDATE web_handoffs SET used_at = ? WHERE code_hash = ? AND used_at IS NULL AND expires_at > ?').bind(now, codeHash, now).run();
    if (taken.meta.changes !== 1) throw new HttpProblem(401);
    const row = await db
      .prepare(
        `SELECT h.member_id, s.revoked_at, s.refresh_expires_at, s.totp_verified_at, m.role, m.status, m.discord_user_id
           FROM web_handoffs h JOIN sessions s ON s.id = h.session_id JOIN members m ON m.id = h.member_id
          WHERE h.code_hash = ?`,
      )
      .bind(codeHash)
      .first<{
        member_id: string;
        revoked_at: number | null;
        refresh_expires_at: number | null;
        totp_verified_at: number | null;
        role: 'admin' | 'member';
        status: 'pending' | 'active' | 'removed';
        discord_user_id: string;
      }>();
    // 元のセッションが無効になった・期限が切れた
    if (!row || row.revoked_at !== null || row.refresh_expires_at === null || Number(row.refresh_expires_at) <= now) throw new HttpProblem(401);
    // ログインと同じく、承認済みでロールを持つこと（A-04）
    if (row.status !== 'active' || !(await hasTeamRole(c.env, row.discord_user_id))) throw new HttpProblem(403);
    const totpVerifiedAt = row.totp_verified_at === null ? null : Number(row.totp_verified_at);
    const session = await issueSession(db, row.member_id, 'web', 'Web ページ', totpVerifiedAt, Number(row.refresh_expires_at));
    await db
      .prepare(`INSERT INTO audit_logs (actor_member_id, action, target_type, target_id, created_at) VALUES (?, 'auth.web_handoff', 'member', ?, ?)`)
      .bind(row.member_id, row.member_id, now)
      .run();
    return c.json({ status: 'ok', ...session, member: { id: row.member_id, role: row.role, status: row.status } });
  });
}
