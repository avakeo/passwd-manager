// セッション（自前のアクセストークンとリフレッシュトークン）。仕様書「認可とセッション」「D1テーブル設計 > sessions」。
//   アクセスは15分、リフレッシュはログインから7日（更新しても延ばさない）。トークンは乱数32バイトで、D1 には SHA-256 だけを置く。
//   更新のたびに両方を新しくする。使い終わったリフレッシュトークンはセッションごとに覚えておき（used_refresh_tokens）、
//   どれかが再び使われたら、直前のものでなくても、セッションごと無効にする（A-12）。

import { sha256Hex } from './auth.ts';
import type { D1Database } from './d1.ts';
import { HttpProblem } from './problem.ts';
import { newId, newToken } from '../crypto/random.ts';

export const ACCESS_TOKEN_TTL_MS = 15 * 60 * 1000;
export const REFRESH_TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000;

export type IssuedTokens = { access_token: string; refresh_token: string; access_expires_at: number; refresh_expires_at: number };

export async function issueSession(
  db: D1Database,
  memberId: string,
  scope: 'extension' | 'web',
  label: string | null,
  totpVerifiedAt: number | null,
): Promise<IssuedTokens> {
  const now = Date.now();
  const accessToken = newToken();
  const refreshToken = newToken();
  // 期限の切れたセッションの、使い終わったリフレッシュトークンの記録を消す（更新できないので、もう検知に要らない）
  await db.prepare('DELETE FROM used_refresh_tokens WHERE expires_at <= ?').bind(now).run();
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

// リフレッシュトークンでセッションを更新する。stillAllowed は、削除済みでないこと・ロールを持つことを確かめる（A-04）。
// 通らなければセッションを無効にして 403。
export async function refreshSession(
  db: D1Database,
  refreshToken: string,
  stillAllowed: (member: { discordUserId: string; status: string }) => Promise<boolean>,
): Promise<IssuedTokens> {
  const now = Date.now();
  const hash = await sha256Hex(refreshToken);
  const row = await db
    .prepare(
      `SELECT s.id, s.revoked_at, s.refresh_expires_at, m.discord_user_id, m.status
         FROM sessions s JOIN members m ON m.id = s.member_id WHERE s.refresh_token_hash = ?`,
    )
    .bind(hash)
    .first<{ id: string; revoked_at: number | null; refresh_expires_at: number | null; discord_user_id: string; status: string }>();
  if (!row) {
    // 使用済みのリフレッシュトークン：盗まれた可能性があるので、そのセッションごと無効にする（A-12）
    await db
      .prepare('UPDATE sessions SET revoked_at = ? WHERE id = (SELECT session_id FROM used_refresh_tokens WHERE token_hash = ?) AND revoked_at IS NULL')
      .bind(now, hash)
      .run();
    throw new HttpProblem(401);
  }
  if (row.revoked_at !== null || row.refresh_expires_at === null || Number(row.refresh_expires_at) <= now) throw new HttpProblem(401);
  if (!(await stillAllowed({ discordUserId: row.discord_user_id, status: row.status }))) {
    await revokeSession(db, row.id);
    throw new HttpProblem(403);
  }
  const accessToken = newToken();
  const newRefreshToken = newToken();
  const [res] = await db.batch([
    db
      .prepare(
        `UPDATE sessions SET access_token_hash = ?, refresh_token_hash = ?, expires_at = ?, last_used_at = ?
          WHERE id = ? AND refresh_token_hash = ? AND revoked_at IS NULL`,
      )
      .bind(await sha256Hex(accessToken), await sha256Hex(newRefreshToken), now + ACCESS_TOKEN_TTL_MS, now, row.id, hash),
    // 更新できたときだけ、使い終わったトークンとして覚える
    db.prepare('INSERT INTO used_refresh_tokens (token_hash, session_id, expires_at) SELECT ?, ?, ? WHERE changes() = 1').bind(hash, row.id, Number(row.refresh_expires_at)),
  ]);
  if (res!.meta.changes !== 1) {
    // 同じトークンで同時に更新された。負けた側も使い回しとみなし、勝った側のトークンも含めてセッションごと無効にする（A-12）
    await revokeSession(db, row.id);
    throw new HttpProblem(401);
  }
  // リフレッシュトークンの期限は、ログインから7日のまま延ばさない
  return { access_token: accessToken, refresh_token: newRefreshToken, access_expires_at: now + ACCESS_TOKEN_TTL_MS, refresh_expires_at: Number(row.refresh_expires_at) };
}

export async function revokeSession(db: D1Database, sessionId: string): Promise<void> {
  await db.prepare('UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL').bind(Date.now(), sessionId).run();
}

// 自分のセッションだけ。トークンのハッシュは返さない
export async function listSessions(db: D1Database, memberId: string, currentSessionId: string) {
  const rows = await db
    .prepare(
      `SELECT id, device_label, scope, created_at, last_used_at FROM sessions
        WHERE member_id = ? AND revoked_at IS NULL AND (refresh_expires_at IS NULL OR refresh_expires_at > ?) ORDER BY created_at, id`,
    )
    .bind(memberId, Date.now())
    .all<{ id: string; device_label: string | null; scope: string; created_at: number; last_used_at: number | null }>();
  return rows.results.map((r) => ({ ...r, current: r.id === currentSessionId }));
}

// 自分のセッションだけを無効にできる。他人のものは、あってもなくても false（呼び出し側が 404 にする：Z-03）
export async function revokeOwnSession(db: D1Database, memberId: string, sessionId: string): Promise<boolean> {
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(sessionId)) return false;
  const res = await db.prepare('UPDATE sessions SET revoked_at = ? WHERE id = ? AND member_id = ? AND revoked_at IS NULL').bind(Date.now(), sessionId, memberId).run();
  return res.meta.changes === 1;
}
