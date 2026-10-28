// この端末を覚える（2026-10-29 追記。仕様書「この端末を覚える」、A-16〜A-19）。
//   POST /v1/me/devices：直近5分以内に TOTP を確かめたセッションで、端末のトークンを作る（パスコードの値を受け取る）
//   POST /v1/auth/resume（公開）：端末のトークンとパスコードの値で、同じセッションの新しいトークンを返す
// パスコードは4桁しかないので、間違いの回数をここで数える。確かめる前に回数を1つ増やし（同時に送られても3回まで）、
// 3回間違えたら端末のトークンを無効にする。D1 には、トークンの SHA-256 と、パスコードの値をサーバーの鍵で HMAC にした値だけを置く
// （D1 だけが漏れても、4桁を総当たりで試せない）。HMAC の鍵は TOTP_ENCRYPTION_KEY から HKDF で別の用途として作る。
// 戻ったセッションは、TOTP を確かめた扱いにしない（管理操作の前に再確認が要る）。期限はセッションのリフレッシュトークンと同じ。

import type { Hono } from 'hono';
import { requireRecentTotp, sha256Hex } from './auth.ts';
import { recoveryCodesRemaining } from './auth-routes.ts';
import { hasTeamRole } from './discord.ts';
import type { Env } from './env.ts';
import { readJson } from './json.ts';
import { HttpProblem } from './problem.ts';
import { ACCESS_TOKEN_TTL_MS, revokeSession } from './session.ts';
import { fromBase64Url, toBase64Url, wipe } from '../crypto/bytes.ts';
import { newId, newToken } from '../crypto/random.ts';

export const DEVICE_PIN_MAX_FAILURES = 3;

const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;

async function pinKey(keyB64: string): Promise<CryptoKey> {
  const raw = fromBase64Url(keyB64);
  try {
    const base = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey']);
    return await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('teampw/v1/device-pin') },
      base,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      false,
      ['sign', 'verify'],
    );
  } finally {
    wipe(raw);
  }
}

function pinMessage(deviceId: string, pinProof: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(`v1|device-pin|${deviceId}|${pinProof}`);
}

async function pinHash(keyB64: string, deviceId: string, pinProof: string): Promise<string> {
  return toBase64Url(new Uint8Array(await crypto.subtle.sign('HMAC', await pinKey(keyB64), pinMessage(deviceId, pinProof))));
}

async function pinMatches(keyB64: string, deviceId: string, pinProof: string, stored: string): Promise<boolean> {
  return crypto.subtle.verify('HMAC', await pinKey(keyB64), fromBase64Url(stored), pinMessage(deviceId, pinProof));
}

type DeviceRow = {
  id: string;
  session_id: string;
  pin_hash: string;
  failed_count: number;
  session_revoked_at: number | null;
  refresh_expires_at: number | null;
  refresh_token_hash: string;
  member_id: string;
  role: 'admin' | 'member';
  status: 'pending' | 'active' | 'removed';
  discord_user_id: string;
};

export function registerDeviceRoutes(app: Hono<Env>): void {
  app.post('/v1/me/devices', async (c) => {
    const p = c.get('principal');
    const body = await readJson(c.req.raw, ['pin_proof']);
    if (typeof body.pin_proof !== 'string' || !TOKEN_PATTERN.test(body.pin_proof)) throw new HttpProblem(400);
    // 盗まれたアクセストークンだけでは覚えさせない。ログインの直後（TOTP を確かめてから5分以内）だけ（A-16）
    requireRecentTotp(p, Date.now());
    const db = c.env.DB;
    const session = await db.prepare('SELECT refresh_expires_at FROM sessions WHERE id = ?').bind(p.sessionId).first<{ refresh_expires_at: number | null }>();
    if (!session || session.refresh_expires_at === null) throw new HttpProblem(403);
    const id = newId('device');
    const token = newToken();
    const now = Date.now();
    const expiresAt = Number(session.refresh_expires_at);
    // 1つのセッションに1つ。覚え直したら前のものは消す
    await db.batch([
      db.prepare('DELETE FROM remembered_devices WHERE session_id = ?').bind(p.sessionId),
      db
        .prepare(`INSERT INTO remembered_devices (id, member_id, session_id, token_hash, pin_hash, failed_count, created_at, expires_at) VALUES (?, ?, ?, ?, ?, 0, ?, ?)`)
        .bind(id, p.memberId, p.sessionId, await sha256Hex(token), await pinHash(c.env.TOTP_ENCRYPTION_KEY, id, body.pin_proof), now, expiresAt),
      db.prepare(`INSERT INTO audit_logs (actor_member_id, action, target_type, target_id, created_at) VALUES (?, 'device.remember', 'member', ?, ?)`).bind(p.memberId, p.memberId, now),
    ]);
    return c.json({ device_token: token, expires_at: expiresAt }, 201);
  });

  app.post('/v1/auth/resume', async (c) => {
    const body = await readJson(c.req.raw, ['device_token', 'pin_proof']);
    if (typeof body.device_token !== 'string' || !TOKEN_PATTERN.test(body.device_token) || typeof body.pin_proof !== 'string' || !TOKEN_PATTERN.test(body.pin_proof)) {
      throw new HttpProblem(400);
    }
    const db = c.env.DB;
    const now = Date.now();
    const tokenHash = await sha256Hex(body.device_token);
    // 確かめる前に、回数を1つ増やす。無効・期限切れ・3回に達したものは増やせないので 403（A-18）
    const taken = await db
      .prepare('UPDATE remembered_devices SET failed_count = failed_count + 1 WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ? AND failed_count < ?')
      .bind(tokenHash, now, DEVICE_PIN_MAX_FAILURES)
      .run();
    if (taken.meta.changes !== 1) throw new HttpProblem(403);
    const d = await db
      .prepare(
        `SELECT d.id, d.session_id, d.pin_hash, d.failed_count, s.revoked_at AS session_revoked_at, s.refresh_expires_at, s.refresh_token_hash,
                m.id AS member_id, m.role, m.status, m.discord_user_id
           FROM remembered_devices d JOIN sessions s ON s.id = d.session_id JOIN members m ON m.id = d.member_id
          WHERE d.token_hash = ?`,
      )
      .bind(tokenHash)
      .first<DeviceRow>();
    if (!d) throw new HttpProblem(403);
    const revokeDevice = () => db.prepare('UPDATE remembered_devices SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL').bind(now, d.id).run();
    if (!(await pinMatches(c.env.TOTP_ENCRYPTION_KEY, d.id, body.pin_proof, d.pin_hash))) {
      const failures = Number(d.failed_count);
      if (failures >= DEVICE_PIN_MAX_FAILURES) {
        await revokeDevice();
        throw new HttpProblem(403);
      }
      throw new HttpProblem(401, { attempts_left: DEVICE_PIN_MAX_FAILURES - failures });
    }
    // ログアウト、別の端末からの無効化、7日の期限（A-19）
    if (d.session_revoked_at !== null || d.refresh_expires_at === null || Number(d.refresh_expires_at) <= now) {
      await revokeDevice();
      throw new HttpProblem(403);
    }
    // セッションの更新と同じく、削除済みでないこととロールを確かめる（A-04）
    if (d.status === 'removed' || !(await hasTeamRole(c.env, d.discord_user_id))) {
      await revokeDevice();
      await revokeSession(db, d.session_id);
      throw new HttpProblem(403);
    }
    const accessToken = newToken();
    const refreshToken = newToken();
    const deviceToken = newToken();
    const results = await db.batch([
      // 同じセッションのトークンを新しくする。TOTP を確かめた扱いは外す
      db
        .prepare(
          `UPDATE sessions SET access_token_hash = ?, refresh_token_hash = ?, expires_at = ?, last_used_at = ?, totp_verified_at = NULL
            WHERE id = ? AND refresh_token_hash = ? AND revoked_at IS NULL`,
        )
        .bind(await sha256Hex(accessToken), await sha256Hex(refreshToken), now + ACCESS_TOKEN_TTL_MS, now, d.session_id, d.refresh_token_hash),
      // ブラウザを閉じて消えたはずの前のリフレッシュトークンが使われたら、セッションごと無効にする（A-12 と同じ）
      db.prepare('INSERT INTO used_refresh_tokens (token_hash, session_id, expires_at) SELECT ?, ?, ? WHERE changes() = 1').bind(d.refresh_token_hash, d.session_id, Number(d.refresh_expires_at)),
      // 端末のトークンも替え、回数を戻す
      db.prepare('UPDATE remembered_devices SET token_hash = ?, failed_count = 0 WHERE id = ? AND token_hash = ? AND changes() = 1').bind(await sha256Hex(deviceToken), d.id, tokenHash),
    ]);
    if (results[0]!.meta.changes !== 1 || results[2]!.meta.changes !== 1) throw new HttpProblem(403); // 同時に戻ろうとした片方
    await db.prepare(`INSERT INTO audit_logs (actor_member_id, action, target_type, target_id, created_at) VALUES (?, 'auth.resume', 'member', ?, ?)`).bind(d.member_id, d.member_id, now).run();
    return c.json({
      status: 'ok',
      access_token: accessToken,
      refresh_token: refreshToken,
      access_expires_at: now + ACCESS_TOKEN_TTL_MS,
      refresh_expires_at: Number(d.refresh_expires_at),
      device_token: deviceToken,
      member: { id: d.member_id, role: d.role, status: d.status },
      recovery_codes_remaining: await recoveryCodesRemaining(db, d.member_id),
    });
  });
}
