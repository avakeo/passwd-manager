// メンバーの一覧・承認・削除と、監査ログ（フェーズ4a。仕様書「メンバーの参加と承認」「メンバーの削除とローテーション」）。
//   GET /v1/members（全員）、POST /v1/members/{id}/approve・DELETE /v1/members/{id}・GET /v1/audit-logs（管理者）
// 管理操作は、5分以内に TOTP を確かめた管理者のセッションだけができる（A-10）。
// 承認は、そのメンバー宛ての署名付きのグラントと同時に行う。グラントのない承認状態は作らない（P-03）。
// サーバーもグラントの署名を確かめ、確認と保存を1つのバッチにする（先頭の rotation_guard で、相手と鍵と世代を確かめる）。

import type { Hono } from 'hono';
import { requireRecentTotp } from './auth.ts';
import type { Principal } from './auth.ts';
import type { Env } from './env.ts';
import { readJson } from './json.ts';
import { HttpProblem } from './problem.ts';
import { GRANT_FIELDS, grantShape, isGuardFailure, verifyGrantSignature } from './key-routes.ts';
import { FORMAT_V1 } from '../crypto/format.ts';

const MEMBER_ID = /^member_[A-Za-z0-9_-]{1,64}$/;
const AUDIT_LIMIT = 200;

function memberIdParam(v: string): string {
  if (!MEMBER_ID.test(v)) throw new HttpProblem(404);
  return v;
}

function requireAdmin(p: Principal): void {
  if (p.role !== 'admin') throw new HttpProblem(403);
  requireRecentTotp(p, Date.now());
}

export function registerMemberRoutes(app: Hono<Env>): void {
  // 全員が見られる。公開鍵は照合に使う公開の値。削除済みの人は出さない
  app.get('/v1/members', async (c) => {
    const p = c.get('principal');
    const rows = await c.env.DB.prepare(
      `SELECT m.id, m.display_name, m.role, m.status, k.id AS key_id, k.ecdh_public_key
         FROM members m LEFT JOIN member_keys k ON k.member_id = m.id AND k.status = 'active'
        WHERE m.status != 'removed' ORDER BY m.created_at, m.id`,
    ).all<{ id: string; display_name: string; role: string; status: string; key_id: string | null; ecdh_public_key: string | null }>();
    return c.json({
      current_vault_key_version: p.currentVaultKeyVersion,
      members: rows.results.map((r) => ({
        id: r.id,
        display_name: r.display_name,
        role: r.role,
        status: r.status,
        key: r.key_id === null ? null : { id: r.key_id, ecdh_public_key: r.ecdh_public_key },
      })),
    });
  });

  app.post('/v1/members/:id/approve', async (c) => {
    const p = c.get('principal');
    requireAdmin(p);
    const id = memberIdParam(c.req.param('id'));
    const g = grantShape(await readJson(c.req.raw, GRANT_FIELDS));
    const db = c.env.DB;
    const target = await db.prepare('SELECT status FROM members WHERE id = ?').bind(id).first<{ status: string }>();
    if (!target) throw new HttpProblem(404);
    if (target.status !== 'pending' || g.vaultKeyVersion !== p.currentVaultKeyVersion) throw new HttpProblem(409);
    const recipient = await db
      .prepare(`SELECT ecdh_public_key FROM member_keys WHERE id = ? AND member_id = ? AND status = 'active'`)
      .bind(g.recipientKeyId, id)
      .first<{ ecdh_public_key: string }>();
    if (!recipient) throw new HttpProblem(409); // その人の有効な鍵ではない
    const signer = await db
      .prepare(`SELECT ecdsa_public_key FROM member_keys WHERE id = ? AND member_id = ? AND status = 'active' AND ecdsa_public_key IS NOT NULL`)
      .bind(g.signerKeyId, p.memberId)
      .first<{ ecdsa_public_key: string }>();
    if (!signer) throw new HttpProblem(409); // 自分の有効な署名鍵ではない
    await verifyGrantSignature(g, { memberId: p.memberId, ecdsaPublicKey: signer.ecdsa_public_key }, { memberId: id, ecdhPublicKey: recipient.ecdh_public_key });
    const now = Date.now();
    try {
      await db.batch([
        // 確かめてから保存するまでの間に、相手の状態・鍵・今の世代・自分の署名鍵が変わっていないこと
        db
          .prepare(
            `INSERT INTO rotation_guard (ok)
             SELECT CASE WHEN EXISTS (SELECT 1 FROM members WHERE id = ? AND status = 'pending')
                          AND EXISTS (SELECT 1 FROM member_keys WHERE id = ? AND member_id = ? AND status = 'active')
                          AND EXISTS (SELECT 1 FROM member_keys WHERE id = ? AND member_id = ? AND status = 'active' AND ecdsa_public_key IS NOT NULL)
                          AND (SELECT current_vault_key_version FROM vault_meta WHERE id = 1) = ?
                         THEN 1 ELSE 0 END`,
          )
          .bind(id, g.recipientKeyId, id, g.signerKeyId, p.memberId, g.vaultKeyVersion),
        db
          .prepare(
            `INSERT INTO vault_key_grants (vault_key_version, recipient_key_id, ephemeral_public_key, wrapped_key, signer_key_id, signature, format_version, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          )
          .bind(g.vaultKeyVersion, g.recipientKeyId, g.ephemeralPublicKey, g.wrappedKey, g.signerKeyId, g.signature, FORMAT_V1, now),
        db.prepare(`UPDATE members SET status = 'active', approved_by = ?, approved_at = ? WHERE id = ?`).bind(p.memberId, now, id),
        db.prepare('DELETE FROM rotation_guard'),
        db.prepare(`INSERT INTO audit_logs (actor_member_id, action, target_type, target_id, created_at) VALUES (?, 'member.approve', 'member', ?, ?)`).bind(p.memberId, id, now),
      ]);
    } catch (e) {
      if (isGuardFailure(e)) throw new HttpProblem(409);
      throw e;
    }
    return c.json({ id, status: 'active' });
  });

  // 削除：状態を removed にし、セッション・覚えた端末・その人の鍵宛てのグラントを無効にする。鍵の行は監査のために残し、revoked にする。
  // 相手の端末に残った Vault 鍵は回収できないので、画面でローテーションを促す（判断待ち8）
  app.delete('/v1/members/:id', async (c) => {
    const p = c.get('principal');
    requireAdmin(p);
    const id = memberIdParam(c.req.param('id'));
    if (id === p.memberId) throw new HttpProblem(409); // 唯一の管理者が自分を削除しない（Z-05）
    const db = c.env.DB;
    const now = Date.now();
    const [res] = await db.batch([
      db.prepare(`UPDATE members SET status = 'removed', removed_at = ? WHERE id = ? AND status != 'removed'`).bind(now, id),
      // 直前の文が1行を変えたときだけ書く
      db.prepare(`INSERT INTO audit_logs (actor_member_id, action, target_type, target_id, created_at) SELECT ?, 'member.remove', 'member', ?, ? WHERE changes() = 1`).bind(p.memberId, id, now),
      db.prepare('UPDATE sessions SET revoked_at = ? WHERE member_id = ? AND revoked_at IS NULL').bind(now, id),
      db.prepare('UPDATE remembered_devices SET revoked_at = ? WHERE member_id = ? AND revoked_at IS NULL').bind(now, id),
      db.prepare('DELETE FROM vault_key_grants WHERE recipient_key_id IN (SELECT id FROM member_keys WHERE member_id = ?)').bind(id),
      db.prepare(`UPDATE member_keys SET status = 'revoked' WHERE member_id = ?`).bind(id),
    ]);
    if (res!.meta.changes !== 1) throw new HttpProblem(404); // いない人、もう削除済みの人（ほかの文は何も変えない）
    return c.body(null, 204);
  });

  app.get('/v1/audit-logs', async (c) => {
    requireAdmin(c.get('principal'));
    const rows = await c.env.DB.prepare(
      `SELECT actor_member_id, action, target_type, target_id, created_at FROM audit_logs ORDER BY created_at DESC, rowid DESC LIMIT ?`,
    )
      .bind(AUDIT_LIMIT)
      .all();
    return c.json({ logs: rows.results });
  });
}
