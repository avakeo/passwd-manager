// ローテーション（フェーズ4b。仕様書「メンバーの削除とローテーション」「ローテーションの1リクエスト化」、S-03〜S-08）。
//   POST /v1/vault/rotate（管理者。5分以内に TOTP を確かめたセッション）
// 管理者の端末が、新しい世代の Vault 鍵で全アイテムを暗号化し直し（リビジョン+1 を AAD に入れて）、有効なメンバー全員分のグラントを作って、1回で送る。
// サーバーは1つのバッチの先頭で次をすべて確かめ、1つでも違えば rotation_guard の制約違反でバッチ全体を巻き戻して 409 にする。
//   - 今の世代が、新しい世代の1つ前
//   - Vault リビジョンが、管理者が取得したときの値のまま
//   - 送られたアイテムの集合が、削除されていない全アイテムと一致し、どれもサーバーのリビジョン+1
//   - グラントの宛先の集合が、有効なメンバーの有効な鍵の集合と一致する
// 確かめた後は、同じバッチで新しい世代の登録、全アイテムの書き換え、グラントの保存、古い世代のグラントの削除、Vault リビジョンの更新を行う。
// グラントの署名もサーバーが確かめる（DeepSeek #2）。1.5MB を超える本文は 413（app.ts の本文の上限）。

import type { Hono } from 'hono';
import { requireRecentTotp } from './auth.ts';
import type { Env } from './env.ts';
import { readJson } from './json.ts';
import { HttpProblem } from './problem.ts';
import { GRANT_FIELDS, grantShape, isGuardFailure, verifyGrantSignature, type CheckedGrant } from './key-routes.ts';
import { ID_PATTERN, checkItemCiphertext } from './item-shape.ts';
import { FORMAT_V1 } from '../crypto/format.ts';

function isPositiveInt(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 1;
}

export function registerRotateRoutes(app: Hono<Env>): void {
  app.post('/v1/vault/rotate', async (c) => {
    const p = c.get('principal');
    if (p.role !== 'admin') throw new HttpProblem(403);
    requireRecentTotp(p, Date.now());
    const body = await readJson(c.req.raw, ['from_vault_revision', 'vault_key_version', 'items', 'grants']);
    if (!Number.isSafeInteger(body.from_vault_revision) || Number(body.from_vault_revision) < 0 || !isPositiveInt(body.vault_key_version)) throw new HttpProblem(400);
    if (!Array.isArray(body.items) || !Array.isArray(body.grants) || body.grants.length === 0) throw new HttpProblem(400);
    const version = body.vault_key_version;

    const itemIds = new Set<string>();
    const items = body.items.map((raw: unknown) => {
      if (typeof raw !== 'object' || raw === null || Array.isArray(raw) || Object.keys(raw).sort().join(',') !== 'ciphertext,id,revision') throw new HttpProblem(400);
      const { id, revision, ciphertext } = raw as Record<string, unknown>;
      if (typeof id !== 'string' || !ID_PATTERN.test(id) || itemIds.has(id) || !isPositiveInt(revision)) throw new HttpProblem(400);
      itemIds.add(id);
      return { id, revision, ciphertext: checkItemCiphertext(ciphertext) };
    });

    const recipients = new Set<string>();
    const grants: CheckedGrant[] = body.grants.map((raw: unknown) => {
      if (typeof raw !== 'object' || raw === null || Array.isArray(raw) || Object.keys(raw).sort().join(',') !== [...GRANT_FIELDS].sort().join(',')) throw new HttpProblem(400);
      const g = grantShape(raw as Record<string, unknown>);
      if (g.vaultKeyVersion !== version || recipients.has(g.recipientKeyId)) throw new HttpProblem(400);
      recipients.add(g.recipientKeyId);
      return g;
    });

    const db = c.env.DB;
    // 署名する管理者の鍵（自分の有効な署名鍵）と、宛先の鍵の持ち主。宛先の集合そのものは、バッチの先頭で確かめる
    const signer = await db
      .prepare(`SELECT id, ecdsa_public_key FROM member_keys WHERE member_id = ? AND status = 'active' AND ecdsa_public_key IS NOT NULL`)
      .bind(p.memberId)
      .first<{ id: string; ecdsa_public_key: string }>();
    if (!signer) throw new HttpProblem(409);
    for (const g of grants) {
      if (g.signerKeyId !== signer.id) throw new HttpProblem(400);
      const r = await db.prepare('SELECT member_id, ecdh_public_key FROM member_keys WHERE id = ?').bind(g.recipientKeyId).first<{ member_id: string; ecdh_public_key: string }>();
      if (!r) throw new HttpProblem(409);
      await verifyGrantSignature(g, { memberId: p.memberId, ecdsaPublicKey: signer.ecdsa_public_key }, { memberId: r.member_id, ecdhPublicKey: r.ecdh_public_key });
    }

    const itemsJson = JSON.stringify(items);
    const grantsJson = JSON.stringify(grants.map((g) => ({ k: g.recipientKeyId, e: g.ephemeralPublicKey, w: g.wrappedKey, s: g.signerKeyId, g: g.signature })));
    const now = Date.now();
    try {
      await db.batch([
        db
          .prepare(
            `INSERT INTO rotation_guard (ok)
             SELECT CASE WHEN (SELECT current_vault_key_version FROM vault_meta WHERE id = 1) = ? - 1
                          AND (SELECT vault_revision FROM vault_meta WHERE id = 1) = ?
                          AND (SELECT COUNT(*) FROM items WHERE deleted_at IS NULL) = json_array_length(?)
                          AND NOT EXISTS (
                            SELECT 1 FROM json_each(?) j
                              LEFT JOIN items i ON i.id = json_extract(j.value, '$.id') AND i.deleted_at IS NULL
                                               AND i.revision + 1 = json_extract(j.value, '$.revision')
                             WHERE i.id IS NULL)
                          AND (SELECT COUNT(*) FROM member_keys k JOIN members m ON m.id = k.member_id
                                WHERE k.status = 'active' AND m.status = 'active') = json_array_length(?)
                          AND NOT EXISTS (
                            SELECT 1 FROM json_each(?) j
                              LEFT JOIN member_keys k ON k.id = json_extract(j.value, '$.k') AND k.status = 'active'
                              LEFT JOIN members m ON m.id = k.member_id AND m.status = 'active'
                             WHERE m.id IS NULL)
                         THEN 1 ELSE 0 END`,
          )
          .bind(version, body.from_vault_revision, itemsJson, itemsJson, grantsJson, grantsJson),
        db.prepare(`UPDATE vault_key_versions SET status = 'retired' WHERE version < ?`).bind(version),
        db.prepare(`INSERT INTO vault_key_versions (version, status, created_by, created_at) VALUES (?, 'current', ?, ?)`).bind(version, p.memberId, now),
        db.prepare('UPDATE vault_meta SET current_vault_key_version = ?, vault_revision = vault_revision + 1 WHERE id = 1').bind(version),
        // 全アイテムを書き換える。change_seq は新しい Vault リビジョン（差分同期で全員に届く）
        db
          .prepare(
            `UPDATE items SET
               ciphertext = (SELECT json_extract(j.value, '$.ciphertext') FROM json_each(?) j WHERE json_extract(j.value, '$.id') = items.id),
               revision = revision + 1, vault_key_version = ?, updated_by = ?, updated_at = ?,
               change_seq = (SELECT vault_revision FROM vault_meta WHERE id = 1)
             WHERE deleted_at IS NULL AND id IN (SELECT json_extract(value, '$.id') FROM json_each(?))`,
          )
          .bind(itemsJson, version, p.memberId, now, itemsJson),
        db
          .prepare(
            `INSERT INTO vault_key_grants (vault_key_version, recipient_key_id, ephemeral_public_key, wrapped_key, signer_key_id, signature, format_version, created_at)
             SELECT ?, json_extract(value, '$.k'), json_extract(value, '$.e'), json_extract(value, '$.w'), json_extract(value, '$.s'), json_extract(value, '$.g'), ?, ? FROM json_each(?)`,
          )
          .bind(version, FORMAT_V1, now, grantsJson),
        // 古い世代のグラントは残さない（削除したメンバーの分も：S-06）
        db.prepare('DELETE FROM vault_key_grants WHERE vault_key_version < ?').bind(version),
        db.prepare('DELETE FROM rotation_guard'),
        db.prepare(`INSERT INTO audit_logs (actor_member_id, action, target_type, target_id, created_at) VALUES (?, 'vault.rotate', 'vault', ?, ?)`).bind(p.memberId, String(version), now),
      ]);
    } catch (e) {
      if (isGuardFailure(e)) throw new HttpProblem(409);
      throw e;
    }
    const meta = await db.prepare('SELECT vault_revision FROM vault_meta WHERE id = 1').first<{ vault_revision: number }>();
    return c.json({ vault_key_version: version, vault_revision: Number(meta?.vault_revision) });
  });
}
