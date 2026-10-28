// 鍵の登録（PUT /v1/me/keys）と、最初の Vault（POST /v1/vault/init）。
// 仕様書「鍵とメンバーのライフサイクル > 初期化（管理者）」。サーバーは鍵も暗号文も読まない。形と長さだけを確かめて保存する。

import type { Hono } from 'hono';
import { hasRecentTotp } from './auth.ts';
import type { Env } from './env.ts';
import { readJson } from './json.ts';
import { HttpProblem } from './problem.ts';
import { fromBase64Url, type Bytes } from '../crypto/bytes.ts';
import { grantSignedMessage } from '../crypto/grant.ts';
import { importPublicKey } from '../crypto/public-key.ts';
import { importSignPublicKey, verifySignature } from '../crypto/signer.ts';
import { ALG_AES_256_GCM, ALG_ECDSA_P256_SHA256, ALG_HPKE_BASE, FORMAT_V1, GRANT_ENVELOPE_LENGTH, NONCE_LENGTH, SIGNATURE_LENGTH, TAG_LENGTH } from '../crypto/format.ts';
import { KDF_PBKDF2_SHA256, PASSWORD_NORMALIZATION, PBKDF2_MAX_ITERATIONS, PBKDF2_MIN_ITERATIONS, SALT_LENGTH } from '../crypto/kdf.ts';

const KEY_ID = /^key_[A-Za-z0-9_-]{22}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const PUBLIC_KEY_LENGTH = 65; // P-256 の非圧縮形式
const MAX_WRAPPED_PRIVATE_KEY = 512; // PKCS#8 の P-256 秘密鍵（約140バイト）を包んだもの。余裕を持たせた上限

function bytes(v: unknown, maxLength = 1024): Bytes {
  if (typeof v !== 'string' || !BASE64URL.test(v) || v.length % 4 === 1 || v.length > Math.ceil((maxLength * 4) / 3)) throw new HttpProblem(400);
  return fromBase64Url(v);
}

function publicKey(v: unknown): string {
  const b = bytes(v);
  if (b.length !== PUBLIC_KEY_LENGTH || b[0] !== 0x04) throw new HttpProblem(400);
  return v as string;
}

// 暗号化した秘密鍵：形式、アルゴリズムID（AES-256-GCM）、ノンス、暗号文と認証タグ
function wrappedPrivateKey(v: unknown): string {
  const b = bytes(v, MAX_WRAPPED_PRIVATE_KEY);
  if (b.length <= 2 + NONCE_LENGTH + TAG_LENGTH || b.length > MAX_WRAPPED_PRIVATE_KEY || b[0] !== FORMAT_V1 || b[1] !== ALG_AES_256_GCM) throw new HttpProblem(400);
  return v as string;
}

function kdfParams(v: unknown): string {
  if (typeof v !== 'string' || v.length > 200) throw new HttpProblem(400);
  let parsed: unknown;
  try {
    parsed = JSON.parse(v);
  } catch {
    throw new HttpProblem(400);
  }
  const p = parsed as { iterations?: unknown; normalization?: unknown };
  if (typeof parsed !== 'object' || parsed === null || Object.keys(parsed).sort().join(',') !== 'iterations,normalization') throw new HttpProblem(400);
  const n = p.iterations;
  if (typeof n !== 'number' || !Number.isSafeInteger(n) || n < PBKDF2_MIN_ITERATIONS || n > PBKDF2_MAX_ITERATIONS || p.normalization !== PASSWORD_NORMALIZATION) throw new HttpProblem(400);
  return v;
}

export function keyId(v: unknown): string {
  if (typeof v !== 'string' || !KEY_ID.test(v)) throw new HttpProblem(400);
  return v;
}

export const GRANT_FIELDS = ['vault_key_version', 'recipient_key_id', 'ephemeral_public_key', 'wrapped_key', 'signer_key_id', 'signature', 'format_version'];

export type CheckedGrant = { vaultKeyVersion: number; recipientKeyId: string; ephemeralPublicKey: string; wrappedKey: string; signerKeyId: string; signature: string };

// 署名付きのグラントの形を確かめる（長さとヘッダーも：DeepSeek #9）。中身は読まない
export function grantShape(body: Record<string, unknown>): CheckedGrant {
  if (!Number.isSafeInteger(body.vault_key_version) || Number(body.vault_key_version) < 1 || body.format_version !== FORMAT_V1) throw new HttpProblem(400);
  const recipientKeyId = keyId(body.recipient_key_id);
  const signerKeyId = keyId(body.signer_key_id);
  const ephemeralPublicKey = publicKey(body.ephemeral_public_key);
  const wrapped = bytes(body.wrapped_key);
  if (wrapped.length !== GRANT_ENVELOPE_LENGTH || wrapped[0] !== FORMAT_V1 || wrapped[1] !== ALG_HPKE_BASE) throw new HttpProblem(400);
  const sig = bytes(body.signature);
  if (sig.length !== 2 + SIGNATURE_LENGTH || sig[0] !== FORMAT_V1 || sig[1] !== ALG_ECDSA_P256_SHA256) throw new HttpProblem(400);
  return { vaultKeyVersion: Number(body.vault_key_version), recipientKeyId, ephemeralPublicKey, wrappedKey: body.wrapped_key as string, signerKeyId, signature: body.signature as string };
}

// サーバーもグラントの署名を確かめる（形だけ合わせた偽のグラントを置かせない：DeepSeek #2）。
// 署名する中身は、暗号コアと同じ関数で組み立てる。使い捨て公開鍵が曲線上の点かも確かめる。違えば 400
export async function verifyGrantSignature(
  g: CheckedGrant,
  signer: { memberId: string; ecdsaPublicKey: string },
  recipient: { memberId: string; ecdhPublicKey: string },
): Promise<void> {
  const epk = fromBase64Url(g.ephemeralPublicKey);
  try {
    await importPublicKey(epk);
  } catch {
    throw new HttpProblem(400);
  }
  const message = grantSignedMessage({
    signerMemberId: signer.memberId,
    signerKeyId: g.signerKeyId,
    vaultKeyVersion: g.vaultKeyVersion,
    recipientMemberId: recipient.memberId,
    recipientKeyId: g.recipientKeyId,
    recipientPublicKeySha256: new Uint8Array(await crypto.subtle.digest('SHA-256', fromBase64Url(recipient.ecdhPublicKey))),
    ephemeralPublicKey: epk,
    wrappedKey: fromBase64Url(g.wrappedKey),
  });
  const verifyKey = await importSignPublicKey(fromBase64Url(signer.ecdsaPublicKey));
  if (!(await verifySignature(verifyKey, fromBase64Url(g.signature).slice(2), message))) throw new HttpProblem(400);
}

// 確認と保存を1つのバッチにするときの、バッチの先頭の確認（0 なら制約違反でバッチ全体が巻き戻る：rotation_guard）
export function isGuardFailure(e: unknown): boolean {
  return e instanceof Error && /constraint/i.test(e.message);
}

export function registerKeyRoutes(app: Hono<Env>): void {
  // 鍵の登録。前の鍵は revoked にし、新しい鍵を active にする。
  //   メンバーの登録し直しは承認待ちに戻る（P-02）。登録し直しは5分以内の TOTP の確認が要る。
  //   管理者の登録し直しは、グラントがまだないときだけ。
  //   「有効な鍵があるか」「あれば5分以内に TOTP を確かめたか」「管理者ならグラントがないか」は、保存と同じバッチの先頭で確かめる
  //   （同時に2回送っても、後の方が TOTP の確認なしに前の鍵を無効にできない：Codex #2）。
  app.put('/v1/me/keys', async (c) => {
    const p = c.get('principal');
    const isAdmin = p.role === 'admin';
    const fields = ['id', 'ecdh_public_key', 'encrypted_private_key', 'kdf_algorithm', 'kdf_params', 'kdf_salt', 'format_version'];
    const body = await readJson(c.req.raw, isAdmin ? [...fields, 'ecdsa_public_key', 'encrypted_sign_private_key'] : fields);
    const id = keyId(body.id);
    const ecdh = publicKey(body.ecdh_public_key);
    const encrypted = wrappedPrivateKey(body.encrypted_private_key);
    const ecdsa = isAdmin ? publicKey(body.ecdsa_public_key) : null;
    const encryptedSign = isAdmin ? wrappedPrivateKey(body.encrypted_sign_private_key) : null;
    if (body.kdf_algorithm !== KDF_PBKDF2_SHA256 || body.format_version !== FORMAT_V1) throw new HttpProblem(400);
    const params = kdfParams(body.kdf_params);
    if (bytes(body.kdf_salt).length !== SALT_LENGTH) throw new HttpProblem(400);
    const salt = body.kdf_salt as string;

    const db = c.env.DB;
    const now = Date.now();
    const recent = hasRecentTotp(p, now) ? 1 : 0;
    const hasActive = `EXISTS (SELECT 1 FROM member_keys WHERE member_id = ? AND status = 'active')`;
    try {
      await db.batch([
        // 1つでも違えば 0 を入れて、バッチ全体を巻き戻す（盗まれたトークンで鍵を差し替えて、承認待ちに落とせないように）
        db
          .prepare(
            `INSERT INTO rotation_guard (ok)
             SELECT CASE WHEN ? = 'admin' AND EXISTS (SELECT 1 FROM vault_key_grants) THEN 0
                         WHEN ${hasActive} AND ? = 0 THEN 0
                         ELSE 1 END`,
          )
          .bind(p.role, p.memberId, recent),
        db
          .prepare(`INSERT INTO audit_logs (actor_member_id, action, target_type, target_id, created_at)
                    SELECT ?, CASE WHEN ${hasActive} THEN 'key.reregister' ELSE 'key.register' END, 'member_key', ?, ?`)
          .bind(p.memberId, p.memberId, id, now),
        // 登録し直し（有効な鍵がある）なら、承認済みのメンバーを承認待ちに戻す（P-02）
        db.prepare(`UPDATE members SET status = 'pending' WHERE id = ? AND role = 'member' AND status = 'active' AND ${hasActive}`).bind(p.memberId, p.memberId),
        db.prepare(`UPDATE member_keys SET status = 'revoked' WHERE member_id = ? AND status = 'active'`).bind(p.memberId),
        db
          .prepare(
            `INSERT INTO member_keys (id, member_id, ecdh_public_key, encrypted_private_key, ecdsa_public_key, encrypted_sign_private_key,
                                      kdf_algorithm, kdf_params, kdf_salt, format_version, status, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)`,
          )
          .bind(id, p.memberId, ecdh, encrypted, ecdsa, encryptedSign, KDF_PBKDF2_SHA256, params, salt, FORMAT_V1, now),
        db.prepare('DELETE FROM rotation_guard'),
      ]);
    } catch (e) {
      if (!isGuardFailure(e)) throw e;
      // 有効な鍵があって5分以内の TOTP の確認がない（403）か、グラントがある管理者・同じ鍵ID（409）
      const existing = await db.prepare(`SELECT 1 AS x FROM member_keys WHERE member_id = ? AND status = 'active'`).bind(p.memberId).first();
      if (existing && recent === 0) throw new HttpProblem(403);
      throw new HttpProblem(409);
    }
    return c.body(null, 204);
  });

  // 最初の Vault。管理者が、世代1の自分宛て・自分の鍵で署名したグラントを1つ置く。
  // 「グラントがまだ1つもない」ことの確認と保存を1つのバッチで行う。同時に2回呼んでも片方しか通らない（P-11）。
  app.post('/v1/vault/init', async (c) => {
    const p = c.get('principal');
    if (p.role !== 'admin') throw new HttpProblem(403);
    const now = Date.now();
    if (!hasRecentTotp(p, now)) throw new HttpProblem(403);
    const body = await readJson(c.req.raw, GRANT_FIELDS);
    const g = grantShape(body);
    if (g.vaultKeyVersion !== 1) throw new HttpProblem(400);
    const recipient = g.recipientKeyId;
    if (g.signerKeyId !== recipient) throw new HttpProblem(400);
    const epk = g.ephemeralPublicKey;

    const db = c.env.DB;
    // サーバーも署名を確かめる（形だけ合わせた偽のグラントで Vault を作らせ、正規の端末が開けないまま
    // 作り直せなくなるのを防ぐ：DeepSeek #2）。署名する中身は、暗号コアと同じ関数で組み立てる
    const own = await db
      .prepare(
        `SELECT k.ecdh_public_key, k.ecdsa_public_key FROM member_keys k JOIN members m ON m.id = k.member_id
          WHERE k.id = ? AND m.id = ? AND m.role = 'admin' AND m.status = 'active' AND k.status = 'active' AND k.ecdsa_public_key IS NOT NULL`,
      )
      .bind(recipient, p.memberId)
      .first<{ ecdh_public_key: string; ecdsa_public_key: string }>();
    if (!own) throw new HttpProblem(409); // 自分の有効な署名鍵付きの鍵ではない
    await verifyGrantSignature(g, { memberId: p.memberId, ecdsaPublicKey: own.ecdsa_public_key }, { memberId: p.memberId, ecdhPublicKey: own.ecdh_public_key });

    try {
      await db.batch([
        // グラントがまだなく、宛先が自分の有効な署名鍵付きの鍵であること。違えば 0 を入れて、バッチ全体を巻き戻す
        db
          .prepare(
            `INSERT INTO rotation_guard (ok)
             SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM vault_key_grants)
                          AND EXISTS (SELECT 1 FROM member_keys k JOIN members m ON m.id = k.member_id
                                       WHERE k.id = ? AND m.id = ? AND m.role = 'admin' AND m.status = 'active'
                                         AND k.status = 'active' AND k.ecdsa_public_key IS NOT NULL)
                         THEN 1 ELSE 0 END`,
          )
          .bind(recipient, p.memberId),
        db.prepare(`INSERT OR IGNORE INTO vault_key_versions (version, status, created_by, created_at) VALUES (1, 'current', ?, ?)`).bind(p.memberId, now),
        db.prepare(`INSERT OR IGNORE INTO vault_meta (id, current_vault_key_version, vault_revision, rotation_in_progress, schema_version) VALUES (1, 1, 0, 0, 1)`),
        db
          .prepare(
            `INSERT INTO vault_key_grants (vault_key_version, recipient_key_id, ephemeral_public_key, wrapped_key, signer_key_id, signature, format_version, created_at)
             VALUES (1, ?, ?, ?, ?, ?, ?, ?)`,
          )
          .bind(recipient, epk, g.wrappedKey, recipient, g.signature, FORMAT_V1, now),
        db.prepare('DELETE FROM rotation_guard'),
        db.prepare(`INSERT INTO audit_logs (actor_member_id, action, target_type, target_id, created_at) VALUES (?, 'vault.init', 'vault', '1', ?)`).bind(p.memberId, now),
      ]);
    } catch (e) {
      if (isGuardFailure(e)) throw new HttpProblem(409);
      throw e;
    }
    return c.json({ vault_key_version: 1 }, 201);
  });
}
