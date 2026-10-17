// 提出版の最小 API（Workers ＋ Hono ＋ D1）。仕様書「API・インフラ」。
// サーバーは暗号文を読まない。形（base64url、ヘッダー、長さ）だけを確かめて保存する。
// ログにトークン、Authorization ヘッダー、リクエスト本文を出さない（ロガーを置かない）。

import { Hono } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { cors } from 'hono/cors';
import { authenticate, authorize, routeKey } from './auth.ts';
import { recoveryCodesRemaining, registerAuthRoutes } from './auth-routes.ts';
import type { D1Database } from './d1.ts';
import type { Env } from './env.ts';
import { readJson } from './json.ts';
import { HttpProblem, problem } from './problem.ts';
import type { Principal } from './auth.ts';
import { fromBase64Url } from '../crypto/bytes.ts';
import { ALG_AES_256_GCM, FORMAT_V1 } from '../crypto/format.ts';


export const WEB_ORIGIN = 'https://pw.example.com'; // 仮の表記。CORS で許可するのはこの1つだけ

// アイテムの暗号文の長さ（パディング単位 ＋ 形式1 ＋ アルゴリズムID1 ＋ ノンス12 ＋ 認証タグ16）
const ITEM_ENVELOPE_LENGTHS = [512, 1024, 4096, 16384, 65536].map((b) => b + 30);
const MAX_ITEM_ENVELOPE = ITEM_ENVELOPE_LENGTHS[ITEM_ENVELOPE_LENGTHS.length - 1]!;
// 本文の上限：最大の暗号文を base64url にした長さ（約 87KB）＋ JSON の余裕
const MAX_BODY_BYTES = 96 * 1024;

const ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
const BASE64URL = /^[A-Za-z0-9_-]*$/;

// アイテムの暗号文の形だけを確かめる（中身は読めないし、読まない）
function checkItemCiphertext(ciphertext: unknown): string {
  if (typeof ciphertext !== 'string' || !BASE64URL.test(ciphertext) || ciphertext.length % 4 === 1) throw new HttpProblem(400);
  if (Math.floor((ciphertext.length * 3) / 4) > MAX_ITEM_ENVELOPE) throw new HttpProblem(413);
  const bytes = fromBase64Url(ciphertext);
  if (!ITEM_ENVELOPE_LENGTHS.includes(bytes.length)) throw new HttpProblem(400);
  // 先頭2バイトが 0x01 0x01（形式 v1、AES-256-GCM）
  if (bytes[0] !== FORMAT_V1 || bytes[1] !== ALG_AES_256_GCM) throw new HttpProblem(400);
  return ciphertext;
}

function isPositiveInt(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 1;
}

function itemIdParam(id: string): string {
  if (!ID_PATTERN.test(id)) throw new HttpProblem(400);
  return id;
}

export function createApp() {
  const app = new Hono<Env>();

  app.onError((err) => (err instanceof HttpProblem ? problem(err.status) : problem(500)));
  app.notFound(() => problem(404));

  app.use(
    '/v1/*',
    cors({
      origin: (origin) => (origin === WEB_ORIGIN ? origin : null),
      allowHeaders: ['Authorization', 'Content-Type'],
      allowMethods: ['GET', 'POST', 'PUT', 'DELETE'],
      maxAge: 600,
    }),
  );
  app.use('/v1/*', bodyLimit({ maxSize: MAX_BODY_BYTES, onError: () => problem(413) }));
  // 公開の入口（ログイン、更新、TOTP の一時トークン）のほかは、セッションで認証し、認可の表（auth.ts の authorize）で確かめる
  app.use('/v1/*', async (c, next) => {
    const key = routeKey(c.req.method, c.req.path);
    const isPublic =
      key === 'POST /v1/auth/discord' || key === 'POST /v1/auth/refresh' || (key === 'POST /v1/auth/totp' && c.req.header('Authorization') === undefined);
    if (!isPublic) {
      const p = await authenticate(c.env.DB, c.req.header('Authorization'));
      authorize(p, c.req.method, c.req.path);
      c.set('principal', p);
    }
    await next();
  });

  registerAuthRoutes(app);

  // 自分と、自分の有効な鍵（新しい端末でロック解除するのに使う）。管理者は署名鍵も返す。
  // admin_signer は照合用の管理者の「メンバーID、鍵ID、署名用公開鍵」。承認待ちでも取れる（双方向の照合）。
  // 端末は、固定した値と比べて使う。サーバーの値をそのまま信用しない（P-05）。
  // 返すのは必要な分だけ（DeepSeek #5・#10）。
  //   拡張機能：自分の鍵を開くのに要る列。署名鍵の列は管理者だけ。
  //   Web 用（読み取り専用）：ID と公開鍵だけ。暗号化した秘密鍵と KDF の設定は返さない。
  //   admin_signer はメンバーだけ（管理者は自分の行を使う）。有効な管理者の署名鍵がちょうど1つでなければ 409。
  app.get('/v1/me', async (c) => {
    const p = c.get('principal');
    const isAdmin = p.role === 'admin';
    const columns =
      p.scope === 'web'
        ? ['id', 'ecdh_public_key', ...(isAdmin ? ['ecdsa_public_key'] : [])]
        : [
            'id',
            'ecdh_public_key',
            'encrypted_private_key',
            ...(isAdmin ? ['ecdsa_public_key', 'encrypted_sign_private_key'] : []),
            'kdf_algorithm',
            'kdf_params',
            'kdf_salt',
            'format_version',
          ];
    const key = await c.env.DB.prepare(`SELECT ${columns.join(', ')} FROM member_keys WHERE member_id = ? AND status = 'active'`)
      .bind(p.memberId)
      .first();
    // 今の世代は、承認の照合で管理者の画面と見比べ、最後に見た世代の初期化に使う（DeepSeek #1）
    const body: Record<string, unknown> = {
      id: p.memberId,
      role: p.role,
      current_vault_key_version: p.currentVaultKeyVersion,
      key,
      // 少なくなったら、拡張機能が TOTP の作り直しを勧める
      recovery_codes_remaining: await recoveryCodesRemaining(c.env.DB, p.memberId),
    };
    if (!isAdmin) {
      const signers = await c.env.DB.prepare(
        `SELECT m.id AS member_id, k.id AS key_id, k.ecdsa_public_key
           FROM members m JOIN member_keys k ON k.member_id = m.id
          WHERE m.role = 'admin' AND m.status = 'active' AND k.status = 'active' AND k.ecdsa_public_key IS NOT NULL
          LIMIT 2`,
      ).all();
      // 0個や2個以上なら、どれかを選んで返すことはしない
      if (signers.results.length !== 1) throw new HttpProblem(409);
      body.admin_signer = signers.results[0];
    }
    return c.json(body);
  });

  // 鍵の世代と、自分の鍵宛ての署名付きのグラントだけ（他人宛ては返さない：Z-04）
  app.get('/v1/vault', async (c) => {
    const p = c.get('principal');
    const grant = await c.env.DB.prepare(
      `SELECT g.vault_key_version, g.recipient_key_id, g.ephemeral_public_key, g.wrapped_key, g.signer_key_id, g.signature,
              g.format_version,
              (SELECT vault_revision FROM vault_meta WHERE id = 1) AS vault_revision
         FROM vault_key_grants g JOIN member_keys k ON k.id = g.recipient_key_id
        WHERE k.member_id = ? AND k.status = 'active' AND g.vault_key_version = ?`,
    )
      .bind(p.memberId, p.currentVaultKeyVersion)
      .first<Record<string, unknown>>();
    const meta = grant
      ? { vault_revision: grant.vault_revision }
      : await c.env.DB.prepare('SELECT vault_revision FROM vault_meta WHERE id = 1').first();
    if (grant) delete grant.vault_revision;
    return c.json({
      current_vault_key_version: p.currentVaultKeyVersion,
      vault_revision: meta?.vault_revision ?? 0,
      grant: grant ?? null,
    });
  });

  // 差分同期。削除も「deleted: true」として返す（S-02）
  app.get('/v1/items', async (c) => {
    const sinceRaw = c.req.query('since') ?? '0';
    if (!/^\d{1,16}$/.test(sinceRaw)) throw new HttpProblem(400);
    const rows = await c.env.DB.prepare(
      `SELECT id, revision, vault_key_version, ciphertext, updated_at, deleted_at,
              (SELECT vault_revision FROM vault_meta WHERE id = 1) AS vault_revision
         FROM items WHERE updated_at > ? ORDER BY updated_at, id`,
    )
      .bind(Number(sinceRaw))
      .all<{ id: string; revision: number; vault_key_version: number; ciphertext: string | null; updated_at: number; deleted_at: number | null; vault_revision: number }>();
    const vaultRevision =
      rows.results[0]?.vault_revision ??
      (await c.env.DB.prepare('SELECT vault_revision FROM vault_meta WHERE id = 1').first<{ vault_revision: number }>())?.vault_revision ??
      0;
    return c.json({
      vault_revision: vaultRevision,
      items: rows.results.map((r) => ({
        id: r.id,
        revision: r.revision,
        vault_key_version: r.vault_key_version,
        ciphertext: r.ciphertext,
        updated_at: r.updated_at,
        deleted: r.deleted_at !== null,
      })),
    });
  });

  // 3つの文を1つのバッチ（トランザクション）にする。
  //   1. アイテムの書き込み（条件付き）
  //   2. 1 が1行を変えたときだけ Vault リビジョンを1増やす（changes() は直前の文が変えた行数）
  //   3. 2 が1行を変えたときだけ監査ログに書く
  async function writeItem(db: D1Database, itemSql: string, itemParams: unknown[], p: Principal, action: string, itemId: string) {
    const now = Date.now();
    const results = await db.batch([
      db.prepare(itemSql).bind(...itemParams),
      db.prepare('UPDATE vault_meta SET vault_revision = vault_revision + 1 WHERE id = 1 AND changes() = 1'),
      db
        .prepare(`INSERT INTO audit_logs (actor_member_id, action, target_type, target_id, created_at) SELECT ?, ?, 'item', ?, ? WHERE changes() = 1`)
        .bind(p.memberId, action, itemId, now),
    ]);
    return results[0]!.meta.changes;
  }

  async function updatedOrConflict(db: D1Database, changes: number, id: string): Promise<void> {
    if (changes === 1) return;
    const exists = await db.prepare('SELECT 1 AS x FROM items WHERE id = ? AND deleted_at IS NULL').bind(id).first();
    throw new HttpProblem(exists ? 409 : 404);
  }

  app.post('/v1/items', async (c) => {
    const p = c.get('principal');
    const body = await readJson(c.req.raw, ['id', 'vault_key_version', 'ciphertext']);
    if (typeof body.id !== 'string' || !ID_PATTERN.test(body.id) || !isPositiveInt(body.vault_key_version)) throw new HttpProblem(400);
    const ciphertext = checkItemCiphertext(body.ciphertext);
    if (body.vault_key_version !== p.currentVaultKeyVersion) throw new HttpProblem(409);
    const now = Date.now();
    const changes = await writeItem(
      c.env.DB,
      `INSERT OR IGNORE INTO items (id, revision, vault_key_version, ciphertext, created_by, created_at, updated_by, updated_at)
       VALUES (?, 1, ?, ?, ?, ?, ?, ?)`,
      [body.id, body.vault_key_version, ciphertext, p.memberId, now, p.memberId, now],
      p,
      'item.create',
      body.id,
    );
    if (changes !== 1) throw new HttpProblem(409); // 既存の ID（I-03）
    return c.json({ id: body.id, revision: 1 }, 201);
  });

  // 楽観的ロック：元にしたリビジョンがサーバーのものと違えば 409（S-01）
  app.put('/v1/items/:id', async (c) => {
    const p = c.get('principal');
    const id = itemIdParam(c.req.param('id'));
    const body = await readJson(c.req.raw, ['revision', 'vault_key_version', 'ciphertext']);
    if (!isPositiveInt(body.revision) || !isPositiveInt(body.vault_key_version)) throw new HttpProblem(400);
    const ciphertext = checkItemCiphertext(body.ciphertext);
    if (body.vault_key_version !== p.currentVaultKeyVersion) throw new HttpProblem(409);
    const changes = await writeItem(
      c.env.DB,
      `UPDATE items SET revision = revision + 1, vault_key_version = ?, ciphertext = ?, updated_by = ?, updated_at = ?
        WHERE id = ? AND revision = ? AND deleted_at IS NULL`,
      [body.vault_key_version, ciphertext, p.memberId, Date.now(), id, body.revision],
      p,
      'item.update',
      id,
    );
    await updatedOrConflict(c.env.DB, changes, id);
    return c.json({ id, revision: body.revision + 1 });
  });

  // 論理削除。暗号文は消し、行だけ残す（S-10）
  app.delete('/v1/items/:id', async (c) => {
    const p = c.get('principal');
    const id = itemIdParam(c.req.param('id'));
    const body = await readJson(c.req.raw, ['revision']);
    if (!isPositiveInt(body.revision)) throw new HttpProblem(400);
    const now = Date.now();
    const changes = await writeItem(
      c.env.DB,
      `UPDATE items SET revision = revision + 1, ciphertext = NULL, deleted_at = ?, updated_by = ?, updated_at = ?
        WHERE id = ? AND revision = ? AND deleted_at IS NULL`,
      [now, p.memberId, now, id, body.revision],
      p,
      'item.delete',
      id,
    );
    await updatedOrConflict(c.env.DB, changes, id);
    return c.json({ id, revision: body.revision + 1 });
  });

  return app;
}
