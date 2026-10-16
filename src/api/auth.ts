// 認証と認可。Bearer トークンの SHA-256 で sessions を引く（D1 にはハッシュだけを置く）。
// テスト用の固定トークンはここに置かない（テストはセッションの行を D1 に入れて、この経路を通す）。
// 仕様書「認可とセッション」「二要素認証（TOTP）」、認可の表は tests/api/authz-matrix.test.ts。

import type { D1Database } from './d1.ts';
import { HttpProblem } from './problem.ts';
import { toHex, utf8 } from '../crypto/bytes.ts';

export type Principal = {
  memberId: string;
  sessionId: string;
  role: 'admin' | 'member';
  status: 'pending' | 'active' | 'removed';
  scope: 'extension' | 'web';
  hasTotp: boolean;
  totpVerifiedAt: number | null;
  currentVaultKeyVersion: number;
};

export async function sha256Hex(s: string): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(s))));
}

// セッション、メンバー、現在の鍵の世代を、1回の結合クエリで取る。ここでは「誰か」だけを決め、何をしてよいかは authorize で決める。
export async function authenticate(db: D1Database, authorization: string | undefined): Promise<Principal> {
  const match = /^Bearer ([A-Za-z0-9_\-.~+/]+=*)$/.exec(authorization ?? '');
  if (!match) throw new HttpProblem(401);
  const row = await db
    .prepare(
      `SELECT s.id AS session_id, s.scope, s.totp_verified_at, m.id AS member_id, m.role, m.status,
              m.totp_secret_encrypted IS NOT NULL AS has_totp,
              (SELECT current_vault_key_version FROM vault_meta WHERE id = 1) AS current_vault_key_version
         FROM sessions s JOIN members m ON m.id = s.member_id
        WHERE s.access_token_hash = ? AND s.revoked_at IS NULL AND s.expires_at > ?`,
    )
    .bind(await sha256Hex(match[1]!), Date.now())
    .first<{
      session_id: string;
      scope: 'extension' | 'web';
      totp_verified_at: number | null;
      member_id: string;
      role: 'admin' | 'member';
      status: 'pending' | 'active' | 'removed';
      has_totp: number;
      current_vault_key_version: number;
    }>();
  if (!row) throw new HttpProblem(401);
  return {
    memberId: row.member_id,
    sessionId: row.session_id,
    role: row.role,
    status: row.status,
    scope: row.scope,
    hasTotp: Number(row.has_totp) === 1,
    totpVerifiedAt: row.totp_verified_at === null ? null : Number(row.totp_verified_at),
    currentVaultKeyVersion: Number(row.current_vault_key_version),
  };
}

// 承認待ちでも使える入口（鍵の登録と照合、セッションと TOTP の管理、ログアウト）
const PENDING_ROUTES = new Set([
  'GET /v1/me',
  'POST /v1/auth/logout',
  'POST /v1/auth/totp',
  'GET /v1/me/sessions',
  'DELETE /v1/me/sessions/:id',
  'POST /v1/me/totp',
  'POST /v1/me/totp/confirm',
  'DELETE /v1/me/totp',
]);

// TOTP を登録していない管理者が使える入口。管理操作だけでなく、読み書きも GET /v1/me もできない（A-11）
const ADMIN_SETUP_ROUTES = new Set(['POST /v1/me/totp', 'POST /v1/me/totp/confirm', 'POST /v1/auth/logout']);

export function routeKey(method: string, path: string): string {
  const p = path.replace(/^\/v1\/me\/sessions\/[^/]+$/, '/v1/me/sessions/:id').replace(/^\/v1\/items\/[^/]+$/, '/v1/items/:id');
  return `${method} ${p}`;
}

// 何をしてよいか。順に：削除済み → Web 用は読み取りだけ → TOTP 未登録の管理者 → 承認待ち。
export function authorize(p: Principal, method: string, path: string): void {
  const key = routeKey(method, path);
  // D1 で承認済み（active）でなければ、削除済みは 403（Z-06）
  if (p.status === 'removed') throw new HttpProblem(403);
  // Web ページ用のトークンは読み取り専用（Z-07）
  if (p.scope === 'web' && method !== 'GET' && method !== 'HEAD') throw new HttpProblem(403);
  if (p.role === 'admin' && !p.hasTotp && !ADMIN_SETUP_ROUTES.has(key)) throw new HttpProblem(403);
  // 承認待ちは、決めた入口だけ（Z-01）
  if (p.status === 'pending' && !PENDING_ROUTES.has(key)) throw new HttpProblem(403);
}

// 管理操作の直前の TOTP の再確認（ステップアップ）。5分以内に確かめたセッションだけを通す（A-10）。
// 管理操作のエンドポイント（承認、削除、ロール変更、ローテーション）はフェーズ4で作り、この判定を通す。
export const STEP_UP_WINDOW_MS = 5 * 60 * 1000;

export function requireRecentTotp(p: { totpVerifiedAt: number | null }, nowMs: number): void {
  const at = p.totpVerifiedAt;
  if (at === null || at > nowMs || nowMs - at > STEP_UP_WINDOW_MS) throw new HttpProblem(403);
}
