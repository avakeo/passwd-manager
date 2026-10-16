// 認証と認可。Bearer トークンの SHA-256 で sessions を引く（D1 にはハッシュだけを置く）。
// 提出版は Discord ログインを入れないので、トークンを発行する入口はまだない。
// テスト用の固定トークンはここに置かない（テストはセッションの行を D1 に入れて、この経路を通す）。

import type { D1Database } from './d1.ts';
import { HttpProblem } from './problem.ts';

export type Principal = {
  memberId: string;
  role: 'admin' | 'member';
  scope: 'extension' | 'web';
  currentVaultKeyVersion: number;
};

async function sha256Hex(s: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)));
  let hex = '';
  for (const b of digest) hex += b.toString(16).padStart(2, '0');
  return hex;
}

// セッション、メンバー、現在の鍵の世代を、1回の結合クエリで取る。
// allowPending：承認待ちでも呼べる入口（GET /v1/me。双方向の照合のために、管理者の署名用公開鍵を受け取る）
export async function authenticate(
  db: D1Database,
  authorization: string | undefined,
  method: string,
  opts: { allowPending?: boolean } = {},
): Promise<Principal> {
  const match = /^Bearer ([A-Za-z0-9_\-.~+/]+=*)$/.exec(authorization ?? '');
  if (!match) throw new HttpProblem(401);
  const row = await db
    .prepare(
      `SELECT m.id AS member_id, m.role, m.status, s.scope,
              (SELECT current_vault_key_version FROM vault_meta WHERE id = 1) AS current_vault_key_version
         FROM sessions s JOIN members m ON m.id = s.member_id
        WHERE s.access_token_hash = ? AND s.revoked_at IS NULL AND s.expires_at > ?`,
    )
    .bind(await sha256Hex(match[1]!), Date.now())
    .first<{ member_id: string; role: 'admin' | 'member'; status: string; scope: 'extension' | 'web'; current_vault_key_version: number }>();
  if (!row) throw new HttpProblem(401);
  // D1 で承認済み（active）でなければ、承認待ちも削除済みも 403（Z-01、Z-06）。承認待ちは allowPending の入口だけ通す
  if (row.status !== 'active' && !(opts.allowPending === true && row.status === 'pending')) throw new HttpProblem(403);
  // Web ページ用のトークンは読み取り専用（Z-07）
  if (row.scope === 'web' && method !== 'GET' && method !== 'HEAD') throw new HttpProblem(403);
  return {
    memberId: row.member_id,
    role: row.role,
    scope: row.scope,
    currentVaultKeyVersion: Number(row.current_vault_key_version),
  };
}
