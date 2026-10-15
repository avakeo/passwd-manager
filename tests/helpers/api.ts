// API テストの準備。メンバーとセッションは D1（SQLite）に直接入れる。
// 本番のコードにテスト用の認証は置かない。本番と同じ認証（トークンの SHA-256 をセッション表で引く）を通す。

import { createApp } from '../../src/api/app.ts';
import { toBase64Url, toHex } from '../../src/crypto/bytes.ts';
import { SqliteD1 } from './sqlite-d1.ts';

export type Status = 'pending' | 'active' | 'removed';

export function setup() {
  const db = new SqliteD1();
  db.db.exec(`INSERT INTO vault_meta (id, current_vault_key_version, vault_revision, schema_version) VALUES (1, 1, 0, 1)`);
  db.db.exec(`INSERT INTO vault_key_versions (version, status, created_by, created_at) VALUES (1, 'current', NULL, 0)`);
  const app = createApp();
  let n = 0;

  async function addMember(status: Status, opts: { role?: 'admin' | 'member'; scope?: 'extension' | 'web' } = {}) {
    n += 1;
    const id = `member_${n}`;
    db.db
      .prepare(`INSERT INTO members (id, discord_user_id, display_name, role, status, created_at) VALUES (?, ?, ?, ?, ?, 0)`)
      .run(id, `discord_${n}`, `メンバー${n}`, opts.role ?? 'member', status);
    const token = toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
    const hash = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token))));
    db.db
      .prepare(
        `INSERT INTO sessions (id, member_id, access_token_hash, refresh_token_hash, device_label, created_at, expires_at, scope)
         VALUES (?, ?, ?, ?, 'test', 0, ?, ?)`,
      )
      .run(`session_${n}`, id, hash, `refresh_${n}`, Date.now() + 15 * 60 * 1000, opts.scope ?? 'extension');
    return { id, token };
  }

  function request(method: string, path: string, token?: string, body?: unknown) {
    const headers: Record<string, string> = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    let payload: string | undefined;
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      payload = typeof body === 'string' ? body : JSON.stringify(body);
    }
    return app.request(path, { method, headers, body: payload }, { DB: db });
  }

  function vaultRevision(): number {
    return Number(db.db.prepare('SELECT vault_revision FROM vault_meta').get()!.vault_revision);
  }

  return { db, app, addMember, request, vaultRevision };
}

// 512 段のアイテムと同じ長さ（542バイト）の、形だけ正しい暗号文
export function fakeCiphertext(fill = 0x55): string {
  const b = new Uint8Array(542).fill(fill);
  b[0] = 0x01;
  b[1] = 0x01;
  return toBase64Url(b);
}
