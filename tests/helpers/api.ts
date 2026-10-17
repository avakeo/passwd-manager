// API テストの準備。メンバーとセッションは D1（SQLite）に直接入れる。
// 本番のコードにテスト用の認証は置かない。本番と同じ認証（トークンの SHA-256 をセッション表で引く）を通す。
// Workers の設定には、テスト用の偽の値を渡す（本物の値はリポジトリにもテストにも入れない）。

import { createApp } from '../../src/api/app.ts';
import { encryptTotpSecret } from '../../src/api/totp.ts';
import { toBase64Url, toHex } from '../../src/crypto/bytes.ts';
import { SqliteD1 } from './sqlite-d1.ts';

export type Status = 'pending' | 'active' | 'removed';

export const EXTENSION_REDIRECT_URI = 'https://abcdefghijklmnopabcdefghijklmnop.chromiumapp.org/';
export const LOCAL_REDIRECT_URI = 'http://localhost:8788/callback';

// テスト用の偽の設定値
export const TEST_ENV = {
  DISCORD_CLIENT_ID: '100000000000000001',
  DISCORD_CLIENT_SECRET: 'test-client-secret-not-real',
  DISCORD_BOT_TOKEN: 'test-bot-token-not-real',
  DISCORD_GUILD_ID: '200000000000000002',
  DISCORD_ROLE_ID: '300000000000000003',
  DISCORD_REDIRECT_URIS: `${EXTENSION_REDIRECT_URI},${LOCAL_REDIRECT_URI}`,
  TOTP_ENCRYPTION_KEY: toBase64Url(new Uint8Array(32).fill(7)),
};

// addMember が既定で登録する TOTP のシークレット（TOTP は全員必須なので、既定で登録済みにする）
export const DEFAULT_TOTP_SECRET = new Uint8Array(20).fill(0x33);

async function sha256Hex(s: string): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s))));
}

export function setup() {
  const db = new SqliteD1();
  db.db.exec(`INSERT INTO vault_meta (id, current_vault_key_version, vault_revision, schema_version) VALUES (1, 1, 0, 1)`);
  db.db.exec(`INSERT INTO vault_key_versions (version, status, created_by, created_at) VALUES (1, 'current', NULL, 0)`);
  const app = createApp();
  const env = { DB: db, ...TEST_ENV };
  let n = 0; // メンバーの番号（member_1、member_2…）
  let s = 0; // セッションの番号（session_1、session_2…）

  async function addMember(
    status: Status,
    opts: {
      role?: 'admin' | 'member';
      scope?: 'extension' | 'web';
      discordUserId?: string;
      totpSecret?: Uint8Array<ArrayBuffer> | null; // 既定は DEFAULT_TOTP_SECRET で登録済み。null なら TOTP を登録していない
      totpVerifiedAt?: number | null;
    } = {},
  ) {
    n += 1;
    const id = `member_${n}`;
    db.db
      .prepare(`INSERT INTO members (id, discord_user_id, display_name, role, status, created_at) VALUES (?, ?, ?, ?, ?, 0)`)
      .run(id, opts.discordUserId ?? `90000000000000${String(n).padStart(4, '0')}`, `メンバー${n}`, opts.role ?? 'member', status);
    const totpSecret = opts.totpSecret === undefined ? DEFAULT_TOTP_SECRET : opts.totpSecret;
    if (totpSecret !== null) {
      db.db
        .prepare(`UPDATE members SET totp_secret_encrypted = ? WHERE id = ?`)
        .run(await encryptTotpSecret(TEST_ENV.TOTP_ENCRYPTION_KEY, id, totpSecret, 'totp-secret'), id);
    }
    const session = await addSession(id, { scope: opts.scope, totpVerifiedAt: opts.totpVerifiedAt });
    return { id, ...session };
  }

  async function addSession(memberId: string, opts: { scope?: 'extension' | 'web'; totpVerifiedAt?: number | null } = {}) {
    s += 1;
    const token = toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
    const refreshToken = toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
    const sessionId = `session_${s}`;
    db.db
      .prepare(
        `INSERT INTO sessions (id, member_id, access_token_hash, refresh_token_hash, device_label, created_at, expires_at,
                               refresh_expires_at, totp_verified_at, scope)
         VALUES (?, ?, ?, ?, 'test', ?, ?, ?, ?, ?)`,
      )
      .run(
        sessionId,
        memberId,
        await sha256Hex(token),
        await sha256Hex(refreshToken),
        Date.now(),
        Date.now() + 15 * 60 * 1000,
        Date.now() + 7 * 24 * 60 * 60 * 1000,
        opts.totpVerifiedAt ?? null,
        opts.scope ?? 'extension',
      );
    return { token, refreshToken, sessionId };
  }

  function request(method: string, path: string, token?: string, body?: unknown) {
    const headers: Record<string, string> = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    let payload: string | undefined;
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      payload = typeof body === 'string' ? body : JSON.stringify(body);
    }
    return app.request(path, { method, headers, body: payload }, env);
  }

  function vaultRevision(): number {
    return Number(db.db.prepare('SELECT vault_revision FROM vault_meta').get()!.vault_revision);
  }

  return { db, app, env, addMember, addSession, request, vaultRevision };
}

// 512 段のアイテムと同じ長さ（542バイト）の、形だけ正しい暗号文
export function fakeCiphertext(fill = 0x55): string {
  const b = new Uint8Array(542).fill(fill);
  b[0] = 0x01;
  b[1] = 0x01;
  return toBase64Url(b);
}
