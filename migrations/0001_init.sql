-- 仕様書「D1テーブル設計」。D1 には暗号文と、認可・同期に必要な平文のメタデータだけを置く。
-- バイト列（公開鍵、暗号文、ソルト）は base64url の文字列で保存する。

CREATE TABLE members (
  id TEXT PRIMARY KEY,
  discord_user_id TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'member')),
  status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'removed')),
  approved_by TEXT,
  approved_at INTEGER,
  removed_at INTEGER,
  created_at INTEGER NOT NULL,
  totp_secret_encrypted TEXT,
  totp_last_step INTEGER,
  recovery_code_hashes TEXT
);

CREATE TABLE member_keys (
  id TEXT PRIMARY KEY, -- 鍵ID。クライアントで生成する（暗号化前に AAD へ入れるため）
  member_id TEXT NOT NULL REFERENCES members (id),
  ecdh_public_key TEXT NOT NULL,
  encrypted_private_key TEXT NOT NULL,
  kdf_algorithm TEXT NOT NULL,
  kdf_params TEXT NOT NULL,
  kdf_salt TEXT NOT NULL,
  format_version INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  created_at INTEGER NOT NULL
);

CREATE TABLE vault_key_versions (
  version INTEGER PRIMARY KEY,
  status TEXT NOT NULL CHECK (status IN ('current', 'retired')),
  created_by TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE vault_key_grants (
  vault_key_version INTEGER NOT NULL,
  recipient_key_id TEXT NOT NULL,
  ephemeral_public_key TEXT NOT NULL,
  wrapped_key TEXT NOT NULL, -- 形式、アルゴリズムID、暗号文と認証タグ。ノンスは持たない
  format_version INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (vault_key_version, recipient_key_id)
);

CREATE TABLE items (
  id TEXT PRIMARY KEY, -- クライアントで生成する（暗号化前に AAD へ入れるため）
  revision INTEGER NOT NULL,
  vault_key_version INTEGER NOT NULL,
  ciphertext TEXT, -- 削除時は NULL にして行だけ残す
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_by TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  deleted_at INTEGER
);
CREATE INDEX items_updated_at ON items (updated_at);

CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  member_id TEXT NOT NULL REFERENCES members (id),
  access_token_hash TEXT NOT NULL UNIQUE,
  refresh_token_hash TEXT NOT NULL UNIQUE,
  device_label TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER,
  scope TEXT NOT NULL CHECK (scope IN ('extension', 'web'))
);

CREATE TABLE audit_logs (
  actor_member_id TEXT,
  action TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE vault_meta (
  id INTEGER PRIMARY KEY CHECK (id = 1), -- 1行だけ
  current_vault_key_version INTEGER NOT NULL,
  vault_revision INTEGER NOT NULL,
  rotation_in_progress INTEGER NOT NULL DEFAULT 0,
  schema_version INTEGER NOT NULL
);

-- ローテーションの検証用。確認結果（1 か 0）を挿入し、0 なら制約違反でバッチ全体を巻き戻す。
CREATE TABLE rotation_guard (
  ok INTEGER NOT NULL CHECK (ok = 1)
);
