-- フェーズ1：Discord ログイン、セッションの更新、TOTP。仕様書「D1テーブル設計」「認証・認可フロー」。

-- TOTP の登録の途中のシークレット（コードで確定するまで使わない）と、失敗の回数（15分で5回まで）
ALTER TABLE members ADD COLUMN totp_pending_secret_encrypted TEXT;
ALTER TABLE members ADD COLUMN totp_failed_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE members ADD COLUMN totp_failed_window_start INTEGER;

-- リフレッシュトークンの期限（ログインから7日。更新しても延ばさない）、
-- このセッションで TOTP を確かめた時刻（管理操作の再確認に使う）
ALTER TABLE sessions ADD COLUMN refresh_expires_at INTEGER;
ALTER TABLE sessions ADD COLUMN totp_verified_at INTEGER;

-- そのセッションで使い終わったリフレッシュトークン（再利用の検知：A-12）。ハッシュだけを置く。
-- expires_at はセッションのリフレッシュトークンの期限。過ぎたら消してよい
CREATE TABLE used_refresh_tokens (
  token_hash TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions (id),
  expires_at INTEGER NOT NULL
);

-- ログインの途中の一時トークン（TOTP のコードを送るまでの5分だけ）。ハッシュだけを置く
CREATE TABLE auth_challenges (
  id TEXT PRIMARY KEY,
  member_id TEXT NOT NULL REFERENCES members (id),
  challenge_hash TEXT NOT NULL UNIQUE,
  scope TEXT NOT NULL CHECK (scope IN ('extension', 'web')),
  device_label TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX sessions_member ON sessions (member_id);
CREATE INDEX used_refresh_tokens_expires ON used_refresh_tokens (expires_at);
