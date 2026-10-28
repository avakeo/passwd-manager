-- この端末を覚える（2026-10-29 追記）。仕様書「この端末を覚える」「D1テーブル設計 > remembered_devices」。
-- ブラウザを閉じた後に、端末のトークンと4桁のパスコードで、同じセッションに戻るための行。
-- 端末のトークンは SHA-256 だけ、パスコードはサーバーの鍵で HMAC にした値だけを置く。
-- パスコードの間違いの回数をここで数え、3回で revoked_at を入れる。期限はセッションのリフレッシュトークンと同じ。
CREATE TABLE remembered_devices (
  id TEXT PRIMARY KEY,
  member_id TEXT NOT NULL REFERENCES members (id),
  session_id TEXT NOT NULL UNIQUE REFERENCES sessions (id),
  token_hash TEXT NOT NULL UNIQUE,
  pin_hash TEXT NOT NULL,
  failed_count INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);
