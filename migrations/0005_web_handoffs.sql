-- 拡張機能から Web ページを開く（2026-11-05 追記、W-09）。仕様書「Webページの配信」「D1テーブル設計 > web_handoffs」。
-- 拡張機能のセッションで作る、1分だけ使える使い捨てのコード。コードは SHA-256 だけを置く。
-- 替えたら used_at を入れる。元のセッション（session_id）が無効になっていれば替えない。
CREATE TABLE web_handoffs (
  code_hash TEXT PRIMARY KEY,
  member_id TEXT NOT NULL REFERENCES members (id),
  session_id TEXT NOT NULL REFERENCES sessions (id),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER
);
