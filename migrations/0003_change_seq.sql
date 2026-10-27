-- フェーズ2b：差分同期のカーソル。仕様書「D1テーブル設計 > items」「同期」。
-- 書いたときの Vault リビジョン。作成・更新・削除で Vault リビジョンを1増やす同じバッチで付けるので、抜けも重なりもない。
-- 更新日時（ミリ秒）で取ると、同じミリ秒に書かれた2件の片方を取りこぼしうる。

ALTER TABLE items ADD COLUMN change_seq INTEGER;
-- 前からある行は、今の Vault リビジョンにする（次の同期で、どの端末も取り直す）
UPDATE items SET change_seq = (SELECT vault_revision FROM vault_meta WHERE id = 1);
CREATE INDEX items_change_seq ON items (change_seq);
