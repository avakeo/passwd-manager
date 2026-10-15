# 手順1 共通の土台：レビュー資料

## 変更したファイル

| ファイル | 中身 |
|---|---|
| src/crypto/bytes.ts | バイト列と文字列の変換（UTF-8、16進、base64url、I2OSP）、比較、0での上書き |
| src/crypto/random.ts | 乱数（getRandomValues だけ）と、アイテムID・鍵IDの生成 |
| src/crypto/errors.ts | エラーの種類。復号の失敗は DECRYPT_FAILED の1つにまとめる |
| src/crypto/format.ts | 形式とアルゴリズムIDのヘッダー、ID の検査、AAD の組み立て |
| tests/crypto/format.test.ts | C-10 と、変換・ID・AAD の確認 |

## 対応する仕様の節

- 暗号仕様 > 共通の規則（保存形式のバイトの並び、アルゴリズムIDの表、形式の照合、IDの作り方）
- 暗号仕様 > アイテムの暗号化（AAD `v1|item|ID|世代`）
- 暗号仕様 > メンバー鍵ペア（AAD `v1|member-key|鍵ID`）

## テスト ID

| ID | テスト |
|---|---|
| C-10 | 未知の形式バージョン、未知のアルゴリズムID、使う所が違うアルゴリズムID、短すぎるデータを、それぞれ拒否する |

## 観点表で見てほしい所

| 観点 | 見てほしい所 |
|---|---|
| 乱数 | `randomBytes` だけが getRandomValues を呼ぶ。src に Math.random がないことは、手順6の検査テストでも確かめる |
| AAD | ID を `[A-Za-z0-9_-]{1,64}` に限り、`|` の区切りが曖昧にならないようにした。世代は1以上の整数だけ受け付ける |
| エラー | 形式の拒否（UNSUPPORTED_FORMAT、MALFORMED）は秘密に依存しない情報なので、復号の失敗とは分けた。分けてよいかを確認してほしい |
| 形式の照合 | `checkHeader` は、復号を試す前に形式バイトが 0x01（AAD の `v1`）であることを確かめる。今は v1 しかないので、照合は「0x01 であること」と同じ |
