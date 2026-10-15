# 手順3 A-1 鍵を作る：レビュー資料

## 変更したファイル

| ファイル | 中身 |
|---|---|
| src/crypto/kdf.ts | KDF パラメータの生成と検査、PBKDF2 → HKDF でラップ鍵を作る |
| src/crypto/member-key.ts | P-256 の鍵ペアを生成し、秘密鍵（PKCS#8）を AAD 付きで暗号化する |
| tests/crypto/kdf.test.ts | C-01（PBKDF2、HKDF、AES-GCM の公開ベクタ）、C-14、A-1 の出力の形 |

## 対応する仕様の節

- 暗号仕様 > 鍵導出（KDF）：PBKDF2-HMAC-SHA256、60万回以上、ソルトは乱数16バイト、クライアントで下限を確かめる
- 暗号仕様 > 用途別の鍵：HKDF のソルトは空、info は teampw/v1/private-key-wrap
- 暗号仕様 > メンバー鍵ペア：秘密鍵の AAD は v1|member-key|鍵ID。鍵IDはクライアントで作る
- 鍵のライフサイクル：秘密鍵は生成時だけ取り出し可。PKCS#8 で書き出したら、取り出し不可で読み込み直す

## テスト ID

| ID | テスト |
|---|---|
| C-01 | PBKDF2-HMAC-SHA256（RFC 7914 §11 の2件）、HKDF-SHA256（RFC 5869 付録 A.1、A.3）、AES-256-GCM（GCM 仕様の Test Case 16）。自前で組む HKDF の Extract と Expand には、手順5で同じ RFC 5869 のベクタを当てる |
| C-14 | 反復回数が599,999回以下、整数でない、NaN、種類が違う、ソルトが16バイトでない、をそれぞれ拒否する。PBKDF2 を計算する前に拒否する |

## 観点表で見てほしい所

| 観点 | 見てほしい所 |
|---|---|
| KDF の下限 | `deriveWrapKey` は、最初に `assertKdfParams` を呼ぶ。上限（1,000万回）は仕様にないが、サーバーが巨大な値を返して端末を止める攻撃を防ぐために足した |
| HKDF のラベル | ラップ鍵の info は `teampw/v1/private-key-wrap` だけ。HPKE の内部ラベルは `HPKE-v1` で始まるので重ならない |
| 取り出し不可 | `generateKey` は PKCS#8 で書き出すために取り出し可で作る。返す秘密鍵は、取り出し不可で読み込み直したもの。生成直後の取り出し可の鍵オブジェクトは関数の外に出さない |
| 乱数 | ソルトと鍵IDは `randomBytes` から作る。鍵ペアは WebCrypto の generateKey が作る |
| メモリ | パスワードの UTF-8、マスターキー、PKCS#8 は使ったら0で上書きする（JavaScript では努力目標） |
| 未決定 | マスターパスワードの Unicode 正規化（docs/判断待ち.md の1）。今は正規化しない |
