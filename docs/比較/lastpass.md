# LastPass との比較

- 日付：2026-11-03
- 比べた資料：論文「Zero Knowledge (About) Encryption」（USENIX Security 2026、以下「論文」）、2022年の漏えいについての報道と解説
- 選んだ理由：2022年に Vault のバックアップが盗まれ、「サーバーが漏れたら何が起きるか」が実際に起きた例になった

## 1. 2022年の漏えいで分かったこと

攻撃者は、利用者の Vault のバックアップを盗んだ。中身は暗号化されていたが、次の点が問題になった。

| 問題 | 中身 | teampw では |
|---|---|---|
| URL が平文だった | どの利用者がどのサイトにアカウントを持つかが、復号しなくても分かった（その後、URL も暗号化した） | URL はアイテムの JSON の中にあり、1つの暗号文になっている。D1 から分かるのは、アイテムの数、ID、日時、作った人、暗号文の長さ（5段階）まで |
| 古いアカウントの反復回数が少なかった | 作った時期によって、PBKDF2 の回数が今の既定より少ないまま残っていた（その後、60万回に上げた） | クライアントが60万回の下限を持ち、それより少ない設定を拒否する（C-14） |

## 2. 論文の攻撃（7件）

| 論文 | 中身 | teampw では |
|---|---|---|
| LP01 Malicious Password Reset | 管理者による回復のために、サーバーが返す管理者の公開鍵で利用者の鍵を包む。公開鍵を確かめないので、偽の鍵を渡せる | 当てはまらない。回復の機能がない |
| LP02 Item Field Swapping | 欄の暗号文を入れ替える | 当てはまらない。1件を1つの暗号文にし、AAD にアイテム ID がある（C-04） |
| LP03 Icon URL Item Decryption | 暗号文を URL の欄に移し、アイコンの取得で平文を送らせる | 当てはまらない |
| LP04 Remove KDF Iterations | 反復回数を減らして返す | 当てはまらない（C-14） |
| LP05 Malleable Vault | 認証のない AES-CBC なので、暗号文を書き換えられる | 当てはまらない。AES-GCM の認証タグ（C-03） |
| LP06 Unprotected Item Metadata | 暗号化していない項目を読み書きされる | 一部は当てはまる（[bitwarden.md](bitwarden.md) の BW04 と同じ） |
| LP07 Sharing Key Overwrite | 共有フォルダーの鍵を包むときに、サーバーが偽の受け手の公開鍵を渡す。画面で確かめる手段もない | 当てはまらない。照合と固定（P-01） |

## 3. teampw のほうが弱い所

- 監査、利用者の数、対応する環境、機能の多さ。総当たりへの強さは同じ PBKDF2 60万回で、差はない。

## 4. 学んだこと

- 「暗号化している」と言えても、暗号化していない項目（URL など）や、古い設定のまま残ったアカウントから漏れる。teampw では、平文で置く項目を [データ一覧.md](../データ一覧.md) にまとめ、KDF の下限をクライアントに持たせている。新しい項目を D1 に足すときも、平文で置いてよいかを同じ表で確かめる。

## 出典

- 論文：https://www.usenix.org/conference/usenixsecurity26/presentation/scarlata 、https://eprint.iacr.org/2026/058
- Wladimir Palant「What's in a PR statement: LastPass breach explained」（2022-12-26）：https://palant.info/2022/12/26/whats-in-a-pr-statement-lastpass-breach-explained/
