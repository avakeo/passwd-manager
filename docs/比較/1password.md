# 1Password との比較

- 日付：2026-11-03
- 比べた資料：1Password Security Design White Paper、1Password のサポート記事
- 論文「Zero Knowledge (About) Encryption」（USENIX Security 2026）の対象には入っていない

## 1. 仕組みの比較

| 項目 | teampw | 1Password |
|---|---|---|
| 鍵の導出 | マスターパスワードだけ。PBKDF2-HMAC-SHA256 60万回 | アカウントパスワードと Secret Key（128ビットの乱数。端末で作り、サーバーに送らない）を混ぜる。PBKDF2-HMAC-SHA256 65万回（2SKD） |
| ログイン | Discord ＋ TOTP | SRP。パスワードを送らずに、サーバーと端末がお互いを確かめる |
| アイテムの暗号 | AES-256-GCM、1件を1つの暗号文 | AES-256-GCM |
| 共有の鍵の受け渡し | HPKE（P-256）＋ 管理者署名 | Vault の鍵を、メンバーの RSA-OAEP の公開鍵で包む |
| 相手の公開鍵 | 双方向の照合と固定 | 確かめない。ホワイトペーパーの付録「Beware of the Leopard」に「No public key verification」として、サーバーが公開鍵を差し替えられる点を書いている |
| 回復 | なし | 管理者などの回復グループが、メンバーの鍵を包み直せる |
| サーバー | Cloudflare Workers ＋ D1 | 1Password のクラウド。サーバーのコードは非公開 |

## 2. teampw のほうが弱い所

- D1 が漏れたときの総当たり。1Password は、サーバーのデータだけでは Secret Key の128ビットが分からないので、パスワードの総当たりが実質できない。teampw は、D1 の暗号文と KDF の設定があれば、マスターパスワードの総当たりを始められる。守りは PBKDF2 の60万回だけ。比べた製品の中で、この差がいちばん大きい。
- 回復の手段。1Password には回復グループがある。teampw は、マスターパスワードを忘れたら、新しい鍵を作って管理者に包み直してもらうしかない。
- 監査、対応する環境、機能。Bitwarden との比較（[bitwarden.md](bitwarden.md) の3章）と同じ。

## 3. teampw のほうが強い、または違う所

- 公開鍵の差し替え。1Password は、ホワイトペーパーで、公開鍵を確かめないことを既知の弱点として書いている。teampw は照合と固定でこれを防ぐ（P-01、P-06）。
- 回復グループを持たない。回復は便利だが、論文が Bitwarden（BW01〜BW03）と LastPass（LP01）で示したように、鍵を預ける先の公開鍵を偽られる穴になりうる。teampw は機能がないので、この穴もない。1Password の回復の仕組みが同じ攻撃に強いかは、公開資料からは確かめられなかった。

## 4. 取り入れる候補

| 候補 | 理由 | 注意 |
|---|---|---|
| Secret Key のような、端末に置く秘密を鍵の導出に混ぜる | D1 が漏れたときの総当たりを、実質できなくする | 新しい端末を足すたびに、Secret Key を手で移す必要がある。フェーズ4の「2台目の端末」の手順と、鍵の形式（KDF の種類）が変わる。今の「マスターパスワードだけで鍵の鎖をたどれる」という前提を変えるので、仕様書の大きな変更になる |

## 出典

- 1Password Security Design White Paper：https://1password.com/files/1password-white-paper.pdf
- 1Password「About the 1Password security model」：https://support.1password.com/1password-security/
- 1Password「How 1Password uses end-to-end encryption」：https://support.1password.com/end-to-end-encryption/
- 1Password「About your Secret Key」：https://support.1password.com/secret-key-security/
