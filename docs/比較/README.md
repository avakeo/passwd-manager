# ほかのパスワードマネージャーとの比較

- 日付：2026-11-03
- 対象：teampw（このリポジトリ）と、Bitwarden、1Password、LastPass、Dashlane、Proton Pass、KeePassXC
- 調べ方：各社の公開資料（ホワイトペーパー、ヘルプ）と、ETH Zurich などの論文「Zero Knowledge (About) Encryption」（USENIX Security 2026）を読んだ。製品を動かして確かめてはいない
- 読み方の注意：各製品は日々変わる。ここに書いた内容は、上の日付の時点で公開資料から読み取れた範囲にとどまる。確かめられなかった点は「確かめられなかった」と書いた

## ファイル

| ファイル | 中身 |
|---|---|
| [bitwarden.md](bitwarden.md) | Bitwarden との詳しい比較。論文の Bitwarden への攻撃12件を、teampw の設計に当てはめた |
| [1password.md](1password.md) | 1Password。Secret Key（2SKD）と、公開鍵を確かめない点 |
| [lastpass.md](lastpass.md) | LastPass。2022年の漏えいと、論文の攻撃7件 |
| [dashlane.md](dashlane.md) | Dashlane。Argon2d と、論文の攻撃6件 |
| [proton-pass.md](proton-pass.md) | Proton Pass。署名付きの共有と Key Transparency |
| [keepassxc.md](keepassxc.md) | KeePassXC。サーバーを持たない方式 |

## まとめの表

teampw は学習用で、監査を受けておらず、利用者もいない。下の表は設計の違いを並べたもので、製品としての優劣を示すものではない。

| 項目 | teampw | Bitwarden | 1Password | LastPass | Dashlane | Proton Pass | KeePassXC |
|---|---|---|---|---|---|---|---|
| 鍵の導出 | PBKDF2-SHA256 60万回 | PBKDF2-SHA256 60万回 か Argon2id | PBKDF2-SHA256 65万回 ＋ Secret Key | PBKDF2-SHA256 60万回 | Argon2d | bcrypt（Proton アカウントのパスワードから鍵のパスフレーズを作る） | Argon2id か AES-KDF |
| アイテムの暗号 | AES-256-GCM、1件を1つの暗号文に | AES-256-CBC ＋ HMAC、欄ごと | AES-256-GCM | AES-256-CBC（認証なし）、欄ごと | AES-256-CBC ＋ HMAC | AES-256-GCM、アイテムごとの鍵 | ファイル全体を AES-256 か ChaCha20 |
| 共有の鍵の受け渡し | HPKE（P-256）＋ 管理者署名 | RSA-OAEP | RSA-OAEP | RSA | RSA | OpenPGP ＋ 署名 | 共有なし（ファイルを渡す） |
| 相手の公開鍵の確かめ方 | 必須の双方向の照合 ＋ 固定 | 承認のときにフィンガープリントを見せる（省ける） | 確かめない（ホワイトペーパーに明記） | 確かめない | 確かめない | Proton の鍵サーバー（Key Transparency は Mail の Web 版でベータ） | 該当なし |
| メンバーを外した後 | Vault 鍵を作り直して全件を包み直す | 組織の鍵を作り直す機能がない（2024年の時点） | 確かめられなかった | 確かめられなかった | 確かめられなかった | 確かめられなかった | マスターキーを変える（古い写しは残る） |
| 悪意あるサーバーの論文 | 対象外 | 12件 | 対象外 | 7件 | 6件 | 対象外 | 対象外（サーバーなし） |
| 監査・実績 | なし | あり | あり | あり | あり | あり | あり |

## 全体を通して分かったこと

1. **teampw の設計で一番違うのは、公開鍵の真正性の扱い**。論文の攻撃の多くは、「サーバーが渡す公開鍵や組織の鍵を、クライアントが確かめない」ことが原因だった。論文は、すぐ打てる対策として「対面などで確かめた公開鍵を保存しておく」ことを挙げている。teampw は、この形（双方向の照合と固定）と、グラントへの管理者署名を最初から入れている。
2. **teampw のほうが弱い所もはっきりある**。D1 が漏れたときのマスターパスワードの総当たりへの強さは、1Password（Secret Key）と Dashlane・Bitwarden（Argon2）に劣る。監査、利用者の数、対応する環境（Windows 版 Chrome だけ）、権限の細かさ（全員が全件を見る）も、どの製品にも及ばない。
3. **機能を絞ったから守れている面がある**。アカウントの回復（鍵の預け先）、緊急アクセス、複数の組織、古い暗号形式の読み込みを持たないので、論文の「鍵の預け先」「後方互換」の攻撃が当てはまらない。同じ機能を足すときは、同じ穴を作らない設計が要る。

## 取り入れる候補

ここでは候補を並べるだけにする。採用するかは本人が決める。採用するときは、仕様書に日付つきで追記する。

| 候補 | 出どころ | 理由 |
|---|---|---|
| マスターパスワードに加えて、端末に置く秘密（Secret Key のようなもの）を鍵の導出に混ぜる | 1Password | D1 が漏れても、マスターパスワードだけでは総当たりできなくなる。代わりに、2台目の端末への持ち運びが増える |
| Argon2id への移行 | Bitwarden、Dashlane、KeePassXC | WebCrypto に Argon2 がないので、今の「依存なし・WebCrypto だけ」の方針と衝突する。仕様書は移行できる形にしてある |
| 公開鍵の記録を監査できる形で公開する（Key Transparency） | Proton | 照合を省いた人も、後から差し替えに気づける。規模に見合うかは別に考える |

## 出典

- Scarlata, Torrisi, Backendal, Paterson「Zero Knowledge (About) Encryption: A Comparative Security Analysis of Three Cloud-based Password Managers」USENIX Security 2026：https://www.usenix.org/conference/usenixsecurity26/presentation/scarlata （全文：https://eprint.iacr.org/2026/058 ）
- 各製品の出典は、それぞれのファイルの末尾に書いた
