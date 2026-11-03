# Proton Pass との比較

- 日付：2026-11-03
- 比べた資料：Proton のブログ「Proton Pass security model」、Key Transparency のサポート記事とホワイトペーパー
- 論文「Zero Knowledge (About) Encryption」（USENIX Security 2026）の対象には入っていない

## 1. 仕組みの比較

| 項目 | teampw | Proton Pass |
|---|---|---|
| 利用者の鍵 | P-256 の ECDH 鍵（と管理者の署名鍵）。マスターパスワードから作ったラップ鍵で包む | Proton アカウントの非対称鍵（OpenPGP） |
| Vault の鍵 | チームに1つ。世代を持つ | Vault ごとに32バイトの乱数。利用者の鍵で暗号化し、署名する |
| アイテムの暗号 | Vault 鍵で AES-256-GCM | アイテムごとに32バイトの鍵を作り、アイテムをその鍵で、アイテムの鍵を Vault の鍵で、どちらも AES-256-GCM で暗号化する |
| 共有 | 管理者がグラントを作り、ECDSA で署名する。受け手は固定した管理者の署名用公開鍵で確かめる | 招待する人が Vault の鍵を受け手向けに暗号化し、署名する。受け手は、招待した人のアドレスの鍵で署名を確かめる |
| 相手の公開鍵 | 双方向の照合と固定 | Proton が動かす鍵サーバーから取る。Key Transparency（公開鍵の記録を監査できる形で残す仕組み）は、Proton Mail の Web 版でベータ。Proton Pass で使っているかは確かめられなかった |

## 2. 似ている所

- **共有に署名を付ける**。teampw のグラントへの管理者署名と同じ考えで、「誰が包んだか」を受け手が確かめる。HPKE の Base モードや RSA で包むだけでは送り手が分からない、という問題への同じ答え。

## 3. 違う所

| 項目 | teampw | Proton Pass |
|---|---|---|
| 公開鍵の真正性の根拠 | 人が Discord 以外の経路で見比べること | Proton の鍵サーバー（と、使える所では Key Transparency） |
| 照合の手間 | メンバーを足すたびに、対面などで見比べる | 利用者の手間はない |
| サーバーが偽の鍵を渡したとき | 照合をしていれば気づける。照合を省いた人は気づけない | Key Transparency がなければ気づけない。あれば、記録と食い違うことに後から気づける |

## 4. teampw のほうが弱い所

- 監査、対応する環境（Proton Pass は主要なブラウザとスマートフォン）、機能の多さ。
- アイテムごとの鍵がない。Vault 鍵が1つなので、アイテムどうしの区別は AAD に頼る。

## 5. 取り入れる候補

| 候補 | 理由 | 注意 |
|---|---|---|
| 公開鍵の記録を、後から監査できる形で残す | 照合を省いた人も、後から差し替えに気づける | 小さなチームでは、照合のほうが手間に見合う。大きくなったときの候補 |

## 出典

- Proton「Proton Pass security model」：https://proton.me/blog/proton-pass-security-model
- Proton「Key Transparency」：https://proton.me/support/key-transparency
- Proton Key Transparency whitepaper：https://proton.me/files/proton_keytransparency_whitepaper.pdf
