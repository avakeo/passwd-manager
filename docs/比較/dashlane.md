# Dashlane との比較

- 日付：2026-11-03
- 比べた資料：Dashlane のセキュリティの資料（Security at a Glance、セキュリティのページ）、論文「Zero Knowledge (About) Encryption」（USENIX Security 2026、以下「論文」）

## 1. 仕組みの比較

| 項目 | teampw | Dashlane |
|---|---|---|
| 鍵の導出 | PBKDF2-HMAC-SHA256 60万回 | Argon2d（3回、32MB、2スレッド） |
| アイテムの暗号 | AES-256-GCM | AES-256-CBC ＋ HMAC |
| 新しい端末 | Discord と TOTP でログインし、マスターパスワードで鍵を開く | 端末ごとの鍵を作り、メールなどで確かめる。パスワードなしの場合は、既存の端末と Curve25519 で組にする |
| 共有の鍵の受け渡し | HPKE（P-256）＋ 管理者署名 | 共有の鍵を、受け手の RSA 公開鍵で包む |
| 相手の公開鍵 | 双方向の照合と固定 | 確かめない（論文 DL02） |

## 2. 論文の攻撃（6件）

| 論文 | 中身 | teampw では |
|---|---|---|
| DL01 Transaction Replay | アイテムの暗号に使う鍵がアイテムごとに違わないので、サーバーが変更を繰り返したり、並べ替えたり、捨てたりできる | 一部は当てはまる。AAD にアイテム ID とリビジョンがあるので、ほかのアイテムへの移し替えと、古い暗号文を今の版として置くことは防ぐ（S-11）。ただし、変更を捨てる（返さない）ことは防げず、Vault リビジョンの巻き戻しの検知（S-09、S-12）にとどまる |
| DL02 Sharing Key Overwrite | 共有のとき、サーバーが偽の受け手の公開鍵を渡す | 当てはまらない（P-01） |
| DL03〜DL06 | CBC の形式を受け付けることを使い、アイテムを差し込む、反復回数を減らす、CBC だけの形式に下げる、鍵を推測する | 当てはまらない。AES-GCM の1形式だけで、未知の形式を拒否する（C-03、C-10） |

Dashlane は、報告を受けて、ブラウザ拡張機能の 6.2544.1（2025-11-05）で修正を出したと報じられている。

## 3. teampw のほうが弱い所

- **総当たりへの強さ**。Argon2d はメモリを多く使うので、GPU での総当たりに PBKDF2 より強い。teampw は WebCrypto に Argon2 がないため、PBKDF2 のまま。
- 監査、対応する環境、機能の多さ。

## 4. 学んだこと

- 新しい端末を足すとき、Dashlane は端末ごとの鍵と確認を求める。teampw は、Discord と TOTP とマスターパスワードがあれば、どの端末でも鍵を開ける。端末を限る仕組みは、teampw では「この端末を覚える」（7日）だけで、これは便利さのための例外であって、端末を限る守りではない。

## 出典

- Dashlane「Security」：https://www.dashlane.com/security
- Dashlane「Security at a Glance」（2026年3月版）：https://www.dashlane.com/uploads/2026/01/Security-at-a-Glance-Two-Pager_Updated-March-2026.pdf
- 論文：https://www.usenix.org/conference/usenixsecurity26/presentation/scarlata 、https://eprint.iacr.org/2026/058
- 修正の版の報道：https://cyberinsider.com/popular-password-managers-fall-short-of-zero-knowledge-claims/
