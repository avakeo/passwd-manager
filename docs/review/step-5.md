# 手順5 A-2 と A-3 後半 グラント（HPKE Base）：レビュー資料

## 変更したファイル

| ファイル | 中身 |
|---|---|
| src/crypto/hkdf.ts | HKDF の Extract と Expand を、WebCrypto の HMAC-SHA256 で RFC 5869 どおりに組む |
| src/crypto/hpke-core.ts | RFC 9180 の DHKEM(P-256, HKDF-SHA256)、LabeledExtract/LabeledExpand、鍵スケジュール、文脈（シーケンス番号からノンスを作る） |
| src/crypto/hpke.ts | 本番の入口。使い捨て鍵ペアを必ず内部で生成し（秘密側は取り出し不可）、AEAD 0x0002 で1回だけ暗号化する |
| src/crypto/public-key.ts | サーバーから来た公開鍵を読み込む。非圧縮形式の65バイトだけを受け付け、曲線上かどうかの検査は WebCrypto に任せる |
| src/crypto/grant.ts | グラントの作成（sealGrant）、開封（openGrant：取り出し不可）、管理操作用の開封（openGrantForAdmin：生の32バイト） |
| scripts/fetch-vectors.ts | HPKE のテストベクタを、コミットとハッシュを固定して取得する |
| tests/vectors/ | Wycheproof の ECDH P-256（Apache-2.0、LICENSE 付き）、HPKE の1件、出典・ライセンスの README |
| tests/crypto/hpke.test.ts | C-15、C-01（自前の Extract/Expand） |
| tests/crypto/grant.test.ts | C-13、C-06、C-03（グラント）、C-10（グラント）、C-16（Vault 鍵） |
| tests/crypto/ecdh.test.ts | C-12 |

## 対応する仕様の節

- 暗号仕様 > Vault鍵の受け渡し（RFC 9180 Base、info と aad、ノンスは鍵スケジュールから、Extract/Expand の組み方、使い捨て秘密鍵の扱い）
- 暗号仕様 > 共通の規則（グラントの保存形式、アルゴリズムID 0x02）
- 鍵のライフサイクル（Vault 鍵の通常利用は取り出し不可、管理操作だけ取り出し可として開き直す、使い捨て鍵ペアは破棄）

## テスト ID

| ID | テスト |
|---|---|
| C-15 | CFRG の test-vectors.json の Base モード、KEM 0x0010・KDF 0x0001・AEAD 0x0002 の1件（tests/vectors/hpke に置いた。2026-10-16 までは付録 A.3 の組も取得して確かめていた）。enc、shared_secret、key_schedule_context、secret、key、base_nonce と、257件の暗号文を、送り手と受け手の両方で照合する |
| C-01 | 自前の Extract と Expand に、RFC 5869 付録 A.1、A.3 の PRK と OKM を当てる |
| C-13 | 管理者が Vault 鍵でアイテムを暗号化し、C さん宛てのグラントを作る。C さんがマスターパスワードで秘密鍵を開け、グラントを開いてアイテムを復号する |
| C-06 | B さんが C さん宛てのグラントを開けない。作った管理者自身も開けない |
| C-12 | Wycheproof の invalid 24件（曲線上にない点、壊れたエンコード、ねじれ曲線上の点）を拒否する。valid 330件は共有秘密が一致する。不正な公開鍵を宛先にしたグラントは作らない |

## 結果

C-15 は、本番と同じ組（KEM 0x0010・KDF 0x0001・AEAD 0x0002）の公開テストベクタと一致した。仕様書の条件（この組で確かめた場合だけ「RFC 9180 準拠」と書く）を満たす。

## 観点表で見てほしい所

| 観点 | 見てほしい所 |
|---|---|
| ノンス | グラントは乱数のノンスを持たない。`HpkeContext` が base_nonce XOR シーケンス番号でノンスを作る。本番の `sealBase` は文脈ごとに1回だけ暗号化する |
| テスト用の口 | 使い捨て鍵ペアを引数で受け取る `setupBaseSWithEphemeral` は hpke-core.ts にある。src の中で hpke-core.ts を import するのは hpke.ts だけで、hpke.ts は必ず鍵ペアを生成してから呼ぶ。この制限は手順6の検査テストで確かめる。テストと本番が同じ関数を通るので、ベクタで確かめた処理がそのまま本番の処理になる |
| HKDF のラベル | HPKE の内部ラベルは RFC どおり `HPKE-v1` ＋ suite_id ＋ ラベル。info は `teampw/v1/vault-key-grant|世代|鍵ID` |
| 取り出し不可 | `openGrant` は取り出し不可の Vault 鍵を返す。生の32バイトを返すのは、管理操作用の `openGrantForAdmin` だけ。使い捨ての秘密鍵は取り出し不可で生成する |
| エラー | 不正な enc、別の宛先、改ざん、世代の書き換えは、どれも DECRYPT_FAILED にまとめる |
| 公開鍵の検査 | 圧縮形式（Wycheproof の acceptable）も拒否している。非圧縮だけを受け付ける方針 |
| info | 開くときの info は、グラントの行の recipientKeyId ではなく、自分の鍵IDから作る。行の宛先が自分の鍵IDと違えば、復号を試す前に失敗にする |
| 順番 | この手順では、本体をテストより先に書いてしまった（ほかの手順はテストが先）。テストはコミットの前に書き、全部通ってからコミットしている。履歴は書き換えず、代わりに末尾の節で、実装をわざと壊してテストが落ちることを確かめた |
| テストベクタ | 2026-10-16 の決定で、本番の組の1件だけを tests/vectors/hpke に置いた。ライセンスの扱いは tests/vectors/README.md |

## テストを後から書いたことの記録と、わざと壊して確かめた結果（2026-10-16）

この手順では、本体（hkdf.ts、hpke-core.ts、hpke.ts、public-key.ts、grant.ts）をテストより先に書いた。コミット e110c8c と f15eca6 は、テストを書いて全部通ってから作ったが、「テストを先に書く」という進め方は守れていない。履歴は書き換えず、ここに記録する。

その代わりに、テストが本当に実装の誤りを捕まえるかを確かめた。手順5の実装を1か所ずつわざと壊し、C-13（暗号コアだけのもの、API 経由のもの）と C-15 を実行した。壊すたびに `git checkout` で元に戻し、作業ツリーに差分が残っていないことを確かめている。

| # | 壊し方 | C-13 | C-13（API 経由） | C-15 | ほかに落ちたテスト |
|---|---|---|---|---|---|
| — | 壊す前 | 通る | 通る | 通る | なし |
| M1 | grant.ts：開く側の info の世代を1ずらす（送り手と受け手で info が食い違う） | **落ちる** | **落ちる** | 通る | C-16（グラント）、管理操作で包み直すテスト |
| M2 | grant.ts：info のラベルを1文字変える（vault-key-grant → vault-key-grans。送り手と受け手の両方） | 通る | 通る | 通る | 「info は teampw/v1/vault-key-grant\|世代\|宛先の鍵ID」 |
| M3 | hpke-core.ts：鍵スケジュールのノンスをずらす（シーケンス番号に1を足す） | 通る | 通る | **落ちる** | なし |
| M4 | hpke-core.ts：鍵スケジュールのラベル key を kex に変える | 通る | 通る | **落ちる** | なし |
| M5 | hpke-core.ts：受け手の kem_context から自分の公開鍵 pkRm を抜く | **落ちる** | **落ちる** | **落ちる** | C-16（グラント）、管理操作で包み直すテスト、sealBase のテスト |
| — | 元に戻した後 | 通る | 通る | 通る | なし |

### 分かったこと

- **C-13 は往復のテスト**なので、送り手と受け手の食い違い（M1、M5）は捕まえるが、両側を同じように変えた誤り（M2、M3、M4）は捕まえない。自分の実装どうしでは、往復が成り立ってしまうため。
- **RFC 9180 からのずれ（M3、M4、M5）は C-15 が捕まえる**。公開テストベクタは、ほかの実装と同じ値になることを求めるので、両側を同じように変えても落ちる。
- **info の形の誤り（M2）は C-13 でも C-15 でも捕まらない**。info はこのプロジェクト独自の値で、公開ベクタには出てこないため。単体テスト「info は teampw/v1/vault-key-grant|世代|宛先の鍵ID」だけが捕まえる。ほかの実装（将来の拡張機能など）と互換性を保つには、この単体テストが必要。
