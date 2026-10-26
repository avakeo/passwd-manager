# 攻撃者の目線レビュー：アイテム、同期、409、クイックロック解除（フェーズ2b）

- 日付：2026-10-27
- 対象：ブランチ feat/extension-items（origin/feat/extension-items、30d1e81）の `git diff origin/main...origin/feat/extension-items` のうち `src/`・`migrations/`・`tests/`。5a61be1（更新の 409 を世代で分ける）を含む
- 参照：docs/review/phase-2b.md、docs/実装状況.md の10章、docs/仕様書.md（「データの置き場所とバックアップ > 同期」「拡張機能と自動入力の方針 > ロックと鍵の置き場所」「クイックロック解除」、S-01・S-02・S-09・S-10、E-11・E-14〜E-18、I-01〜I-03、A-5）、docs/review/phase-2a_deepseek.md の文体
- 前提：攻撃者は、利用者に開かせる Web ページを自由に作れる。盗んだトークンで API を直接叩ける。サーバー（Workers・D1）の応答を書き換えられる（巻き戻し、古い Vault リビジョン、別の世代のグラント、409 の本文）。`chrome.storage.session` を読める場合は4桁パスコードの総当たりが成立する（受け入れ済み）。このレビューでは、その延長として過去の `storage.session` のスナップショットを戻せる場合も見た（5回制限と世代の扱いの確認のため）。別の拡張機能の `webRequest`・`debugger`、OS の掌握、マスターパスワードの漏洩は範囲外
- 見たファイル：`src/extension/background/{background,messages,storage,api-client}.ts`、`src/extension/page/{app,items}.ts`、`src/extension/popup/popup.ts`、`src/crypto/{quick-unlock,format,grant,kdf,item}.ts`、`src/api/{app,key-routes}.ts`、`migrations/0003_change_seq.sql`、`tests/extension/{background,items,quick-unlock,build}.test.ts`、`tests/crypto/{quick-unlock,signature,trust}.test.ts`、`tests/helpers/{extension-world,api,fake-chrome}.ts`
- この文書は「どこが・なぜ危ないか」だけを示す。直し方は書かない
- `docs/review/phase-2b_self-check.md` は、この文書を書く前に読んでいない
- 実測：このブランチで `npm test` 420件すべて成功、`npm run typecheck` 成功。以下の「実測」は、リポジトリの外に置いた一時テストから、実コードと本物の API（`app.request` ＋ SQLite）に対して実行して確認した（実測して確認済み）。未実行のものは「推測」と書いた

## 結論

2b の土台は、**アイテムの AAD（アイテム ID・世代）**、**双方向の公開鍵の固定**、**クイックロック解除の5回制限**が効いており、指定された狙いのうち「別アイテムへの暗号文の差し替え」「Web ページからのメッセージ」「HTML としての解釈」「5回制限の同時・再起動での迂回」は成立しない。5a61be1 の 409 の修正も、サーバーが正直に今の世代を返す場合は効いている（実測）。

残る重い穴は3つに分かれる。

1. **アイテムの完全性**：古い暗号文を「今の版」として受け取る。とくに、**盗んだトークンだけ**で、以前に控えた暗号文を今のリビジョンで送り直せば、サーバーは 200 で受け付け、ほかの端末は古いパスワードを新しい版として表示する（#1、高）。仕様はアイテムのロールバック防止を範囲外として「検知のみ」とするが、この実装にはアイテム単位の検知の口がない。
2. **ロックのすり抜け**：復号や失敗回数のリセットの途中でロックすると、`quickUnlock` が Vault 鍵をメモリに戻し（#3）、`getItem` がロック後に平文を返す（#4）。どちらも「終わった時点でロックを確かめる」という 2a からの約束の抜けである。
3. **同期の状態**：応答の `change_seq` と `vault_revision` をそのまま保存するため、大きな値で同期が黙って止まる（#6）か、以後ずっと巻き戻し扱いになる（#7）。重なった同期は、古い応答で新しいキャッシュと「最後に見た Vault リビジョン」を巻き戻す（#2）。パスコード解除は、端末が最後に見た世代を見ないので、古い世代の保存で復帰できる（#5）。

平文そのものが攻撃者に渡るのは、マスターパスワードかパスコードを得た場合（受け入れ済み）に限られる。ただし #1 は、鍵なしで「古いパスワードを使わせる」ことができる点で、単なる可用性ではなく完全性の問題である。#3・#4 はロックの意味を弱め、#5 はローテーション後の巻き戻し検知を弱める。

## 指摘一覧

| 番号 | 重大度 | 攻撃の手順 | 狙われる箇所 | 再現テストの内容 |
|---|---|---|---|---|
| 1 | 高 | ①攻撃者は、盗んだトークンで `GET /v1/items` を定期的に読み、各アイテムの暗号文を控えておく。②利用者がそのアイテムのパスワードを変更する。③攻撃者は `GET /v1/items` で今の `revision` を取り、控えておいた古い暗号文を `PUT /v1/items/<id>` に `{revision: 今の値, vault_key_version: 今の世代, ciphertext: 古い暗号文}` で送る。④サーバーは暗号文を不透明なまま受け付け、`revision` を1増やして 200 を返す。⑤ほかの端末の差分同期は、それを「新しい版」として受け取り、復号して古いパスワードを表示する。AAD は形式・アイテム ID・世代だけで、リビジョンを見ないので、復号は成功する。⑥サーバー自身が `GET /v1/items` の応答を、古い暗号文＋今の `revision`・`change_seq` に書き換えても同じことが起きる。利用者には「更新された」ように見え、警告は出ない | `src/api/app.ts` `PUT /v1/items/:id`・`writeItem`（暗号文を不透明なまま受理し、リビジョンだけを進める）、`src/crypto/format.ts` `itemAad`（AAD は形式・アイテム ID・世代だけで、リビジョンや更新時刻を含まない）、`src/extension/background/background.ts` `sync`・`putEntry`（アイテムごとのリビジョンの単調性も見ない） | 実測して確認済み（2通り）。(a) 「古いパスワード」で保存→同期→暗号文 c1 を控える→「新しいパスワード」で更新（revision 2）→盗んだトークンで `GET /v1/items`（revision 2）→`PUT` に c1 と revision 2 を送る→**200・revision 3**→client が同期→`getItem` が「古いパスワード」、revision 3。(b) 応答の `GET /v1/items` を c1＋revision 2＋change_seq 2 に書き換える→同期→`getItem` が「古いパスワード」、キャッシュも revision 2 として保存。正直なサーバーに戻しても、カーソルが 2 なので再取得されない（次の書き込みまで直らない） |
| 2 | 中 | ①サーバーは、1回目の同期 A の `GET /v1/items` の応答を遅らせる。②その間に利用者がアイテムを保存し、保存後の同期 B が先に完了する。③遅らせていた A の古い応答が最後に適用され、`index` の新しい暗号文が古い暗号文に戻り、`cursor` と `lastVaultRevision` が古い値に下がる。④「最後に見た Vault リビジョンは下げない」という S-09 の前提が崩れ、次の巻き戻し検知の基準が低くなる | `background.ts` `sync`（`let maxSeq = cursor` を `await` の前に固定し、`lastVaultRevision = revision` を無条件に代入する。`putEntry` が復号で `await` する間に、別の同期が進める）、`putEntry` | 実測。`crypto.subtle.decrypt` をフックして最初の同期を復号の直前で止める→別の保存で revision 2「new」→さらに revision 3「newer」を保存して同期→止めていた同期を解放→`getItem` が「new」（revision 2）になり、キャッシュの `cursor` が 2、`lastVaultRevision` が 3 から 2 に下がった。次の同期で「newer」に戻るが、下がった基準は攻撃者が次の応答で利用できる |
| 3 | 中 | ①利用者がパスコードで戻る。②復号が終わり、失敗回数を0に戻す `storage.session` の読み書きを待たせている間に、`lock` を送る。③`lock` はメモリの鍵を消し、`lockEpoch` を進める。④待たせていた処理が再開し、`unlockedBy='passcode'`・`vaultKey=復号した鍵`・`vaultState='ready'` を、ロックの後に書き戻す。⑤`status` は `locked:false` を返し、一覧・取得ができる（保存も同じ Vault 鍵を使う経路）。利用者がロックした後も、鍵が残ったまま同じ画面からアイテムを読める | `background.ts` `quickUnlock`（成功後の `stillCurrent(epoch)` が、失敗回数のリセットを待つ `await serialized(...)` の**前**にあり、鍵の代入の後にもう一度確かめない）、`serialized` | 実測。`storage.session.get` の2回目（失敗回数のリセット）を止める→`quickUnlock` を送る→`lock` を送る→止めていた処理を解放→応答 `{ok:true, vault:'ready'}`、`memoryState()` が `{unlocked:false, vaultKey:true}`、`status` が `{locked:false, unlockedBy:'passcode'}`。E-11 の「ロック中は断る」に対する抜け |
| 4 | 中 | ①利用者がアイテムを開く（`getItem`）。②復号が終わった直後に `lock` を送る。③`getItem` は復号の後にロックを確かめず、そのまま平文（タイトル・パスワード・メモ）を画面へ返す。④ロック後も、画面には平文が残る。`saveItem`・`deleteItem` も、通信の後にロックを確かめず、ロック後に「成功」を返してキャッシュを書く（平文は返らない） | `background.ts` `getItem`（`openEntry` の後に `stillCurrent` がない）、`saveItem`・`deleteItem`（API の後に `stillCurrent` がない） | 実測。`crypto.subtle.decrypt` をフックして `getItem` を復号の直後で止める→`lock`→解放→応答が `ok:true` で `item.title='秘密'`、そのとき `memoryState()` は `{unlocked:false, vaultKey:false}`。仕様の「時間のかかる処理は、終わった時点でもロックを確かめ、ロックされていれば鍵を捨てる」に対する抜け |
| 5 | 中 | ①端末は世代1でクイックロック解除を設定する。②その後、端末は同期で世代2のグラントを開き、最後に見た世代を2にした（ロックはしていない）。Service Worker が停止しても、世代1のパスコード保存は `storage.session` に残る（ロックすると消えるが、攻撃者が古い `storage.session` のスナップショットを戻す場合も同じ）。③`quickUnlock` は保存の `vaultKeyVersion`（1）を、端末の最後に見た世代（2）と比べずに採用し、世代1の Vault 鍵で復帰する。④サーバーが（保持している）世代1のアイテムを返すと、それは「今より新しくない」ので E-17 の新世代の判定に掛からず、古い内容が一覧・取得に出る | `background.ts` `quickUnlock`（`rec.vaultKeyVersion` をそのまま `vaultVersion` に入れ、`trustFor(memberId).generations.get()` を見ない）、`sync` の新世代判定が `>` だけ、`src/crypto/quick-unlock.ts` `openQuickUnlock`（AAD は保存の世代を使うが、端末の記録とは比べない） | 実測。世代1で `setupQuickUnlock('2580')`→`storage.local` の `teampw/v1/trust\|…\|generation` を `2` に設定（同期で世代2を開いた状態の再現）→`restart`（保存が残ることの確認）→`quickUnlock('2580')` が `{ok:true, vault:'ready'}`、`vaultKey:true`、世代1のアイテムが `listItems` に出た。仕様の「最後に見た世代より古いものは拒否する」に対する抜け |
| 6 | 中 | ①サーバーが差分応答の `change_seq` に大きな値（例：999999）を入れる。②クライアントはそれをそのまま `cursor` に保存する。③以後の `GET /v1/items?after=999999` は空を返し、正直なサーバーに戻っても、別の端末が作った新しいアイテムは永久に来ない。画面は「同期成功・0件」のままなので、利用者は気づかない。④`1e20` のように 16 桁を超えると、API の `after` の検査で 400 になり、`sync` は `SERVER` エラーを返し続ける。⑤偽の削除（`deleted:true`）でも同じで、カーソルが進み、キャッシュの暗号文が消える。正直なサーバーに戻しても、そのアイテムは再取得されない | `background.ts` `sync`（`maxSeq = Math.max(maxSeq, Number(i.change_seq) \|\| 0)`。上限・単調性の検査がなく、全件を取り直す口もない）、`saveCache`、`src/api/app.ts` `GET /v1/items`（`after` は 16 桁まで） | 実測（3通り）。(a) 応答の `change_seq` を 999999 に→同期→`cursor=999999`→正直なサーバー＋2台目で新規作成→1台目の同期が `received:0`、`listItems` は古い1件だけ→再起動＋ロック解除後も同じ。(b) `change_seq=1e20`→`cursor=1e20` が `storage.local` に残り、再起動後の同期が `{ok:false, error:'SERVER'}`。(c) 偽の `deleted:true`（change_seq 99）→アイテムが `NOT_FOUND` になり、正直なサーバーに戻して `received:0`、再起動後も一覧に戻らない |
| 7 | 低 | ①サーバーが応答の `vault_revision` に `1e15` を入れる。②クライアントはそれを「最後に見た Vault リビジョン」として保存する。③以後、正直なサーバーが 2 などを返しても `ROLLBACK_DETECTED` で同期を止める。④再起動しても保存が残るので、手で `storage.local` を消すまで同期できない。警告は出るが、復旧の口がない | `background.ts` `sync`（`lastVaultRevision = revision` を無条件に保存。上限の検査がない）、`saveCache` | 実測。応答を `{vault_revision: 1e15, items: []}` に書き換え→同期は成功→再起動＋ロック解除→正直なサーバーで同期すると `{ok:false, error:'ROLLBACK_DETECTED'}`、`storage.local` の `lastVaultRevision` は `1e15` のまま |
| 8 | 低 | ①利用者がアイテムを保存し、サーバーが 409 を返す。②`saveItem` は原因を分けるために `GET /v1/vault` を呼ぶが、サーバーが「今の世代」を古い 1 と偽る。③`generationChanged` は `vaultVersion`（1）と同じなので false を返し、選択の画面に回る。④利用者が「自分の内容で上書きする」を選んでも、実際には世代2なので同じ 409 が続く。古い Vault 鍵を持ったまま、マスターパスワードを求められない。⑤逆に、サーバーが「今の世代」を新しい値と偽ると、ロックして `PASSWORD_REQUIRED` にできる（強制ロックの DoS） | `background.ts` `saveItem` の 409 分岐、`generationChanged`（署名のない `current_vault_key_version` を信じる）、`src/api/app.ts` `GET /v1/vault` | 実測。世代1で `setupQuickUnlock`→DB を世代2に更新→`GET /v1/vault` を世代1の本文（`current_vault_key_version: 1`）に固定→`saveItem` が `CONFLICT`（`PASSWORD_REQUIRED` ではない）、`memoryState().vaultKey` は `true`。同じ状況で `GET /v1/vault` が正直に 2 を返す版は `PASSWORD_REQUIRED` になり、`{unlocked:false, vaultKey:false}` にロックされる（5a61be1 の修正は効いている） |

## 試したが成立しなかったもの

| 試した攻撃 | 結果 | 根拠 |
|---|---|---|
| 別のアイテムの暗号文を、今のアイテムの暗号文として差し替える | 読めないアイテムになる | AAD のアイテム ID が違うので復号に失敗する。実測：アイテム A の行に B の暗号文を入れて同期→`listItems` で A が `unreadable:true`、`getItem` が `UNREADABLE` |
| 別の世代の暗号文を、今の世代の暗号文として差し替える | 読めないアイテムになる | AAD が `v1\|item\|<id>\|<世代>` で、復号は保存された世代で AAD を作り直す。コード確認（未実行、推測）。A-3 の AAD のテストと同じ性質 |
| 同時に10個のパスコードを送る／Service Worker を再起動して続ける／5回目で消える | 5回を超えて試せない。再起動をまたいで回数が残る | `reserveAttempt` が試す前に数を増やし、`serialized` で1つずつ順に行う。実測：2回失敗→再起動→3回失敗→5回目が `QUICK_UNLOCK_CLEARED`、次が `NO_QUICK_UNLOCK`、`memoryState` は `{unlocked:false, vaultKey:false}`。既存の E-15（同時10個）も成功。ただし、古い `storage.session` を丸ごと戻すと `failures` も0に戻る。これは保存を読める前提（総当たり可）と同じで、受け入れた範囲 |
| 409 の本文に偽の「今の版」を入れて、画面に偽の中身を出させる | 本文は使われない | `saveItem` は 409 の本文を読まず、`conflictReply` が同期してサーバーの今の版を取り直す。実測：409 の本文に `title:'偽物'`・`currentRevision:999` を入れても、返った `current` は本物、`currentRevision` は 1 |
| タイトル・URL・メモを HTML や `href` として解釈させる | 文字として出る | `items.ts` は `textContent`・`createElement`・`input`/`textarea` の `value` だけを使い、URL をリンクにしない。`build.test.ts` が `innerHTML`・`outerHTML`・`insertAdjacentHTML`・`document.write`・`href`/`src` への代入・イベント属性の付与を禁止している。静的検査は実測。ブラウザでの描画は未実行（推測） |
| Web ページや別の拡張機能から、ポップアップ／全画面ページのふりをしてメッセージを送る | 届かない | `acceptedSender` が拡張機能 ID と2つのページの URL を完全一致で見る。manifest に `externally_connectable`・`content_scripts` がない。既存の E-08 が成功 |
| `sync`・`listItems` 以外で、利用者の操作なしに放置のロックを延ばす | 見つからない | `PASSIVE_TYPES` は `status`・`sync`・`listItems`。`opened`・`getItem`・`saveItem`・`deleteItem` は利用者の操作として延ばす（10.4 のとおり）。`listSessions`・`stepUp` は passive ではないが、呼ぶのは画面の描画（`opened` の後）と利用者の操作だけで、自動で送る口がない。コード確認（未実行、推測） |
| Web ページから `storage.local` の同期キャッシュを直接書き換える | 書き換えられない | `storage.local` に書くのは Service Worker だけで、ページ／Web ページからは触れない。ただし、サーバーの応答経由で `cursor`・`vault_revision` を毒せる（#6・#7）。コード確認（未実行、推測） |
| 別のメンバー・別の接続先のパスコード保存を使い回す | 開けない | AAD が `v1\|quick-unlock\|<接続先>\|<メンバーID>\|<世代>`。既存の A-5 テストが、別のメンバー・接続先・世代の書き換えで開けないことを確認している（実測） |
| 古い世代のグラントを「今の世代」と偽って開かせる | 開けない（パスワード経路） | `verifyGrant` が、固定した署名鍵、`grant.vaultKeyVersion >= lastSeen`、`grant.vaultKeyVersion === currentVaultKeyVersion` を確かめる。既存の C-20 テストがある（実測）。ただし、クイックロック解除はこの経路を通らない（#5） |

## 補足

- 重大度の基準：**高**は、鍵を持たない攻撃者が、秘密の内容を気づかれずに差し替え・巻き戻しできるもの。**中**は、ロックのすり抜け、世代・リビジョンの巻き戻し、持続する可用性の低下。**低**は、気づかれる DoS や、仕様で範囲と決めた制約の再確認。
- #1 は、仕様の「アイテムのロールバック・隠蔽の防止は MVP では検知のみ」という範囲の外側ではないが、**アイテム単位の検知の実装がない**。`itemAad` にリビジョンがなく、`putEntry` もアイテムごとのリビジョンを比べないので、サーバーが「今のリビジョン」と言えばクライアントは受け入れる。盗んだトークンだけでパスワードの巻き戻しが成立するため、このレビューでは高とした。仕様の範囲を理由に重大度を下げるかは、チームの判断が要る。
- #3・#4 は、いずれも「時間のかかる処理の後にロックを確かめる」という 2a の Codex #3 の約束が、2b で足した `quickUnlock`・`getItem`・`saveItem`・`deleteItem` に届いていないものである。`lock` を送れるのは拡張機能のページだけなので、攻撃者が任意のタイミングで起こすことはできない。ただし、利用者がロックを押したときや15分の放置と重なると、ロック後も鍵・平文が残る。
- #2 は、サーバーが応答を遅らせて、利用者の保存・同期と重ねることで起こす。次の同期で自己修復する場合が多いが、`lastVaultRevision` が下がるので、S-09 の「下げる口は作らない」という前提が崩れる。攻撃者がその後に古い `vault_revision` を返すと、検知の基準が下がった状態で受け入れられる。
- #5 は、Service Worker が停止しても残るパスコード保存、または古い `storage.session` のスナップショットを戻した場合の話である。パスコード保存の `vaultKeyVersion` と、`storage.local` の最後に見た世代が別々に保存され、`quickUnlock` が両者を照合しない。保存が消えるのは明示的なロック・ログアウト・15分の放置・5回の失敗・ブラウザの終了だけなので、ローテーションを知った後も、ロックする前なら古い世代の保存が残る。仕様の「最後に見た世代より古いものは拒否する」は、グラントの経路（`openGrant`）にはあるが、包んだ Vault 鍵の経路にはない。
- #6・#7 は、サーバーが自由に決められる `change_seq`・`vault_revision` を、クライアントが上限も単調性もなく保存するもの。サーバーはもともと同期を止められるので、単独では新しい権限にはならない。重いのは、**正直なサーバーに戻ってもクライアントが自力で回復しない**点（全件を取り直す口がない）と、#6 が警告なしで進む点である。
- サーバーがアイテムを返さない、または偽の削除を返すことで内容を隠すことは、仕様の脅威モデルが「整合した古い状態全体を返された場合は検知できない」「一部を返さない」として範囲に認めている。このレビューでは、偽の削除（`deleted:true`）と大きな `change_seq` で、正直なサーバーに戻った後も再取得されないことを実測した（#6）。全件を取り直す口がないため、一時的な偽装が永続化する。
- #8 は、5a61be1 で「正直なサーバーが新しい世代を返す」場合は直っている。残るのは、サーバーが古い世代と偽る場合で、仕様の「サーバーが新しい世代を隠すことには気づけない」と同じ範囲ではある。ただし、409 のたびに署名のない `current_vault_key_version` を読み直すので、サーバーはロックを強制することもできる（DoS）。
- 5回制限そのものは、このブランチの実装（試す前に数える、`serialized`、5回目で消す）で保たれている。同時10個・再起動・5回目のいずれも実測で確認した。保存の巻き戻しは、保存を読める前提と同じ扱いで、新しい迂回ではない。
- アイテムの暗号文そのものは `storage.local` にしか置かれず、平文の一覧はメモリだけである。`lock()` は `index` と `cacheLoadedFor` を消し、`storage.session` の `teampw/v1/unlock\|…` も消す。この点は 2a の設計どおりで、今回の指摘は「消した後に、進行中の処理が書き戻す」競合である。
- このレビューの実測テストは、リポジトリを変更しないよう、リポジトリの外の一時ファイルから実行した。再現の手順は上の表に書いたとおりで、必要な場合は `tests/extension/` に移して固定する。`npm test` は 420件成功、`npm run typecheck` も成功している。
