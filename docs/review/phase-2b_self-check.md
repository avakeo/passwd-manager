# PR #6（feat/extension-items、フェーズ2b）自己点検

作った AI 自身の点検であり、MVP 実装計画の3つのレビューには数えない。

- 日付：2026-10-25
- 対象：`4f6ceb9`（`origin/main` との差分）
- 照らし合わせたもの：docs/実装状況.md の10章、docs/仕様書.md、docs/review/phase-2b.md の「観点表で見てほしい所」、docs/review/phase-2a.md の「レビューの指摘と対応」
- コードもテストも変えていない。#1 と #2 は、リポジトリの外に置いた使い捨てのテストで実際に動かして確かめた（実測）。ほかは、コードを読んで判断した

| 番号 | 重大度 | ファイルと行 | 内容 | 根拠 |
|---|---|---|---|---|
| 1 | 高 | `src/extension/background/background.ts:331-340`、`272-276` | `sync` が新しい世代のアイテムを受けて `openVault()` を呼んでいる間にロックすると、ロックの後に `openVault()` が `vaultKey` と `vaultVersion` を書き戻す。続く `stillCurrent` の確認は `LOCKED` を投げるだけで `lock()` を呼ばないので、鍵がメモリに残る。`vaultMember()` は `vaultKey` と `vaultVersion` しか見ないため、`status` が `locked: true` を返す状態でも `listItems` と `getItem` が平文を返す。新しい世代のアイテムはサーバーが返すだけで作れる。実測：GET /v1/vault を止めている間に `lock` を送ると、`sync` は `LOCKED` を返したが、`memoryState()` は `vaultKey: true` のままで、`listItems` は `ok: true` でタイトルを返した。2a の Codex #3 と同じ種類の誤りで、`afterUnlock` には入れた「確かめて違えば `lock()`」が、2b で足した経路に入っていない | 仕様書「拡張機能と自動入力の方針 > ロックと鍵の置き場所」、E-11、phase-2a.md の Codex #3 |
| 2 | 中 | `background.ts:722-735`、`src/extension/page/items.ts:78`、`100-118` | 新しく作るときの 409 を、すべて ID の重なりとして扱う。サーバーの今の世代が変わったときも、新しい ID で同じ世代のまま送り直し、2回とも 409 で `CONFLICT` を返す。10.2 の計画「鍵の世代が違うなら、マスターパスワードでのロック解除を求める」と違う。さらに画面は、この `CONFLICT` を更新の 409 と同じに扱って選択の画面を出す。`id` がないまま「自分の内容で上書きする」を押すと、`id: null`、`revision: NaN` のメッセージになり、`BAD_REQUEST` で必ず失敗する。実測：`current_vault_key_version` を2にして作ると、POST /v1/items を2回送って `CONFLICT` | 実装状況 10.2「アイテム ID」、10.3「409 が返ったとき」、S-01 |
| 3 | 低 | `background.ts:337-338`、`272-276` | `sync` の中で開き直した結果が `ready` でない（`grant-rejected` など）とき、`vaultState` は変わるが、前の世代の `vaultKey` は残る。`vaultMember()` が `vaultState` を見ないので、`status` が `grant-rejected` を返す間も、一覧・取得・保存が前の世代の鍵で動く。#1 と同じ所の確かめ方の不足 | 仕様書「鍵とメンバーのライフサイクル」の P-04・P-07（固定と違うグラントは開かずに警告する） |
| 4 | 低 | `src/extension/page/items.ts:86-92` | 削除の 409 で、画面は「読み直してから、もう一度削除してください」と出し、リビジョンだけを今のものに替える。今の版の中身を見せないまま、次に押した削除がそのまま通る。10.3 の計画は「同期した後に『先に変更されています。それでも削除しますか』と聞く」。Service Worker は今の版を返しているので、画面で見せていないだけ | 実装状況 10.3「409 が返ったとき」、S-01 |
| 5 | 低 | `background.ts:305-314` | storage.local への書き込みに失敗すると（`cacheFull`）、最後に見た Vault リビジョンも保存されない。Service Worker を起動し直すと、前に保存できた古い値から比べ直すので、その間に進んだ分の巻き戻しを S-09 として検知できない。容量を超えたときもメモリだけで続ける決定（判断待ち 2b-4）は、暗号文のキャッシュについての決定で、最後に見たリビジョンの扱いは書いていない | 実装状況 10.3「巻き戻しの検知（S-09）」、判断待ち 2026-10-18 #4 |
| 6 | 低 | `tests/extension/build.test.ts`、`tests/browser/extension.spec.ts` | 10.1 の E-16 の自動テストは「ソースに setAccessLevel がないことの検査と、manifest の検査」。setAccessLevel の検査はどのテストにもない。本物のブラウザのテストは、Web ページから `chrome.storage` が見えないことを確かめているが、ソースに `setAccessLevel` を足しても落ちるテストはない | 実装状況 10.1 の E-16、仕様書 E-16 |
| 7 | 低 | `tests/extension/items.test.ts:54` | 「I-01 I-02」と名付けたテストは、一覧にパスワードを出さないことと、D1・storage.local に平文がないことを確かめている。I-01（大きすぎる）と I-02（形が違う）の条件は、70行目のテストが確かめている。名前の ID と中身が合っていない | 仕様書 I-01・I-02、CLAUDE.md「テスト名に ID を入れる」 |

## 対応（2026-10-25）

7件とも PR #6 で直した。行番号は上の表のとおり `4f6ceb9` の時点のもの。

| 番号 | コミット | 直したこと | 足したテスト |
|---|---|---|---|
| 1 | `6ae0214` | 開き直しの後に確かめて違えば `lock()` を呼ぶ（`afterUnlock` と同じ） | items.test.ts「E-11 同期が新しい世代の Vault を開き直している間にロックしたら…」 |
| 2 | `37dcbab` | 作成の 409 は GET /v1/vault の今の世代で原因を分け、世代が違えばロックして `PASSWORD_REQUIRED`。画面は作成の `CONFLICT` で選択の画面を出さない | items.test.ts「I-03 作成の 409 が鍵の世代の違い…」 |
| 3 | `04136b3` | 開き直しが `ready` でなければ、前の世代の Vault 鍵と一覧も捨てる | items.test.ts「E-11 同期で新しい世代の Vault を開き直せなかったら…」 |
| 4 | `413a619` | 削除の 409 で今の版を見せ、「それでも削除する」を押したときだけ今のリビジョンで送り直す | なし（画面の自動テストはない。S-01 の手で確かめる項目で見る） |
| 5 | `49ec27f` | 書き込みに失敗したら、暗号文を入れない記録（カーソル0、最後に見たリビジョン）を書く | items.test.ts「S-09 キャッシュが容量を超えても…」。偽の storage に値の大きさの上限を足した |
| 6 | `04a7e49` | — | build.test.ts「E-16 … setAccessLevel がない」 |
| 7 | `aa803ed` | テスト名から ID を外した（合う ID が仕様書にない） | — |

直した後：`npm test` 419件成功・失敗0件、`npm run typecheck` 成功。#1〜#3、#5 のテストは、直す前に落ちることを確かめた。

## #1 と #2 の再現テストの案（重大度が高のもの）

#1：`tests/extension/items.test.ts` に足す。

1. `adminReady` の後にアイテムを1件作る
2. D1 に、世代2のアイテムを `change_seq` を大きくして1行入れる（E-17 のテストと同じ書き方）。`current_vault_key_version` は1のままにして、開き直しが成功するようにする
3. `hold(w, 'GET /v1/vault')` で開き直しの通信を止め、`sync` を送る
4. 通信が届いたら `lock` を送り、通信を流す
5. `sync` が `LOCKED` を返し、`memoryState()` が `{ unlocked: false, vaultKey: false }` であること、`listItems` が `LOCKED` を返すことを確かめる（今は `vaultKey: true` と `ok: true` で落ちる）

#2：同じファイルに足す。D1 の `current_vault_key_version` を2にしてから `saveItem`（id なし）を送り、POST /v1/items が1回だけで、返事が `CONFLICT` ではなく、マスターパスワードを求めるもの（例：`PASSWORD_REQUIRED`）であることを確かめる。直すときの返事の名前は、10.2 に合わせて決める。

## 確認できた点

- 2a の採用済みの指摘は、#1 の経路を除いて戻っていない。ロックはログインの途中の一時トークンも消す（DeepSeek #5）。`status`・`sync`・`listItems` は放置の時刻を新しくしない（DeepSeek #4、10.4）。クイックロック解除の `quickUnlock` と `setupQuickUnlock` は、重い計算の後に `stillCurrent` を確かめてから鍵を置く（Codex #3）
- クイックロック解除の数え方：`reserveAttempt` は `serialized` の中で読み、比べ、書く。試す前に回数を書くので、同時に送っても、PBKDF2 の途中で Service Worker が止まっても、5回を超えて試せない
- パスコードで戻った状態は `unlocked = null` で、鍵の作り直し・最初の Vault・パスコードの設定は `PASSWORD_REQUIRED`、新しい世代のアイテムを受けたらロックする（E-17）
- 一覧（`Summary`）にパスワード・メモ・カスタム項目を入れない。ポップアップは一覧だけを受け取る
- 画面は `textContent` と `value` だけで描き、URL をリンクにしない。build.test.ts は `href`・`src` への代入とイベント属性も検査する
- migrations/0003 と `writeItem`：`change_seq` は Vault リビジョンを上げる同じバッチで付き、削除（論理削除）も同じ経路を通る。1回の呼び出しのクエリは4つ

## 確かめられなかったこと

- `writeItem` のバッチは文が4つになり、3つ目と4つ目が `changes()` に頼る。node:sqlite では通るが、実際の D1 での動きはまだ確かめていない（docs/実装状況.md の5章）

## 実行結果

`npm ci` 成功、`npm test` 414件成功・失敗0件、`npm run typecheck` 成功（2026-10-25、`4f6ceb9`）。
