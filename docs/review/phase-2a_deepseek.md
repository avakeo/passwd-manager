# 攻撃者の目線レビュー：拡張機能の土台（ログイン、ロック解除、最初の Vault、鍵の登録）

- 日付：2026-10-17
- 対象：ブランチ feat/extension-base（`src/extension/` と、この差分で足した `src/api/key-routes.ts`）
- 参照：docs/review/phase-2a.md、docs/仕様書.md（「拡張機能と自動入力の方針」「鍵とメンバーのライフサイクル > 初期化（管理者）」「二要素認証」、E-08・E-11・E-14・E-16・E-18・P-02・P-04・P-09・P-11）、docs/判断待ち.md、docs/review/phase-1_deepseek.md の文体
- 前提：攻撃者は、利用者に開かせる Web ページ（フィッシングのページを含む）を自由に作れる。加えて、利用者のブラウザに**別の拡張機能**を入れさせられる。サーバー（Workers・D1）は正直に動き、端末 OS とマスターパスワードは攻撃者の手にない。攻撃者は自分の端末で API を直接叩ける
- 見たファイル：`src/extension/manifest.json`、`src/extension/config.ts`、`src/extension/background/{service-worker,messages,storage,api-client,chrome-like,background}.ts`、`src/extension/popup/popup.ts`、`src/extension/page/app.ts`、`src/extension/shared/ui.ts`、`src/api/key-routes.ts`、`src/api/auth.ts`、`src/client/discord-login.ts`、`src/crypto/{grant,signer,kdf,format,member-key}.ts`、`scripts/{build-extension,extension-key}.ts`、`tests/extension/*.test.ts`、`tests/helpers/{api,fake-chrome,fake-discord}.ts`、docs/review/phase-2a.md
- この文書は「どこが・なぜ危ないか」だけを示す。本体のコードの直し方は書かない。

## 結論

拡張機能の入口は固い。ユーザーが指定した4つの狙い——(1) ページや別拡張機能からのメッセージ、(2) 鍵・トークン・平文の持ち出し、(3) ロックのすり抜け、(4) ログインの戻りと最初の Vault の悪用——は、**このブランチの攻撃者（ページ＋別拡張機能）からは単独では成立しない**。根拠は、manifest に `externally_connectable`・`content_scripts`・`web_accessible_resources` がなく `onMessageExternal` も登録しないこと、描画が `textContent`／`createElement` だけであること、鍵が取り出し不可の鍵オブジェクトのまま Service Worker のメモリにしかないこと。

重いのは、**「トークンを `storage.session` に置いても、送信の瞬間は別の拡張機能から見える」**という拡張機能の原理的な穴（#1）と、**最初の Vault の作成 API がグラントの署名をサーバーで検証しないため、正規の端末が永久に Vault を開けなくなる**点（#2）。この2つはトークン窃取（フェーズ1 の #2・#3）と組み合わさると現実になり、#1→#2 の順で連鎖する。#1・#2 は平文の漏洩には至らない（マスターパスワードと署名鍵は攻撃者の手にない）が、完全性と可用性は失われる。

## 指摘一覧

| 番号 | 重大度 | 攻撃の手順 | 狙われる箇所 | 再現テストの内容 |
|---|---|---|---|---|
| 1 | 中 | ①利用者に、`host_permissions` に API の接続先を含み（`<all_urls>` で十分）、`webRequest` 権限を持つ別の拡張機能を入れさせる。②その拡張機能で `chrome.webRequest.onBeforeSendHeaders` を `["requestHeaders","extraHeaders"]` 付きで購読する。③利用者が teampw を操作すると Service Worker が `apiOrigin` へ `fetch` する。④購読側に `Authorization: Bearer <アクセストークン>` が現れる。`requestBody` を付ければ `POST /v1/auth/refresh` の本文の `refresh_token` も取れる。⑤盗んだトークンで、暗号文の取得、アイテムの削除・上書き、セッションの無効化、鍵の登録し直し（承認待ちへの降格）を実行する。`storage.session` は他拡張機能から読めないが、**送信ヘッダはその限りではない** | `src/extension/background/api-client.ts` `#send`（`Authorization` を素のヘッダで送る）、`src/extension/manifest.json`（こちらでは防げない）、`src/extension/background/storage.ts`（保存先を `session` に変えても送信時に見える） | 自動テスト不可（実ブラウザと拡張機能の権限が要る）。手で確かめる: 2つ目の拡張機能を作り、`host_permissions:[apiOrigin]` と `webRequest` を宣言して `onBeforeSendHeaders` を `extraHeaders` 付きで購読し、teampw でログインしたときに `Authorization` と `refresh_token` が観測できることを記録する。自動化できる範囲として、「Service Worker が API へトークンを平文ヘッダで送る」ことを送信ヘッダの検査で固定する記録テストを足す |
| 2 | 中 | ①まず #1（またはフェーズ1 #2・#3）で管理者のアクセストークンを得る。②`GET /v1/me` で自分の有効な鍵の `id` を取る。③`POST /v1/vault/init` に、`recipient_key_id`＝その鍵、`signer_key_id`＝同じ、`ephemeral_public_key` は長さ65・先頭 `0x04` だけ合った任意バイト、`wrapped_key` は長さと先頭2バイトだけ合った任意バイト、`signature` は長さと先頭2バイトだけ合った任意バイト、`vault_key_version:1` を送る。④サーバーは ECDSA を検証しないので **201** で保存する。⑤以後 `vault_key_grants` が1行あるため、管理者の鍵の再登録も最初の Vault の作成も **409** で弾かれ、正規の端末は `openGrant` の `SIGNATURE_INVALID` で grant-rejected になる。復旧の口がなく Vault が使えなくなる（可用性）。署名鍵が攻撃者にないので平文は漏れない | `src/api/key-routes.ts` `POST /v1/vault/init`（`ephemeral_public_key` は長さと先頭のみ、`wrapped_key`／`signature` は長さとヘッダのみで署名を検証しない）、同 `rotation_guard`（「グラントが無いこと」だけを見る）、`PUT /v1/me/keys` の管理者ガード（グラントがあると 409） | `tests/helpers/api.ts` の `addMember('active',{role:'admin',totpVerifiedAt:Date.now()})` で管理者セッションを作り、`member_keys` に有効な鍵（`ecdsa_public_key` 非 NULL）を入れる。偽造グラントを `POST /v1/vault/init` に送って **201**、続けて同じ管理者で `PUT /v1/me/keys`（新鍵）が **409**、`POST /v1/vault/init` の2回目も **409** を assert（このレビューで実測して確認済み）。併せて本物の鍵で `openGrant` すると `SIGNATURE_INVALID` になることを assert。既存の P-11 はハッピーパスなので署名検証が無くても落ちない |
| 3 | 低 | ①別の拡張機能に `debugger` 権限を付けさせる。②`chrome.debugger` で teampw の全画面ページ／ポップアップ（タブで開いた場合）にアタッチして DOM を読む。③利用者が入力したマスターパスワード、TOTP のシークレット、回復コードがそのまま取れる。④Service Worker のターゲットにもアタッチしてメモリ上の鍵を調べる余地がある。⑤マスターパスワードが取れれば、保存済みの暗号化秘密鍵から Vault 鍵まで復元できる | `src/extension/popup/popup.ts`（パスワード欄）、`src/extension/page/app.ts`（TOTP のシークレット・回復コードの表示）、`src/extension/background/background.ts` の `unlocked`／`vaultKey`（メモリ） | 自動テスト不可。手で確かめる: 2つ目の拡張機能を開発者モードで入れ、`chrome.debugger` で app ページに attach して入力値と表示中の値を読めること、attach 中は Chrome が警告を出すことを記録する（phase-2a の「手で確かめる項目」に追加） |
| 4 | 低 | ①利用者がロック解除して放置する。②放置の判定は `chrome.storage.session` の最終操作時刻を「受け付けたメッセージ」ごとに更新する。③2b/3 で足す同期やポーリングが `status` などを定期送信すると、利用者の操作が無くても時刻が更新され続け、15分の自動ロックが訪れない。④共有端末で放置してもロックされない | `src/extension/background/background.ts` `handleMessage`（`checkIdle` の後に、種類を問わず `LAST_ACTIVITY_KEY` を更新）、`IDLE_LOCK_MS` | `tests/extension/background.test.ts` を土台に、ロック解除後 `IDLE_LOCK_MS - 1000` ごとに `status` を送り、60分後も `locked:false` を assert（このレビューで実測して確認済み）。「利用者の操作だけで延命する」ことを期待する検査を足すと落ちる |
| 5 | 低 | ①受け付けた送り元（ポップアップ／全画面ページ）からしか送れないので実害は小さいが、`lock`（ロック）は進行中のログインの一時トークン（`challenge`）を消さない。②ログインが `totp_required` を返した後で `lock` を送っても `challenge` が残り、`loginTotp` でログインを続けられる。③ログアウトは `challenge` を消すので、ロックとログアウトで後始末が食い違う | `src/extension/background/background.ts` `lock()`（`challenge` を触らない）と `handlers.logout`（`challenge=null`） | `login` が `totp_required` を返した状態で `type:'lock'` を送り、続けて `loginTotp` が `NO_LOGIN_IN_PROGRESS` にならない（`challenge` が残っている）ことを assert。`logout` 後の `loginTotp` は `NO_LOGIN_IN_PROGRESS` になる対比を付ける |

## 試したが成立しなかったもの（指定された狙い。根拠は実行して確認）

| 試した攻撃 | 結果 | 根拠 |
|---|---|---|
| Web ページから `chrome.runtime.sendMessage('<拡張機能 ID>', {type:'lock'\|'unlock'\|'logout'\|'status'})` | 届かない | `manifest.json` に `externally_connectable` も `content_scripts` も無い。`service-worker.ts` は `onMessage` だけを登録し `onMessageExternal` を持たない。E-08 テストが「正しい ID でも URL が Web ページなら `{ok:false,error:'BAD_REQUEST'}`、保存も変わらない」ことを確認 |
| 別の拡張機能から `chrome.runtime.sendMessage('<拡張機能 ID>', …)` | 届かない | 同上（`externally_connectable` が無いと他拡張機能からも接続先にならない） |
| ページに注入したスクリプトから `chrome.storage.session` を読む | ブロック | `content_scripts` が無い。`storage.session` の既定のアクセス範囲は信頼できるコンテキストだけで、コンテンツスクリプトからは読めない（実機確認は phase-2a の手で確かめる項目） |
| ページがポップアップ／全画面ページを開く・iframe に入れる | ブロック | `web_accessible_resources` が無いのでページから `chrome-extension://<id>/…` を開けない。CSP の `frame-ancestors 'none'` で埋め込みも拒否 |
| 応答から鍵・トークン・平文を取る | 取れない | `background.ts` の各ハンドラは鍵もトークンも返さない。通しテストで、応答と `storage.local` にトークンとマスターパスワードが無いことを確認 |
| `storage.local` から秘密鍵・平文を取る | 取れない | `storage.local` にあるのは署名鍵の固定（公開鍵）・最後に見た世代・照合済みの公開鍵だけ。秘密鍵と Vault 鍵は Service Worker のメモリに `extractable:false` で置く |
| ログ・応答本文に秘密を残す | 無し | 拡張機能に `console` 出力が無い。トークンは `api-client.ts` と `storage.ts` の外に出ない |
| ログインの戻り（identity／`chromiumapp.org`）を乗っ取る | 乗っ取れない | `<id>.chromiumapp.org` は Chrome が拡張機能にだけ渡す。`parseLoginRedirect` が戻り先の origin+path と state を照合し、PKCE の S256 も付く |
| ログインの戻りに state を付けない／2つ付ける／code を差し替える | 拒否 | `parseLoginRedirect` が `states.length !== 1` と `codes.length !== 1` を拒否（`discord-login.ts`、A-01） |
| 最初の Vault を2回作る／別の鍵宛てのグラントがある状態で作る | 拒否 | `rotation_guard` の確認と保存が1バッチで、グラントがあれば巻き戻して 409（P-11 のテスト）。ただし「1回目が偽造」ならば #2 のとおり 201 で通る |
| メッセージの余分な項目・型違い・長すぎる値・`__proto__` | 拒否 | `messages.ts` `parseMessage` が表とぴったり一致する項目だけで作り直す（E-08 テスト。実測でも `__proto__` の種類や汚染オブジェクトは拒否） |
| 送り元 URL への細工（クエリ、ポート、userinfo、末尾スラッシュ、大文字パス、URL でない値） | 拒否 | `acceptedSender` が `search`／`username`／`password` と `protocol//host//pathname` の完全一致で判定（実測で全拒否。`/extension/popup/./popup.html` は同じファイルに正規化され通るが、攻撃の意味は無い） |
| メッセージの getter／Symbol キー | 危険な項目は作れない | `parseMessage` は表にある値をコピーして作り直すので、`get type(){return 'lock'}` や Symbol キーがあっても生じるメッセージは表のとおり（実測）。拡張機能のメッセージは構造化複製なので通常は残らない |
| 別の拡張機能が teampw のページにスクリプトを注入する | 注入できない | Chrome は他拡張機能のコンテンツスクリプトを `chrome-extension://` のページに注入できない（`host_permissions` は `chrome-extension:` に一致しない）。したがって UI の平文は #3 の debugger のような別権限が要る |
| マスターパスワードのログ・保存 | 残らない | 通しテストで `storage.local`／`storage.session` に残らないことを確認。入力欄は送信後すぐ空にする（`popup.ts`／`app.ts`） |
| クイックロック解除（4桁パスコード）の総当たり | このブランチには無い | 2b で実装。`UNLOCK_KEY_PREFIX` と `lock()` の消去だけが用意してある（未実装なので評価対象外） |

## 補足

- 前提の外側（トークン窃取）を足すと #1・#2 が現実になり、#1→#2 の順で連鎖する。フェーズ1 レビューの #2・#3（トークンの窃取と、5分のステップアップが端末に紐づかない点）と同じ土台にある。今回の攻撃者（ページ＋別拡張機能）だけでは、#2 は単独では届かない。
- **クイックロック解除（4桁、5回失敗で消去）と `chrome.storage.session` のアクセス範囲の実機確認は、このブランチ（2a）にはまだ無い（2b）。** `UNLOCK_KEY_PREFIX` と `lock()` の消去だけが用意してある。実装時に、4桁パスコードのオフライン総当たり耐性（KDF の反復回数）と、5回失敗での消去が別拡張機能の debugger／`storage` から妨害できないかを再レビューする。
- 鍵の登録（`PUT /v1/me/keys`）は、有効な鍵が既にあるときだけ `requireRecentTotp`。最初の登録は承認待ちのまま通る（仕様どおり）。盗まれたトークンで「まだ鍵が無いメンバー」の鍵を先に登録し、後で管理者がそのメンバーを承認すると、攻撃者の鍵が承認される余地がある（フェーズ4の承認とセットで確認する）。
- 放置のロックは「操作」ではなく「メッセージ」で延命される（#4）。2b で同期のポーリングを足すとき、`status` のような参照系で延命させるかどうかを決める。
- 重大度の基準：E2EE のため #1〜#5 のいずれも平文の漏洩には至らない。重いのは、盗んだトークンで API を操作できること（#1、完全性・可用性）と、偽造グラントで Vault を復旧不能にできること（#2、可用性）。#3 は取得できる情報の重さ（マスターパスワード）が大きいが、`debugger` 権限と目に見える警告が要る一般則で、この拡張機能側では防げない。
- 実測した確認：拡張機能のテスト17件はすべて成功（`node --experimental-strip-types --no-warnings --test "tests/extension/*.test.ts"`）。送り元と種類の細工、放置の延命（60分）、偽造グラントでの 201 と、その後の 409（鍵の再登録・2回目の init）は、このレビューで実コードに対して実行して確認した。
