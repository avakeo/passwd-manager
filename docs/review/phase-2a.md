# フェーズ2a 拡張機能の土台、ログイン、TOTP、鍵の登録とロック解除、最初の Vault、放置のロック：レビュー資料

- 日付：2026-10-17
- ブランチ：feat/extension-base
- 計画：docs/実装状況.md の9章（2a の範囲）。判断待ちの7件は案どおりに決定し、仕様書に反映した（docs/判断待ち.md の決定済み）
- テスト：`npm test` 376件すべて成功、`npm run typecheck` 成功
- 2b（アイテムの一覧・作成・編集・削除と同期、クイックロック解除）は次の PR

## 変更したファイル

| ファイル | 中身 |
|---|---|
| .github/workflows/ci.yml | push と pull request のたびに `npm ci --ignore-scripts`、`npm test`、`npm run typecheck`。actions/checkout v7.0.1 と actions/setup-node v7.0.0 をコミットの SHA で固定。権限は contents の読み取りだけ |
| src/api/key-routes.ts | PUT /v1/me/keys（鍵の登録）と POST /v1/vault/init（最初の Vault） |
| src/extension/background/ | Service Worker：メッセージの入口と検査（messages.ts）、保存先（storage.ts）、API との通信と更新（api-client.ts）、ログイン・TOTP・鍵・ロック解除・最初の Vault・放置のロック（background.ts）、入口（service-worker.ts） |
| src/extension/popup/、page/、shared/ | ポップアップ（ログイン、コード、ロック解除、ロック）と全画面ページ（TOTP の登録と作り直し、鍵の作成、最初の Vault、再確認、セッション）。textContent と createElement だけで描く |
| src/extension/manifest.json | 権限は storage と identity。API の接続先は host_permissions にビルドで入れる |
| scripts/build-extension.ts、tsconfig.extension.json | 依存を足さずに tsc で JS にし、HTML・CSS・manifest を dist/extension に写す |
| scripts/extension-key.ts | 拡張機能 ID を固定する鍵を作る（node:crypto だけ。秘密鍵はリポジトリの外にだけ書く） |
| tests/helpers/fake-chrome.ts | 偽の chrome（storage.local・storage.session・runtime・identity） |

## 2a の対象のテスト ID ごとの結果

| ID | テスト | 結果 |
|---|---|---|
| E-08 | 送り元：自分の拡張機能のポップアップと全画面ページだけ。ページのアドレス、別の拡張機能、クエリ付き、別のページは断る。種類：表にある種類と項目だけ。余分な項目・型違い・長すぎる値・`__proto__` は断る。ページに注入したスクリプトや別の拡張機能から、ロック・ログアウト・ロック解除を送っても何も起きない（保存も変わらない） | 成功（4件） |
| E-11（2a の分） | ロック中は、鍵を使う指示（最初の Vault）を LOCKED で断る。自動入力の分はフェーズ3 | 成功 |
| E-14 | Service Worker を起動し直すと、鍵がなくロック状態から始まる。ログインは続き、マスターパスワードで Vault まで開ける。間違ったパスワードは BAD_PASSWORD | 成功 |
| E-16（manifest の分） | manifest の権限は storage と identity と API の接続先だけ。content_scripts・externally_connectable・web_accessible_resources を持たない。実際に読めないことの確認は手で | 成功 |
| E-18 | storage.session が消えると（ブラウザを閉じた）、ログインからやり直す。storage.local の固定は残り、ログインし直した後に Vault まで開ける | 成功 |
| 放置のロック（判断待ち4） | 15分を過ぎてから来たメッセージは処理の前にロックする。15分以内なら続く。Service Worker が起きたときも確かめ、15分を過ぎていればロック解除用の保存を消す | 成功（2件） |
| P-02 | 承認済みのメンバーが鍵を登録し直すと承認待ちに戻り、前の鍵は revoked、Vault は 403 | 成功 |
| P-04（拡張機能） | メンバーは鍵を作っても、照合と承認が済むまでグラントを開かない（awaiting-approval） | 成功 |
| P-09（拡張機能） | 署名鍵の固定と最後に見た世代は、storage.local の `teampw/v1/trust\|<接続先>\|<メンバーID>\|…` に置く。暗号コアの P-09 も成功 | 成功 |
| P-11 | 最初の Vault を同時に2回作っても片方だけ（201 と 409）。別の鍵宛てのグラントが1つでもあれば 409（確認はバッチの中）。宛先と署名は管理者自身の有効な鍵、世代1だけ。管理者の5分以内の TOTP の確認が要る | 成功（4件） |
| I-02（鍵の登録） | 形・長さ・種類の違い、メンバーの署名鍵、管理者の署名鍵の不足は 400 | 成功 |
| A-01（拡張機能） | 拡張機能のログインは src/client/discord-login.ts で state を照合する（既存のテストと、通しのテスト） | 成功 |
| 認可の表 | PUT /v1/me/keys と POST /v1/vault/init の2行（20マス）を足し、全141マスが成功 | 成功 |
| DeepSeek #2（持ち越し） | 端末名は送られたとおりの文字列で返し、画面のコードに innerHTML などがない | 成功（2件） |

ほかに、鍵の登録（承認待ちのまま入る、登録し直しは5分以内の TOTP、管理者はグラントがないときだけ）、最初の Vault を API から取ったものだけで開ける通しのテスト、アクセストークンの更新とセッションの無効化、鍵の作り直しは明示したときだけ、ビルドの出力（.ts の import が .js に、src/api は入らない）のテストがある。

## わざと壊して確かめた結果

| 壊し方 | 落ちたテスト |
|---|---|
| 最初の Vault の確認（バッチの先頭の「グラントがまだない」）を外す | P-11 別の鍵宛てのグラントがあれば作れない（同時に2回の方は、同じ宛先の主キーでも止まるので落ちない） |
| メッセージのたびの放置の確認を外す | 放置のロック（メッセージ） |
| 起きたときの放置の確認を外す | 放置のロック（起きたとき） |
| 送り元の確認を外す | E-08（ページや別の拡張機能からのメッセージ） |
| ロックで解除用の保存を消さない | 放置のロック（起きたとき） |

壊すたびに元に戻し、差分が残っていないことを確かめた。

## 手で確かめる項目

自動テストは偽の chrome と偽の Discord で行っているので、次は実際の Chrome と Discord で確かめる。

| 項目 | 確かめ方 |
|---|---|
| 拡張機能を読み込める | 下の手順で読み込み、エラーが出ないこと。拡張機能 ID が scripts/extension-key.ts の表示と同じこと |
| identity API でのログイン | ポップアップの「Discord でログイン」で Discord の画面が開き、戻ってくること（A-01、A-02 の通し） |
| TOTP の登録 | 全画面ページでシークレットを認証アプリに手入力し、確定できること。回復コードが10個出ること |
| 鍵の作成と最初の Vault | 管理者で鍵を作り、最初の Vault を作れること。2つ目のプロファイルや2回押しで、2つ目が作られないこと（P-11） |
| E-14 | chrome://serviceworker-internals で Service Worker を止めた後、ポップアップがロック状態になり、マスターパスワードで戻れること |
| 放置のロック | 15分操作しないで、ポップアップを開くとロックされていること |
| E-16 | 任意のページの開発者ツールのコンソールで `chrome.storage` が使えないこと（コンテンツスクリプトを持たないので、ページからは届かない） |
| E-18 | ブラウザを閉じて開き直すと、ログインからやり直しになること |
| E-08 | 任意のページのコンソールから `chrome.runtime.sendMessage('<拡張機能 ID>', {type:'lock'})` を試し、届かないこと |
| 端末名の表示 | 端末名は文字として出ること（ポップアップからのログインは「Chrome」で固定） |
| メンバーの鍵 | 2つ目のアカウントでログインし、鍵を作ると「承認を待っています」になること |
| 悪意ある拡張機能：webRequest（範囲外の確認。DeepSeek #1） | 2つ目の拡張機能を開発者モードで作る（manifest に `"permissions": ["webRequest"]` と `"host_permissions": ["<API の接続先>/*"]`）。Service Worker で `chrome.webRequest.onBeforeSendHeaders.addListener(d => …, { urls: ['<API の接続先>/*'] }, ['requestHeaders', 'extraHeaders'])` を登録し、teampw で操作したときに Authorization ヘッダーが見えることを記録する。`onBeforeRequest` に `['requestBody']` を付けると、更新の本文のリフレッシュトークンも見える。防げないことを確かめる項目（仕様書の範囲外の表） |
| 悪意ある拡張機能：debugger（範囲外の確認。DeepSeek #3） | 2つ目の拡張機能に `"permissions": ["debugger"]` を付け、`chrome.debugger.attach({ tabId }, '1.3')` で teampw の全画面ページのタブにつなぎ、`Runtime.evaluate` で入力欄の値が読めることと、つないでいる間 Chrome が警告のバーを出すことを記録する |

## 拡張機能を Chrome に読み込む手順

1. 拡張機能 ID を固定する鍵を作る（1回だけ）。秘密鍵はリポジトリの外に置く
   ```
   node --experimental-strip-types scripts/extension-key.ts C:\Users\<あなた>\.teampw\extension-key.pem
   ```
   表示される manifestKey と拡張機能 ID を控える（秘密鍵の中身は表示されない）。
2. `extension.config.example.json` を `extension.config.local.json` に写し、apiOrigin（開発用の Worker の https の URL）、discordClientId、manifestKey を書く。このファイルは Git の管理外。
3. Discord Developer Portal の OAuth2 の Redirects と、wrangler.toml の DISCORD_REDIRECT_URIS に `https://<拡張機能 ID>.chromiumapp.org/` を足し、開発用の Worker にデプロイし直す（`npx wrangler d1 migrations apply teampw-dev --remote`、`npx wrangler deploy`）。
4. `npm run build:extension` で dist/extension を作る。
5. Chrome で chrome://extensions を開き、右上の「デベロッパー モード」をオンにする。
6. 「パッケージ化されていない拡張機能を読み込む」で dist/extension を選ぶ。
7. ビルドし直したら、拡張機能のカードの再読み込みボタンを押す。

## 観点表で見てほしい所

| 観点 | 見てほしい所 |
|---|---|
| 鍵の置き場所 | background.ts の `unlocked`・`vaultKey` だけ。応答（handlers の戻り値）に CryptoKey もトークンも入れない。通しのテストで、応答と storage.local にトークンとマスターパスワードがないことを確かめる |
| メッセージの入口 | messages.ts の `acceptedSender` と `parseMessage`。handleMessage は、この2つを通る前に何もしない（放置の時刻も更新しない） |
| 最初の Vault | key-routes.ts の rotation_guard の行。確認と保存が1つのバッチで、グラントがあれば巻き戻る |
| 鍵の登録し直し | 前の鍵の revoked と承認待ちへの戻しが同じバッチ（`changes() > 0`）。5分以内の TOTP の確認 |
| 放置のロック | handleMessage の checkIdle の位置（検査の後、処理の前）と onStartup |
| ビルド | 実際の接続先と key は extension.config.local.json だけ。src/extension/config.ts は仮の値 |
