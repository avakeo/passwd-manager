# Web ページ（W 系）：レビュー資料

- 日付：2026-11-01
- ブランチ：feat/web-page（feat/admin-generation-init から切った。P-08 の画面と判断待ち10・11の決定を含む）
- 決定：判断待ち10（API とは別の Worker の静的アセットとして配る）、11（Web ページではセッションの一覧だけ。無効化は拡張機能）
- 仕様：docs/仕様書.md「Webページの配信」（2026-11-01 追記）、「画面の分担」、テスト項目 W-01〜W-07
- テスト：`npm test` 635件すべて成功、`npm run typecheck` 成功

## 変更したファイル

| ファイル | 中身 |
|---|---|
| src/api/auth-routes.ts、env.ts、app.ts | redirect_uri のオリジンが WEB_ORIGIN なら Web 用（読み取り専用）のセッション。TOTP 未登録なら 403。CORS のオリジンを、コードの仮の値から Workers の設定（WEB_ORIGIN）に移した |
| src/web/worker.ts（新規） | Web ページを配る Worker。すべての応答にセキュリティのヘッダーを付け、http なら https へ転送する。API のオリジンの設定がおかしければ 500 |
| src/web/page/web-client.ts（新規） | ログイン（state と PKCE を sessionStorage に1回だけ置く）、TOTP、決めた GET の入口だけを呼ぶセッション（401 なら1回だけ更新） |
| src/web/page/app.ts、index.html、style.css、src/web/config.ts（新規） | メンバー、自分のセッション、監査ログ（管理者）を表で出す。textContent だけで描く |
| scripts/build-web.ts、tsconfig.web.json、web.config.example.json、wrangler.web.example.toml（新規） | `npm run build:web` で dist/web を作り、`npx wrangler deploy -c wrangler.web.toml` で配る |
| wrangler.example.toml | WEB_ORIGIN と、DISCORD_REDIRECT_URIS の Web ページの戻り先 |

## 対象のテスト ID ごとの結果

| ID | テスト | 結果 |
|---|---|---|
| W-01、W-02 | CORS は設定したオリジン1つだけ。設定を変えればそれだけ、設定がなければどこも許可しない。似たドメイン、http、`null` は許可しない | 成功 |
| W-03 | どの応答にも CSP（unsafe-inline・ワイルドカードなし）、HSTS、X-Frame-Options、nosniff、no-referrer、COOP、Permissions-Policy。API のオリジンの設定がおかしければページを返さない | 成功（2件） |
| W-04 | http なら、アセットを返さずに https へ 301 | 成功 |
| W-05 | ログを出さない（Worker にロガーを置かない） | コードの確認だけ |
| W-06 | Web ページの戻り先なら Web 用のセッション。書き込みは 403、/v1/me は秘密鍵の暗号文と KDF を返さない。拡張機能の戻り先なら今までどおり。state と検証値は1回だけ使い、戻ったら消す。state が違えば API に送らない | 成功（API 2件、ページ 3件） |
| W-07 | TOTP を登録していない人は Web ページでログインできない。リフレッシュしても Web 用のまま | 成功（API 2件、ページ 1件） |
| その他 | 監査ログは管理者がログインしてから5分だけ。決めた GET 以外は呼ばない。アクセストークンが切れたら1回だけ更新 | 成功 |
| ビルド | 設定の検査、出力に API と拡張機能のコードと Worker を入れない、innerHTML などとインラインのスクリプト・スタイルがない | 成功（3件） |

手元で `wrangler dev --local-protocol https` で配り、Playwright で開いて確かめた（リポジトリには入れていない）：CSP の違反がない、スタイルが効く、ログインのボタンで Discord の認可画面へ PKCE（S256）付きで移る、戻り先がおかしければ断って URL から認可コードを消す。

## わざと壊して確かめた結果

| 壊し方 | 落ちたテスト |
|---|---|
| 戻り先が Web ページでも、拡張機能用のセッションにする | W-06 |
| TOTP 未登録でも Web 用のログインを通す | W-07 |
| TOTP の一時トークンを拡張機能用で作る | W-06 |
| CORS のオリジンを前方一致で比べる | W-01・W-02 |
| Web 用のトークンの書き込みを止めない（auth.ts） | W-06 |
| 戻った後に sessionStorage の値を消さない | W-06（2件） |
| 決めた GET 以外も呼べるようにする | 決めた GET の入口だけ |
| 401 で更新しない | 更新のテスト |
| 置いた値の戻り先を確かめない | W-06 |
| http を転送しない | W-04 |
| API のオリジンの設定を確かめない | W-03 |
| CSP から frame-ancestors を外す、Referrer-Policy を外す | W-03 |

壊すたびに元に戻し、差分が残っていないことを確かめた。

## 手で確かめる項目（まだ確かめていない）

| 項目 | 確かめ方 |
|---|---|
| 設定 | wrangler.web.example.toml を wrangler.web.toml に、web.config.example.json を web.config.local.json に写して値を書く。API の wrangler.toml に WEB_ORIGIN と、DISCORD_REDIRECT_URIS に `<WEB_ORIGIN>/callback` を足す。Discord のアプリの OAuth2 の Redirects にも同じ戻り先を足す |
| デプロイ | `npx wrangler deploy`（API）、`npm run build:web`、`npx wrangler deploy -c wrangler.web.toml` |
| ログイン | Web ページで「Discord でログイン」→ TOTP のコード → メンバー、自分のセッション、監査ログ（管理者）が出る。アドレスバーに認可コードが残らない |
| ヘッダー | ブラウザの開発者ツールで、応答のヘッダーと、コンソールに CSP の違反がないこと |
| 拡張機能 | 拡張機能の「セッション」に「Web ページ」のセッションが出て、無効化できる |

## 残した課題

- Web ページを閉じても、サーバーのセッション（リフレッシュは7日）は残る。トークンはページのメモリだけにあるので、閉じた後は使われない。消したいときは拡張機能で無効化する（仕様書「Webページの配信」）。
- 監査ログの「操作した人」はメンバー ID のまま。名前に直すと読みやすいが、メンバー一覧と突き合わせるだけなので後回しにした。
- 本番のドメインを使うときは、DNS とカスタムドメインの設定が別に要る。
