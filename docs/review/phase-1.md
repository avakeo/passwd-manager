# フェーズ1 Discord ログイン、Bot によるロール確認、セッション発行、TOTP：レビュー資料

- 日付：2026-10-17
- ブランチ：feat/discord-login
- 計画：docs/実装状況.md の8章。判断待ちの8件は案どおりに決定し、仕様書に反映した（docs/判断待ち.md の決定済み）
- テスト：`npm test` 273件すべて成功（認可の表は1マス1テストで104件）、`npm run typecheck` 成功

## 変更したファイル

| ファイル | 中身 |
|---|---|
| src/client/discord-login.ts | ログインの開始（state と code_verifier は乱数32バイト、S256 の code_challenge、スコープは identify だけ）と、戻ってきた URL の state と戻り先の照合。依存ゼロ |
| src/api/discord.ts | トークンの交換（クライアントシークレットと PKCE の検証値）、/users/@me、Bot でのロールの確認。Discord の拒否は 400、障害は 502 |
| src/api/auth-routes.ts | ログイン、更新、TOTP（一時トークンと再確認）、ログアウト、セッションの一覧と無効化、TOTP の登録・確定・解除 |
| src/api/totp.ts | RFC 6238（WebCrypto の HMAC-SHA1）、base32、otpauth の URI、シークレットの暗号化（形式とアルゴリズムID 付き、AAD にメンバーID）、回復コード |
| src/api/auth.ts | 認証（セッション、メンバー、TOTP の有無を1回の結合クエリで）と、認可の表（authorize）、再確認の判定（requireRecentTotp） |
| src/api/app.ts、env.ts、json.ts、problem.ts | 公開の入口の扱い、Workers の設定の型、本文の読み方、429 と 502 |
| migrations/0002_auth.sql | members に TOTP の登録途中と失敗の回数、sessions にリフレッシュトークンの期限・直前のハッシュ・TOTP の確認時刻、auth_challenges |
| tests/helpers/fake-discord.ts | 偽の Discord（fetch を置き換える） |
| tests/helpers/totp-reference.ts | src を使わない TOTP の計算（node:crypto） |
| wrangler.example.toml、scripts/discord-login-check.ts | 例の設定と、本物の Discord で手で確かめる道具 |
| package.json、package-lock.json | wrangler 4.147.0（開発依存、版を固定。公開から2週間以上たった版） |

## テスト ID ごとの結果

| ID | テスト | 結果 |
|---|---|---|
| A-01 | 戻ってきた URL の state が違う・ない・空・1文字違い・2つある、なら拒否。戻り先の違い、コードなし、利用者の拒否も拒否 | 成功 |
| A-02 | PKCE の検証値が違うと Discord が拒否し、ログインも 400（検証値を Discord に渡していることも確認）。認可コードの2回目の使用も 400 | 成功 |
| A-03 | ロールがない、ロールが空、サーバーにいない人は 403。メンバーの行もセッションも作らない | 成功 |
| A-04 | ロールを外された後、サーバーから抜けた後の更新は 403 で、セッションを無効にする。ロールを戻しても無効のまま | 成功 |
| A-05、A-06 | 期限切れのアクセストークン・リフレッシュトークン（更新しても延びない）、無効化されたセッションは 401 | 成功 |
| A-07 | ログアウトの後は、アクセストークンもリフレッシュトークンも 401 | 成功 |
| A-08 | 間違ったコードを5回送ると、正しいコードでも 429。再確認でも同じ数え方。15分たてば通る | 成功 |
| A-09 | 使ったコード、それより前のステップのコードは拒否。次のステップ（前後1ステップまで）は通る | 成功 |
| A-10 | 再確認の判定（単体テスト）：一度も確かめていない、5分より前、未来の時刻は 403。5分ちょうどまでは通る | 成功 |
| A-11 | TOTP を登録していない管理者は、ログインで登録を求められ、GET /v1/me・Vault・アイテムの読み書き・セッションの一覧が 403。登録した後は使える | 成功 |
| A-12 | 使用済みのリフレッシュトークンで 401、正規の利用者の新しいトークンも含めてセッションごと無効 | 成功 |
| A-13 | 許可していない redirect_uri は 400 で、Discord に問い合わせもしない | 成功 |
| A-14 | ログインの応答、D1 の全表、ログ（console）に、Discord のアクセストークン・クライアントシークレット・Bot のトークンが残らない。シークレットはトークンの交換、Bot のトークンはメンバーの取得だけに使う | 成功 |
| Z-01 | 承認待ちは /v1/me などだけで、Vault とアイテムは 403（ログインの通しのテストと、認可の表） | 成功 |
| Z-03 | 他人のセッションは一覧に出ず、無効化は 404。自分の別のセッションは無効化できる | 成功 |
| Z-06 | 削除済みは全エンドポイントで 403、ログインもできない | 成功 |
| Z-07 | Web 用のトークンは GET だけ（書き込み、ログアウト、TOTP の操作は 403） | 成功 |

ほかに、TOTP の中身（RFC 6238 付録 B のベクタ）、TOTP の暗号文の形（先頭の形式 0x01・アルゴリズムID 0x01、AAD のメンバーID、知らない形式の拒否）、回復コード（10個、80ビット以上、1回だけ）、一時トークン（5分、1回だけ、セッションとしては使えない）、TOTP の登録と解除、Discord の障害（502）のテストがある。

## 認可の表（全マスを tests/api/authz-matrix.test.ts で自動テストにしている）

ok は許可（401・403 にならない）、数字はその番号で拒否。マスごとにデータベースを作り直して確かめる。

| エンドポイント | 未ログイン | TOTP 待ち | 承認待ち | メンバー | 管理者（TOTP 未登録） | 管理者 | 削除済み | Web 用（メンバー） |
|---|---|---|---|---|---|---|---|---|
| POST /v1/auth/logout | 401 | 401 | ok | ok | ok | ok | 403 | 403 |
| GET /v1/me | 401 | 401 | ok | ok | 403 | ok | 403 | ok |
| GET /v1/me/sessions | 401 | 401 | ok | ok | 403 | ok | 403 | ok |
| DELETE /v1/me/sessions/{id} | 401 | 401 | ok | ok | 403 | ok | 403 | 403 |
| POST /v1/me/totp | 401 | 401 | ok | ok | ok | ok | 403 | 403 |
| POST /v1/me/totp/confirm | 401 | 401 | ok | ok | ok | ok | 403 | 403 |
| DELETE /v1/me/totp | 401 | 401 | ok | ok | 403 | 403 | 403 | 403 |
| POST /v1/auth/totp（再確認、Bearer 付き） | 400 | 401 | ok | ok | 403 | ok | 403 | 403 |
| GET /v1/vault | 401 | 401 | 403 | ok | 403 | ok | 403 | ok |
| GET /v1/items | 401 | 401 | 403 | ok | 403 | ok | 403 | ok |
| POST /v1/items | 401 | 401 | 403 | ok | 403 | ok | 403 | 403 |
| PUT /v1/items/{id} | 401 | 401 | 403 | ok | 403 | ok | 403 | 403 |
| DELETE /v1/items/{id} | 401 | 401 | 403 | ok | 403 | ok | 403 | 403 |

- 公開の入口（POST /v1/auth/discord、POST /v1/auth/refresh、一時トークンでの POST /v1/auth/totp）は、Bearer なしで呼べ、不正な中身は 400・401 になることを別のテストで確かめる。
- 「TOTP 待ち」は、ログインの途中の一時トークンを Bearer として使おうとした状態。セッションではないので 401。
- 「POST /v1/auth/totp」の未ログインは、Bearer がないので一時トークンの形として読み、challenge_token がないので 400。
- 管理操作のエンドポイント（承認、削除、ロール変更、ローテーション、監査ログ）は、フェーズ4で作るときにこの表へ行を足す（Z-02、Z-05、A-10 のエンドポイントでのテスト）。

## わざと壊して確かめた結果

| 壊し方 | 落ちたテスト |
|---|---|
| TOTP を登録していない管理者の制限（authorize の1行）を外す | A-11 と、認可の表の「管理者（TOTP 未登録）」が 403 の行すべて（10件） |
| 使用済みのリフレッシュトークンの検知（1行）を外す | A-12 |

壊すたびに元に戻し、差分が残っていないことを確かめた。テストは実装より先に書き、実装がない状態で落ちることを確かめてから実装した。

## Discord の差し替え方

- src/api/discord.ts は本番でもテストでも同じ `fetch('https://discord.com/api/v10/...')` を呼ぶ。テストは `globalThis.fetch` を偽の Discord に置き換える。本番の入口（worker.ts、createApp）に差し込み口はない（guard.test.ts の検査はそのまま通る）。
- 偽の Discord は、クライアントシークレット、redirect_uri の一致、認可コードの1回だけの使用、PKCE の S256、Bot のトークンを本物と同じように確かめ、違えば本物と同じ形で拒否する。discord.com/api/v10 以外への通信はテストを失敗させる。
- 時刻は node:test の mock.timers で固定する。期待する TOTP のコードは src を使わずに計算する。

## 本物の Discord で手で確かめる項目

自動テストでは偽の Discord を使っているので、次は本物で確かめる（scripts/discord-login-check.ts と `npx wrangler dev`）。

| 項目 | 確かめ方 |
|---|---|
| トークンの交換が本物の Discord で通る（クライアントシークレット、PKCE、redirect_uri） | スクリプトでログインし、POST /v1/auth/discord が 200 になる |
| ロールを持たないアカウントが 403 になる | ロールを外した（または別の）アカウントでログインする |
| Bot がロールを読める。Server Members Intent が要るかどうか | インテントをオフのままでメンバーの取得が通るかを見て、結果を記録する（403 ならオンにする） |
| ロールを外した後のセッションの更新が 403 になる | ロールを外してから POST /v1/auth/refresh を呼ぶ |
| 管理者の TOTP の登録と、認証アプリでのコードの確認 | 最初の管理者を作った後、POST /v1/me/totp の otpauth の URI を認証アプリに入れ、確定とログインを試す |
| 実際の D1 でマイグレーションと書き込みが動く（バッチの中の changes() を含む） | `npx wrangler d1 migrations apply teampw-dev --local`（と --remote）の後、上の流れを通す |
| identity API の画面の流れ（拡張機能の chromiumapp.org への戻り） | フェーズ2の拡張機能で確かめる |
| esbuild と workerd の postinstall | npm が止めたままにしている。wrangler dev を使う前に、`npm install-scripts ls` で中身を見て、許可するかを決める |

## 観点表で見てほしい所

| 観点 | 見てほしい所 |
|---|---|
| Discord の秘密 | クライアントシークレットと Bot のトークンは Workers のシークレットだけ。Discord のアクセストークンは discord.ts の中だけで使い、保存も応答もしない |
| トークン | 乱数32バイト（crypto/random.ts の newToken）。D1 は SHA-256 だけ。更新のたびに作り直し、直前のリフレッシュトークンの再利用でセッションごと無効 |
| TOTP | 最後に使ったステップの書き込みは「それより前のときだけ」の条件付きの UPDATE で、同時の再利用も防ぐ。失敗の回数の UPDATE は更新前の値で計算される |
| 管理者の制限 | 管理者かつ TOTP 未登録なら、セッションの状態ではなくメンバーの状態から判定する（登録前に発行された古いセッションでも効く） |
| エラー | Discord の拒否は 400、Discord の障害は 502、TOTP の失敗はログインの途中は 401・ログイン後は 403、制限は 429。内部の詳細は返さない |
