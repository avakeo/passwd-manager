# テスト用ログインページ（test-sites）

拡張機能の自動入力を手で確かめるための、小さな静的サイトです。同じ `worker.ts` を **site-a**（teampw-site-a）と **site-b**（teampw-site-b）の2つの Cloudflare Worker としてデプロイし、オリジンが違う2つのサイトとして使います。拡張機能と API のコードには触れません。

- 外部の CSS・フォント・画像・スクリプト・アクセス解析は読み込みません。スタイルは各ページの `<style>` に書いています。
- 応答には `Content-Security-Policy` を付け、スクリプトとスタイルは nonce で許可しています。
- フォームはどこにも送信しません。`submit` を `preventDefault()` で止め、ページの中に「受け取ったユーザー名：〜、パスワードの長さ：〜文字」とだけ出します。パスワードそのものは画面にも console にも出しません。
- **本物のパスワードは入れないでください。** 確認には使い捨ての値を使ってください。

## ファイル

| ファイル | 中身 |
| --- | --- |
| `test-sites/worker.ts` | Worker の入口。パスごとに HTML を返す |
| `test-sites/wrangler.example.toml` | 設定の例（環境 a が site-a、環境 b が site-b） |
| `test-sites/README.md` | このファイル |
| `tests/test-sites/pages.test.ts` | 各パスが 200 を返し、決めた要素があることを確かめるテスト |

## ページ一覧

各ページの上に、ページの名前、テスト ID、期待する結果を出しています。`/iframe` と `/navigate` は、環境変数 `OTHER_ORIGIN` に「もう一方のサイト」のオリジンが入っているときだけ、そのサイトを使います。

| パス | 中身 | テスト ID と期待する結果 |
| --- | --- | --- |
| `/` | 下のページへのリンクの一覧 | なし |
| `/simple` | ユーザー名とパスワードの欄が1画面にある、ふつうのフォーム | E-01：入力される |
| `/two-step` | 最初はユーザー名だけ。「次へ」を押すと、同じページの中でパスワードの欄が出る | E-01 の変形：入力の様子を記録する |
| `/spa` | 読み込みの1秒後に、JavaScript でフォームを描く | E-01 の変形：入力の様子を記録する |
| `/hidden` | 見える欄のほかに、`display:none`、`visibility:hidden`、大きさ0、画面の外の4種類の見えない欄がある。見えない欄の name は `password_display_none` などのパスワードらしい名前にしている | E-06：見えない欄には入力されない |
| `/iframe` | もう一方のサイト（site-a なら site-b）の `/simple` を iframe で埋め込む | E-02：iframe の中には入力されない |
| `/navigate` | 「3秒後に移動する」ボタン。押すと3秒後に、もう一方のサイトの `/simple` に移る | E-13：移った先には入力されない |

`OTHER_ORIGIN` が空のときは、`/iframe` と `/navigate` に「OTHER_ORIGIN が未設定」と出します。`http` と `https` のオリジンを受け付けますが、拡張機能の自動入力は https だけが対象なので、手で確かめるときはデプロイした https の URL を使ってください。

## デプロイの手順

前提：Node.js 22.16 以上、Cloudflare のアカウント、`npm ci` が済んでいること。

1. Cloudflare にログインする。

   ```sh
   npx wrangler login
   ```

2. 設定の例をコピーする。`test-sites/wrangler.toml` はコミットしない。

   ```sh
   cp test-sites/wrangler.example.toml test-sites/wrangler.toml
   ```

3. `test-sites/wrangler.toml` の `OTHER_ORIGIN` の `example` を、自分の workers.dev のサブドメインに変える。workers.dev の URL は `https://<Worker の名前>.<サブドメイン>.workers.dev` になるので、相手の URL はデプロイの前に分かる。

4. 2つのサイトをデプロイする。

   ```sh
   npx wrangler deploy --config test-sites/wrangler.toml --env a
   npx wrangler deploy --config test-sites/wrangler.toml --env b
   ```

   表示された URL が、`OTHER_ORIGIN` に書いた値と同じか確かめる（例：`https://teampw-site-a.example.workers.dev`）。

5. site-a の `/` を開き、各ページへのリンクと表示を確かめる。

手元で見た目だけを確かめる場合は `npx wrangler dev --config test-sites/wrangler.toml --env a` も使えます。ただし `wrangler dev` は既定で http になり、拡張機能の自動入力の対象外です。E-02 と E-13 は、デプロイした https の2つのサイトで確かめてください。

## 手で確かめるときの手順

1. 拡張機能に site-a のオリジンと、使い捨てのユーザー名・パスワードを登録する。
2. site-a の各ページを開き、ポップアップから自動入力を実行する。
3. ページの下に出る「受け取ったユーザー名：〜、パスワードの長さ：〜文字」で、入力されたかを確かめる。

ページごとの見方：

- `/simple`：ユーザー名とパスワードの両方が入る（E-01）。
- `/two-step`：「次へ」を押す前はユーザー名だけ、「次へ」を押した後にパスワードの欄が出る。入力の様子を記録する。
- `/spa`：1秒待ってフォームが出てから、入力の様子を記録する。
- `/hidden`：見えているユーザー名とパスワードだけが入り、`password_display_none`、`password_visibility_hidden`、`password_zero_size`、`password_offscreen` には入らない（E-06）。送信すると、2行目に「見えない欄：4つとも空」か、入力された欄の名前が出る。
- `/iframe`：site-a のページから自動入力を実行しても、iframe の中の site-b の `/simple` には入らない（E-02）。site-b にも別のアイテムを登録しておくと、オリジン不一致の確認になる。
- `/navigate`：「3秒後に移動する」を押し、3秒の間にポップアップから自動入力を始める。site-b の `/simple` に移った後に、site-a のアイテムが入らないことを確かめる（E-13）。site-b 側にもアイテムを登録しておくと、移った先で別のアイテムを選んだ場合との区別がしやすい。

## 作っていないもの

- **E-03（http のページ）**：workers.dev は常に https で、Workers から訪問者に平文の http を返すことはできません。http のオリジンを別に用意する必要があるため、このサイトには作っていません。
- **E-05（www の有無の違い）**：workers.dev の URL には www 付きの別ホストがなく、www の有無を作り分けられません。独自ドメインを2つ用意する必要があるため、このサイトには作っていません。
- **E-04（似たドメイン、サブドメイン、ポート違い）**：site-a と site-b のオリジンが違うことで、登録したオリジン以外には入力されないことを代わりに確かめます。ただし、同じ登録可能ドメインのサブドメイン、見た目が似たドメイン、ポートだけが違う URL のすべてを網羅するものではありません。それらは実際のドメインを用意して別に確かめる必要があります。

このサイトが対象にしているのは E-01、E-02、E-06、E-13 と E-01 の変形です。E-07 以降のうち、ページを必要としないもの（ロック中の操作、クリップボード、Service Worker の停止など）は拡張機能側の別の確認で扱います。
