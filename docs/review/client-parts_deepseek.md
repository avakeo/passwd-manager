# 攻撃者の目線レビュー：拡張機能の部品（自動入力・CSV・カスタム項目・パスワード生成・クリップボード）

- 日付：2026-10-17
- 対象：ブランチ feat/client-parts（`src/client/` の5ファイルと、その仕様・テスト）
- 参照：docs/仕様書.md（「拡張機能と自動入力の方針」「アイテムの項目」「パスワード生成」「CSVインポート」、E/C/I のテスト表）、docs/判断待ち_codex.md、docs/review/phase-1.md の文体
- 前提：攻撃者は、利用者に開かせる Web ページ（フィッシングのページを含む）と、利用者に読み込ませる CSV の中身を自由に作れる。サーバー、端末、マスターパスワードは攻撃者の手にない
- 見たファイル：`src/client/autofill-policy.ts`、`src/client/clipboard-policy.ts`、`src/client/csv-import.ts`、`src/client/item-data.ts`、`src/client/password.ts`、`tests/client/*.test.ts`、`src/crypto/random.ts`
- この文書は「どこが・なぜ危ないか」だけを示す。本体のコードの直し方は書かない。

## 結論

自動入力のオリジン照合は素直で堅く、指定された抜け道（国際化ドメイン、ポート、末尾のドット、大文字、`@`、IP、http、iframe、www の有無、標準ポートの省略）は**すべて塞がっているか、安全側（一致しない）に倒れている**。平文が漏れる経路は見つからなかった。重いのは、**CSV が「正規オリジンの認証情報を植え付ける」経路**になる点と、**見出し1つの不備で取り込み全体が止まる**点。カスタム項目の型検査とクリップボードの消去判定は、呼び出し側の使い方次第で効きが弱い。

## 指摘一覧

| 番号 | 重大度 | 攻撃の手順 | 狙われる箇所 | 再現テストの内容 |
|---|---|---|---|---|
| 1 | 中 | ①Chrome/Proton/1Password 形式で CSV を作る。②`url` 列に実在サイトの正規オリジン（例 `https://wiki.example.com`）を入れる（`originForSavedUrl` は正規 https を通す）。③`username`/`password`/`notes` に攻撃者が決めた値を入れる。④プレビューは文字列を見せるだけなので正規サイトの行に見える。⑤重複判定は「タイトル＋ユーザー名（小文字）＋URL 集合」で**パスワードを見ない**ので、既存と同タイトル・同ユーザー名・同 URL にすると印だけ付き、フェーズ3で「置き換え」を選ばせれば正規の認証情報を攻撃値で上書きできる。⑥自動入力は正規オリジンに一致するため、植えたパスワードが実サイトに入る | `csv-import.ts` `importCsvPreview`（URL は `originForSavedUrl` を通すだけ）・`duplicateKey`（password を見ない）、`item-data.ts` `validateItem`、`autofill-policy.ts` `canAutofill` | `importCsvPreview('name,url,username,password\nWiki,https://wiki.example.com/login,me@x.test,attackerpw\n','chrome')` の item が `urls:['https://wiki.example.com']`・`password:'attackerpw'` で通り、`duplicate:false` のまま。同じ title/username/urls を既存に渡すと、パスワードが違っても `duplicate:true` になる（＝置換しうる）ことを assert。続けて `canAutofill` が `https://wiki.example.com` で true になることを assert |
| 2 | 低 | ①CSV の見出しに、未対応列も含めて同名の列を2つ入れる（`name,url,username,password,note,note`、または空名2つ）。②`columns()` は使用可否に関係なく重複見出しで `TypeError`。③`importCsvPreview` は捕まえないので**1行の不備で取り込み全体が例外停止**（仕様の「壊れた行は報告して全体は止めない」I-02/M-03 に違反） | `csv-import.ts` `columns()`（`new Set(h).size !== h.length` で無条件 throw）・`importCsvPreview`（try/catch なし） | `importCsvPreview('name,url,username,password,note,note\nX,https://a.example,u,p,n,n\n','chrome')` が throw することを assert。あるべきは「重複見出し」を警告して後続を読む。空名2列も同様 |
| 3 | 低 | ①呼び出し側がカスタム項目の `type` に文字列以外（`new String('hidden')`、`toString` を上書きしたオブジェクト）を入れる。②`checkField` は `includes(String(value.type))` で**文字列化して通す**が `value.type` を正規化しない。③`validateItem` は元オブジェクトをそのまま返すので `field.type === 'hidden'` が false になり、非表示項目が表示扱い・コピー後1分で消えない（E-12 の対象外） | `item-data.ts` `checkField`（`String()` 比較）・`validateItem`（`return value as ClientItem`）、`clipboard-policy.ts` | `validateItem({type:'login',...,customFields:[{type:new String('hidden'),label:'L',value:'v'}]})` が例外にならず返り、返った `customFields[0].type === 'hidden'` が **false**（型取り違え）を assert。`__proto__` を自前キーに持つ JSON は `exactKeys` の長さ不一致で拒否されることも確認 |
| 4 | 低 | ①利用者がパスワード／非表示項目をコピー。②読み戻しが書き込み値と完全一致しない（末尾改行が落ちる、`\n`→`\r\n`、NUL 除去等）。③`shouldClearClipboard` は `currentText === copiedText` を要求するので false のままで、1分を過ぎても消えず、クリップボード履歴に残り続ける。④判定（true）と実際の消去は別処理なので、判定直後に別のコピーが入るとその新しい内容を消してしまう | `clipboard-policy.ts` `shouldClearClipboard`（完全一致・下限時刻のみ）、呼び出し側の読み書きタイミング | `shouldClearClipboard({copiedText:'pw\n',currentText:'pw',copiedAt:0,now:61000})` が false（消えない）を assert。併せて「判定→別コピー→消去」の順で新しい内容が消える競合を模擬（消去直前の再読込が必要） |
| 5 | 低 | ①`canAutofill` は `pageUrl`・`livePageUrl`・`topFrame`・`documentId`・`popupInitiated`・`unlocked` を全部呼び出し側から受け取る。②呼び出し側が `pageUrl` と `livePageUrl` に同じ値（照合時の値）を渡すと、E-13 の「入力直前の再確認」が無条件成立。③`documentId`/`tabId` も同様に同じ出所から埋めれば固定の意味が消える。④E-08（Webページからの偽メッセージ）の入口はこの差分に無く、純関数では検知できない | `autofill-policy.ts` `canAutofill`、`docs/判断待ち_codex.md` #3 | `canAutofill({ ...ok, pageUrl:'https://wiki.example.com', livePageUrl:'https://wiki.example.com' })` が true（独立再取得を強制しない）を assert。メッセージハンドラを公開しない（ポップアップ起点のみ）ことを確かめる E-08 テストがこの差分に無いことを示す |
| 6 | 低 | ①パスワード生成で数字・記号を有効にする。②`generatePassword` は選んだ集合から一様に選ぶだけで**各文字種を1文字以上含む保証がない**（判断待ち #1 の決定どおり）。③数字・記号が1つも無い結果が出うる。サイトに弾かれ、「トグルを有効にしたのに」と映る。偏り自体は棄却サンプリングで無く、エントロピー表示も一様集合に対しては正確 | `password.ts` `generatePassword`（クラス別保証なし）、`passwordEntropyBits` | 多数回の生成や `alphabet:'ab1'` で、ある文字種が0回の結果がありうることを示す（偏り検査＝3文字集合で各頻度が妥当域、は既存どおり通る） |
| 7 | 低 | ①攻撃者が巨大な CSV（数百万行・1セル巨大）を作る。②`importCsvPreview` は行数・総バイト数に上限が無く `parseCsv` は全体を1パスで蓄積。③プレビュー生成でメモリ・時間を食い、全画面ページが固まる／タブが落ちる（ローカル DoS）。解析は線形で、閉じ忘れ引用符の回復も深い再帰にはならない | `csv-import.ts` `parseCsv`・`importCsvPreview`（上限なし） | 100k 行 CSV が線形（実測 ~600ms）で通ることと、行数・総サイズの上限が無いことを assert。`'"' + '\n'.repeat(200000)` 等で `RangeError`（再帰暴走）にならないことも確認 |

## 試したが成立しなかったもの（指定された抜け道。根拠は実行して確認）

| 試した攻撃 | 結果 | 根拠 |
|---|---|---|
| 見た目が似た国際化ドメイン（`wıki.example.com`、`wiki.exаmple.com`） | 拒否 | `new URL` が IDNA で punycode 化（`https://xn--wki-jua.example.com` 等）し、保存オリジンと別オリジンになる |
| 全角ピリオド等の混入（`wiki.example.com。evil.test`） | 拒否 | `wiki.example.com.evil.test` に正規化され別オリジン |
| ポート（`:8443`）と省略（`:443`） | 仕様どおり | `:443` は無指定と同一に正規化（一致）、`:8443` は別オリジン（拒否） |
| 末尾のドット（`wiki.example.com.`） | 拒否（安全側） | `new URL` は末尾ドットを保持し `https://wiki.example.com.` の別オリジン |
| 大文字（`WIKI.example.com`） | 一致（正しい） | ホストは小文字化される |
| `@` を含む（`user@evil.test`、`wiki.example.com@evil.test`） | 拒否 | `url.username` が非空 → `httpsOrigin` が undefined |
| タブ／改行の混入（`wiki.example.com\t.evil.test`） | 拒否 | パーサが除去し別ホスト |
| IP アドレス・IPv6（`[0:0:0:0:0:0:0:1]`） | 正規化して比較 | `[::1]` に正規化。保存側も同じ関数で正規化 |
| http | 拒否 | `protocol !== 'https:'` |
| iframe | 拒否 | `topFrame` が false（呼び出し側が正しく渡す前提） |
| www の有無 | 仕様どおり不一致 | ホスト完全一致 |
| CSV に `javascript:`／`data:`／`http:` の URL | ブロック | `originForSavedUrl` が throw → 行はエラー、アイテムは作られない。`validateItem` も `originForSavedUrl(url)===url` を強制（実測で `invalid item`） |
| カスタム項目の `__proto__` | CSV/JSON 経由は拒否 | `JSON.parse` の `__proto__` は自前キーになり `exactKeys` の長さ不一致で拒否。`setPrototypeOf` 由来は素通りするがグローバル汚染は起きない |
| アイテムのサイズ上限 | 有効 | `JSON.stringify` の UTF-8 バイト数 > 65,532 で `RangeError`（実測 200,000 文字で `item too large`） |
| パスワード生成の偏り | 無し | `value >= limit` を捨てる棄却サンプリング。既存テスト（3文字集合・6万回）で頻度が妥当域 |
| 壊れた CSV による解析停止 | 起きない | 400k 行規模・閉じ忘れ引用符でも停止も深い再帰も無し |

## 補足

- フェーズ3で必ず効く：プレビュー／編集画面で CSV 由来の値を HTML として解釈しない（`docs/判断待ち_codex.md` 末尾）。この差分は文字列を返すだけで描画はフェーズ3。
- 一括送信時の ID 割り当て（クライアント生成）で衝突しないこと。重複を「置き換え」で送ると #1 の上書きが現実になる。
- CSV 専用のテスト ID が未定で I-02 を流用している（判断待ち）。
- 自動入力の安全性はこの純関数ではなく呼び出し側（メッセージ入口、URL・文書 ID の取得元）に依存する。#5 のとおり E-08 のテストがこの差分に無い。
- #1・#3・#4 はすべて「呼び出し側／後続フェーズの使い方」で効きが変わるので、フェーズ3の画面設計とセットで確認したい。
