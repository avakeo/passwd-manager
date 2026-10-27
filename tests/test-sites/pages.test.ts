// 自動入力の手動確認用テストサイト（test-sites/worker.ts）の検査。
// Worker の fetch を直接呼び、パスごとの応答と、期待する要素・CSP を確かめる。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../../test-sites/worker.ts';

const SITE_A = 'https://site-a.example.workers.dev';
const SITE_B = 'https://site-b.example.workers.dev';
const PAGES = ['/', '/simple', '/two-step', '/spa', '/hidden', '/iframe', '/navigate'] as const;

function request(path: string, otherOrigin: string | undefined = SITE_B, method = 'GET') {
  return worker.fetch(new Request(`${SITE_A}${path}`, { method }), { OTHER_ORIGIN: otherOrigin });
}

async function page(path: string, otherOrigin: string | undefined = SITE_B) {
  const res = await request(path, otherOrigin);
  return { res, text: await res.text() };
}

function csp(res: Response): string {
  const value = res.headers.get('content-security-policy');
  assert.ok(value, 'Content-Security-Policy がある');
  return value;
}

function nonceOf(res: Response): string {
  const match = /'nonce-([0-9a-f]{32})'/.exec(csp(res));
  assert.ok(match, 'CSP に nonce がある');
  return match[1]!;
}

test('テストサイト：/ は各ページへのリンクを返す', async () => {
  const { res, text } = await page('/');
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type') ?? '', /^text\/html; charset=utf-8$/);
  for (const path of PAGES.filter((path) => path !== '/')) {
    assert.ok(text.includes(`href="${path}"`), `${path} へのリンクがある`);
  }
});

test('E-01 /simple：ユーザー名とパスワードの欄が1画面にあり、送信しても通信しない', async () => {
  const { res, text } = await page('/simple');
  assert.equal(res.status, 200);
  for (const fragment of [
    'id="login-form"',
    'id="username"',
    'name="username"',
    'autocomplete="username"',
    'id="password"',
    'name="password"',
    'type="password"',
    'autocomplete="current-password"',
    'E-01 通常のログインフォーム。期待：入力される',
  ]) {
    assert.ok(text.includes(fragment), fragment);
  }
  assert.match(text, /preventDefault\(\)/);
  assert.ok(text.includes('password.value.length'), 'パスワードは長さだけを出す');
  assert.ok(text.includes('result.textContent'), '結果は textContent で出す');
  assert.ok(text.includes(`nonce="${nonceOf(res)}"`));
});

test('E-01 の変形 /two-step：最初はユーザー名だけ。次へでパスワード欄が出る', async () => {
  const { res, text } = await page('/two-step');
  assert.equal(res.status, 200);
  assert.ok(text.includes('id="username"'));
  assert.ok(text.includes('autocomplete="username"'));
  assert.ok(text.includes('id="password-step"'));
  assert.match(text, /id="password-step"[^>]*\shidden/);
  assert.ok(text.includes('id="password"'));
  assert.ok(text.includes('autocomplete="current-password"'));
  assert.ok(text.includes('次へ'));
  assert.ok(text.includes('E-01（変形）二段階のログインフォーム。期待：入力の様子を記録する'));
  assert.ok(text.includes('step.hidden = false'), '次へでパスワード欄を出す');
  assert.ok(text.includes(`nonce="${nonceOf(res)}"`));
});

test('E-01 の変形 /spa：1秒後に JavaScript でフォームを描く', async () => {
  const { res, text } = await page('/spa');
  assert.equal(res.status, 200);
  assert.ok(text.includes('id="app"'));
  assert.ok(text.includes('1秒後にフォームを表示します'));
  assert.ok(text.includes('E-01（変形）JavaScript で描くフォーム。期待：入力の様子を記録する'));
  assert.ok(!text.includes('<form'), '最初の HTML にはフォームを書かない');
  assert.match(text, /createElement\('form'\)/);
  assert.ok(text.includes('1000'), '1秒後に描く');
  assert.ok(text.includes('current-password'));
  assert.ok(text.includes('replaceChildren'));
  assert.ok(text.includes(`nonce="${nonceOf(res)}"`));
});

test('E-06 /hidden：見えない欄には入力されないよう、4種類の隠し方がある', async () => {
  const { res, text } = await page('/hidden');
  assert.equal(res.status, 200);
  assert.ok(text.includes('E-06 見えない入力欄。期待：見えない欄には入力されない'));
  assert.ok(text.includes('id="password"'));
  assert.ok(text.includes('autocomplete="current-password"'));
  for (const name of ['password_display_none', 'password_visibility_hidden', 'password_zero_size', 'password_offscreen']) {
    assert.ok(text.includes(`name="${name}"`), name);
  }
  assert.match(text, /\.field-display-none\s*\{[^}]*display:\s*none/);
  assert.match(text, /\.field-visibility-hidden\s*\{[^}]*visibility:\s*hidden/);
  assert.match(text, /\.field-zero-size\s*\{[^}]*width:\s*0/);
  assert.match(text, /\.field-offscreen\s*\{[^}]*left:\s*-10000px/);
  assert.ok(text.includes('input[name="password"]'), '結果には見える欄だけを使う');
});

test('E-02 /iframe：もう一方のサイトの /simple を埋め込む。未設定ならその旨を出す', async () => {
  const configured = await page('/iframe');
  assert.equal(configured.res.status, 200);
  assert.ok(configured.text.includes('E-02 iframe 内のログインフォーム。期待：iframe の中には入力されない'));
  assert.ok(configured.text.includes('<iframe'));
  assert.ok(configured.text.includes(`src="${SITE_B}/simple"`));
  assert.ok(csp(configured.res).includes(`frame-src ${SITE_B}`));
  assert.ok(csp(configured.res).includes("frame-ancestors 'none'"));

  const unset = await page('/iframe', '');
  assert.equal(unset.res.status, 200);
  assert.ok(unset.text.includes('OTHER_ORIGIN が未設定'));
  assert.ok(!unset.text.includes('<iframe'));
});

test('E-13 /navigate：3秒後に移動するボタン。未設定ならその旨を出す', async () => {
  const configured = await page('/navigate');
  assert.equal(configured.res.status, 200);
  assert.ok(configured.text.includes('E-13 入力前の遷移。期待：移った先には入力されない'));
  assert.ok(configured.text.includes('3秒後に移動する'));
  assert.ok(configured.text.includes(`"${SITE_B}"`));
  assert.ok(configured.text.includes("'/simple'"));
  assert.ok(configured.text.includes('3000'));
  assert.ok(configured.text.includes('window.location.assign'));

  const unset = await page('/navigate', '');
  assert.equal(unset.res.status, 200);
  assert.ok(unset.text.includes('OTHER_ORIGIN が未設定'));
  assert.ok(!unset.text.includes('<button'));
});

test('CSP：全ページで default-src none、script/style は nonce、frame-ancestors を決める', async () => {
  for (const path of PAGES) {
    const { res } = await page(path);
    const value = csp(res);
    assert.ok(value.includes("default-src 'none'"), `${path}: default-src`);
    assert.ok(value.includes("script-src 'nonce-"), `${path}: script-src`);
    assert.ok(value.includes("style-src 'nonce-"), `${path}: style-src`);
    const ancestors = path === '/simple' ? SITE_B : "'none'";
    assert.ok(value.includes(`frame-ancestors ${ancestors}`), `${path}: frame-ancestors`);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  }
});

test('/simple だけがもう一方のサイトからの iframe 埋め込みを許す', async () => {
  const { res } = await page('/simple');
  assert.ok(csp(res).includes(`frame-ancestors ${SITE_B}`));
  assert.ok(!csp(res).includes("frame-ancestors 'none'"));

  const unset = await page('/simple', '');
  assert.ok(csp(unset.res).includes("frame-ancestors 'none'"), '未設定なら埋め込ませない');
});

test('CSP の nonce は応答ごとに変わり、HTML の style と script に付く', async () => {
  const first = await page('/');
  const second = await page('/');
  assert.notEqual(nonceOf(first.res), nonceOf(second.res));
  assert.ok(first.text.includes(`<style nonce="${nonceOf(first.res)}">`));

  const simple = await page('/simple');
  assert.ok(simple.text.includes(`<script nonce="${nonceOf(simple.res)}">`));
});

test('どのページも外部の CSS・フォント・画像・スクリプト・解析を読み込まない', async () => {
  for (const path of PAGES) {
    const { text } = await page(path);
    assert.ok(!/<(?:link|img|script)[^>]+(?:src|href)=["']https?:/i.test(text), path);
    assert.ok(!text.includes('@import'), path);
    assert.ok(!text.includes('fonts.googleapis.com'), path);
    assert.ok(!text.includes('innerHTML'), path);
    assert.ok(!text.includes('console.'), `${path}: パスワードを console に出さない`);
  }
});

test('存在しないパスは 404、GET 以外は 405 を返す', async () => {
  const notFound = await page('/unknown');
  assert.equal(notFound.res.status, 404);
  assert.ok(notFound.text.includes('ページが見つかりません'));
  assert.ok(csp(notFound.res).includes("frame-ancestors 'none'"));

  const post = await request('/simple', SITE_B, 'POST');
  assert.equal(post.status, 405);
  assert.equal(post.headers.get('allow'), 'GET, HEAD');
});

test('HEAD は本文を返さず、GET と同じヘッダーを返す', async () => {
  const res = await request('/simple', SITE_B, 'HEAD');
  assert.equal(res.status, 200);
  assert.equal(await res.text(), '');
  assert.ok(csp(res).includes(`frame-ancestors ${SITE_B}`));
});
