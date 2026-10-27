// 自動入力の手動確認用のテストサイト。同じコードを2つの Worker（site-a と site-b）としてデプロイし、
// オリジンが違う2つのサイトとして使う。外部の CSS・フォント・画像・スクリプトは読み込まない。

export type Env = {
  /** もう一方のサイトのオリジン。例：https://site-b.example.workers.dev */
  OTHER_ORIGIN?: string;
};

type PageOptions = {
  title: string;
  heading: string;
  testLine?: string;
  body: string;
  script?: string;
  extraStyle?: string;
  status?: number;
  frameAncestors: string;
  frameSrc?: string;
  wide?: boolean;
};

const BASE_STYLE = `
*, *::before, *::after { box-sizing: border-box; }
html, body { margin: 0; }
body {
  min-height: 100vh;
  display: grid;
  place-items: center;
  padding: 24px;
  background: #ffffff;
  color: #111827;
  font-family: system-ui, -apple-system, "Segoe UI", "Hiragino Kaku Gothic ProN", "Noto Sans JP", sans-serif;
  line-height: 1.7;
}
.card {
  width: 100%;
  max-width: 360px;
  padding: 28px;
  background: #ffffff;
  border: 1px solid #d1d5db;
  border-radius: 12px;
  box-shadow: 0 10px 30px rgba(17, 24, 39, 0.08);
}
.card-wide { max-width: 520px; }
h1 { margin: 0 0 6px; font-size: 1.25rem; line-height: 1.4; }
.test-id { margin: 0 0 14px; color: #4b5563; font-size: 0.8125rem; }
p { margin: 12px 0; }
.field { margin: 14px 0; }
label { display: block; margin-bottom: 6px; font-size: 0.875rem; font-weight: 600; }
input[type="text"], input[type="password"] {
  width: 100%;
  padding: 10px 12px;
  border: 1px solid #9ca3af;
  border-radius: 8px;
  background: #ffffff;
  color: #111827;
  font: inherit;
}
input:focus { outline: 3px solid #93c5fd; outline-offset: 1px; border-color: #2563eb; }
button {
  width: 100%;
  margin-top: 4px;
  padding: 10px 14px;
  border: 0;
  border-radius: 8px;
  background: #1d4ed8;
  color: #ffffff;
  font: inherit;
  font-weight: 600;
  cursor: pointer;
}
button:hover { background: #1e40af; }
button:disabled { background: #6b7280; cursor: default; }
.result {
  min-height: 1.7em;
  margin: 16px 0 0;
  padding: 10px 12px;
  border-radius: 8px;
  background: #f3f4f6;
  font-size: 0.875rem;
  word-break: break-word;
}
.notice {
  margin: 16px 0 0;
  padding: 12px;
  border-radius: 8px;
  background: #fef3c7;
  color: #92400e;
  font-size: 0.875rem;
}
.links { margin: 16px 0 0; padding-left: 1.25rem; }
.links li { margin: 8px 0; }
a { color: #1d4ed8; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.875em; }
[hidden] { display: none !important; }
.field-display-none { display: none; }
.field-visibility-hidden { visibility: hidden; }
.field-zero-size { width: 0; height: 0; padding: 0; border: 0; margin: 0; opacity: 0; }
.field-offscreen { position: absolute; left: -10000px; top: auto; width: 1px; height: 1px; overflow: hidden; }
iframe { width: 100%; height: 520px; border: 1px solid #d1d5db; border-radius: 8px; background: #ffffff; }
`;

const FORM_SCRIPT = `(function () {
  const form = document.getElementById('login-form');
  const result = document.getElementById('result');
  if (!form || !result) return;
  form.addEventListener('submit', function (event) {
    event.preventDefault();
    const username = form.querySelector('input[name="username"]');
    const password = form.querySelector('input[name="password"]');
    const usernameValue = username && typeof username.value === 'string' ? username.value : '';
    const passwordLength = password && typeof password.value === 'string' ? password.value.length : 0;
    result.textContent = '受け取ったユーザー名：' + usernameValue + '、パスワードの長さ：' + passwordLength + '文字';
  });
})();`;

const TWO_STEP_SCRIPT = `(function () {
  const next = document.getElementById('next');
  const step = document.getElementById('password-step');
  if (next && step) {
    next.addEventListener('click', function () {
      step.hidden = false;
      next.hidden = true;
      const password = document.getElementById('password');
      if (password) password.focus();
    });
  }
})();
${FORM_SCRIPT}`;

const SPA_SCRIPT = `(function () {
  const app = document.getElementById('app');
  if (!app) return;

  function addField(form, id, labelText, type, autocomplete) {
    const field = document.createElement('div');
    field.className = 'field';
    const label = document.createElement('label');
    label.htmlFor = id;
    label.textContent = labelText;
    const input = document.createElement('input');
    input.id = id;
    input.name = id;
    input.type = type;
    input.autocomplete = autocomplete;
    input.required = true;
    field.append(label, input);
    form.append(field);
  }

  window.setTimeout(function () {
    const form = document.createElement('form');
    form.id = 'login-form';
    form.method = 'post';
    form.action = '';
    addField(form, 'username', 'ユーザー名', 'text', 'username');
    addField(form, 'password', 'パスワード', 'password', 'current-password');
    const button = document.createElement('button');
    button.type = 'submit';
    button.textContent = 'ログイン';
    form.append(button);
    const result = document.createElement('p');
    result.id = 'result';
    result.className = 'result';
    result.setAttribute('role', 'status');
    form.addEventListener('submit', function (event) {
      event.preventDefault();
      const username = form.querySelector('input[name="username"]');
      const password = form.querySelector('input[name="password"]');
      const usernameValue = username && typeof username.value === 'string' ? username.value : '';
      const passwordLength = password && typeof password.value === 'string' ? password.value.length : 0;
      result.textContent = '受け取ったユーザー名：' + usernameValue + '、パスワードの長さ：' + passwordLength + '文字';
    });
    app.replaceChildren(form, result);
  }, 1000);
})();`;

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function scriptJson(value: string): string {
  return JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

function randomNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let nonce = '';
  for (const byte of bytes) nonce += byte.toString(16).padStart(2, '0');
  return nonce;
}

function parseOtherOrigin(raw: string | undefined): string | null {
  const value = raw?.trim();
  if (!value) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
    if (!url.hostname || url.username || url.password) return null;
    return url.origin;
  } catch {
    return null;
  }
}

function renderPage(options: PageOptions): Response {
  const nonce = randomNonce();
  const testLine = options.testLine ? `<p class="test-id">${escapeHtml(options.testLine)}</p>` : '';
  const script = options.script ? `\n<script nonce="${nonce}">\n${options.script}\n</script>` : '';
  const extraStyle = options.extraStyle ? `\n${options.extraStyle}` : '';
  const cardClass = options.wide ? 'card card-wide' : 'card';

  const html = `<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(options.title)}</title>
<style nonce="${nonce}">${BASE_STYLE}${extraStyle}
</style>
</head>
<body>
<main class="${cardClass}">
<header>
<h1>${escapeHtml(options.heading)}</h1>
${testLine}
</header>
${options.body}
</main>${script}
</body>
</html>`;

  const directives = [
    "default-src 'none'",
    `script-src 'nonce-${nonce}'`,
    `style-src 'nonce-${nonce}'`,
    "base-uri 'none'",
    "form-action 'none'",
    `frame-ancestors ${options.frameAncestors}`,
  ];
  if (options.frameSrc) directives.push(`frame-src ${options.frameSrc}`);

  return new Response(html, {
    status: options.status ?? 200,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'content-security-policy': directives.join('; '),
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'cache-control': 'no-store',
    },
  });
}

function indexPage(): Response {
  return renderPage({
    title: 'テスト用ログインページ',
    heading: 'テスト用ログインページ',
    frameAncestors: "'none'",
    body: `<p>自動入力を手で確かめるためのページです。各ページの上に、テスト ID と期待する結果を出しています。</p>
<ul class="links">
<li><a href="/simple">/simple</a>（通常のログインフォーム）</li>
<li><a href="/two-step">/two-step</a>（二段階のログインフォーム）</li>
<li><a href="/spa">/spa</a>（1秒後に描くフォーム）</li>
<li><a href="/hidden">/hidden</a>（見えない入力欄）</li>
<li><a href="/iframe">/iframe</a>（もう一方のサイトの /simple を埋め込む）</li>
<li><a href="/navigate">/navigate</a>（3秒後に移動する）</li>
</ul>`,
  });
}

function simplePage(frameAncestors: string): Response {
  return renderPage({
    title: '通常のログインフォーム',
    heading: '通常のログインフォーム',
    testLine: 'E-01 通常のログインフォーム。期待：入力される',
    frameAncestors,
    script: FORM_SCRIPT,
    body: `<form id="login-form" method="post" action="">
<div class="field">
<label for="username">ユーザー名</label>
<input id="username" name="username" type="text" autocomplete="username" required>
</div>
<div class="field">
<label for="password">パスワード</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
</div>
<button type="submit">ログイン</button>
</form>
<p id="result" class="result" role="status"></p>`,
  });
}

function twoStepPage(): Response {
  return renderPage({
    title: '二段階のログインフォーム',
    heading: '二段階のログインフォーム',
    testLine: 'E-01（変形）二段階のログインフォーム。期待：入力の様子を記録する',
    frameAncestors: "'none'",
    script: TWO_STEP_SCRIPT,
    body: `<form id="login-form" method="post" action="">
<div class="field">
<label for="username">ユーザー名</label>
<input id="username" name="username" type="text" autocomplete="username" required>
</div>
<button id="next" type="button">次へ</button>
<div id="password-step" hidden>
<div class="field">
<label for="password">パスワード</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
</div>
<button type="submit">ログイン</button>
</div>
</form>
<p id="result" class="result" role="status"></p>`,
  });
}

function spaPage(): Response {
  return renderPage({
    title: 'JavaScript で描くフォーム',
    heading: 'JavaScript で描くフォーム',
    testLine: 'E-01（変形）JavaScript で描くフォーム。期待：入力の様子を記録する',
    frameAncestors: "'none'",
    script: SPA_SCRIPT,
    body: `<div id="app" aria-live="polite">
<p>1秒後にフォームを表示します。</p>
</div>`,
  });
}

function hiddenPage(): Response {
  return renderPage({
    title: '見えない入力欄',
    heading: '見えない入力欄',
    testLine: 'E-06 見えない入力欄。期待：見えない欄には入力されない',
    frameAncestors: "'none'",
    script: FORM_SCRIPT,
    body: `<form id="login-form" method="post" action="">
<div class="field">
<label for="username">ユーザー名</label>
<input id="username" name="username" type="text" autocomplete="username" required>
</div>
<div class="field">
<label for="password">パスワード</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
</div>
<button type="submit">ログイン</button>
<div class="hidden-fields" aria-hidden="true">
<input class="field-display-none" id="password_display_none" name="password_display_none" type="password" autocomplete="current-password" tabindex="-1">
<input class="field-visibility-hidden" id="password_visibility_hidden" name="password_visibility_hidden" type="password" autocomplete="current-password" tabindex="-1">
<input class="field-zero-size" id="password_zero_size" name="password_zero_size" type="password" autocomplete="current-password" tabindex="-1">
<input class="field-offscreen" id="password_offscreen" name="password_offscreen" type="password" autocomplete="current-password" tabindex="-1">
</div>
</form>
<p id="result" class="result" role="status"></p>`,
  });
}

function iframePage(otherOrigin: string | null): Response {
  const body = otherOrigin
    ? `<p>もう一方のサイト（<code>${escapeHtml(otherOrigin)}</code>）の /simple を iframe で埋め込んでいます。</p>
<iframe src="${escapeHtml(otherOrigin)}/simple" title="もう一方のサイトのログインフォーム"></iframe>`
    : `<p class="notice">OTHER_ORIGIN が未設定です。Worker の環境変数 OTHER_ORIGIN に、もう一方のサイトのオリジンを設定してください。</p>`;

  return renderPage({
    title: 'iframe 内のログインフォーム',
    heading: 'iframe 内のログインフォーム',
    testLine: 'E-02 iframe 内のログインフォーム。期待：iframe の中には入力されない',
    frameAncestors: "'none'",
    frameSrc: otherOrigin ?? undefined,
    wide: true,
    body,
  });
}

function navigatePage(otherOrigin: string | null): Response {
  if (!otherOrigin) {
    return renderPage({
      title: '入力前の遷移',
      heading: '入力前の遷移',
      testLine: 'E-13 入力前の遷移。期待：移った先には入力されない',
      frameAncestors: "'none'",
      body: `<p class="notice">OTHER_ORIGIN が未設定です。Worker の環境変数 OTHER_ORIGIN に、もう一方のサイトのオリジンを設定してください。</p>`,
    });
  }

  return renderPage({
    title: '入力前の遷移',
    heading: '入力前の遷移',
    testLine: 'E-13 入力前の遷移。期待：移った先には入力されない',
    frameAncestors: "'none'",
    body: `<p>ボタンを押すと3秒後に、もう一方のサイト（<code>${escapeHtml(otherOrigin)}</code>）の /simple に移動します。</p>
<button id="go" type="button">3秒後に移動する</button>
<p id="status" class="result" role="status"></p>`,
    script: `(function () {
  const target = ${scriptJson(otherOrigin)};
  const go = document.getElementById('go');
  const status = document.getElementById('status');
  if (!go || !status) return;
  go.addEventListener('click', function () {
    go.disabled = true;
    status.textContent = '3秒後に移動します…';
    window.setTimeout(function () {
      window.location.assign(target + '/simple');
    }, 3000);
  });
})();`,
  });
}

function notFoundPage(): Response {
  return renderPage({
    title: 'ページが見つかりません',
    heading: 'ページが見つかりません',
    status: 404,
    frameAncestors: "'none'",
    body: `<p class="notice">URL を確かめて、<a href="/">一覧</a> から開き直してください。</p>`,
  });
}

function route(path: string, otherOrigin: string | null): Response {
  switch (path) {
    case '/':
      return indexPage();
    case '/simple':
      return simplePage(otherOrigin ?? "'none'");
    case '/two-step':
      return twoStepPage();
    case '/spa':
      return spaPage();
    case '/hidden':
      return hiddenPage();
    case '/iframe':
      return iframePage(otherOrigin);
    case '/navigate':
      return navigatePage(otherOrigin);
    default:
      return notFoundPage();
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const method = request.method.toUpperCase();
    if (method !== 'GET' && method !== 'HEAD') {
      return new Response('Method Not Allowed\n', {
        status: 405,
        headers: {
          'content-type': 'text/plain; charset=utf-8',
          'x-content-type-options': 'nosniff',
          allow: 'GET, HEAD',
        },
      });
    }

    const otherOrigin = parseOtherOrigin(env.OTHER_ORIGIN);
    const response = route(new URL(request.url).pathname, otherOrigin);
    if (method === 'HEAD') {
      return new Response(null, { status: response.status, headers: response.headers });
    }
    return response;
  },
};
