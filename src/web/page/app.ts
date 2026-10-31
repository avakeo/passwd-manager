// Web ページの画面（2026-11-01 追記、判断待ち10）。仕様書「画面の分担」「Webページの配信」。
// メンバー一覧と状態、監査ログ（管理者）、自分のセッションの一覧を出すだけ。鍵は使わない。書き込みはしない。
// 表示はすべて textContent で出す（サーバーから来た名前などを HTML として解釈しない）。
// トークンはこのページのメモリだけ。再読み込みしたらログインし直す。

import { CONFIG } from '../config.ts';
import { WebError, WebSession, finishLogin, startLogin } from './web-client.ts';

const root = document.getElementById('root')!;

type Props = { text?: string; className?: string; type?: string; placeholder?: string; autocomplete?: string };

function el<K extends keyof HTMLElementTagNameMap>(tag: K, props: Props = {}, ...children: Node[]): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (props.text !== undefined) node.textContent = props.text;
  if (props.className !== undefined) node.className = props.className;
  const input = node as unknown as HTMLInputElement;
  if (props.type !== undefined) input.type = props.type;
  if (props.placeholder !== undefined) input.placeholder = props.placeholder;
  if (props.autocomplete !== undefined) input.autocomplete = props.autocomplete as AutoFill;
  node.append(...children);
  return node;
}

const MESSAGES: Record<string, string> = {
  NO_PENDING: 'ログインの途中の情報がありません。もう一度ログインしてください',
  STATE_MISMATCH: 'ログインの確認に失敗しました。もう一度ログインしてください',
  ACCESS_DENIED: 'Discord でログインが許可されませんでした',
  MALFORMED: 'ログインの戻り先が正しくありません',
  FORBIDDEN: 'ログインできませんでした。チームのロールがあるか、拡張機能で TOTP を登録済みかを確かめてください',
  BAD_CODE: 'コードが違うか、期限が切れました。もう一度ログインしてください',
  EXPIRED: 'ログインの期限が切れました。再読み込みしてログインし直してください',
  SERVER: 'サーバーでエラーが起きました',
};

function errorText(e: unknown): string {
  return e instanceof WebError ? (MESSAGES[e.code] ?? e.code) : 'エラーが起きました';
}

function time(ms: unknown): string {
  return typeof ms === 'number' ? new Date(ms).toLocaleString('ja-JP') : '';
}

function table(headers: string[], rows: string[][]): HTMLElement {
  const head = el('tr', {}, ...headers.map((h) => el('th', { text: h })));
  const body = rows.map((r) => el('tr', {}, ...r.map((c) => el('td', { text: c }))));
  return el('div', { className: 'table-wrap' }, el('table', {}, el('thead', {}, head), el('tbody', {}, ...body)));
}

function header(): HTMLElement {
  return el('h1', { text: 'teampw' });
}

function showLogin(notice?: string): void {
  const button = el('button', { text: 'Discord でログイン' });
  button.addEventListener('click', async () => {
    location.assign(await startLogin(CONFIG, sessionStorage));
  });
  root.replaceChildren(
    header(),
    ...(notice ? [el('p', { text: notice, className: 'error' })] : []),
    el('p', { text: 'メンバーの一覧、監査ログ、自分のセッションを見るページです。パスワードの一覧と編集は、拡張機能で行います。', className: 'muted' }),
    button,
  );
}

function showTotp(challengeToken: string): void {
  const form = el('form');
  const input = el('input', { type: 'text', placeholder: '認証アプリの6桁のコード', autocomplete: 'one-time-code' });
  const out = el('p', { className: 'error' });
  form.append(input, el('button', { text: '送る' }));
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const code = input.value.trim();
    input.value = '';
    try {
      await showDashboard(await WebSession.verifyTotp(CONFIG, fetch.bind(globalThis), challengeToken, code));
    } catch (err) {
      // 一時トークンは1回だけなので、間違えたらログインからやり直す
      showLogin(errorText(err));
    }
  });
  root.replaceChildren(header(), el('section', {}, el('h2', { text: '認証アプリ（TOTP）のコード' }), form, out));
}

async function showDashboard(session: WebSession): Promise<void> {
  const isAdmin = session.member.role === 'admin';
  root.replaceChildren(
    header(),
    el('p', { text: `役割：${isAdmin ? '管理者' : 'メンバー'}。このページは表示だけです。再読み込みするとログアウトします。`, className: 'muted' }),
  );
  const part = async (title: string, load: () => Promise<HTMLElement>, onForbidden?: string) => {
    const s = el('section', {}, el('h2', { text: title }));
    root.append(s);
    try {
      s.append(await load());
    } catch (e) {
      s.append(el('p', { text: e instanceof WebError && e.code === 'FORBIDDEN' && onForbidden ? onForbidden : errorText(e), className: 'error' }));
    }
  };
  await part('メンバー', async () => {
    const r = await session.get('/v1/members');
    const rows = (r.members as { display_name: string; role: string; status: string; key: unknown }[]).map((m) => [
      m.display_name,
      m.role === 'admin' ? '管理者' : 'メンバー',
      m.status === 'active' ? '承認済み' : m.status === 'pending' ? '承認待ち' : m.status,
      m.key ? 'あり' : 'なし',
    ]);
    return table(['名前', '役割', '状態', '鍵'], rows);
  });
  await part('自分のセッション', async () => {
    const r = await session.get('/v1/me/sessions');
    const rows = (r.sessions as { device_label: string | null; scope: string; created_at: number; last_used_at: number | null; current: boolean }[]).map((x) => [
      `${x.device_label ?? '（名前なし）'}${x.current ? '（このページ）' : ''}`,
      x.scope === 'web' ? 'Web（表示だけ）' : '拡張機能',
      time(x.created_at),
      time(x.last_used_at),
    ]);
    const wrap = el('div', {}, table(['端末', '用途', 'ログイン', '最後に使った'], rows));
    wrap.append(el('p', { text: 'セッションの無効化は、拡張機能の全画面ページの「セッション」で行います。', className: 'muted' }));
    return wrap;
  });
  if (isAdmin) {
    await part(
      '監査ログ（新しい順）',
      async () => {
        const r = await session.get('/v1/audit-logs');
        const rows = (r.logs as { actor_member_id: string | null; action: string; target_type: string | null; target_id: string | null; created_at: number }[]).map((l) => [
          time(l.created_at),
          l.action,
          l.actor_member_id ?? '',
          [l.target_type, l.target_id].filter((x) => x).join(' '),
        ]);
        return table(['日時', '操作', '操作した人', '対象'], rows);
      },
      '監査ログは、ログインから5分の間だけ見られます。再読み込みしてログインし直してください。',
    );
  }
}

async function start(): Promise<void> {
  if (location.pathname === '/callback') {
    const href = location.href;
    // 認可コードと state を URL から消す（履歴や、ほかへの送信に残さない）
    history.replaceState(null, '', '/');
    try {
      const { challengeToken } = await finishLogin(href, CONFIG, sessionStorage, fetch.bind(globalThis));
      showTotp(challengeToken);
    } catch (e) {
      showLogin(errorText(e));
    }
    return;
  }
  showLogin();
}

void start();
