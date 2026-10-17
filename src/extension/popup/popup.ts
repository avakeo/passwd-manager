// ポップアップ：ログイン、ログインの途中の TOTP のコード、ロック解除、ロック、全画面ページを開く。
// 鍵は持たない。マスターパスワードは Service Worker に1回だけ送り、送ったら入力欄を空にする。

import { el, errorText, pageUrl, recoveryNotice, send } from '../shared/ui.ts';

const root = document.getElementById('root')!;

function message(text: string, className = 'note'): HTMLElement {
  return el('p', { text, className });
}

function openPage(hash = ''): void {
  window.open(pageUrl('extension/page/app.html') + hash);
}

async function render(notice?: string): Promise<void> {
  const s = await send({ type: 'status' });
  root.replaceChildren();
  root.append(el('h1', { text: 'teampw' }));
  if (notice) root.append(message(notice, 'error'));
  if (!s.ok) {
    root.append(message(errorText(s.error), 'error'));
    return;
  }
  if (s.loginInProgress && !s.loggedIn) return renderTotp();
  if (!s.loggedIn) {
    const button = el('button', { text: 'Discord でログイン' });
    button.addEventListener('click', async () => {
      const r = await send({ type: 'login', deviceLabel: 'Chrome' });
      await render(r.ok ? undefined : errorText(r.error));
    });
    root.append(button);
    return;
  }
  if (s.totpSetupRequired) {
    root.append(message('はじめに認証アプリ（TOTP）を登録します。'));
    const button = el('button', { text: '登録の画面を開く' });
    button.addEventListener('click', () => openPage('#totp'));
    root.append(button);
    return;
  }
  const notice2 = recoveryNotice(s.recoveryCodesRemaining);
  if (notice2) root.append(message(notice2, 'warn'));
  if (s.vault === 'no-key') {
    root.append(message('マスターパスワードと鍵をまだ作っていません。'));
    const button = el('button', { text: '鍵を作る画面を開く' });
    button.addEventListener('click', () => openPage('#key'));
    root.append(button);
    return;
  }
  if (s.locked) {
    const form = el('form');
    const password = el('input', { type: 'password', placeholder: 'マスターパスワード', autocomplete: 'current-password' });
    form.append(password, el('button', { text: 'ロック解除' }));
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const value = password.value;
      password.value = '';
      const r = await send({ type: 'unlock', masterPassword: value });
      await render(r.ok ? undefined : errorText(r.error));
    });
    root.append(form);
  } else {
    root.append(message(vaultText(String(s.vault))));
    const lock = el('button', { text: 'ロック' });
    lock.addEventListener('click', async () => {
      await send({ type: 'lock' });
      await render();
    });
    root.append(lock);
  }
  const open = el('button', { text: '全画面で開く', className: 'secondary' });
  open.addEventListener('click', () => openPage());
  root.append(open);
}

function vaultText(state: string): string {
  switch (state) {
    case 'ready':
      return 'ロック解除済み。Vault を開きました。';
    case 'needs-init':
      return 'まだ Vault がありません。全画面ページで最初の Vault を作ってください。';
    case 'awaiting-approval':
      return '管理者の照合と承認を待っています。';
    case 'needs-generation-init':
      return 'この端末の世代の初期化（対面の照合）が必要です。';
    default:
      return '自分宛てのグラントを開けませんでした。管理者に知らせてください。';
  }
}

function renderTotp(): void {
  root.append(message('認証アプリのコード（または回復コード）を入れてください。'));
  const form = el('form');
  const code = el('input', { type: 'text', placeholder: '6桁のコード、または回復コード', autocomplete: 'one-time-code' });
  form.append(code, el('button', { text: '確かめる' }));
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const value = code.value.trim();
    code.value = '';
    const r = await send(/^\d{6}$/.test(value) ? { type: 'loginTotp', code: value } : { type: 'loginTotp', recoveryCode: value });
    await render(r.ok ? undefined : errorText(r.error));
  });
  root.append(form);
}

void render();
