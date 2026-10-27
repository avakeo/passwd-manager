// ポップアップ：ログインの画面を開く、ログインの途中の TOTP のコード、ロック解除、ロック、全画面ページを開く。
// 鍵は持たない。マスターパスワードは Service Worker に1回だけ送り、送ったら入力欄を空にする。
// ログインは全画面ページで行う。Discord の窓が開くとポップアップは閉じ、結果を見せられないため（2026-10-27）。

import { loginTotpForm, unlockForms } from '../shared/forms.ts';
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
  if (s.loginInProgress && !s.loggedIn) {
    root.append(loginTotpForm(render));
    return;
  }
  if (!s.loggedIn) {
    const button = el('button', { text: 'Discord でログイン' });
    button.addEventListener('click', () => openPage('#login'));
    root.append(message('全画面ページを開いてログインします。'), button);
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
    root.append(unlockForms(s.quickUnlockAvailable === true, render));
  } else {
    root.append(message(vaultText(String(s.vault))));
    if (s.vault === 'ready') await renderList();
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

// 一覧（タイトルとユーザー名だけ。パスワードはポップアップに渡さない）。同期と一覧は放置のロックを延ばさない
async function renderList(): Promise<void> {
  const synced = await send({ type: 'sync' });
  if (!synced.ok && synced.error === 'ROLLBACK_DETECTED') root.append(message('サーバーが古い状態を返しました。同期を止めています。', 'error'));
  const r = await send({ type: 'listItems' });
  if (!r.ok) return;
  const search = el('input', { type: 'search', placeholder: '検索' });
  const list = el('ul');
  const items = r.items as { title: string; username?: string; unreadable: boolean }[];
  const draw = () => {
    const q = search.value.trim().toLowerCase();
    list.replaceChildren(
      ...items
        .filter((i) => !i.unreadable && (q === '' || i.title.toLowerCase().includes(q) || (i.username ?? '').toLowerCase().includes(q)))
        .map((i) => el('li', {}, el('span', { text: i.title }), el('span', { text: i.username ? `  ${i.username}` : '', className: 'muted' }))),
    );
  };
  search.addEventListener('input', draw);
  draw();
  root.append(search, list);
}

// ポップアップを開いたのは利用者の操作（放置の時刻を新しくする）。status は新しくしない
void send({ type: 'opened' }).then(() => render());
