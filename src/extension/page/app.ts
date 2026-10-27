// 全画面ページ（2a）：TOTP の登録と作り直し、鍵の作成、最初の Vault、TOTP の再確認、セッションの一覧と無効化、ロック、ログアウト。
// 2026-10-27 から、ログインとロック解除もここでできる（ポップアップは Discord の窓が開くと閉じ、ログインの結果を見せられないため）。
// アイテムの一覧・編集は 2b。鍵は持たない。表示はすべて文字として出す（shared/ui.ts）。

import { loginTotpForm, unlockForms } from '../shared/forms.ts';
import { el, errorText, recoveryNotice, send } from '../shared/ui.ts';
import { blankItem, editorSection, itemsSection, openItem, passcodeSection } from './items.ts';

const root = document.getElementById('root')!;

function section(title: string, id: string, ...children: Node[]): HTMLElement {
  const s = el('section', {}, el('h2', { text: title }), ...children);
  s.id = id;
  return s;
}

function result(): HTMLElement {
  return el('p', { className: 'note' });
}

function show(out: HTMLElement, r: { ok: boolean; error?: string }, okText: string): void {
  out.textContent = r.ok ? okText : errorText(r.error);
  out.className = r.ok ? 'note' : 'error';
}

function codeForm(label: string, onCode: (value: string) => Promise<void>): HTMLFormElement {
  const form = el('form');
  const input = el('input', { type: 'text', placeholder: label, autocomplete: 'one-time-code' });
  form.append(input, el('button', { text: '送る' }));
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const value = input.value.trim();
    input.value = '';
    await onCode(value);
  });
  return form;
}

function totpSection(registered: boolean): HTMLElement {
  const out = result();
  const area = el('div');
  const begin = async (payload: Record<string, unknown>) => {
    const r = await send({ type: 'totpSetupStart', ...payload });
    if (!r.ok) return show(out, r, '');
    area.replaceChildren(
      el('p', { text: '認証アプリで「キーを手入力」を選び、次のシークレットを入れてください（QR コードは表示しません）。' }),
      el('p', { text: String(r.secret), className: 'secret' }),
      el('p', { text: String(r.otpauthUri), className: 'uri' }),
      codeForm('認証アプリに出た6桁のコード', async (code) => {
        const c = await send({ type: 'totpSetupConfirm', code });
        if (!c.ok) return show(out, c, '');
        area.replaceChildren(
          el('p', { text: '回復コードです。今だけ表示します。安全な場所に控えてください（1つ1回だけ使えます）。' }),
          el('ul', {}, ...(c.recoveryCodes as string[]).map((code) => el('li', { text: code, className: 'secret' }))),
          (() => {
            const done = el('button', { text: '控えた' });
            done.addEventListener('click', () => void render());
            return done;
          })(),
        );
      }),
    );
  };
  if (registered) {
    area.append(
      el('p', { text: '作り直し：今の認証アプリのコードか回復コードを入れて始めます（TOTP を確かめてから5分以内なら、空のまま始められます）。' }),
      codeForm('6桁のコード、回復コード、または空', async (value) => {
        await begin(value === '' ? {} : /^\d{6}$/.test(value) ? { code: value } : { recoveryCode: value });
      }),
    );
  } else {
    const start = el('button', { text: '登録を始める' });
    start.addEventListener('click', () => void begin({}));
    area.append(start);
  }
  return section(registered ? '認証アプリ（TOTP）の作り直し' : '認証アプリ（TOTP）の登録', 'totp', area, out);
}

function keySection(hasKey: boolean): HTMLElement {
  const out = result();
  const form = el('form');
  const p1 = el('input', { type: 'password', placeholder: 'マスターパスワード（14文字以上）', autocomplete: 'new-password' });
  const p2 = el('input', { type: 'password', placeholder: 'もう一度', autocomplete: 'new-password' });
  form.append(p1, p2, el('button', { text: hasKey ? '鍵を作り直す（承認待ちに戻ります）' : '鍵を作る' }));
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const [a, b] = [p1.value, p2.value];
    p1.value = '';
    p2.value = '';
    if (a !== b) return show(out, { ok: false, error: 'MISMATCH' }, '');
    const r = await send({ type: 'createKey', masterPassword: a, replace: hasKey });
    show(out, r, '鍵を作りました。');
    if (r.ok) await render();
  });
  return section(hasKey ? '鍵の作り直し' : 'マスターパスワードと鍵', 'key', form, out);
}

function initSection(): HTMLElement {
  const out = result();
  const button = el('button', { text: '最初の Vault を作る' });
  button.addEventListener('click', async () => {
    const r = await send({ type: 'initVault' });
    show(out, r, 'Vault を作りました。');
    if (r.ok) await render();
  });
  return section('最初の Vault', 'vault', el('p', { text: '管理者だけが、1回だけ作れます。' }), button, out);
}

function stepUpSection(): HTMLElement {
  const out = result();
  return section(
    'TOTP の再確認',
    'stepup',
    el('p', { text: '鍵の作り直し、最初の Vault、セッションの無効化の前に、5分以内の再確認が要ります。' }),
    codeForm('6桁のコード', async (code) => show(out, await send({ type: 'stepUp', code }), '再確認しました（5分有効）。')),
    out,
  );
}

async function sessionsSection(): Promise<HTMLElement> {
  const out = result();
  const r = await send({ type: 'listSessions' });
  const list = el('ul');
  if (r.ok) {
    for (const s of r.sessions as { id: string; deviceLabel: string; current: boolean; createdAt: number }[]) {
      // 端末名は文字として表示する（DeepSeek #2）
      const item = el('li', {}, el('span', { text: s.deviceLabel }), el('span', { text: ` ${new Date(s.createdAt).toLocaleString()}${s.current ? '（この端末）' : ''}`, className: 'muted' }));
      if (!s.current) {
        const revoke = el('button', { text: '無効にする', className: 'secondary' });
        revoke.addEventListener('click', async () => {
          const x = await send({ type: 'revokeSession', sessionId: s.id });
          show(out, x, '無効にしました。');
          if (x.ok) await render();
        });
        item.append(revoke);
      }
      list.append(item);
    }
  } else show(out, r, '');
  return section('セッション', 'sessions', list, out);
}

// ログイン。Discord の窓を閉じても、このページは残るので、結果をここに出せる
function loginSection(): HTMLElement {
  const out = result();
  const button = el('button', { text: 'Discord でログイン' });
  button.addEventListener('click', async () => {
    const r = await send({ type: 'login', deviceLabel: 'Chrome' });
    await render(r.ok ? undefined : errorText(r.error));
  });
  return section('ログイン', 'login', button, out);
}

async function render(notice?: string): Promise<void> {
  const s = await send({ type: 'status' });
  root.replaceChildren(el('h1', { text: 'teampw' }));
  if (notice) root.append(el('p', { text: notice, className: 'error' }));
  if (!s.ok) {
    root.append(el('p', { text: errorText(s.error), className: 'error' }));
    return;
  }
  if (s.loginInProgress && !s.loggedIn) {
    root.append(section('ログイン', 'login', loginTotpForm(render)));
    return;
  }
  if (!s.loggedIn) {
    root.append(loginSection());
    return;
  }
  if (s.totpSetupRequired) {
    root.append(totpSection(false));
    return;
  }
  const recovery = recoveryNotice(s.recoveryCodesRemaining);
  if (recovery) root.append(el('p', { text: recovery, className: 'warn' }));
  const member = s.member as { role: string };
  root.append(el('p', { text: `役割：${member.role === 'admin' ? '管理者' : 'メンバー'}　状態：${String(s.vault)}`, className: 'muted' }));
  if (s.hasKey === false) root.append(keySection(false));
  if (s.vault === 'needs-init') root.append(initSection());
  if (s.locked) root.append(section('ロック解除', 'unlock', unlockForms(s.quickUnlockAvailable === true, render)));
  if (s.vault === 'ready') {
    // アイテム（2b）。開いた1件の中身は、この画面のメモリにだけ置く
    const slot = el('div');
    const showList = async () => slot.replaceChildren(await itemsSection(open));
    const open = async (id: string | null, type: 'login' | 'note') => {
      if (id === null) return slot.replaceChildren(editorSection(blankItem(type), null, null, () => void showList()));
      const got = await openItem(id);
      if (typeof got === 'string') return slot.replaceChildren(el('p', { text: got, className: 'error' }));
      slot.replaceChildren(editorSection(got.item, id, got.revision, () => void showList()));
    };
    await showList();
    root.append(slot);
    if (s.unlockedBy === 'password') root.append(passcodeSection(() => void render()));
  }
  if (s.cacheFull) root.append(el('p', { text: '端末の保存の容量を超えたので、暗号文のキャッシュをやめています（オフラインでは見られません）。', className: 'warn' }));
  root.append(stepUpSection(), await sessionsSection(), totpSection(true));
  if (s.hasKey === true) root.append(keySection(true));
  const lock = el('button', { text: 'ロック', className: 'secondary' });
  lock.addEventListener('click', async () => {
    await send({ type: 'lock' });
    await render();
  });
  const logout = el('button', { text: 'ログアウト', className: 'secondary' });
  logout.addEventListener('click', async () => {
    await send({ type: 'logout' });
    await render();
  });
  root.append(el('div', {}, lock, logout));
  const target = document.getElementById(location.hash.slice(1));
  if (target) target.scrollIntoView();
}

// 全画面ページを開いたのは利用者の操作（放置の時刻を新しくする）。status は新しくしない
void send({ type: 'opened' }).then(() => render());
