// 全画面ページ（2a）：TOTP の登録と作り直し、鍵の作成、最初の Vault、TOTP の再確認、セッションの一覧と無効化、ロック、ログアウト。
// 2026-10-27 から、ログインとロック解除もここでできる（ポップアップは Discord の窓が開くと閉じ、ログインの結果を見せられないため）。
// アイテムの一覧・編集は 2b。鍵は持たない。表示はすべて文字として出す（shared/ui.ts）。

import { deviceResumeForm, loginTotpForm, unlockForms } from '../shared/forms.ts';
import { el, errorText, onLocked, recoveryNotice, send } from '../shared/ui.ts';
import { blankItem, editorSection, itemsSection, openItem, passcodeSection } from './items.ts';
import { importSection } from './import.ts';
import { auditSection, memberVerifySection, membersSection, rotationSection } from './members.ts';

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
  // アイテムの一覧と同じ行の形（名前を左、ボタンを右。行の間に線）
  const list = el('ul', { className: 'item-list' });
  if (r.ok) {
    for (const s of r.sessions as { id: string; deviceLabel: string; current: boolean; createdAt: number }[]) {
      // 端末名は文字として表示する（DeepSeek #2）
      const label = el(
        'div',
        { className: 'item-label' },
        el('span', { text: `${s.deviceLabel}${s.current ? '（この端末）' : ''}`, className: 'item-title' }),
        el('span', { text: `ログイン：${new Date(s.createdAt).toLocaleString()}`, className: 'muted' }),
      );
      const item = el('li', {}, label);
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

// ログイン。Discord の窓を閉じても、このページは残るので、結果をここに出せる。覚えた端末なら、パスコードの欄も出す
function loginSection(deviceResumeAvailable: boolean): HTMLElement {
  const out = result();
  const button = el('button', { text: 'Discord でログイン', className: deviceResumeAvailable ? 'secondary' : '' });
  button.addEventListener('click', async () => {
    const r = await send({ type: 'login', deviceLabel: 'Chrome' });
    await render(r.ok ? undefined : errorText(r.error));
  });
  return deviceResumeAvailable ? section('ログイン', 'login', deviceResumeForm(render), button, out) : section('ログイン', 'login', button, out);
}

// この端末を覚える（2026-10-29 追記）。ログインから7日まで、ブラウザを開き直しても4桁のパスコードで戻れる
function rememberSection(remembered: boolean): HTMLElement {
  const out = result();
  if (remembered) {
    const forget = el('button', { text: 'この端末を忘れる', className: 'secondary' });
    forget.addEventListener('click', async () => {
      await send({ type: 'forgetDevice' });
      await render();
    });
    return section('この端末を覚える', 'remember', el('p', { text: 'この端末を覚えています。ブラウザを開き直したら、4桁のパスコードで戻れます（ログインから7日まで）。', className: 'muted' }), forget, out);
  }
  const form = el('form');
  const p1 = el('input', { type: 'password', placeholder: '4桁の数字', autocomplete: 'off' });
  const p2 = el('input', { type: 'password', placeholder: 'もう一度', autocomplete: 'off' });
  form.append(p1, p2, el('button', { text: '覚える' }));
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const [a, b] = [p1.value, p2.value];
    p1.value = '';
    p2.value = '';
    if (a !== b) {
      out.textContent = '2回の入力が違います';
      out.className = 'error';
      return;
    }
    const r = await send({ type: 'rememberDevice', pin: a });
    if (r.ok) return render();
    out.textContent = r.error === 'STEP_UP_REQUIRED' ? 'ログインから5分を過ぎました。「設定とセキュリティ」の TOTP の再確認をしてから、もう一度押してください。' : errorText(r.error);
    out.className = 'error';
  });
  return section(
    'この端末を覚える',
    'remember',
    el('p', { text: 'ブラウザを開き直したときに、Discord と認証アプリの代わりに4桁のパスコードで戻れます（ログインから7日まで）。3回間違えると忘れます。ログインの直後（5分以内）に決めてください。', className: 'muted' }),
    form,
    out,
  );
}

// ロック解除を保つ（2026-10-29 追記）。オンにするのはマスターパスワードで解除した状態からだけ
function keepUnlockedSection(on: boolean, canEnable: boolean): HTMLElement {
  const out = result();
  const toggle = el('input', { type: 'checkbox', className: 'switch' });
  toggle.checked = on;
  toggle.disabled = !on && !canEnable;
  toggle.addEventListener('change', async () => {
    const r = await send({ type: 'setKeepUnlocked', enabled: toggle.checked });
    if (!r.ok) toggle.checked = !toggle.checked;
    show(out, r, r.keepUnlocked ? 'オンにしました。ブラウザを閉じるまで、入力なしで使えます。' : 'オフにしました。');
  });
  return section(
    'ロック解除を保つ',
    'keep-unlocked',
    el('label', { className: 'toggle' }, toggle, el('span', { text: 'ブラウザを閉じるまで、マスターパスワードなしで使う' })),
    el('p', {
      text: 'Vault 鍵を、ブラウザのメモリ（ディスクには書かない）に置きます。ロックを押す、45分放置する、ブラウザを閉じると消えます。その間にこのブラウザを触れる人は、アイテムをすべて見られます。管理操作には、いつもマスターパスワードが要ります。',
      className: 'muted',
    }),
    ...(on || canEnable ? [] : [el('p', { text: 'オンにするには、マスターパスワードでロック解除してください。', className: 'muted' })]),
    out,
  );
}

// 今ロック解除だけの画面を出しているか（タブに戻ったときに、描き直すかを決める）
let showingLock = false;

// ロック中の画面：マスターパスワード（使えるならパスコードも）の欄と、ログアウトだけ
function lockScreen(quickUnlockAvailable: boolean): HTMLElement {
  const logout = el('button', { text: 'ログアウト', className: 'secondary' });
  logout.addEventListener('click', async () => {
    await send({ type: 'logout' });
    await render();
  });
  const s = section('ロック解除', 'unlock', unlockForms(quickUnlockAvailable, render), el('div', { className: 'row' }, logout));
  queueMicrotask(() => s.querySelector<HTMLInputElement>('input[autocomplete="current-password"]')?.focus());
  return s;
}

async function render(notice?: string): Promise<void> {
  const s = await send({ type: 'status' });
  showingLock = false;
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
    root.append(loginSection(s.deviceResumeAvailable === true));
    return;
  }
  if (s.totpSetupRequired) {
    root.append(totpSection(false));
    return;
  }
  // 鍵があってロックされているときは、ロック解除の欄だけを出す（一覧や設定は解除してから）
  if (s.locked && s.hasKey === true) {
    showingLock = true;
    root.append(lockScreen(s.quickUnlockAvailable === true));
    return;
  }
  const recovery = recoveryNotice(s.recoveryCodesRemaining);
  if (recovery) root.append(el('p', { text: recovery, className: 'warn' }));
  const member = s.member as { role: string };
  const header = el('div', { className: 'page-header' }, el('p', { text: `役割：${member.role === 'admin' ? '管理者' : 'メンバー'}　状態：${String(s.vault)}`, className: 'muted' }));
  root.append(header);
  if (s.hasKey === false) root.append(keySection(false));
  if (s.vault === 'needs-init') root.append(initSection());
  if (s.locked) root.append(section('ロック解除', 'unlock', unlockForms(s.quickUnlockAvailable === true, render)));
  // まだ覚えていない端末では、一覧の上に出す（ログインの直後の5分以内に決めるため）。覚えた後は設定の中に置く
  if (s.deviceRemembered === false) root.append(rememberSection(false));
  if (s.vault === 'ready') {
    // アイテム（2b）。開いた1件の中身は、この画面のメモリにだけ置く
    const slot = el('div');
    const showList = async () => slot.replaceChildren(await itemsSection(open, () => slot.replaceChildren(importSection(() => void showList()))));
    const open = async (id: string | null, type: 'login' | 'note') => {
      if (id === null) return slot.replaceChildren(editorSection(blankItem(type), null, null, () => void showList()));
      const got = await openItem(id);
      if (typeof got === 'string') return slot.replaceChildren(el('p', { text: got, className: 'error' }));
      slot.replaceChildren(editorSection(got.item, id, got.revision, () => void showList()));
    };
    await showList();
    root.append(slot);
    // 管理者：メンバーの照合・承認・削除と、監査ログ（フェーズ4a）
    if (member.role === 'admin') root.append(await membersSection(() => void render()), rotationSection(() => void showList()), await auditSection());
  }
  // メンバー：承認を待っている間は、管理者との照合の画面を出す（P-04・P-06）
  if (s.vault === 'awaiting-approval') root.append(await memberVerifySection(() => void render()));
  if (s.cacheFull) root.append(el('p', { text: '端末の保存の容量を超えたので、暗号文のキャッシュをやめています（オフラインでは見られません）。', className: 'warn' }));
  // ふだん使わない設定は、たたんでおく。URL の # が中の節を指すときだけ開く
  const settings = el('details', { className: 'settings' }, el('summary', { text: '設定とセキュリティ（パスコード、TOTP、セッション、鍵）' }));
  if (s.deviceRemembered === true) settings.append(rememberSection(true));
  if (s.vault === 'ready') settings.append(keepUnlockedSection(s.keepUnlocked === true, s.unlockedBy === 'password'));
  if (s.vault === 'ready' && s.unlockedBy === 'password') settings.append(passcodeSection(() => void render()));
  settings.append(stepUpSection(), await sessionsSection(), totpSection(true));
  if (s.hasKey === true) settings.append(keySection(true));
  root.append(settings);
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
  header.append(el('div', { className: 'row' }, lock, logout));
  const target = location.hash.length > 1 ? document.getElementById(location.hash.slice(1)) : null;
  if (target && settings.contains(target)) settings.open = true;
  if (target) target.scrollIntoView();
}

// 操作の途中でロックされていると分かったら（放置のロックなど）、ロック解除だけの画面に描き直す
onLocked(() => {
  if (!showingLock) void render();
});
// タブに戻ったときも確かめる。status は放置の時刻を新しくしない
document.addEventListener('visibilitychange', async () => {
  if (document.visibilityState !== 'visible' || showingLock) return;
  const s = await send({ type: 'status' });
  if (s.ok && s.locked && s.hasKey === true) await render();
});

// 全画面ページを開いたのは利用者の操作（放置の時刻を新しくする）。status は新しくしない
void send({ type: 'opened' }).then(() => render());
