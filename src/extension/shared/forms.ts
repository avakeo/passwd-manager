// ポップアップと全画面ページで共通のフォーム：ログインの途中の TOTP、ロック解除（パスコードとマスターパスワード）。
// マスターパスワードとコードは Service Worker に1回だけ送り、送ったら入力欄を空にする。結果は onDone に渡す。

import { el, errorText, send } from './ui.ts';

type Done = (notice?: string) => Promise<void> | void;

export function loginTotpForm(onDone: Done): HTMLElement {
  const form = el('form');
  const code = el('input', { type: 'text', placeholder: '6桁のコード、または回復コード', autocomplete: 'one-time-code' });
  form.append(code, el('button', { text: '確かめる' }));
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const value = code.value.trim();
    code.value = '';
    const r = await send(/^\d{6}$/.test(value) ? { type: 'loginTotp', code: value } : { type: 'loginTotp', recoveryCode: value });
    await onDone(r.ok ? undefined : errorText(r.error));
  });
  return el('div', {}, el('p', { text: '認証アプリのコード（または回復コード）を入れてください。', className: 'note' }), form);
}

// この端末を覚えた後、ブラウザを開き直したときのフォーム（2026-10-29 追記）。間違いはサーバーが数え、3回で忘れる
export function deviceResumeForm(onDone: Done): HTMLElement {
  const form = el('form');
  const pin = el('input', { type: 'password', placeholder: '4桁のパスコード', autocomplete: 'off' });
  form.append(pin, el('button', { text: 'パスコードで戻る' }));
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const value = pin.value;
    pin.value = '';
    const r = await send({ type: 'resumeDevice', pin: value });
    if (r.ok) return onDone();
    await onDone(r.error === 'BAD_PASSCODE' ? `パスコードが違います。あと ${Number(r.attemptsLeft)} 回間違えると、この端末を忘れます` : errorText(r.error));
  });
  return el('div', {}, el('p', { text: 'この端末を覚えています。4桁のパスコードで戻れます（Discord と認証アプリは要りません）。', className: 'note' }), form);
}

// ロックされているときのフォーム。クイックロック解除（4桁）は、使えるときだけ出す。5回間違えると消え、マスターパスワードに戻る
export function unlockForms(quickUnlockAvailable: boolean, onDone: Done): HTMLElement {
  const wrap = el('div');
  if (quickUnlockAvailable) {
    const form = el('form');
    const code = el('input', { type: 'password', placeholder: '4桁のパスコード', autocomplete: 'off' });
    form.append(code, el('button', { text: 'パスコードで解除' }));
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const value = code.value;
      code.value = '';
      const r = await send({ type: 'quickUnlock', passcode: value });
      await onDone(r.ok ? undefined : errorText(r.error));
    });
    wrap.append(form);
  }
  const form = el('form');
  const password = el('input', { type: 'password', placeholder: 'マスターパスワード', autocomplete: 'current-password' });
  form.append(password, el('button', { text: 'ロック解除' }));
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const value = password.value;
    password.value = '';
    const r = await send({ type: 'unlock', masterPassword: value });
    await onDone(r.ok ? undefined : errorText(r.error));
  });
  wrap.append(form);
  return wrap;
}
