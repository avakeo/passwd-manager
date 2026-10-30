// 同期の状態を作り直す画面（2026-10-30 追記、判断待ち1。S-12）。
// サーバーが一度でも大きな Vault リビジョンを返すと、以後は同期が止まったままになる（S-09）。
// 管理者と対面で Vault リビジョンを見比べてから、マスターパスワードを入れて、端末の同期の状態を消して全件を取り直す。
// 押したときは、画面に出した「サーバーの今の値」をそのまま Service Worker に送り返し、サーバーの値が変わっていれば何もしない。

import { el, errorText, send } from '../shared/ui.ts';

const EXTRA_ERRORS: Record<string, string> = {
  REVISION_CHANGED: 'サーバーの値が、画面に出した値から変わりました。何も消していません。もう一度「値を出す」から見比べてください',
  KEY_CHANGED: 'サーバーにある鍵が、今ロックを解除している鍵と違います。何も消していません',
};

export function syncResetSection(onDone: () => void): HTMLElement {
  const out = el('p', { className: 'note' });
  const area = el('div');
  const showValues = el('button', { text: '値を出す', className: 'secondary' });
  showValues.addEventListener('click', async () => {
    const r = await send({ type: 'syncStatus' });
    out.textContent = '';
    if (!r.ok) {
      out.textContent = errorText(r.error);
      out.className = 'error';
      return;
    }
    const serverRevision = Number(r.serverRevision);
    const form = el('form');
    const password = el('input', { type: 'password', placeholder: 'マスターパスワード', autocomplete: 'current-password' });
    form.append(password, el('button', { text: '同期の状態を作り直す' }));
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const masterPassword = password.value;
      password.value = '';
      const x = await send({ type: 'resetSync', masterPassword, vaultRevision: serverRevision });
      out.textContent = x.ok ? `作り直しました。${Number(x.items)}件を取り直しました。` : (EXTRA_ERRORS[x.error ?? ''] ?? errorText(x.error));
      out.className = x.ok ? 'note' : 'error';
      if (x.ok) onDone();
    });
    area.replaceChildren(
      el('p', { text: `この端末が最後に見た値：${Number(r.deviceRevision)}` }),
      el('p', { text: `サーバーの今の値：${serverRevision}` }),
      el('p', {
        text: 'Discord 以外の経路（対面か電話）で、管理者の画面のこの欄と見比べてください（管理者が作り直すときは、メンバーのだれかと見比べます）。相手の「この端末が最後に見た値」が、あなたの「サーバーの今の値」以下なら、作り直してかまいません。',
        className: 'muted',
      }),
      el('p', { text: '相手の値のほうが大きいときは、サーバーが古い状態を見せています。作り直さずに、管理者に知らせてください。', className: 'warn' }),
      form,
    );
  });
  area.append(showValues);
  const s = el(
    'section',
    {},
    el('h2', { text: '同期の状態を作り直す' }),
    el('p', { text: '「サーバーが古い状態を返しました」と出て同期が止まったときに使います。端末の暗号文のキャッシュと同期の記録を消して、全件を取り直します。', className: 'muted' }),
    area,
    out,
  );
  s.id = 'sync-reset';
  return s;
}
