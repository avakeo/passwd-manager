// 全画面ページの照合と承認（フェーズ4a、docs/実装状況.md の12.2・12.3）。
// フィンガープリントは全桁を出す（DeepSeek #13）。「一致」を押すまで固定しない（DeepSeek #3）。
// 押したときは、画面に出した値をそのまま Service Worker に送り返し、サーバーの今の値と同じときだけ固定する。
// 表示はすべて文字として出す（textContent）。

import { el, errorText, send } from '../shared/ui.ts';

type Member = { id: string; displayName: string; role: string; status: string; keyId: string | null; fingerprint: string | null; pinned: boolean; self: boolean };

const EXTRA_ERRORS: Record<string, string> = {
  SIGNER_CHANGED: 'サーバーの値が、画面に出した値から変わりました。押さずに管理者に知らせてください',
  KEY_CHANGED: 'サーバーの値が、画面に出した値から変わりました。押さずに、もう一度照合してください',
  KEY_MISMATCH: 'サーバーの公開鍵が、照合して固定したものと違います。グラントを作らずに止めました。サーバーが書き換えられたおそれがあります',
  NOT_PINNED: '先に、フィンガープリントを照合して「一致した」を押してください',
  STEP_UP_REQUIRED: '先に「設定とセキュリティ」の TOTP の再確認をしてください（管理操作は5分以内の確認が要ります）',
  CANNOT_REMOVE_SELF: '自分は削除できません',
  NOT_MEMBER: '管理者の照合はメンバーだけが行います',
  ROTATION_CONFLICT: '途中でほかの人がアイテムを変えたか、メンバーが増減しました。何も変わっていないので、もう一度押してください',
  UNREADABLE_ITEMS: '開けないアイテムがあるので止めました。書き換えると中身が失われるためです',
  TOO_LARGE: 'アイテムが多すぎて、1回で送れる大きさ（1.5MB）を超えました',
};

function message(code: string | undefined): string {
  return EXTRA_ERRORS[code ?? ''] ?? errorText(code);
}

function fingerprintBox(value: string): HTMLElement {
  return el('p', { text: value, className: 'fingerprint' });
}

// メンバー：承認を待っている間の画面。管理者の署名鍵のフィンガープリントと今の世代を見比べ、一致したら押す
export async function memberVerifySection(onDone: () => void): Promise<HTMLElement> {
  const out = el('p', { className: 'note' });
  const r = await send({ type: 'adminSigner' });
  const section = el('section', {}, el('h2', { text: '管理者と照合する' }));
  if (!r.ok) {
    section.append(el('p', { text: message(r.error), className: 'error' }));
    return section;
  }
  section.append(
    el('p', { text: 'Discord 以外の経路（対面か電話）で、管理者と次の2つを見比べてください。Discord のアカウントが乗っ取られていても、すり抜けられないようにするためです。', className: 'muted' }),
    el('h3', { text: 'あなたの公開鍵（管理者の画面の「メンバー」に出ます）' }),
    fingerprintBox(String(r.ownFingerprint ?? '（鍵がありません）')),
    el('h3', { text: '管理者の署名鍵（管理者の画面の「あなたの署名鍵」と同じか）' }),
    fingerprintBox(String(r.fingerprint)),
    el('p', { text: `今の世代：${Number(r.vaultKeyVersion)}（管理者の画面の「最後に見た世代」と同じか）` }),
  );
  const reopen = el('button', { text: 'もう一度確かめる', className: 'secondary' });
  reopen.addEventListener('click', async () => {
    const x = await send({ type: 'reopenVault' });
    if (x.ok && x.vault === 'ready') return onDone();
    out.textContent = x.ok ? 'まだ承認されていません。管理者の承認を待ってください。' : message(x.error);
    out.className = x.ok ? 'note' : 'error';
  });
  if (r.pinned) {
    section.append(el('p', { text: '照合は済んでいます。管理者の承認を待っています。', className: 'note' }), reopen, out);
    return section;
  }
  const confirm = el('button', { text: '両方とも一致した' });
  confirm.addEventListener('click', async () => {
    const x = await send({ type: 'confirmAdminSigner', keyId: r.keyId, fingerprint: r.fingerprint, vaultKeyVersion: r.vaultKeyVersion });
    if (x.ok && x.vault === 'ready') return onDone();
    out.textContent = x.ok ? '照合しました。管理者の承認を待っています。承認されたら「もう一度確かめる」を押してください。' : message(x.error);
    out.className = x.ok ? 'note' : 'error';
    if (x.ok) confirm.replaceWith(reopen);
  });
  section.append(el('p', { text: '1桁でも違ったら押さずに、管理者に知らせてください。', className: 'warn' }), el('div', { className: 'row' }, confirm), out);
  return section;
}

// 管理者：メンバーの一覧、照合、承認、削除
export async function membersSection(onChanged: () => void): Promise<HTMLElement> {
  const out = el('p', { className: 'note' });
  const r = await send({ type: 'listMembers' });
  const section = el('section', {}, el('h2', { text: 'メンバー' }));
  section.id = 'members';
  if (!r.ok) {
    section.append(el('p', { text: message(r.error), className: 'error' }));
    return section;
  }
  section.append(
    el('p', { text: '承認するときは、Discord 以外の経路（対面か電話）で、メンバーの画面と次を見比べてもらいます。', className: 'muted' }),
    el('h3', { text: 'あなたの署名鍵' }),
    fingerprintBox(String(r.signFingerprint ?? '（署名鍵がありません）')),
    el('p', { text: `最後に見た世代：${r.lastSeenGeneration === null ? '（未設定）' : Number(r.lastSeenGeneration)}` }),
  );
  const list = el('ul', { className: 'item-list' });
  for (const m of (r.members as Member[]).filter((x) => !x.self)) {
    const label = el(
      'div',
      { className: 'item-label' },
      el('span', { text: `${m.displayName}（${m.status === 'pending' ? '承認待ち' : m.role === 'admin' ? '管理者' : 'メンバー'}）`, className: 'item-title' }),
    );
    const buttons = el('div', { className: 'row' });
    if (m.status === 'pending') {
      if (m.fingerprint === null) label.append(el('span', { text: 'まだ鍵を作っていません', className: 'muted' }));
      else {
        label.append(el('span', { text: 'メンバーの公開鍵', className: 'muted' }), fingerprintBox(m.fingerprint));
        if (!m.pinned) {
          const pin = el('button', { text: '一致した', className: 'secondary' });
          pin.addEventListener('click', async () => {
            const x = await send({ type: 'pinMember', memberId: m.id, keyId: m.keyId, fingerprint: m.fingerprint });
            if (x.ok) return onChanged();
            out.textContent = message(x.error);
            out.className = 'error';
          });
          buttons.append(pin);
        } else {
          label.append(el('span', { text: '照合済み', className: 'note' }));
          const approve = el('button', { text: '承認する' });
          approve.addEventListener('click', async () => {
            const x = await send({ type: 'approveMember', memberId: m.id });
            if (x.ok) return onChanged();
            out.textContent = message(x.error);
            out.className = 'error';
          });
          buttons.append(approve);
        }
      }
    }
    if (m.role !== 'admin') {
      const remove = el('button', { text: '削除', className: 'secondary' });
      remove.addEventListener('click', async () => {
        if (!window.confirm(`${m.displayName} を削除しますか。セッションとグラントを無効にします。`)) return;
        const x = await send({ type: 'removeMember', memberId: m.id });
        if (!x.ok) {
          out.textContent = message(x.error);
          out.className = 'error';
          return;
        }
        // 一覧から消し、ローテーションを勧める知らせを一覧の上に出す（描き直すと知らせが消えるので、ここでは描き直さない）
        li.remove();
        list.before(rotationNotice());
      });
      buttons.append(remove);
    }
    const li = el('li', {}, label, buttons);
    list.append(li);
  }
  if (list.childElementCount === 0) section.append(el('p', { text: 'ほかのメンバーはいません。', className: 'muted' }));
  section.append(list, out);
  return section;
}

// 削除の後の知らせ。相手の端末に残った Vault 鍵は回収できないので、ローテーションを勧める（判断待ち8）
export function rotationNotice(): HTMLElement {
  return el('p', {
    text: 'メンバーを削除しました。その人の端末には、今の世代の Vault 鍵が残っているおそれがあります。ローテーションをしてください。その人が見たパスワードは、実際のサービス側でも変えてください。',
    className: 'warn',
  });
}

// ローテーション（フェーズ4b）。新しい世代の Vault 鍵を作り、全アイテムを暗号化し直し、有効なメンバー全員分のグラントを作る
export function rotationSection(onDone: () => void): HTMLElement {
  const out = el('p', { className: 'note' });
  const button = el('button', { text: 'ローテーションする', className: 'secondary' });
  button.addEventListener('click', async () => {
    if (!window.confirm('Vault 鍵を新しい世代にし、全アイテムを暗号化し直します。よろしいですか。')) return;
    button.disabled = true;
    out.textContent = '暗号化し直しています…';
    out.className = 'muted';
    const r = await send({ type: 'rotateVault' });
    button.disabled = false;
    if (!r.ok) {
      out.textContent = message(r.error);
      out.className = 'error';
      return;
    }
    out.textContent = `世代 ${Number(r.vaultKeyVersion)} にしました（${Number(r.items)} 件を暗号化し直しました）。メンバーの画面にも、新しい世代を伝えてください。`;
    out.className = 'note';
    onDone();
  });
  return el(
    'section',
    {},
    el('h2', { text: 'ローテーション' }),
    el('p', { text: 'メンバーを削除した後や、Vault 鍵が漏れたおそれがあるときに行います。削除した人は、新しい世代の鍵を受け取れません。', className: 'muted' }),
    button,
    out,
  );
}

// 監査ログ（新しい順に50件）
export async function auditSection(): Promise<HTMLElement> {
  const details = el('details', {}, el('summary', { text: '監査ログ' }));
  details.addEventListener('toggle', async () => {
    if (!details.open || details.childElementCount > 1) return;
    const r = await send({ type: 'auditLogs' });
    if (!r.ok) {
      details.append(el('p', { text: message(r.error), className: 'error' }));
      return;
    }
    const list = el('ul', {});
    for (const l of (r.logs as { actor: string; action: string; targetId: string; createdAt: number }[]).slice(0, 50)) {
      list.append(el('li', { text: `${new Date(l.createdAt).toLocaleString()}　${l.action}　${l.targetId}（${l.actor}）` }));
    }
    details.append(list);
  });
  return details;
}
