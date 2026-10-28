// 全画面ページの CSV インポート（フェーズ5、docs/実装状況.md の11.5）。
// ファイルはこのページの中だけで読み、サーバーには送らない。プレビューは Service Worker が作る（既存のアイテムとの重複を見るため）。
// CSV 由来の値は、すべて textContent で文字として出す。パスワードはプレビューに出さない。

import { el, errorText, send } from '../shared/ui.ts';

type Row = { row: number; item: { title: string; username: string; urls: string[] }; duplicate: boolean; passwordChangedFromExisting: boolean };
type Issue = { row: number; reason: string };

const MAX_CSV_BYTES = 5 * 1024 * 1024; // src/client/csv-import.ts と同じ上限

const FORMATS = [
  { value: 'chrome', label: 'Chrome' },
  { value: 'proton', label: 'Proton Pass' },
  { value: '1password', label: '1Password' },
];

const REASONS: Record<string, string> = {
  'invalid CSV quoting': '引用符の形が正しくありません',
  'unclosed quoted field': '引用符が閉じていません（この後の行は読み直しました。内容を確かめてください）',
  'CSV recovery limit exceeded': '引用符の閉じ忘れが多すぎるので、読み直しをやめました',
  'column count mismatch': '列の数が見出しと違います',
  'item too large': 'アイテムが大きすぎます',
  'invalid item': '項目の形が正しくありません（URL が https でない、長すぎるなど）',
  'invalid CSV header': '見出しが、選んだ形式と合いません',
  'CSV too large': 'CSV が大きすぎます（5 MiB まで）',
  'too many CSV rows': '行が多すぎます（10,000行まで）',
  'unsupported columns have values': '取り込まない列（TOTP、タグなど）に値があります。その値は取り込みません',
};

function issueList(title: string, issues: Issue[], className: string): HTMLElement {
  return el(
    'div',
    {},
    el('p', { text: `${title}（${issues.length}件）`, className }),
    el('ul', {}, ...issues.map((i) => el('li', { text: `行 ${i.row}：${REASONS[i.reason] ?? i.reason}` }))),
  );
}

export function importSection(done: () => void): HTMLElement {
  const out = el('p', { className: 'note' });
  const format = el('select');
  for (const f of FORMATS) {
    const option = el('option', { text: f.label });
    option.value = f.value;
    format.append(option);
  }
  const file = el('input', { type: 'file' });
  file.accept = '.csv,text/csv';
  const previewButton = el('button', { text: 'プレビュー', type: 'button' });
  const result = el('div');
  const cancel = el('button', { text: 'キャンセル', className: 'secondary', type: 'button' });
  cancel.addEventListener('click', () => done());

  previewButton.addEventListener('click', async () => {
    result.replaceChildren();
    const chosen = file.files?.[0];
    if (!chosen) {
      out.textContent = 'CSV のファイルを選んでください';
      out.className = 'error';
      return;
    }
    if (chosen.size > MAX_CSV_BYTES) {
      out.textContent = 'CSV が大きすぎます（5 MiB まで）';
      out.className = 'error';
      return;
    }
    out.textContent = '';
    const r = await send({ type: 'previewCsv', csv: await chosen.text(), format: format.value });
    if (!r.ok) {
      out.textContent = errorText(r.error);
      out.className = 'error';
      return;
    }
    result.replaceChildren(preview(r.items as Row[], r.errors as Issue[], r.warnings as Issue[]));
  });

  // プレビュー。重複の行は、初めは取り込まない（チェックを外しておく）。既存と違うパスワードの重複は、はっきり警告する
  function preview(rows: Row[], errors: Issue[], warnings: Issue[]): HTMLElement {
    const checks: { box: HTMLInputElement; row: Row }[] = [];
    const count = el('p', { className: 'muted' });
    const run = el('button', { text: '取り込む', type: 'button' });
    const update = () => {
      const n = checks.filter((c) => c.box.checked).length;
      count.textContent = `取り込む：${n}件／読めた行：${rows.length}件`;
      run.textContent = `選んだ ${n} 件を取り込む`;
      run.disabled = n === 0;
    };
    const list = el(
      'ul',
      { className: 'item-list' },
      ...rows.map((row) => {
        const box = el('input', { type: 'checkbox' });
        box.checked = !row.duplicate;
        box.addEventListener('change', update);
        checks.push({ box, row });
        const label = el(
          'div',
          { className: 'item-label' },
          el('span', { text: row.item.title || '（タイトルなし）', className: 'item-title' }),
          el('span', { text: `${row.item.username}　${row.item.urls.join(' ')}`, className: 'muted' }),
        );
        if (row.passwordChangedFromExisting) label.append(el('span', { text: '既存のアイテムと重なり、パスワードが違います。取り込むと、別のアイテムとして増えます', className: 'warn' }));
        else if (row.duplicate) label.append(el('span', { text: '既存のアイテムか、CSV の前の行と重なっています', className: 'warn' }));
        return el('li', {}, el('label', { className: 'toggle' }, box, label), el('span', { text: `行 ${row.row}`, className: 'muted' }));
      }),
    );
    const all = el('button', { text: 'すべて選ぶ', className: 'secondary', type: 'button' });
    all.addEventListener('click', () => {
      for (const c of checks) c.box.checked = true;
      update();
    });
    const none = el('button', { text: 'すべて外す', className: 'secondary', type: 'button' });
    none.addEventListener('click', () => {
      for (const c of checks) c.box.checked = false;
      update();
    });
    run.addEventListener('click', async () => {
      const chosen = checks.filter((c) => c.box.checked).map((c) => c.row.item);
      run.disabled = true;
      out.textContent = `${chosen.length} 件を暗号化して送っています…`;
      out.className = 'muted';
      const r = await send({ type: 'importItems', items: chosen });
      const imported = Number(r.imported ?? 0);
      const remove = '元の CSV ファイルにはパスワードが平文で入っています。取り込みが済んだら、ファイルを削除してください（ゴミ箱も空にしてください）。';
      if (r.ok) {
        result.replaceChildren(el('p', { text: `${imported} 件を取り込みました。`, className: 'note' }), el('p', { text: remove, className: 'warn' }));
        out.textContent = '';
        cancel.textContent = '一覧に戻る';
        return;
      }
      // 分けて送った途中で失敗したら、どこまで入ったかを出す（仕様書「CSVインポート」）
      out.textContent = `${chosen.length} 件のうち ${imported} 件まで取り込みました。残りは入っていません（${errorText(r.error)}）。`;
      out.className = 'error';
      if (imported === 0) run.disabled = false;
    });
    update();
    const parts: HTMLElement[] = [];
    if (errors.length > 0) parts.push(issueList('読めなかった行', errors, 'error'));
    if (warnings.length > 0) parts.push(issueList('確かめてほしい行', warnings, 'warn'));
    parts.push(count, el('div', { className: 'row' }, all, none), list, el('div', { className: 'row' }, run));
    return el('div', {}, ...parts);
  }

  return el(
    'section',
    {},
    el('h2', { text: 'CSV から取り込む' }),
    el('p', { text: 'ファイルはこのページの中だけで読みます。サーバーには、1件ずつ暗号化したものだけを送ります。TOTP やタグなどの列は取り込みません。', className: 'muted' }),
    el('label', { className: 'field' }, el('span', { text: '形式', className: 'muted' }), format),
    el('label', { className: 'field' }, el('span', { text: 'CSV のファイル', className: 'muted' }), file),
    el('div', { className: 'row' }, previewButton, cancel),
    out,
    result,
  );
}
