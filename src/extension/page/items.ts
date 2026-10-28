// 全画面ページのアイテムの画面（2b）：一覧、作成・編集・削除、409 のときの選択。
// 中身はすべて文字として出す（textContent、input・textarea の value）。URL もリンクにしない。HTML として解釈する書き方は使わない。
// パスワードと非表示の項目は伏せ字の欄に入れ、「表示」を押したときだけ文字にする。

import { el, errorText, send } from '../shared/ui.ts';
import { generatorPanel } from './generator.ts';

type Summary = { id: string; type: 'login' | 'note' | null; title: string; username?: string; unreadable: boolean; revision: number };
type CustomField = { type: 'text' | 'hidden' | 'date'; label: string; value: string };
type LoginItem = { type: 'login'; title: string; username: string; password: string; urls: string[]; notes: string; customFields: CustomField[] };
type NoteItem = { type: 'note'; title: string; body: string };
type Item = LoginItem | NoteItem;

// withGenerator のときは「作成」のボタンを足し、自動作成のパネルを開けるようにする（アイテムのパスワードの欄だけ）
function secretInput(value: string, withGenerator = false): HTMLElement {
  const input = el('input', { type: 'password', value, autocomplete: 'off' });
  const toggle = el('button', { text: '表示', className: 'secondary', type: 'button' });
  toggle.addEventListener('click', () => {
    input.type = input.type === 'password' ? 'text' : 'password';
    toggle.textContent = input.type === 'password' ? '表示' : '隠す';
  });
  const row = el('div', { className: 'row' }, input, toggle);
  const slot = el('div');
  if (withGenerator) {
    const create = el('button', { text: '自動作成', className: 'secondary', type: 'button' });
    create.addEventListener('click', () => {
      slot.replaceChildren(
        generatorPanel(
          (password) => {
            input.value = password;
            slot.replaceChildren();
          },
          () => slot.replaceChildren(),
        ),
      );
    });
    row.append(create);
  }
  const wrap = el('div', {}, row, slot);
  (wrap as unknown as { read: () => string }).read = () => input.value;
  return wrap;
}

function readSecret(node: HTMLElement): string {
  return (node as unknown as { read: () => string }).read();
}

function labeled(label: string, field: HTMLElement): HTMLElement {
  return el('label', { className: 'field' }, el('span', { text: label, className: 'muted' }), field);
}

const MAX_CUSTOM_FIELDS = 20; // src/client/item-data.ts と同じ上限
const CUSTOM_TYPES: { value: CustomField['type']; label: string }[] = [
  { value: 'text', label: 'テキスト' },
  { value: 'hidden', label: '非表示' },
  { value: 'date', label: '日付' },
];

// コピーのボタン。値は Service Worker がアイテムから取り出し、オフスクリーンドキュメントで書いて1分後に消す（E-10・E-12）。
// 保存済みのアイテムにだけ出す。コピーするのは保存した値（画面で書き換えた、まだ保存していない値ではない）
function copyButton(id: string, target: { field: 'password' } | { customIndex: number }, out: HTMLElement): HTMLElement {
  const button = el('button', { text: 'コピー', className: 'secondary', type: 'button' });
  button.addEventListener('click', async () => {
    const r = await send({ type: 'copyToClipboard', id, ...target });
    out.textContent = r.ok ? 'コピーしました。1分後に消します（Windows のクリップボードの履歴には残ります）。' : errorText(r.error);
    out.className = r.ok ? 'muted' : 'error';
  });
  return button;
}

// カスタム項目の編集（テキスト・非表示・日付。20項目まで）。カスタム項目は自動入力に使わず、コピーだけ
function customFieldsEditor(fields: CustomField[], id: string | null, out: HTMLElement): { node: HTMLElement; read: () => CustomField[] } {
  type Row = { node: HTMLElement; read: () => CustomField };
  const rows: Row[] = [];
  const list = el('div');
  const add = el('button', { text: '項目を足す', className: 'secondary', type: 'button' });

  function makeRow(field: CustomField, savedIndex: number | null): Row {
    const type = el('select');
    for (const t of CUSTOM_TYPES) {
      const option = el('option', { text: t.label });
      option.value = t.value;
      type.append(option);
    }
    type.value = field.type;
    const label = el('input', { type: 'text', value: field.label, placeholder: '項目の名前' });
    const slot = el('div');
    let readValue: () => string = () => field.value;
    const drawValue = (value: string) => {
      if (type.value === 'hidden') {
        const secret = secretInput(value);
        readValue = () => readSecret(secret);
        slot.replaceChildren(secret);
      } else {
        const input = el('input', { type: type.value === 'date' ? 'date' : 'text', value, autocomplete: 'off' });
        readValue = () => input.value;
        slot.replaceChildren(input);
      }
    };
    drawValue(field.value);
    type.addEventListener('change', () => drawValue(readValue()));
    const remove = el('button', { text: '消す', className: 'secondary', type: 'button' });
    const buttons = el('div', { className: 'row' }, remove);
    if (id !== null && savedIndex !== null) buttons.append(copyButton(id, { customIndex: savedIndex }, out));
    const node = el('div', { className: 'custom-field' }, el('div', { className: 'row' }, type, label), slot, buttons);
    const row: Row = { node, read: () => ({ type: type.value as CustomField['type'], label: label.value, value: readValue() }) };
    remove.addEventListener('click', () => {
      rows.splice(rows.indexOf(row), 1);
      node.remove();
      add.disabled = rows.length >= MAX_CUSTOM_FIELDS;
    });
    return row;
  }

  fields.forEach((f, i) => rows.push(makeRow(f, i)));
  list.append(...rows.map((r) => r.node));
  add.disabled = rows.length >= MAX_CUSTOM_FIELDS;
  add.addEventListener('click', () => {
    if (rows.length >= MAX_CUSTOM_FIELDS) return;
    const row = makeRow({ type: 'text', label: '', value: '' }, null);
    rows.push(row);
    list.append(row.node);
    add.disabled = rows.length >= MAX_CUSTOM_FIELDS;
  });
  return { node: el('div', {}, el('span', { text: 'カスタム項目（自動入力には使わない）', className: 'muted' }), list, add), read: () => rows.map((r) => r.read()) };
}

// 編集のフォーム。read() で、画面の値からアイテムを組み立てる（形の確かめは Service Worker の validateItem）。
// id があれば（保存済みなら）、パスワードとカスタム項目にコピーのボタンを付ける
function editorFields(item: Item, id: string | null = null): { node: HTMLElement; read: () => Item } {
  const title = el('input', { type: 'text', value: item.title });
  if (item.type === 'note') {
    const body = el('textarea');
    body.value = item.body;
    return { node: el('div', {}, labeled('タイトル', title), labeled('本文', body)), read: () => ({ type: 'note', title: title.value, body: body.value }) };
  }
  const username = el('input', { type: 'text', value: item.username, autocomplete: 'off' });
  const password = secretInput(item.password, true);
  const urls = el('textarea');
  urls.value = item.urls.join('\n');
  const notes = el('textarea');
  notes.value = item.notes;
  const copyOut = el('p', { className: 'muted' });
  if (id !== null) password.append(el('div', { className: 'row' }, copyButton(id, { field: 'password' }, copyOut)));
  const custom = customFieldsEditor(item.customFields, id, copyOut);
  return {
    node: el('div', {}, labeled('タイトル', title), labeled('ユーザー名', username), labeled('パスワード', password), labeled('URL（1行に1つ、https だけ）', urls), labeled('メモ', notes), custom.node, copyOut),
    read: () => ({
      type: 'login',
      title: title.value,
      username: username.value,
      password: readSecret(password),
      urls: urls.value.split('\n').map((u) => u.trim()).filter((u) => u !== ''),
      notes: notes.value,
      customFields: custom.read(),
    }),
  };
}

export function blankItem(type: 'login' | 'note'): Item {
  return type === 'note' ? { type: 'note', title: '', body: '' } : { type: 'login', title: '', username: '', password: '', urls: [], notes: '', customFields: [] };
}

// 1件の編集（id がなければ新しく作る）。409 のときは、今の版と自分の入力を並べて選ばせる
export function editorSection(item: Item, id: string | null, revision: number | null, done: () => void): HTMLElement {
  const out = el('p', { className: 'note' });
  const form = editorFields(item, id);
  const area = el('div', {}, form.node);
  const save = el('button', { text: id ? '保存' : '作成' });
  save.addEventListener('click', async () => {
    const mine = form.read();
    const r = await send(id ? { type: 'saveItem', id, revision, item: mine } : { type: 'saveItem', item: mine });
    if (r.ok) return done();
    // 選ばせるのは更新の 409 だけ。作成の CONFLICT（ID が2回重なった）には上書きする相手がない
    if (r.error === 'CONFLICT' && id) return showConflict(mine, r.current as Item | null, Number(r.currentRevision));
    out.textContent = r.error === 'DELETED' ? 'ほかの端末で削除されました。' : errorText(r.error);
    out.className = 'error';
  });
  const actions = el('div', { className: 'row' }, save);
  if (id) {
    const del = el('button', { text: '削除', className: 'secondary' });
    del.addEventListener('click', async () => {
      const r = await send({ type: 'deleteItem', id, revision });
      if (r.ok) return done();
      if (r.error === 'CONFLICT') return showDeleteConflict(r.current as Item | null, Number(r.currentRevision));
      out.textContent = r.error === 'DELETED' ? 'ほかの端末で削除されました。' : errorText(r.error);
      out.className = 'error';
    });
    actions.append(del);
  }
  const cancel = el('button', { text: 'キャンセル', className: 'secondary' });
  cancel.addEventListener('click', () => done());
  actions.append(cancel);

  // 削除の 409（10.3）：今の版を見せてから、それでも削除するかを聞く。押したときだけ、今のリビジョンで送り直す
  function showDeleteConflict(current: Item | null, currentRevision: number): void {
    area.replaceChildren(
      el('p', { text: '先に変更されています。それでも削除しますか。', className: 'warn' }),
      el('h3', { text: '今の版（サーバー）' }),
      current ? editorFields(current).node : el('p', { text: '今の版は読めません。', className: 'error' }),
    );
    const keep = el('button', { text: '削除しない', className: 'secondary' });
    keep.addEventListener('click', () => done());
    const del = el('button', { text: 'それでも削除する' });
    del.addEventListener('click', async () => {
      const r = await send({ type: 'deleteItem', id, revision: currentRevision });
      if (r.ok) return done();
      out.textContent = errorText(r.error);
      out.className = 'error';
    });
    actions.replaceChildren(keep, del);
  }

  function showConflict(mine: Item, current: Item | null, currentRevision: number): void {
    area.replaceChildren(
      el('p', { text: 'ほかの人が先に変更しました。どちらを残すか選んでください。', className: 'warn' }),
      el('h3', { text: '今の版（サーバー）' }),
      current ? editorFields(current).node : el('p', { text: '今の版は読めません。', className: 'error' }),
      el('h3', { text: '自分の入力' }),
      editorFields(mine).node,
    );
    const useCurrent = el('button', { text: '今の版を使う（自分の変更を捨てる）', className: 'secondary' });
    useCurrent.addEventListener('click', () => done());
    const overwrite = el('button', { text: '自分の内容で上書きする' });
    overwrite.addEventListener('click', async () => {
      const r = await send({ type: 'saveItem', id, revision: currentRevision, item: mine });
      if (r.ok) return done();
      out.textContent = errorText(r.error);
      out.className = 'error';
    });
    actions.replaceChildren(useCurrent, overwrite);
  }

  return el('section', {}, el('h2', { text: id ? 'アイテムの編集' : '新しいアイテム' }), area, actions, out);
}

export async function itemsSection(open: (id: string | null, type: 'login' | 'note') => void, openImport: () => void): Promise<HTMLElement> {
  const out = el('p', { className: 'note' });
  const s = await send({ type: 'sync' });
  if (!s.ok) {
    out.textContent = s.error === 'ROLLBACK_DETECTED' ? 'サーバーが古い状態を返しました。同期を止めています。管理者に知らせてください。' : errorText(s.error);
    out.className = 'error';
  }
  const r = await send({ type: 'listItems' });
  const search = el('input', { type: 'search', placeholder: '検索（タイトル、ユーザー名）' });
  const list = el('ul', { className: 'item-list' });
  const items = r.ok ? (r.items as Summary[]) : [];
  const draw = () => {
    const q = search.value.trim().toLowerCase();
    list.replaceChildren(
      ...items
        .filter((i) => q === '' || i.title.toLowerCase().includes(q) || (i.username ?? '').toLowerCase().includes(q))
        .map((i) => {
          const label = el('div', { className: 'item-label' }, el('span', { text: i.unreadable ? `読めないアイテム（${i.id}）` : i.title || '（タイトルなし）', className: i.unreadable ? 'error' : 'item-title' }));
          if (i.username) label.append(el('span', { text: i.username, className: 'muted' }));
          const li = el('li', {}, label);
          if (!i.unreadable) {
            const edit = el('button', { text: '開く', className: 'secondary' });
            edit.addEventListener('click', () => open(i.id, i.type ?? 'login'));
            li.append(edit);
          }
          return li;
        }),
    );
  };
  search.addEventListener('input', draw);
  draw();
  const newLogin = el('button', { text: '新しいログイン' });
  newLogin.addEventListener('click', () => open(null, 'login'));
  const newNote = el('button', { text: '新しいメモ', className: 'secondary' });
  newNote.addEventListener('click', () => open(null, 'note'));
  const importCsv = el('button', { text: 'CSV から取り込む', className: 'secondary' });
  importCsv.addEventListener('click', () => openImport());
  if (!r.ok) out.textContent = errorText(r.error);
  return el('section', {}, el('h2', { text: 'アイテム' }), el('div', { className: 'row' }, newLogin, newNote, importCsv), search, list, out);
}

export function passcodeSection(onDone: () => void): HTMLElement {
  const out = el('p', { className: 'note' });
  const form = el('form');
  const p1 = el('input', { type: 'password', placeholder: '4桁の数字', autocomplete: 'off' });
  const p2 = el('input', { type: 'password', placeholder: 'もう一度', autocomplete: 'off' });
  form.append(p1, p2, el('button', { text: 'パスコードを決める' }));
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
    const r = await send({ type: 'setupQuickUnlock', passcode: a });
    out.textContent = r.ok ? 'パスコードを決めました。ブラウザを閉じる、ロックする、45分放置する、5回間違えると消えます。' : errorText(r.error);
    out.className = r.ok ? 'note' : 'error';
    if (r.ok) onDone();
  });
  return el(
    'section',
    {},
    el('h2', { text: 'クイックロック解除（4桁のパスコード）' }),
    el('p', { text: 'Service Worker が止まった後に、4桁で戻れるようにします（任意）。管理操作には、いつもマスターパスワードが要ります。', className: 'muted' }),
    form,
    out,
  );
}

export async function openItem(id: string): Promise<{ item: Item; revision: number } | string> {
  const r = await send({ type: 'getItem', id });
  return r.ok ? { item: r.item as Item, revision: Number(r.revision) } : errorText(r.error);
}
