// フェーズ5：CSV インポート（docs/実装状況.md の11.5）。偽の chrome と本物の API（app.request ＋ SQLite）をつなぐ。
// プレビューは Service Worker が作る（既存のアイテムとの重複を見るため。既存のパスワードは画面に渡さない）。

import { after, beforeEach, mock, test } from 'node:test';
import assert from 'node:assert/strict';
import { adminReady, newDiscord, send, world, type World } from '../helpers/extension-world.ts';

const T0 = 1_800_000_000_000;
mock.timers.enable({ apis: ['Date'], now: T0 });
after(() => mock.timers.reset());
beforeEach(() => mock.timers.setTime(T0));

const discord = newDiscord();
after(discord.install());

const CHROME_CSV = [
  'name,url,username,password,note',
  '社内 Wiki,https://wiki.example.com/login,team@example.com,new-password-1,"メモ, 改行\nあり"',
  'チャット,https://chat.example.com/,team@example.com,chat-password-2,',
  'メール,https://mail.example.com/,team@example.com,mail-password-3,',
].join('\n');

type Row = { row: number; item: Record<string, unknown>; duplicate: boolean; passwordChangedFromExisting: boolean };

async function ready(): Promise<World> {
  const w = world(discord);
  await adminReady(w, discord);
  return w;
}

function login(i: number, notes = '') {
  return { type: 'login', title: `サイト${i}`, username: `user${i}@example.com`, password: `password-${i}`, urls: [`https://site${i}.example.com/`], notes, customFields: [] };
}

function imports(w: World): number {
  return w.calls.filter((c) => c === 'POST /v1/items/import').length;
}

test('M-02 Chrome の CSV をプレビューして取り込む。中身は暗号化して入り、一覧と1件の表示で読める', async () => {
  const w = await ready();
  const p = await send(w, { type: 'previewCsv', csv: CHROME_CSV, format: 'chrome' });
  assert.equal(p.ok, true, JSON.stringify(p));
  const rows = p.items as Row[];
  assert.deepEqual(rows.map((r) => r.row), [2, 4, 5]);
  assert.equal(rows[0]!.item.notes, 'メモ, 改行\nあり');
  const r = await send(w, { type: 'importItems', items: rows.map((x) => x.item) });
  assert.deepEqual(r, { ok: true, imported: 3 });
  assert.equal(imports(w), 1);
  const list = await send(w, { type: 'listItems' });
  assert.deepEqual((list.items as { title: string }[]).map((i) => i.title).sort(), ['チャット', 'メール', '社内 Wiki'].sort());
  const wiki = (list.items as { id: string; title: string }[]).find((i) => i.title === '社内 Wiki')!;
  assert.equal(((await send(w, { type: 'getItem', id: wiki.id })).item as { password: string }).password, 'new-password-1');
  // サーバーには平文を送っていない
  const stored = JSON.stringify(w.t.db.db.prepare('SELECT * FROM items').all());
  for (const plain of ['new-password-1', 'team@example.com', 'wiki.example.com']) assert.ok(!stored.includes(plain), plain);
});

test('既存のアイテムとの重複に印を付ける。既存と違うパスワードなら passwordChangedFromExisting。既存のパスワードは返さない', async () => {
  const w = await ready();
  const old = { type: 'login', title: '社内 wiki', username: 'TEAM@example.com', password: 'old-password', urls: ['https://wiki.example.com/login'], notes: '', customFields: [] };
  assert.equal((await send(w, { type: 'saveItem', item: old })).ok, true);
  const p = await send(w, { type: 'previewCsv', csv: CHROME_CSV, format: 'chrome' });
  const rows = p.items as Row[];
  assert.deepEqual(rows.map((r) => [r.duplicate, r.passwordChangedFromExisting]), [[true, true], [false, false], [false, false]]);
  assert.ok(!JSON.stringify(p).includes('old-password'));
});

test('M-03 壊れた行は行番号付きで返し、ほかの行はプレビューに出す', async () => {
  const w = await ready();
  const csv = 'name,url,username,password,note\nA,https://a.example.com/,u,p,\nB,https://b.example.com/,u\nC,https://c.example.com/,u,p,,extra\n';
  const p = await send(w, { type: 'previewCsv', csv, format: 'chrome' });
  assert.deepEqual((p.items as Row[]).map((r) => r.row), [2]);
  assert.deepEqual(p.errors, [{ row: 3, reason: 'column count mismatch' }, { row: 4, reason: 'column count mismatch' }]);
});

test('M-04 1,200件は 500・500・200 の3回に分けて送る', async () => {
  const w = await ready();
  const items = Array.from({ length: 1200 }, (_, i) => login(i));
  const r = await send(w, { type: 'importItems', items });
  assert.deepEqual(r, { ok: true, imported: 1200 });
  assert.equal(imports(w), 3);
  assert.equal(Number(w.t.db.db.prepare('SELECT COUNT(*) AS n FROM items').get()!.n), 1200);
});

test('M-04 大きいアイテムは、1回の送信が 1.5MB を超えないように分けて送る', async () => {
  const w = await ready();
  // メモが 40KB のアイテムは 64KB 段（約 87KB の暗号文）になる。1回に17件まで
  const items = Array.from({ length: 40 }, (_, i) => login(i, 'あ'.repeat(14_000)));
  const r = await send(w, { type: 'importItems', items });
  assert.deepEqual(r, { ok: true, imported: 40 });
  assert.equal(imports(w), 3);
});

test('途中の送信が失敗したら止め、どこまで入ったか（件数）を返す。入った分は一覧に出る', async () => {
  const w = await ready();
  // 2回目の送信のバッチで D1 が失敗する（API は 500 を返し、2回目の分は1件も入らない）
  let n = 0;
  w.t.db.beforeBatch = async () => {
    if (++n === 2) throw new Error('D1 が落ちた');
  };
  const r = await send(w, { type: 'importItems', items: Array.from({ length: 1200 }, (_, i) => login(i)) });
  assert.deepEqual(r, { ok: false, error: 'SERVER', imported: 500 });
  assert.equal(imports(w), 2, '失敗の後は送らない');
  assert.equal(((await send(w, { type: 'listItems' })).items as unknown[]).length, 500);
});

test('ロック中は、プレビューも取り込みも断る', async () => {
  const w = await ready();
  await send(w, { type: 'lock' });
  assert.deepEqual(await send(w, { type: 'previewCsv', csv: CHROME_CSV, format: 'chrome' }), { ok: false, error: 'LOCKED' });
  assert.deepEqual(await send(w, { type: 'importItems', items: [login(1)] }), { ok: false, error: 'LOCKED' });
  assert.equal(imports(w), 0);
});

test('形式は3つだけ。アイテムの形が違う、空の配列は受け付けない', async () => {
  const w = await ready();
  for (const bad of [
    { type: 'previewCsv', csv: CHROME_CSV, format: 'bitwarden' },
    { type: 'importItems', items: [] },
    { type: 'importItems', items: [{ ...login(1), extra: 1 }] },
    { type: 'importItems', items: login(1) },
  ]) {
    assert.deepEqual(await send(w, bad), { ok: false, error: 'BAD_REQUEST' }, JSON.stringify(bad).slice(0, 60));
  }
  assert.equal(imports(w), 0);
});
