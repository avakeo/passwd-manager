// フェーズ3：自動入力とコピー（docs/実装状況.md の11.2・11.3）。
// 偽の chrome のタブと注入（tests/helpers/fake-chrome.ts）と、本物の API をつなぐ。入力のスクリプトそのものは tests/browser で確かめる。

import { after, beforeEach, mock, test } from 'node:test';
import assert from 'node:assert/strict';
import { POPUP, PAGE, adminReady, newDiscord, send, world, type World } from '../helpers/extension-world.ts';

const T0 = 1_800_000_000_000;
mock.timers.enable({ apis: ['Date'], now: T0 });
after(() => mock.timers.reset());
beforeEach(() => mock.timers.setTime(T0));

const discord = newDiscord();
after(discord.install());

const TAB = 7;
const LOGIN = {
  type: 'login',
  title: '社内 Wiki',
  username: 'team@example.com',
  password: 'correct-horse-battery-staple',
  urls: ['https://wiki.example.com/login?next=/'],
  notes: 'メモ',
  customFields: [
    { type: 'hidden', label: 'PIN', value: '0420' },
    { type: 'text', label: '契約番号', value: 'C-123' },
  ],
};

async function ready(): Promise<{ w: World; id: string }> {
  const w = world(discord);
  await adminReady(w, discord);
  const r = await send(w, { type: 'saveItem', item: LOGIN });
  assert.equal(r.ok, true, JSON.stringify(r));
  // ほかのアイテム（注入の引数に混ざらないこと）
  assert.equal((await send(w, { type: 'saveItem', item: { ...LOGIN, title: '別', password: 'other-secret-password', urls: ['https://other.example.com/'] } })).ok, true);
  return { w, id: String(r.id) };
}

function openTab(w: World, url: string, documentId = 'doc-1', frames = [0]): void {
  w.chrome.openTabs.set(TAB, { url, documentId, frames });
}

function fills(w: World) {
  return w.chrome.injections.filter((i) => i.func === 'fillLogin');
}

test('E-01 E-02 E-09 ポップアップから入力すると、トップフレームの確認した文書だけに、1件分のユーザー名とパスワードだけを渡す', async () => {
  const { w, id } = await ready();
  openTab(w, 'https://wiki.example.com/login', 'doc-1', [0, 3]);
  const r = await send(w, { type: 'autofill', id, tabId: TAB }, POPUP);
  assert.deepEqual(r, { ok: true, filled: 2 });
  const probes = w.chrome.injections.filter((i) => i.func === 'probePage');
  assert.equal(probes.length, 2, '照合のときと入力の直前の2回、文書を確かめる');
  for (const p of probes) assert.deepEqual(p.target, { tabId: TAB, frameIds: [0] }, 'トップフレームだけ（iframe の frame 3 には入れない）');
  assert.equal(fills(w).length, 1);
  assert.deepEqual(fills(w)[0]!.target, { tabId: TAB, documentIds: ['doc-1'] });
  assert.deepEqual(fills(w)[0]!.args, ['https://wiki.example.com', 'team@example.com', 'correct-horse-battery-staple']);
  const dump = JSON.stringify(w.chrome.injections);
  for (const other of ['other-secret-password', '0420', 'C-123', 'メモ']) assert.ok(!dump.includes(other), `${other} を渡さない`);
});

test('E-07 E-08 自動入力はポップアップからだけ始める。全画面ページやページに注入したスクリプトからは断る', async () => {
  const { w, id } = await ready();
  openTab(w, 'https://wiki.example.com/login');
  assert.deepEqual(await send(w, { type: 'autofill', id, tabId: TAB }, PAGE), { ok: false, error: 'BAD_REQUEST' });
  // ページの中から送ったもの（送り主の url がページのアドレス）
  const fromPage = await w.bg.handleMessage({ type: 'autofill', id, tabId: TAB }, { id: w.chrome.runtime.id, url: 'https://wiki.example.com/login', frameId: 0 });
  assert.deepEqual(fromPage, { ok: false, error: 'BAD_REQUEST' });
  assert.equal(w.chrome.injections.length, 0, '何も注入しない');
});

test('E-03 http のページには入れない', async () => {
  const { w, id } = await ready();
  openTab(w, 'http://wiki.example.com/login');
  assert.deepEqual(await send(w, { type: 'autofill', id, tabId: TAB }, POPUP), { ok: false, error: 'AUTOFILL_REFUSED' });
  assert.equal(fills(w).length, 0);
});

test('E-04 E-05 似たドメイン、サブドメイン、ポート違い、www の有無が違うページには入れない', async () => {
  const { w, id } = await ready();
  for (const url of [
    'https://wiki.example.com.evil.example/login',
    'https://login.wiki.example.com/',
    'https://wiki.example.com:8443/login',
    'https://www.wiki.example.com/login',
    'https://example.com/',
    'https://wiki-example.com/',
  ]) {
    openTab(w, url);
    assert.deepEqual(await send(w, { type: 'autofill', id, tabId: TAB }, POPUP), { ok: false, error: 'AUTOFILL_REFUSED' }, url);
  }
  assert.equal(fills(w).length, 0);
  // パスとクエリは照合に使わない。ポート 443 の明示は同じオリジン
  openTab(w, 'https://wiki.example.com:443/other/path?x=1');
  assert.equal((await send(w, { type: 'autofill', id, tabId: TAB }, POPUP)).ok, true);
});

test('E-13 照合の後、入力の前に別のオリジンへ移ったら入れない（タブのアドレスを取り直す）', async () => {
  const { w, id } = await ready();
  openTab(w, 'https://wiki.example.com/login', 'doc-1');
  let probes = 0;
  w.chrome.onInject = (i) => {
    // 1回目の確認の後に、同じタブで別のサイトへ移る
    if (i.func === 'probePage' && ++probes === 1) queueMicrotask(() => w.chrome.openTabs.set(TAB, { url: 'https://evil.example/login', documentId: 'doc-2' }));
  };
  assert.deepEqual(await send(w, { type: 'autofill', id, tabId: TAB }, POPUP), { ok: false, error: 'AUTOFILL_REFUSED' });
  assert.equal(fills(w).length, 0);
});

test('E-13 照合の後、同じオリジンのまま文書が入れ替わったら入れない（文書 ID を取り直す）', async () => {
  const { w, id } = await ready();
  openTab(w, 'https://wiki.example.com/login', 'doc-1');
  let probes = 0;
  w.chrome.onInject = (i) => {
    // 1回目の確認が doc-1 を返した後に入れ替わる
    if (i.func === 'probePage' && ++probes === 1) queueMicrotask(() => w.chrome.openTabs.set(TAB, { url: 'https://wiki.example.com/login', documentId: 'doc-2' }));
  };
  assert.deepEqual(await send(w, { type: 'autofill', id, tabId: TAB }, POPUP), { ok: false, error: 'AUTOFILL_REFUSED' });
  assert.equal(fills(w).length, 0);
});

test('E-13 文書 ID が同じに見えても、タブのアドレスが別のオリジンに変わっていたら入れない（アドレスもブラウザから取り直す）', async () => {
  const { w, id } = await ready();
  openTab(w, 'https://wiki.example.com/login', 'doc-1');
  let probes = 0;
  w.chrome.onInject = (i) => {
    if (i.func === 'probePage' && ++probes === 2) queueMicrotask(() => w.chrome.openTabs.set(TAB, { url: 'https://evil.example/login', documentId: 'doc-1' }));
  };
  assert.deepEqual(await send(w, { type: 'autofill', id, tabId: TAB }, POPUP), { ok: false, error: 'AUTOFILL_REFUSED' });
  assert.equal(fills(w).length, 0);
});

test('E-13 判定の後、入力のスクリプトを入れる前に文書が変わったら、古い文書を指定した注入は届かない', async () => {
  const { w, id } = await ready();
  openTab(w, 'https://wiki.example.com/login', 'doc-1');
  let probes = 0;
  w.chrome.onInject = (i) => {
    if (i.func === 'probePage' && ++probes === 2) {
      // 2回目の確認のすぐ後（入力の注入の直前）に移る。注入は doc-1 を指定するので、新しい文書には入らない
      queueMicrotask(() => w.chrome.openTabs.set(TAB, { url: 'https://wiki.example.com/login', documentId: 'doc-3' }));
    }
  };
  const r = await send(w, { type: 'autofill', id, tabId: TAB }, POPUP);
  assert.deepEqual(r, { ok: true, filled: 0 });
  assert.deepEqual(fills(w)[0]?.target.documentIds, ['doc-1']);
});

test('E-11 ロック中は、自動入力もコピーも断り、何も注入しない', async () => {
  const { w, id } = await ready();
  openTab(w, 'https://wiki.example.com/login');
  await send(w, { type: 'lock' });
  assert.deepEqual(await send(w, { type: 'autofill', id, tabId: TAB }, POPUP), { ok: false, error: 'LOCKED' });
  assert.deepEqual(await send(w, { type: 'copyToClipboard', id, field: 'password' }, POPUP), { ok: false, error: 'LOCKED' });
  assert.equal(w.chrome.injections.length, 0);
  assert.equal(w.chrome.sentToOffscreen.length, 0);
});

test('タブが閉じられていたら、入れずに断る', async () => {
  const { w, id } = await ready();
  assert.deepEqual(await send(w, { type: 'autofill', id, tabId: 999 }, POPUP), { ok: false, error: 'AUTOFILL_REFUSED' });
});

test('E-10 E-12 パスワードと、カスタム項目の1つを、オフスクリーンドキュメントでコピーする。オフスクリーンドキュメントは1つだけ作る', async () => {
  const { w, id } = await ready();
  assert.deepEqual(await send(w, { type: 'copyToClipboard', id, field: 'password' }, POPUP), { ok: true, clearsAfterSeconds: 60 });
  assert.deepEqual(await send(w, { type: 'copyToClipboard', id, customIndex: 0 }), { ok: true, clearsAfterSeconds: 60 });
  assert.deepEqual(w.chrome.sentToOffscreen, [
    { target: 'teampw-offscreen', type: 'copy', text: 'correct-horse-battery-staple' },
    { target: 'teampw-offscreen', type: 'copy', text: '0420' },
  ]);
  assert.deepEqual(await send(w, { type: 'copyToClipboard', id, customIndex: 5 }), { ok: false, error: 'NOT_FOUND' });
  w.chrome.offscreenReply = { ok: false };
  assert.deepEqual(await send(w, { type: 'copyToClipboard', id, field: 'password' }), { ok: false, error: 'CLIPBOARD' });
});

test('コピーの種類は password とカスタム項目の番号だけ。ほかの名前は受け付けない', async () => {
  const { w, id } = await ready();
  for (const bad of [{ field: 'username' }, { field: 'notes' }, { customIndex: -1 }, { customIndex: 1.5 }, { field: 'password', customIndex: 0 }]) {
    assert.deepEqual(await send(w, { type: 'copyToClipboard', id, ...bad }), { ok: false, error: 'BAD_REQUEST' }, JSON.stringify(bad));
  }
});
