// ツールバーのアイコンに、今のタブで入力できるアイテムの件数を出す（2026-11-06 追記、E-22）。
// 件数はメモリの一覧（平文の summary）だけで数える。タブの URL はサーバーに送らず、保存もしない。
// ロック中は何も出さない。照合は自動入力と同じ（https のオリジンの完全一致。www・サブドメイン・ポート違いは別）。

import { after, beforeEach, mock, test } from 'node:test';
import assert from 'node:assert/strict';
import { adminReady, newDiscord, restart, send, world, type World } from '../helpers/extension-world.ts';

const T0 = 1_800_000_000_000;
mock.timers.enable({ apis: ['Date'], now: T0 });
after(() => mock.timers.reset());
beforeEach(() => mock.timers.setTime(T0));

const discord = newDiscord();
after(discord.install());

const LOGIN = { type: 'login', title: '社内 Wiki', username: 'team@example.com', password: 'correct-horse-battery-staple', urls: ['https://wiki.example.com/login'], notes: '', customFields: [] };

async function ready(): Promise<World> {
  const w = world(discord);
  await adminReady(w, discord);
  assert.equal((await send(w, { type: 'saveItem', item: LOGIN })).ok, true);
  assert.equal((await send(w, { type: 'saveItem', item: { ...LOGIN, title: '別', urls: ['https://other.example.com/'] } })).ok, true);
  assert.equal((await send(w, { type: 'saveItem', item: { type: 'note', title: 'wiki.example.com のメモ', body: 'https://wiki.example.com/' } })).ok, true);
  return w;
}

function openTab(w: World, tabId: number, url: string): void {
  w.chrome.openTabs.set(tabId, { url, documentId: `doc-${tabId}` });
}

test('E-22 タブを開くと、そのオリジンのログインアイテムの件数をアイコンに出す。メモと、ほかのオリジンは数えない', async () => {
  const w = await ready();
  openTab(w, 1, 'https://wiki.example.com/top');
  openTab(w, 2, 'https://news.example.com/');
  await w.bg.onTabChanged(1);
  await w.bg.onTabChanged(2);
  assert.equal(w.chrome.badges.get(1), '1');
  assert.equal(w.chrome.badges.get(2), '');
});

test('E-22 照合は自動入力と同じ。http・www 付き・サブドメイン・ポート違いは数えない', async () => {
  const w = await ready();
  const urls = ['http://wiki.example.com/', 'https://www.wiki.example.com/', 'https://a.wiki.example.com/', 'https://wiki.example.com:8443/', 'chrome://newtab/'];
  for (const [i, url] of urls.entries()) {
    openTab(w, 10 + i, url);
    await w.bg.onTabChanged(10 + i);
    assert.equal(w.chrome.badges.get(10 + i), '', url);
  }
});

test('E-22 アイテムを足すと、開いているタブの件数も変わる。ロックすると、すべてのタブで消す', async () => {
  const w = await ready();
  openTab(w, 1, 'https://wiki.example.com/');
  openTab(w, 2, 'https://other.example.com/');
  await w.bg.onTabChanged(1);
  assert.equal((await send(w, { type: 'saveItem', item: { ...LOGIN, title: '2つ目' } })).ok, true);
  assert.equal(w.chrome.badges.get(1), '2');
  assert.equal(w.chrome.badges.get(2), '1');
  assert.equal((await send(w, { type: 'lock' })).ok, true);
  assert.equal(w.chrome.badges.get(1), '');
  assert.equal(w.chrome.badges.get(2), '');
});

test('E-22 Service Worker が止まった後（ロック状態）は、タブを開いても件数を出さない', async () => {
  const w = await ready();
  restart(w);
  openTab(w, 1, 'https://wiki.example.com/');
  await w.bg.onTabChanged(1);
  assert.equal(w.chrome.badges.get(1), '');
});

test('E-22 ロック解除を保つ設定なら、Service Worker が止まった後も、タブを開いたときに件数を出す', async () => {
  const w = await ready();
  assert.equal((await send(w, { type: 'setKeepUnlocked', enabled: true })).ok, true);
  restart(w);
  openTab(w, 1, 'https://wiki.example.com/');
  await w.bg.onTabChanged(1);
  assert.equal(w.chrome.badges.get(1), '1');
});

test('E-22 件数を数えるときに、API へ送らず、タブの URL を保存しない', async () => {
  const w = await ready();
  const before = w.calls.length;
  openTab(w, 1, 'https://wiki.example.com/secret-path?q=1');
  await w.bg.onTabChanged(1);
  assert.equal(w.chrome.badges.get(1), '1');
  assert.equal(w.calls.length, before, 'API を呼ばない');
  for (const area of [w.chrome.storage.local, w.chrome.storage.session]) assert.ok(!area.dump().includes('secret-path'));
});

test('E-22 閉じたタブの通知が来ても止まらない', async () => {
  const w = await ready();
  await w.bg.onTabChanged(99);
  assert.equal(w.chrome.badges.has(99), false);
});

test('E-22 数え直している間に閉じたタブがあっても、ほかのタブの件数は変える', async () => {
  const w = await ready();
  openTab(w, 2, 'https://wiki.example.com/');
  const query = w.chrome.tabs.query;
  // 一覧を取った直後に閉じられたタブ（50）が先頭にある
  w.chrome.tabs.query = async (q) => [{ id: 50, url: 'https://wiki.example.com/' }, ...(await query(q))];
  assert.equal((await send(w, { type: 'saveItem', item: { ...LOGIN, title: '2つ目' } })).ok, true);
  assert.equal(w.chrome.badges.get(2), '2');
});
