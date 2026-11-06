// 入力できるページを開いたときの通知（2026-11-06 追記、E-23）。
//   - 件数とショートカットだけを出す。アイテムの名前・ユーザー名・URL は通知に入れない（OS の通知センターに残るため）
//   - 同じオリジンへの通知は、ロックするまで1回だけ。通知したオリジンは storage.session に置き、ロックで消す
//   - 前に出ているタブだけ。ロック中は出さない。設定でオフにでき、最初はオン（端末ごとの設定。storage.local）

import { after, beforeEach, mock, test } from 'node:test';
import assert from 'node:assert/strict';
import { ADMIN_PASSWORD, POPUP, adminReady, newDiscord, restart, send, world, type World } from '../helpers/extension-world.ts';

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
  assert.equal((await send(w, { type: 'saveItem', item: { ...LOGIN, title: '別', username: 'other@example.com', urls: ['https://other.example.com/'] } })).ok, true);
  return w;
}

async function visit(w: World, tabId: number, url: string, active = true): Promise<void> {
  w.chrome.openTabs.set(tabId, { url, documentId: `doc-${tabId}`, active });
  await w.bg.onTabChanged(tabId);
}

test('E-23 入力できるページを開くと、件数とショートカットだけの通知を出す。名前・ユーザー名・URL は入れない', async () => {
  const w = await ready();
  await visit(w, 1, 'https://wiki.example.com/secret-path');
  assert.equal(w.chrome.shownNotifications.length, 1);
  const n = w.chrome.shownNotifications[0]!;
  assert.match(n.options.message, /1件/);
  assert.match(n.options.message, /Alt\+L/);
  assert.equal(n.options.type, 'basic');
  const text = JSON.stringify({ title: n.options.title, message: n.options.message });
  for (const secret of ['社内 Wiki', 'team@example.com', 'correct-horse', 'wiki.example.com', 'secret-path']) assert.ok(!text.includes(secret), secret);
});

test('E-23 同じオリジンには、ロックするまで1回だけ。別のオリジンには出す。ロックして解除し直すと、また出す', async () => {
  const w = await ready();
  await visit(w, 1, 'https://wiki.example.com/a');
  await visit(w, 2, 'https://wiki.example.com/b');
  await visit(w, 1, 'https://wiki.example.com/c');
  assert.equal(w.chrome.shownNotifications.length, 1);
  await visit(w, 3, 'https://other.example.com/');
  assert.equal(w.chrome.shownNotifications.length, 2);
  assert.equal((await send(w, { type: 'lock' })).ok, true);
  assert.equal((await send(w, { type: 'unlock', masterPassword: ADMIN_PASSWORD }, POPUP)).vault, 'ready');
  await visit(w, 1, 'https://wiki.example.com/d');
  assert.equal(w.chrome.shownNotifications.length, 3);
});

test('E-23 通知したオリジンは storage.session だけに置き、ロックで消す', async () => {
  const w = await ready();
  await visit(w, 1, 'https://wiki.example.com/secret-path');
  assert.ok(w.chrome.storage.session.dump().includes('https://wiki.example.com'));
  assert.ok(!w.chrome.storage.session.dump().includes('secret-path'), 'パスは置かない');
  assert.ok(!w.chrome.storage.local.dump().includes('https://wiki.example.com"'), 'storage.local には置かない');
  assert.equal((await send(w, { type: 'lock' })).ok, true);
  assert.ok(!w.chrome.storage.session.dump().includes('https://wiki.example.com'));
});

test('E-23 後ろのタブ、入力できるアイテムがないページ、ロック中には出さない', async () => {
  const w = await ready();
  await visit(w, 1, 'https://wiki.example.com/', false);
  await visit(w, 2, 'https://news.example.com/');
  assert.equal(w.chrome.shownNotifications.length, 0);
  assert.equal((await send(w, { type: 'lock' })).ok, true);
  await visit(w, 3, 'https://wiki.example.com/');
  restart(w);
  await visit(w, 4, 'https://wiki.example.com/');
  assert.equal(w.chrome.shownNotifications.length, 0);
});

test('E-23 アイテムを保存しただけ（タブの変化なし）では出さない', async () => {
  const w = await ready();
  w.chrome.openTabs.set(1, { url: 'https://wiki.example.com/', documentId: 'doc-1' });
  assert.equal((await send(w, { type: 'saveItem', item: { ...LOGIN, title: '2つ目' } })).ok, true);
  assert.equal(w.chrome.badges.get(1), '2');
  assert.equal(w.chrome.shownNotifications.length, 0);
});

test('E-23 設定は最初はオン。オフにすると出さず、Service Worker が止まってもオフのまま', async () => {
  const w = await ready();
  assert.deepEqual(await send(w, { type: 'getNotify' }), { ok: true, notify: true });
  assert.deepEqual(await send(w, { type: 'setNotify', enabled: false }), { ok: true, notify: false });
  restart(w);
  assert.deepEqual(await send(w, { type: 'getNotify' }), { ok: true, notify: false });
  assert.equal((await send(w, { type: 'unlock', masterPassword: ADMIN_PASSWORD }, POPUP)).vault, 'ready');
  await visit(w, 1, 'https://wiki.example.com/');
  assert.equal(w.chrome.shownNotifications.length, 0);
  assert.equal(w.chrome.badges.get(1), '1', 'アイコンの件数は出す');
  assert.deepEqual(await send(w, { type: 'setNotify', enabled: true }), { ok: true, notify: true });
  await visit(w, 2, 'https://other.example.com/');
  assert.equal(w.chrome.shownNotifications.length, 1);
});

test('E-23 ショートカットが割り当てられていなければ、キーは書かない', async () => {
  const w = await ready();
  w.chrome.shortcut = '';
  await visit(w, 1, 'https://wiki.example.com/');
  assert.equal(w.chrome.shownNotifications.length, 1);
  assert.ok(!/Alt|\+/.test(w.chrome.shownNotifications[0]!.options.message));
  assert.match(w.chrome.shownNotifications[0]!.options.message, /ツールバーの teampw から/);
});

test('E-23 setNotify の値は真偽値だけ', async () => {
  const w = await ready();
  assert.equal((await send(w, { type: 'setNotify', enabled: 'yes' })).error, 'BAD_REQUEST');
});
