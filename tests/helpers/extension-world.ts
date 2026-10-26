// 拡張機能のテストの準備：偽の chrome（fake-chrome.ts）と、本物の API（app.request ＋ SQLite）と、偽の Discord をつなぐ。
// 時刻は、テストのファイルの側で mock.timers を使って固定する。

import assert from 'node:assert/strict';
import { createBackground, type Background } from '../../src/extension/background/background.ts';
import { FakeDiscord } from './fake-discord.ts';
import { FakeChrome } from './fake-chrome.ts';
import { TEST_ENV, setup } from './api.ts';
import { base32ToBytes, referenceTotp, stepAt } from './totp-reference.ts';

export const API_ORIGIN = 'https://pw-api.example.com';
export const POPUP = 'extension/popup/popup.html';
export const PAGE = 'extension/page/app.html';
export const ADMIN_PASSWORD = 'admin-hoshi-sora-umi-42';

export type Reply = { ok: boolean; error?: string } & Record<string, unknown>;

export type World = {
  t: ReturnType<typeof setup>;
  chrome: FakeChrome;
  bg: Background;
  calls: string[];
  gates: Map<string, { arrive: () => void; released: Promise<void> }>;
  rewrite: ((call: string, res: Response) => Promise<Response | null>) | null;
};

export function newDiscord(): FakeDiscord {
  return new FakeDiscord({
    clientId: TEST_ENV.DISCORD_CLIENT_ID,
    clientSecret: TEST_ENV.DISCORD_CLIENT_SECRET,
    botToken: TEST_ENV.DISCORD_BOT_TOKEN,
    guildId: TEST_ENV.DISCORD_GUILD_ID,
  });
}

// t を渡すと、同じサーバーにもう1つの端末（別の chrome）を作る
export function world(discord: FakeDiscord, t?: ReturnType<typeof setup>): World {
  const server = t ?? setup();
  if (!t) server.db.db.exec('DELETE FROM vault_meta; DELETE FROM vault_key_versions');
  const w: World = { t: server, chrome: new FakeChrome(discord), bg: null as unknown as Background, calls: [], gates: new Map(), rewrite: null };
  w.bg = restart(w);
  return w;
}

// Service Worker を起動し直す（メモリは消え、chrome.storage は残る）
export function restart(w: World): Background {
  w.bg = createBackground({
    chrome: w.chrome,
    apiOrigin: API_ORIGIN,
    discordClientId: TEST_ENV.DISCORD_CLIENT_ID,
    fetch: async (input, init) => {
      const url = new URL(String(input));
      assert.equal(url.origin, API_ORIGIN, 'API の接続先にだけ送る');
      const call = `${init.method ?? 'GET'} ${url.pathname}`;
      const gate = w.gates.get(call);
      if (gate) {
        w.gates.delete(call);
        gate.arrive();
        await gate.released;
      }
      w.calls.push(call);
      const res = await w.t.app.request(url.pathname + url.search, init, w.t.env);
      return (w.rewrite && (await w.rewrite(call, res))) || res;
    },
  });
  return w.bg;
}

export async function send(w: World, message: Record<string, unknown>, from = PAGE): Promise<Reply> {
  return (await w.bg.handleMessage(message, w.chrome.senderFrom(from))) as Reply;
}

let nextUser = 800000000000000000n;
export function newDiscordUser(discord: FakeDiscord): string {
  nextUser += 1n;
  const id = String(nextUser);
  discord.addUser(id, { roles: [TEST_ENV.DISCORD_ROLE_ID], globalName: 'チームの人' });
  return id;
}

// 管理者：ログイン → TOTP の登録 → 鍵の作成 → 最初の Vault
export async function adminReady(w: World, discord: FakeDiscord, password = ADMIN_PASSWORD) {
  const userId = newDiscordUser(discord);
  w.chrome.loginAs = userId;
  assert.equal((await send(w, { type: 'login', deviceLabel: 'テスト端末' }, POPUP)).status, 'totp_setup_required');
  w.t.db.db.prepare(`UPDATE members SET role = 'admin', status = 'active' WHERE discord_user_id = ?`).run(userId);
  const start = await send(w, { type: 'totpSetupStart' });
  const secret = base32ToBytes(String(start.secret).replace(/ /g, ''));
  assert.equal((await send(w, { type: 'totpSetupConfirm', code: referenceTotp(secret, stepAt(Date.now())) })).ok, true);
  assert.equal((await send(w, { type: 'createKey', masterPassword: password, replace: false })).vault, 'needs-init');
  assert.equal((await send(w, { type: 'initVault' })).vault, 'ready');
  return { userId, secret };
}

// 同じ管理者で、もう1つの端末（別のプロファイル）からログインし、ロック解除する。
// 管理者の端末を初期化した扱いになるので、世代の初期化（フェーズ4の対面の照合）の代わりに、1つ目の端末の固定を写す
export async function secondDevice(first: World, discord: FakeDiscord, userId: string, secret: Uint8Array, password = ADMIN_PASSWORD): Promise<World> {
  const w = world(discord, first.t);
  for (const [k, v] of first.chrome.storage.local.values) if (k.startsWith('teampw/v1/trust|')) w.chrome.storage.local.values.set(k, v);
  w.chrome.loginAs = userId;
  assert.equal((await send(w, { type: 'login', deviceLabel: '2台目' }, POPUP)).status, 'totp_required');
  const step = stepAt(Date.now());
  // 1つ目の端末が同じステップのコードを使っていれば、次のステップを使う
  let ok = await send(w, { type: 'loginTotp', code: referenceTotp(secret, step + 1) }, POPUP);
  if (!ok.ok) ok = await send(w, { type: 'loginTotp', code: referenceTotp(secret, step) }, POPUP);
  assert.equal(ok.ok, true, JSON.stringify(ok));
  assert.equal((await send(w, { type: 'unlock', masterPassword: password }, POPUP)).vault, 'ready');
  return w;
}

export function hold(w: World, call: string): { arrived: Promise<void>; release: () => void } {
  let arrive!: () => void;
  let release!: () => void;
  const arrived = new Promise<void>((r) => (arrive = r));
  const released = new Promise<void>((r) => (release = r));
  w.gates.set(call, { arrive, released });
  return { arrived, release };
}

// obj.name の呼び出しのうち、match が true を返す最初の1回を、結果ができてから呼び出し元へ返す前に止める。
// 「時間のかかる処理の途中でロックされた」順を作るため（2b の Codex #1〜#3、DeepSeek #2〜#4）
export function holdResult<T extends object>(obj: T, name: keyof T & string, match: (args: unknown[]) => boolean = () => true) {
  let arrive!: () => void;
  let release!: () => void;
  const arrived = new Promise<void>((r) => (arrive = r));
  const released = new Promise<void>((r) => (release = r));
  const own = Object.hasOwn(obj, name);
  const original = obj[name] as unknown as (...args: unknown[]) => Promise<unknown>;
  let fired = false;
  (obj as Record<string, unknown>)[name] = async function (this: unknown, ...args: unknown[]) {
    const result = await original.apply(this, args);
    if (!fired && match(args)) {
      fired = true;
      arrive();
      await released;
    }
    return result;
  };
  const restore = () => {
    if (own) (obj as Record<string, unknown>)[name] = original;
    else delete (obj as Record<string, unknown>)[name];
  };
  return { arrived, release, restore };
}
