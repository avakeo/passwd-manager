// テスト用の偽の chrome。拡張機能の Service Worker の処理が使う API だけを、ブラウザなしで再現する。
//   storage.local / storage.session：キーと値（値は structuredClone で写す）。session はブラウザを閉じると消える（clear で再現）
//   runtime：拡張機能の ID と、自分のページの URL
//   identity：Discord の認可画面の代わりに、偽の Discord から認可コードをもらって戻り先の URL を返す
//   tabs・scripting：タブの URL と、トップフレームの文書 ID だけを持つ。注入は呼ばれた引数を記録し、関数は本物を動かさない
//     （確認のスクリプトはタブのオリジンを、入力のスクリプトは入れた欄の数を返したことにする）
//   offscreen・runtime.sendMessage：オフスクリーンドキュメントへのコピーの依頼を記録する

import type { ChromeLike, InjectionResult, InjectionTarget, StorageArea } from '../../src/extension/background/chrome-like.ts';
import assert from 'node:assert/strict';
import type { FakeDiscord } from './fake-discord.ts';
import { EXTENSION_REDIRECT_URI } from './api.ts';

export const EXTENSION_ID = 'abcdefghijklmnopabcdefghijklmnop';

export class FakeStorageArea implements StorageArea {
  readonly values = new Map<string, unknown>();
  // 1つの値の大きさ（JSON の文字数）の上限。超える set は、本物の容量超えと同じく投げて、何も書かない
  maxValueLength: number | null = null;

  async get(keys: string | string[] | null): Promise<Record<string, unknown>> {
    const list = keys === null ? [...this.values.keys()] : typeof keys === 'string' ? [keys] : keys;
    const out: Record<string, unknown> = {};
    for (const k of list) if (this.values.has(k)) out[k] = structuredClone(this.values.get(k));
    return out;
  }

  async set(items: Record<string, unknown>): Promise<void> {
    const max = this.maxValueLength;
    if (max !== null && Object.values(items).some((v) => JSON.stringify(v).length > max)) throw new Error('QUOTA_BYTES quota exceeded');
    for (const [k, v] of Object.entries(items)) this.values.set(k, structuredClone(v));
  }

  async remove(keys: string | string[]): Promise<void> {
    for (const k of typeof keys === 'string' ? [keys] : keys) this.values.delete(k);
  }

  clear(): void {
    this.values.clear();
  }

  dump(): string {
    return JSON.stringify([...this.values.entries()]);
  }
}

export type FakeTab = { url: string; documentId: string; frames?: number[] };
export type Injection = { target: InjectionTarget; func: string; args: unknown[] };

export class FakeChrome implements ChromeLike {
  readonly storage = { local: new FakeStorageArea(), session: new FakeStorageArea() };
  // オフスクリーンドキュメントに送ったメッセージ。reply が返事
  readonly sentToOffscreen: unknown[] = [];
  offscreenReply: unknown = { ok: true };
  readonly runtime = {
    id: EXTENSION_ID,
    getURL: (path: string) => `chrome-extension://${EXTENSION_ID}/${path.replace(/^\//, '')}`,
    sendMessage: async (message: unknown) => {
      if (!this.offscreenOpen) throw new Error('Could not establish connection. Receiving end does not exist.');
      this.sentToOffscreen.push(structuredClone(message));
      return this.offscreenReply;
    },
  };
  offscreenOpen = false;
  readonly offscreen = {
    hasDocument: async () => this.offscreenOpen,
    createDocument: async (details: { url: string; reasons: string[]; justification: string }) => {
      if (this.offscreenOpen) throw new Error('Only a single offscreen document may be created.');
      assert.deepEqual(details.reasons, ['CLIPBOARD']);
      this.offscreenOpen = true;
    },
  };
  readonly openTabs = new Map<number, FakeTab>();
  readonly injections: Injection[] = [];
  // 注入のたびに呼ぶ（照合と入力の間にページを移す、などのテストで使う）
  onInject: ((injection: Injection) => void) | null = null;
  readonly tabs = {
    get: async (tabId: number) => {
      const tab = this.openTabs.get(tabId);
      if (!tab) throw new Error(`No tab with id: ${tabId}.`);
      return { id: tabId, url: tab.url };
    },
  };
  readonly scripting = {
    executeScript: async <A extends unknown[], R>(injection: { target: InjectionTarget; func: (...args: A) => R; args?: A }): Promise<InjectionResult<Awaited<R>>[]> => {
      const record: Injection = { target: structuredClone(injection.target), func: injection.func.name, args: structuredClone(injection.args ?? []) as unknown[] };
      this.injections.push(record);
      this.onInject?.(record);
      const tab = this.openTabs.get(injection.target.tabId);
      if (!tab) throw new Error(`No tab with id: ${injection.target.tabId}.`);
      if (injection.target.documentIds && !injection.target.documentIds.includes(tab.documentId)) throw new Error('No document with id.');
      const frames = injection.target.frameIds ?? [0];
      return frames
        .filter((f) => (tab.frames ?? [0]).includes(f))
        .map((frameId) => {
          const result = record.func === 'probePage' ? { origin: new URL(tab.url).origin } : record.func === 'fillLogin' ? { filled: 2 } : undefined;
          return { frameId, documentId: frameId === 0 ? tab.documentId : `${tab.documentId}-frame${frameId}`, result: result as Awaited<R> };
        });
    },
  };
  // 次の launchWebAuthFlow で、どの Discord ユーザーとしてログインするか
  loginAs: string | null = null;
  readonly identity;

  constructor(discord: FakeDiscord) {
    this.identity = {
      getRedirectURL: () => EXTENSION_REDIRECT_URI,
      launchWebAuthFlow: async (details: { url: string; interactive: boolean }) => {
        const url = new URL(details.url);
        if (this.loginAs === null) throw new Error('利用者が画面を閉じた');
        const code = discord.issueCode({ userId: this.loginAs, redirectUri: url.searchParams.get('redirect_uri')!, codeChallenge: url.searchParams.get('code_challenge')! });
        const back = new URL(url.searchParams.get('redirect_uri')!);
        back.searchParams.set('code', code);
        back.searchParams.set('state', url.searchParams.get('state')!);
        return back.toString();
      },
    };
  }

  // 自分の拡張機能のページから送ったときの sender
  senderFrom(path: string): { id: string; url: string } {
    return { id: EXTENSION_ID, url: this.runtime.getURL(path) };
  }
}
