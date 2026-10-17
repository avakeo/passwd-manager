// テスト用の偽の chrome。拡張機能の Service Worker の処理が使う API だけを、ブラウザなしで再現する。
//   storage.local / storage.session：キーと値（値は structuredClone で写す）。session はブラウザを閉じると消える（clear で再現）
//   runtime：拡張機能の ID と、自分のページの URL
//   identity：Discord の認可画面の代わりに、偽の Discord から認可コードをもらって戻り先の URL を返す

import type { ChromeLike, StorageArea } from '../../src/extension/background/chrome-like.ts';
import type { FakeDiscord } from './fake-discord.ts';
import { EXTENSION_REDIRECT_URI } from './api.ts';

export const EXTENSION_ID = 'abcdefghijklmnopabcdefghijklmnop';

export class FakeStorageArea implements StorageArea {
  readonly values = new Map<string, unknown>();

  async get(keys: string | string[] | null): Promise<Record<string, unknown>> {
    const list = keys === null ? [...this.values.keys()] : typeof keys === 'string' ? [keys] : keys;
    const out: Record<string, unknown> = {};
    for (const k of list) if (this.values.has(k)) out[k] = structuredClone(this.values.get(k));
    return out;
  }

  async set(items: Record<string, unknown>): Promise<void> {
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

export class FakeChrome implements ChromeLike {
  readonly storage = { local: new FakeStorageArea(), session: new FakeStorageArea() };
  readonly runtime = { id: EXTENSION_ID, getURL: (path: string) => `chrome-extension://${EXTENSION_ID}/${path.replace(/^\//, '')}` };
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
