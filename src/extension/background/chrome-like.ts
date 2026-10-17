// Service Worker が使う chrome の API だけを型にしたもの（@types/chrome は入れない）。
// 本番は globalThis.chrome、テストは tests/helpers/fake-chrome.ts を渡す。

export interface StorageArea {
  get(keys: string | string[] | null): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string | string[]): Promise<void>;
}

// chrome.runtime.onMessage の送り元。id は送った拡張機能、url は送ったページ（タブのページに注入したスクリプトなら、そのページのアドレス）
export type MessageSender = { id?: string; url?: string; tab?: unknown; frameId?: number };

export interface ChromeLike {
  runtime: { id: string; getURL(path: string): string };
  storage: { local: StorageArea; session: StorageArea };
  identity: {
    getRedirectURL(): string;
    launchWebAuthFlow(details: { url: string; interactive: boolean }): Promise<string | undefined>;
  };
}
