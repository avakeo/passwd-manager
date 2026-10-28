// Service Worker が使う chrome の API だけを型にしたもの（@types/chrome は入れない）。
// 本番は globalThis.chrome、テストは tests/helpers/fake-chrome.ts を渡す。

export interface StorageArea {
  get(keys: string | string[] | null): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string | string[]): Promise<void>;
}

// chrome.runtime.onMessage の送り元。id は送った拡張機能、url は送ったページ（タブのページに注入したスクリプトなら、そのページのアドレス）
export type MessageSender = { id?: string; url?: string; tab?: unknown; frameId?: number };

// executeScript の注入先。frameIds [0] はトップフレーム。documentIds は、確認のスクリプトが返した文書だけに入れるときに使う
export type InjectionTarget = { tabId: number; frameIds?: number[]; documentIds?: string[] };
export type InjectionResult<R> = { frameId: number; documentId: string; result?: R };

export interface ChromeLike {
  runtime: { id: string; getURL(path: string): string; sendMessage(message: unknown): Promise<unknown> };
  // 今のタブの URL は、ポップアップの操作で得た一時権限（activeTab）で読む
  tabs: { get(tabId: number): Promise<{ id?: number; url?: string }> };
  scripting: {
    executeScript<A extends unknown[], R>(injection: { target: InjectionTarget; func: (...args: A) => R; args?: A }): Promise<InjectionResult<Awaited<R>>[]>;
  };
  // クリップボードの書き込みと、1分後の消去は、オフスクリーンドキュメントで行う（Service Worker からは書けない）
  offscreen: {
    createDocument(details: { url: string; reasons: string[]; justification: string }): Promise<void>;
    hasDocument(): Promise<boolean>;
  };
  storage: { local: StorageArea; session: StorageArea };
  identity: {
    getRedirectURL(): string;
    launchWebAuthFlow(details: { url: string; interactive: boolean }): Promise<string | undefined>;
  };
}
