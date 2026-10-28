// 拡張機能の Service Worker の中身（chrome の API は引数で受け取る。テストは偽物を渡す）。
// 仕様書「拡張機能と自動入力の方針 > ロックと鍵の置き場所」。
//   - 秘密鍵・署名用秘密鍵・Vault 鍵は、createBackground ごとの状態（context.ts。メモリ）だけに、取り出し不可で置く。画面には渡さない
//   - トークンは chrome.storage.session（storage.ts）。応答には入れない
//   - 放置のロックは45分。Service Worker が起きたとき（onStartup）と、メッセージを受け取るたびに、処理の前に確かめる
//   - メッセージは messages.ts の検査を通ったものだけを処理する（E-08）
//   - アイテム（2b）：保存の前と復号の後に validateItem を通す。storage.local には暗号文だけをキャッシュし、平文の一覧はメモリだけ（item-sync.ts）
//   - 自動入力とコピー（3）：ポップアップからの操作でだけ注入する。入力の直前にタブと文書を取り直す。コピーはオフスクリーンドキュメントで1分後に消す（autofill.ts）
//   - クイックロック解除（2b）：Vault 鍵だけを、パスコード由来の鍵で包んで storage.session に置く。戻った状態は秘密鍵を持たない（passcode.ts）
// このファイルは、メッセージの入口と、種類ごとの処理の表をまとめる。処理の中身は account.ts、vault.ts、passcode.ts、item-sync.ts にある

import type { MessageSender } from './chrome-like.ts';
import { PASSIVE_TYPES, acceptedSender, parseMessage, type Message } from './messages.ts';
import { ApiError } from './api-client.ts';
import { createAccount } from './account.ts';
import { createItemSync } from './item-sync.ts';
import { createPasscode } from './passcode.ts';
import { createVault } from './vault.ts';
import { createAutofill } from './autofill.ts';
import { Fail, LAST_ACTIVITY_KEY, createContext, type BackgroundDeps, type Handler, type Reply } from './context.ts';
import { CryptoError } from '../../crypto/errors.ts';

export { IDLE_LOCK_MS, QUICK_UNLOCK_MAX_FAILURES, UNLOCK_KEY_PREFIX } from './context.ts';
export type { BackgroundDeps, VaultState } from './context.ts';

export type Background = {
  handleMessage(message: unknown, sender: MessageSender): Promise<Reply>;
  onStartup(): Promise<void>;
  // テスト用：メモリに鍵が残っているか（メッセージからは呼べない。中身は返さない）
  memoryState(): { unlocked: boolean; vaultKey: boolean };
};

export function createBackground(deps: BackgroundDeps): Background {
  const ctx = createContext(deps);
  const { chrome, state, checkIdle } = ctx;

  // 処理のまとまりごとのファイル。どれも同じ ctx（この createBackground の状態）を使う
  const vault = createVault(ctx); // ロック解除、鍵の作成、最初の Vault
  const passcode = createPasscode(ctx); // クイックロック解除
  const items = createItemSync(ctx, vault.openVault); // アイテムと同期
  const account = createAccount(ctx, passcode); // 状態、ログイン、TOTP、ロック、セッション
  const autofill = createAutofill(ctx, items.readItem); // 自動入力とコピー（フェーズ3）

  const handlers: Record<Message['type'], Handler> = {
    ...account.handlers,
    ...vault.handlers,
    ...passcode.handlers,
    ...items.handlers,
    ...autofill.handlers,
  };

  return {
    memoryState() {
      return { unlocked: state.unlocked !== null, vaultKey: state.vaultKey !== null };
    },

    async onStartup() {
      await checkIdle();
    },

    async handleMessage(raw, sender) {
      if (!acceptedSender(chrome.runtime, sender)) return { ok: false, error: 'BAD_REQUEST' };
      const message = parseMessage(raw);
      if (message === null) return { ok: false, error: 'BAD_REQUEST' };
      // 放置のロックは、どの指示も処理する前に確かめる。時刻を新しくするのは利用者の操作から来たものだけ（DeepSeek #4）
      await checkIdle();
      if (!PASSIVE_TYPES.has(message.type)) await chrome.storage.session.set({ [LAST_ACTIVITY_KEY]: Date.now() });
      try {
        return await handlers[message.type](message, sender);
      } catch (e) {
        if (e instanceof Fail || e instanceof ApiError) return { ok: false, error: e.code };
        if (e instanceof CryptoError) return { ok: false, error: 'CRYPTO' };
        return { ok: false, error: 'INTERNAL' };
      }
    },
  };
}
