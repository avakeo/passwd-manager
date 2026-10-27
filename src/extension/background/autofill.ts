// 自動入力とコピー（フェーズ3、docs/実装状況.md の11.2・11.3）。
//   - 自動入力はポップアップからのメッセージでだけ始める（E-07・E-08）
//   - トップフレームに確認のスクリプトを入れて文書 ID を受け取り、入力の直前にタブの URL と文書 ID をブラウザから取り直して判定する（E-13。持ち越し）
//   - 入力のスクリプトには1件分のユーザー名とパスワードだけを渡す（E-09）。注入先はトップフレームの、確認した文書だけ（E-02）
//   - コピーはオフスクリーンドキュメントで書き、1分後に中身が同じときだけ消す（E-10・E-12）

import { canAutofill } from '../../client/autofill-policy.ts';
import type { ClientItem } from '../../client/item-data.ts';
import type { InjectionResult } from './chrome-like.ts';
import { Fail, type Context, type Handler } from './context.ts';
import { fillLogin, probePage } from './inject.ts';
import { fromPopup } from './messages.ts';
import { OFFSCREEN_PAGE, OFFSCREEN_TARGET } from '../shared/offscreen-message.ts';

export function createAutofill(ctx: Context, readItem: (id: string) => Promise<{ item: ClientItem }>) {
  const { chrome, state, stillCurrent } = ctx;

  function locked(): boolean {
    return state.unlockedBy === null || state.vaultKey === null;
  }

  // トップフレームの文書を確かめる。結果の文書 ID は、ブラウザが付けたもの（ページの自己申告ではない）
  async function topDocument(tabId: number): Promise<InjectionResult<{ origin: string }> | null> {
    const results = await chrome.scripting.executeScript({ target: { tabId, frameIds: [0] }, func: probePage }).catch(() => []);
    const top = results.find((r) => r.frameId === 0);
    return top && typeof top.documentId === 'string' && top.documentId !== '' ? top : null;
  }

  async function tabUrl(tabId: number): Promise<{ id: number; url: string } | null> {
    const tab = await chrome.tabs.get(tabId).catch(() => null);
    return tab && typeof tab.id === 'number' && typeof tab.url === 'string' ? { id: tab.id, url: tab.url } : null;
  }

  async function ensureOffscreen(): Promise<void> {
    if (await chrome.offscreen.hasDocument()) return;
    await chrome.offscreen
      .createDocument({ url: OFFSCREEN_PAGE, reasons: ['CLIPBOARD'], justification: 'コピーしたパスワードを、1分後に中身が同じときだけ消すため' })
      .catch(async (e) => {
        // 同時に作ろうとして、もう1つ目ができていた
        if (!(await chrome.offscreen.hasDocument())) throw e;
      });
  }

  const handlers = {
    async autofill(m, sender) {
      if (!fromPopup(chrome.runtime, sender)) throw new Fail('BAD_REQUEST');
      if (locked()) throw new Fail('LOCKED');
      const epoch = state.lockEpoch;
      const { item } = await readItem(String(m.id));
      if (item.type !== 'login') throw new Fail('NOT_LOGIN');
      const tabId = Number(m.tabId);

      const tab = await tabUrl(tabId);
      const first = await topDocument(tabId);
      if (tab === null || first === null) throw new Fail('AUTOFILL_REFUSED');
      // 入力の直前に、タブのアドレスと文書 ID をブラウザから取り直す（E-13。照合と入力の間のページ遷移）
      const again = await topDocument(tabId);
      const live = await tabUrl(tabId);
      const allowed =
        again !== null &&
        live !== null &&
        canAutofill({
          popupInitiated: true,
          unlocked: !locked() && (await stillCurrent(epoch)),
          topFrame: first.frameId === 0 && again.frameId === 0,
          tabId: live.id,
          expectedTabId: tabId,
          documentId: again.documentId,
          expectedDocumentId: first.documentId,
          pageUrl: tab.url,
          livePageUrl: live.url,
          savedOrigins: item.urls,
        });
      if (!allowed) throw new Fail('AUTOFILL_REFUSED');

      const origin = new URL(live!.url).origin;
      const results = await chrome.scripting
        .executeScript({ target: { tabId, documentIds: [first.documentId] }, func: fillLogin, args: [origin, item.username, item.password] })
        .catch(() => []);
      const filled = results.find((r) => r.documentId === first.documentId)?.result?.filled ?? 0;
      return { ok: true, filled };
    },

    // パスワードか、カスタム項目の1つをコピーする（カスタム項目は自動入力に使わず、コピーだけ）
    async copyToClipboard(m) {
      if (locked()) throw new Fail('LOCKED');
      const { item } = await readItem(String(m.id));
      if (item.type !== 'login') throw new Fail('NOT_LOGIN');
      const text = m.field === 'password' ? item.password : item.customFields[Number(m.customIndex)]?.value;
      if (typeof text !== 'string') throw new Fail('NOT_FOUND');
      if (text === '') throw new Fail('EMPTY');
      await ensureOffscreen();
      const reply = (await chrome.runtime.sendMessage({ target: OFFSCREEN_TARGET, type: 'copy', text }).catch(() => null)) as { ok?: unknown } | null;
      if (reply?.ok !== true) throw new Fail('CLIPBOARD');
      return { ok: true, clearsAfterSeconds: 60 };
    },
  } satisfies Record<string, Handler>;

  return { handlers };
}
