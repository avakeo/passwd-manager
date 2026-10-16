// 拡張機能側が取得したタブ・文書・トップフレーム・入力直前URLを渡す純粋な判定。
export type AutofillContext = {
  popupInitiated: boolean;
  unlocked: boolean;
  topFrame: boolean;
  tabId: number;
  expectedTabId: number;
  documentId: string;
  expectedDocumentId: string;
  pageUrl: string;
  livePageUrl: string;
  savedOrigins: readonly string[];
};

function httpsOrigin(raw: string): string | undefined {
  try {
    const url = new URL(raw);
    if (url.protocol !== 'https:' || !url.hostname || url.username || url.password) return undefined;
    return url.origin;
  } catch { return undefined; }
}

export function originForSavedUrl(raw: string): string {
  const origin = httpsOrigin(raw);
  if (origin === undefined) throw new TypeError('only HTTPS URLs without credentials can be saved');
  return origin;
}

export function canAutofill(ctx: AutofillContext): boolean {
  if (!ctx.popupInitiated || !ctx.unlocked || !ctx.topFrame) return false;
  if (!Number.isSafeInteger(ctx.tabId) || ctx.tabId !== ctx.expectedTabId) return false;
  if (!ctx.documentId || ctx.documentId !== ctx.expectedDocumentId) return false;
  const page = httpsOrigin(ctx.pageUrl);
  const live = httpsOrigin(ctx.livePageUrl);
  if (!page || page !== live) return false;
  return ctx.savedOrigins.some((saved) => httpsOrigin(saved) === page);
}
