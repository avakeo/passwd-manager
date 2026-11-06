// ツールバーのアイコンに、今のタブで入力できるログインアイテムの件数を出す（2026-11-06 追記、E-22）。
//   - 数えるのはメモリの一覧（summary）だけ。ロック中は何も出さない
//   - 照合は自動入力と同じ https のオリジンの完全一致（www・サブドメイン・ポート違いは別）
//   - タブの URL は tabs の権限で読む。数えるのに使うだけで、API に送らず、保存もしない
//   - 件数を出すだけで、入力はしない。入力は今まで通りポップアップの操作から（autofill.ts）
// 入力できるページを開いたときの通知（2026-11-06 追記、E-23）。
//   - 件数とショートカットだけを書く。アイテムの名前・ユーザー名・URL は書かない（OS の通知センターに残るため）
//   - 同じオリジンへは、ロックするまで1回だけ。通知したオリジンは storage.session に置き、ロック（context.ts の lock）で消す
//   - 前に出ているタブだけ。タブの変化のときだけ出し、メッセージの後の数え直しでは出さない
//   - 設定は端末ごと（storage.local）。最初はオン

import { originForSavedUrl } from '../../client/autofill-policy.ts';
import { NOTIFIED_KEY, type Context, type Handler } from './context.ts';

const NOTIFY_KEY = 'teampw/v1/notify'; // オフにしたときだけ false を置く

// 通知に出すアイコン（scripts/make-icons.ts で作ったもの）
const NOTIFY_ICON = 'extension/icons/icon-128.png';

function originOf(url: string): string | null {
  try {
    return originForSavedUrl(url);
  } catch {
    return null;
  }
}

export function createBadge(ctx: Context) {
  const { chrome, state } = ctx;

  function countFor(url: string): { origin: string; n: number } | null {
    if (state.unlockedBy === null || state.vaultKey === null || state.cacheLoadedFor === null) return null;
    const origin = originOf(url);
    if (origin === null) return null;
    let n = 0;
    // urls を持つのはログインアイテムだけ（メモと読めないアイテムは持たない）
    for (const { summary } of state.index.values()) {
      if ((summary.urls ?? []).some((u) => originOf(u) === origin)) n += 1;
    }
    return { origin, n };
  }

  // 閉じたタブに書くと投げるので、失敗は無視する
  async function show(tabId: number, count: { n: number } | null): Promise<void> {
    const text = count === null || count.n === 0 ? '' : String(count.n);
    await chrome.action.setBadgeText({ tabId, text }).catch(() => undefined);
  }

  async function notifyOn(): Promise<boolean> {
    return (await chrome.storage.local.get(NOTIFY_KEY))[NOTIFY_KEY] !== false;
  }

  async function notify(tabId: number, origin: string, n: number): Promise<void> {
    if (!(await notifyOn())) return;
    const epoch = state.lockEpoch;
    const saved = (await chrome.storage.session.get(NOTIFIED_KEY))[NOTIFIED_KEY];
    const notified = Array.isArray(saved) ? saved.filter((o): o is string => typeof o === 'string') : [];
    if (notified.includes(origin)) return;
    const commands = await chrome.commands.getAll().catch(() => []);
    const shortcut = commands.find((c) => c.name === '_execute_action')?.shortcut ?? '';
    // 待っている間にロックされたら、記録も通知もしない。確かめた後は await を挟まずに書き始める
    if (epoch !== state.lockEpoch) return;
    const remembered = chrome.storage.session.set({ [NOTIFIED_KEY]: [...notified, origin] });
    const message = `このページで入力できるアイテムが${n}件あります。` + (shortcut === '' ? 'ツールバーの teampw から入力できます。' : `${shortcut} で開けます。`);
    await remembered;
    await chrome.notifications.create(`teampw|${tabId}`, { type: 'basic', iconUrl: chrome.runtime.getURL(NOTIFY_ICON), title: 'teampw', message }).catch(() => undefined);
  }

  const handlers = {
    async getNotify() {
      return { ok: true, notify: await notifyOn() };
    },

    async setNotify(m) {
      if (m.enabled === true) await chrome.storage.local.remove(NOTIFY_KEY);
      else await chrome.storage.local.set({ [NOTIFY_KEY]: false });
      return { ok: true, notify: m.enabled === true };
    },
  } satisfies Record<string, Handler>;

  return {
    handlers,

    // タブを開いた・移った・切り替えたとき。前に出ているタブなら通知も出す
    async refreshTab(tabId: number): Promise<void> {
      const tab = await chrome.tabs.get(tabId).catch(() => null);
      if (!tab || typeof tab.url !== 'string') return;
      const count = countFor(tab.url);
      await show(tabId, count);
      if (count !== null && count.n > 0 && tab.active !== false) await notify(tabId, count.origin, count.n);
    },

    // ロック・ロック解除・アイテムの変更の後に、開いているタブすべて（通知は出さない）
    async refreshAll(): Promise<void> {
      const tabs = await chrome.tabs.query({}).catch(() => []);
      for (const tab of tabs) if (typeof tab.id === 'number' && typeof tab.url === 'string') await show(tab.id, countFor(tab.url));
    },
  };
}
