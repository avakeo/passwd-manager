// Service Worker の入口。chrome の本物の API を background.ts に渡すだけ。
// 入口は chrome.runtime.onMessage の1つだけ（onMessageExternal は登録しない）。

import { createBackground } from './background.ts';
import type { ChromeLike, MessageSender } from './chrome-like.ts';
import { CONFIG } from '../config.ts';

type RealChrome = ChromeLike & {
  runtime: ChromeLike['runtime'] & {
    onMessage: { addListener(listener: (message: unknown, sender: MessageSender, sendResponse: (reply: unknown) => void) => boolean): void };
  };
  tabs: ChromeLike['tabs'] & {
    onActivated: { addListener(listener: (info: { tabId: number }) => void): void };
    onUpdated: { addListener(listener: (tabId: number, change: { url?: string; status?: string }) => void): void };
  };
};

const chromeApi = (globalThis as unknown as { chrome: RealChrome }).chrome;

const background = createBackground({
  chrome: chromeApi,
  apiOrigin: CONFIG.apiOrigin,
  webOrigin: CONFIG.webOrigin,
  discordClientId: CONFIG.discordClientId,
  fetch: (input, init) => fetch(input, init),
});

// 起きたときに、放置のロックを確かめる
void background.onStartup();

chromeApi.runtime.onMessage.addListener((message, sender, sendResponse) => {
  background.handleMessage(message, sender).then(sendResponse, () => sendResponse({ ok: false, error: 'INTERNAL' }));
  return true; // 返事は非同期
});

// アイコンの件数（E-22）：タブを切り替えた・ページを移ったときに数え直す
chromeApi.tabs.onActivated.addListener(({ tabId }) => void background.onTabChanged(tabId));
chromeApi.tabs.onUpdated.addListener((tabId, change) => {
  if (change.url !== undefined || change.status === 'complete') void background.onTabChanged(tabId);
});
