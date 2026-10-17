// Service Worker の入口。chrome の本物の API を background.ts に渡すだけ。
// 入口は chrome.runtime.onMessage の1つだけ（onMessageExternal は登録しない）。

import { createBackground } from './background.ts';
import type { ChromeLike, MessageSender } from './chrome-like.ts';
import { CONFIG } from '../config.ts';

type RealChrome = ChromeLike & {
  runtime: ChromeLike['runtime'] & {
    onMessage: { addListener(listener: (message: unknown, sender: MessageSender, sendResponse: (reply: unknown) => void) => boolean): void };
  };
};

const chromeApi = (globalThis as unknown as { chrome: RealChrome }).chrome;

const background = createBackground({
  chrome: chromeApi,
  apiOrigin: CONFIG.apiOrigin,
  discordClientId: CONFIG.discordClientId,
  fetch: (input, init) => fetch(input, init),
});

// 起きたときに、放置のロックを確かめる
void background.onStartup();

chromeApi.runtime.onMessage.addListener((message, sender, sendResponse) => {
  background.handleMessage(message, sender).then(sendResponse, () => sendResponse({ ok: false, error: 'INTERNAL' }));
  return true; // 返事は非同期
});
