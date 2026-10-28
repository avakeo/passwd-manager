// オフスクリーンドキュメント（理由 CLIPBOARD）。Service Worker からの「コピー」だけを受け、書き込みと1分後の消去を行う。
// 受け付けるのは、自分の拡張機能の Service Worker から来た、target が合うメッセージだけ。

import { createClipboardKeeper } from './keeper.ts';
import { OFFSCREEN_TARGET, SERVICE_WORKER_SCRIPT } from '../shared/offscreen-message.ts';

type Runtime = {
  id: string;
  getURL(path: string): string;
  onMessage: { addListener(listener: (message: unknown, sender: { id?: string; url?: string }, sendResponse: (reply: unknown) => void) => boolean): void };
};
const runtime = (globalThis as unknown as { chrome: { runtime: Runtime } }).chrome.runtime;
const buffer = document.getElementById('buffer') as HTMLTextAreaElement;

// copy のイベントで中身を差し替える。空の文字列を書くと、クリップボードを空にできる
function write(text: string): boolean {
  const onCopy = (e: ClipboardEvent) => {
    e.clipboardData?.setData('text/plain', text);
    e.preventDefault();
  };
  document.addEventListener('copy', onCopy);
  try {
    buffer.value = text === '' ? ' ' : text;
    buffer.select();
    return document.execCommand('copy');
  } finally {
    document.removeEventListener('copy', onCopy);
    buffer.value = '';
  }
}

// 読み直し（clipboardRead の権限を使う。2026-10-27 決定、フェーズ3の判断待ち2）。比べるためだけに使い、どこにも送らない
function read(): string | null {
  buffer.value = '';
  buffer.focus();
  try {
    return document.execCommand('paste') ? buffer.value : null;
  } finally {
    buffer.value = '';
  }
}

const keeper = createClipboardKeeper({ write, read, now: () => Date.now(), schedule: (run, ms) => void setTimeout(run, ms) });

runtime.onMessage.addListener((message, sender, sendResponse) => {
  const m = message as { target?: unknown; type?: unknown; text?: unknown } | null;
  if (typeof m !== 'object' || m === null || m.target !== OFFSCREEN_TARGET) return false;
  if (sender.id !== runtime.id || sender.url !== runtime.getURL(SERVICE_WORKER_SCRIPT)) return false;
  if (m.type !== 'copy' || typeof m.text !== 'string') {
    sendResponse({ ok: false });
    return false;
  }
  sendResponse({ ok: keeper.copy(m.text) });
  return false;
});
