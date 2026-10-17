// OS のクリップボード操作は呼び出し側が担当する。この関数は消去可否だけを返す。
export const CLIPBOARD_CLEAR_DELAY_MS = 60_000;

function comparableText(value: string): string {
  return value.replace(/\r\n/g, '\n').replace(/\n+$/, '');
}

export function shouldClearClipboard(args: {
  copiedText: string;
  currentText: string;
  copiedAt: number;
  now: number;
}): boolean {
  const copied = comparableText(args.copiedText);
  return copied.length > 0 &&
    comparableText(args.currentText) === copied &&
    Number.isFinite(args.copiedAt) &&
    Number.isFinite(args.now) &&
    args.now - args.copiedAt >= CLIPBOARD_CLEAR_DELAY_MS;
}
