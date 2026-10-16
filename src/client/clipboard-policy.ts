// OS のクリップボード操作は呼び出し側が担当する。この関数は消去可否だけを返す。
export const CLIPBOARD_CLEAR_DELAY_MS = 60_000;

export function shouldClearClipboard(args: {
  copiedText: string;
  currentText: string;
  copiedAt: number;
  now: number;
}): boolean {
  return args.copiedText.length > 0 &&
    args.currentText === args.copiedText &&
    Number.isFinite(args.copiedAt) &&
    Number.isFinite(args.now) &&
    args.now - args.copiedAt >= CLIPBOARD_CLEAR_DELAY_MS;
}
