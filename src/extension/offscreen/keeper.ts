// クリップボードの書き込みと、1分後の消去の判断（仕様書「クリップボードコピー」）。DOM を使わない部分だけ。
//   - コピーした値は、このオフスクリーンドキュメントのメモリにだけ置く。storage には置かない
//   - 60秒後に今の中身を読み直し、shouldClearClipboard が「消してよい」と返したときだけ空にする（E-10・E-12。持ち越し：消す直前に読み直す）

import { CLIPBOARD_CLEAR_DELAY_MS, shouldClearClipboard } from '../../client/clipboard-policy.ts';

export type ClipboardIo = {
  write(text: string): boolean;
  // 読めなければ null（そのときは消さない）
  read(): string | null;
  now(): number;
  schedule(run: () => void, ms: number): void;
};

export function createClipboardKeeper(io: ClipboardIo) {
  return {
    copy(text: string): boolean {
      if (text === '' || !io.write(text)) return false;
      const copiedAt = io.now();
      io.schedule(() => {
        const current = io.read();
        if (current !== null && shouldClearClipboard({ copiedText: text, currentText: current, copiedAt, now: io.now() })) io.write('');
      }, CLIPBOARD_CLEAR_DELAY_MS);
      return true;
    },
  };
}
