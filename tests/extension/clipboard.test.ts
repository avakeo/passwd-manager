// フェーズ3：クリップボードの1分後の消去（src/extension/offscreen/keeper.ts）。時計とクリップボードは偽物。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createClipboardKeeper } from '../../src/extension/offscreen/keeper.ts';

function fakeIo() {
  const io = {
    clipboard: '',
    time: 0,
    timers: [] as { at: number; run: () => void }[],
    writes: [] as string[],
    readable: true,
    write(text: string) {
      io.clipboard = text;
      io.writes.push(text);
      return true;
    },
    read() {
      return io.readable ? io.clipboard : null;
    },
    now() {
      return io.time;
    },
    schedule(run: () => void, ms: number) {
      io.timers.push({ at: io.time + ms, run });
    },
    advance(ms: number) {
      io.time += ms;
      for (const t of io.timers.filter((t) => t.at <= io.time)) {
        io.timers.splice(io.timers.indexOf(t), 1);
        t.run();
      }
    },
  };
  return io;
}

test('E-10 コピーから1分たち、中身がコピーしたままなら消す。1分より前には消さない', () => {
  const io = fakeIo();
  const keeper = createClipboardKeeper(io);
  assert.equal(keeper.copy('correct-horse'), true);
  io.advance(59_999);
  assert.equal(io.clipboard, 'correct-horse');
  io.advance(1);
  assert.equal(io.clipboard, '');
});

test('E-10 途中で利用者が別のものをコピーしたら、消さない（消す直前に読み直す）', () => {
  const io = fakeIo();
  const keeper = createClipboardKeeper(io);
  keeper.copy('correct-horse');
  io.advance(30_000);
  io.clipboard = '利用者がコピーした別の文';
  io.advance(30_000);
  assert.equal(io.clipboard, '利用者がコピーした別の文');
});

test('E-12 続けて2つコピーしたら、古い方の時刻では消さず、新しい方の1分後に消す', () => {
  const io = fakeIo();
  const keeper = createClipboardKeeper(io);
  keeper.copy('password-1');
  io.advance(30_000);
  keeper.copy('pin-0420');
  io.advance(30_000);
  assert.equal(io.clipboard, 'pin-0420', '古い方の1分では、中身が違うので消さない');
  io.advance(30_000);
  assert.equal(io.clipboard, '');
});

test('読み直せなかったときは消さない。空の文字列はコピーしない', () => {
  const io = fakeIo();
  const keeper = createClipboardKeeper(io);
  keeper.copy('correct-horse');
  io.readable = false;
  io.advance(60_000);
  assert.equal(io.clipboard, 'correct-horse');
  assert.equal(keeper.copy(''), false);
});
