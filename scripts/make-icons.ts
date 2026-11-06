// 拡張機能のアイコン（16・32・48・128px の PNG）を作る（2026-11-06 追記）。依存は足さず、node の zlib だけで書く。
//   node --experimental-strip-types --no-warnings scripts/make-icons.ts   → src/extension/icons/icon-<大きさ>.png
// 絵は、紫のグラデーションの角丸の四角に、白い南京錠（鍵穴つき）。形は距離の関数で決め、1ピクセルを4×4に分けて縁をなめらかにする。
// 出来上がった PNG はコミットする（ビルドのたびには作らない）。

import { mkdirSync, writeFileSync } from 'node:fs';
import { crc32, deflateSync } from 'node:zlib';

type Rgba = [number, number, number, number];

const SIZES = [16, 32, 48, 128];
const FROM: Rgba = [79, 70, 229, 255]; // 左上 #4F46E5
const TO: Rgba = [124, 58, 237, 255]; // 右下 #7C3AED
const WHITE: Rgba = [255, 255, 255, 255];

// 中心 (cx, cy)、半分の幅と高さ (hx, hy)、角の丸み r の角丸の四角までの距離（内側は負）
function roundBox(x: number, y: number, cx: number, cy: number, hx: number, hy: number, r: number): number {
  const qx = Math.abs(x - cx) - hx + r;
  const qy = Math.abs(y - cy) - hy + r;
  return Math.hypot(Math.max(qx, 0), Math.max(qy, 0)) + Math.min(Math.max(qx, qy), 0) - r;
}

// 南京錠のつる：上は半円、下は左右のまっすぐな脚（本体の中まで）
function shackle(x: number, y: number): number {
  const cx = 0.5;
  const cy = 0.42;
  const r = 0.14;
  const t = 0.05;
  if (y <= cy) return Math.abs(Math.hypot(x - cx, y - cy) - r) - t;
  return Math.max(Math.abs(Math.abs(x - cx) - r) - t, y - 0.6);
}

function colorAt(x: number, y: number): Rgba | null {
  if (roundBox(x, y, 0.5, 0.5, 0.5, 0.5, 0.22) > 0) return null;
  const k = (x + y) / 2;
  const bg = FROM.map((v, i) => Math.round(v + (TO[i]! - v) * k)) as Rgba;
  const keyhole = Math.min(Math.hypot(x - 0.5, y - 0.6) - 0.05, roundBox(x, y, 0.5, 0.67, 0.022, 0.07, 0.01));
  const body = roundBox(x, y, 0.5, 0.63, 0.24, 0.18, 0.05);
  if (body <= 0) return keyhole <= 0 ? bg : WHITE;
  if (shackle(x, y) <= 0) return WHITE;
  return bg;
}

function render(size: number): Uint8Array {
  const n = 4;
  const out = new Uint8Array(size * size * 4);
  for (let py = 0; py < size; py++) {
    for (let px = 0; px < size; px++) {
      let r = 0;
      let g = 0;
      let b = 0;
      let a = 0;
      for (let sy = 0; sy < n; sy++) {
        for (let sx = 0; sx < n; sx++) {
          const c = colorAt((px + (sx + 0.5) / n) / size, (py + (sy + 0.5) / n) / size);
          if (c === null) continue;
          r += c[0];
          g += c[1];
          b += c[2];
          a += 1;
        }
      }
      const o = (py * size + px) * 4;
      if (a > 0) {
        out[o] = Math.round(r / a);
        out[o + 1] = Math.round(g / a);
        out[o + 2] = Math.round(b / a);
      }
      out[o + 3] = Math.round((255 * a) / (n * n));
    }
  }
  return out;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function u32(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n);
  return b;
}

function chunk(type: string, data: Uint8Array): Uint8Array {
  const typed = concat([new TextEncoder().encode(type), data]);
  return concat([u32(data.length), typed, u32(crc32(typed))]);
}

export function png(size: number, rgba: Uint8Array): Uint8Array {
  const ihdr = concat([u32(size), u32(size), new Uint8Array([8, 6, 0, 0, 0])]); // 8ビット、RGBA
  const rows = new Uint8Array(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) rows.set(rgba.subarray(y * size * 4, (y + 1) * size * 4), y * (size * 4 + 1) + 1);
  const signature = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  return concat([signature, chunk('IHDR', ihdr), chunk('IDAT', deflateSync(rows, { level: 9 })), chunk('IEND', new Uint8Array())]);
}

const dir = new URL('../src/extension/icons/', import.meta.url);
mkdirSync(dir, { recursive: true });
for (const size of SIZES) writeFileSync(new URL(`icon-${size}.png`, dir), png(size, render(size)));
process.stdout.write(`src/extension/icons に ${SIZES.join('・')}px を作った\n`);
