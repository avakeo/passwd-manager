// ポップアップ・全画面ページから Service Worker へのメッセージの入口の検査（E-08）。
//   1. 送り元：自分の拡張機能の、決めた2つのページだけ。ページに注入したスクリプト、別の拡張機能、Web ページからは受け付けない
//      （manifest に externally_connectable と content_scripts を書かないので、Web ページからはそもそも届かない）
//   2. 種類：下の表にあるものだけ。項目の名前・型・長さが表のどれかとぴったり合わなければ、処理しない
// 返事に鍵とトークンは入れない（background.ts）。

import type { MessageSender } from './chrome-like.ts';
import { validateItem, type ClientItem } from '../../client/item-data.ts';
import { MAX_CSV_BYTES, MAX_CSV_ROWS } from '../../client/csv-import.ts';

export const POPUP_PAGE = 'extension/popup/popup.html';
export const APP_PAGE = 'extension/page/app.html';

// item は、アイテムの中身（src/client/item-data.ts の validateItem を通す。確かめた値だけの新しいオブジェクトにする）。items はその配列
// text は長い文字列（CSV）。長さは UTF-16 の単位で見る（バイト数の上限は importCsvPreview が確かめる）
type Field =
  | { kind: 'string'; min: number; max: number; pattern?: RegExp }
  | { kind: 'text'; max: number }
  | { kind: 'boolean' }
  | { kind: 'int'; min: number }
  | { kind: 'item' }
  | { kind: 'items'; max: number };

const CODE: Field = { kind: 'string', min: 6, max: 6, pattern: /^\d{6}$/ };
const RECOVERY: Field = { kind: 'string', min: 1, max: 64, pattern: /^[A-Za-z0-9-]+$/ };
const PASSCODE: Field = { kind: 'string', min: 4, max: 4, pattern: /^[0-9]{4}$/ };
const ITEM_ID: Field = { kind: 'string', min: 1, max: 64, pattern: /^item_[A-Za-z0-9_-]{22}$/ };
const REVISION: Field = { kind: 'int', min: 1 };

// 種類ごとに、受け付ける項目の組（どれか1つにぴったり合うこと）
export const MESSAGE_SCHEMAS = {
  status: [{}],
  opened: [{}], // ポップアップや全画面ページを開いた（利用者の操作）
  login: [{ deviceLabel: { kind: 'string', min: 1, max: 64 } }],
  loginTotp: [{ code: CODE }, { recoveryCode: RECOVERY }],
  logout: [{}],
  totpSetupStart: [{}, { code: CODE }, { recoveryCode: RECOVERY }],
  totpSetupConfirm: [{ code: CODE }],
  stepUp: [{ code: CODE }],
  createKey: [{ masterPassword: { kind: 'string', min: 14, max: 1024 }, replace: { kind: 'boolean' } }],
  unlock: [{ masterPassword: { kind: 'string', min: 1, max: 1024 } }],
  lock: [{}],
  initVault: [{}],
  listSessions: [{}],
  revokeSession: [{ sessionId: { kind: 'string', min: 1, max: 64, pattern: /^[A-Za-z0-9_-]+$/ } }],
  // クイックロック解除（フェーズ2b）
  setupQuickUnlock: [{ passcode: PASSCODE }],
  // ロック解除を保つ（2026-10-29 追記）
  setKeepUnlocked: [{ enabled: { kind: 'boolean' } }],
  quickUnlock: [{ passcode: PASSCODE }],
  // アイテムと同期（フェーズ2b）。新しく作るときは id を受け取らない（Service Worker が作る）
  sync: [{}],
  listItems: [{}],
  getItem: [{ id: ITEM_ID }],
  saveItem: [{ item: { kind: 'item' } }, { id: ITEM_ID, revision: REVISION, item: { kind: 'item' } }],
  deleteItem: [{ id: ITEM_ID, revision: REVISION }],
  // 自動入力とコピー（フェーズ3）。autofill はポップアップからだけ受ける（autofill.ts で送り主を確かめる）
  autofill: [{ id: ITEM_ID, tabId: { kind: 'int', min: 0 } }],
  // CSV インポート（フェーズ5）。プレビューは既存のアイテムとの重複を見るので Service Worker で作る
  previewCsv: [{ csv: { kind: 'text', max: MAX_CSV_BYTES }, format: { kind: 'string', min: 6, max: 9, pattern: /^(chrome|proton|1password)$/ } }],
  importItems: [{ items: { kind: 'items', max: MAX_CSV_ROWS } }],
  copyToClipboard: [{ id: ITEM_ID, field: { kind: 'string', min: 8, max: 8, pattern: /^password$/ } }, { id: ITEM_ID, customIndex: { kind: 'int', min: 0 } }],
} satisfies Record<string, Record<string, Field>[]>;

export type MessageType = keyof typeof MESSAGE_SCHEMAS;

// 放置のロックの時刻を新しくしない、確認だけの種類。ほかはすべて利用者の操作から来る（DeepSeek #4）。
// 同期のポーリングなど、利用者が触っていないのに送られるものは、ここに入れる
// 同期と一覧の読み直しも、利用者が触っていなくても画面が送りうるので、時刻を新しくしない（フェーズ2b、10.4）
export const PASSIVE_TYPES: ReadonlySet<MessageType> = new Set(['status', 'sync', 'listItems']);
type Value = string | boolean | number | ClientItem | ClientItem[];
export type Message = { type: MessageType } & Record<string, Value>;

export function acceptedSender(runtime: { id: string; getURL(path: string): string }, sender: MessageSender): boolean {
  if (typeof sender !== 'object' || sender === null || sender.id !== runtime.id || typeof sender.url !== 'string') return false;
  let url: URL;
  try {
    url = new URL(sender.url);
  } catch {
    return false;
  }
  if (url.search !== '' || url.username !== '' || url.password !== '') return false;
  const where = `${url.protocol}//${url.host}${url.pathname}`;
  return [POPUP_PAGE, APP_PAGE].some((page) => {
    const allowed = new URL(runtime.getURL(page));
    return where === `${allowed.protocol}//${allowed.host}${allowed.pathname}`;
  });
}

// ポップアップのページから来たか（自動入力はポップアップの操作でだけ始める：E-07・E-08）
export function fromPopup(runtime: { id: string; getURL(path: string): string }, sender: MessageSender): boolean {
  if (!acceptedSender(runtime, sender)) return false;
  const url = new URL(sender.url!);
  const popup = new URL(runtime.getURL(POPUP_PAGE));
  return url.host === popup.host && url.pathname === popup.pathname;
}

function fieldOk(field: Field, value: unknown): boolean {
  if (field.kind === 'boolean') return typeof value === 'boolean';
  if (field.kind === 'int') return typeof value === 'number' && Number.isSafeInteger(value) && value >= field.min;
  if (field.kind === 'item') return checkedItem(value) !== null;
  if (field.kind === 'items') return checkedItems(value, field.max) !== null;
  if (field.kind === 'text') return typeof value === 'string' && value.length <= field.max;
  if (typeof value !== 'string') return false;
  const length = [...value].length;
  return length >= field.min && length <= field.max && (field.pattern === undefined || field.pattern.test(value));
}

function checkedItem(value: unknown): ClientItem | null {
  try {
    return validateItem(value);
  } catch {
    return null;
  }
}

function checkedItems(value: unknown, max: number): ClientItem[] | null {
  if (!Array.isArray(value) || value.length === 0 || value.length > max) return null;
  const out: ClientItem[] = [];
  for (const v of value) {
    const item = checkedItem(v);
    if (item === null) return null;
    out.push(item);
  }
  return out;
}

// 表に合えば、確かめた項目だけで作り直したメッセージを返す。合わなければ null
export function parseMessage(raw: unknown): Message | null {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null;
  const proto = Object.getPrototypeOf(raw);
  if (proto !== Object.prototype && proto !== null) return null;
  const value = raw as Record<string, unknown>;
  const type = value.type;
  if (typeof type !== 'string' || !Object.hasOwn(MESSAGE_SCHEMAS, type)) return null;
  const keys = Object.keys(value).filter((k) => k !== 'type').sort();
  for (const schema of MESSAGE_SCHEMAS[type as MessageType] as Record<string, Field>[]) {
    const names = Object.keys(schema).sort();
    if (names.length !== keys.length || names.some((n, i) => n !== keys[i])) continue;
    if (!names.every((n) => fieldOk(schema[n]!, value[n]))) continue;
    const out: Record<string, Value> = { type };
    for (const n of names) {
      const f = schema[n]!;
      out[n] = f.kind === 'item' ? checkedItem(value[n])! : f.kind === 'items' ? checkedItems(value[n], f.max)! : (value[n] as string | boolean | number);
    }
    return out as Message;
  }
  return null;
}
