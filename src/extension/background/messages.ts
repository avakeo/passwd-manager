// ポップアップ・全画面ページから Service Worker へのメッセージの入口の検査（E-08）。
//   1. 送り元：自分の拡張機能の、決めた2つのページだけ。ページに注入したスクリプト、別の拡張機能、Web ページからは受け付けない
//      （manifest に externally_connectable と content_scripts を書かないので、Web ページからはそもそも届かない）
//   2. 種類：下の表にあるものだけ。項目の名前・型・長さが表のどれかとぴったり合わなければ、処理しない
// 返事に鍵とトークンは入れない（background.ts）。

import type { MessageSender } from './chrome-like.ts';

export const POPUP_PAGE = 'extension/popup/popup.html';
export const APP_PAGE = 'extension/page/app.html';

type Field = { kind: 'string'; min: number; max: number; pattern?: RegExp } | { kind: 'boolean' };

const CODE: Field = { kind: 'string', min: 6, max: 6, pattern: /^\d{6}$/ };
const RECOVERY: Field = { kind: 'string', min: 1, max: 64, pattern: /^[A-Za-z0-9-]+$/ };

// 種類ごとに、受け付ける項目の組（どれか1つにぴったり合うこと）
export const MESSAGE_SCHEMAS = {
  status: [{}],
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
} satisfies Record<string, Record<string, Field>[]>;

export type MessageType = keyof typeof MESSAGE_SCHEMAS;
export type Message = { type: MessageType } & Record<string, string | boolean>;

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

function fieldOk(field: Field, value: unknown): boolean {
  if (field.kind === 'boolean') return typeof value === 'boolean';
  if (typeof value !== 'string') return false;
  const length = [...value].length;
  return length >= field.min && length <= field.max && (field.pattern === undefined || field.pattern.test(value));
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
    const out: Record<string, string | boolean> = { type };
    for (const n of names) out[n] = value[n] as string | boolean;
    return out as Message;
  }
  return null;
}
