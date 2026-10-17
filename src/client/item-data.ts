import { originForSavedUrl } from './autofill-policy.ts';

export type CustomField =
  | { type: 'text'; label: string; value: string }
  | { type: 'hidden'; label: string; value: string }
  | { type: 'date'; label: string; value: string }; // YYYY-MM-DD

export type LoginItem = {
  type: 'login'; title: string; username: string; password: string;
  urls: string[]; notes: string; customFields: CustomField[];
};
export type NoteItem = { type: 'note'; title: string; body: string };
export type ClientItem = LoginItem | NoteItem;
export const MAX_CUSTOM_FIELDS = 20;
// 64 KiB のパディング枠に4バイトの長さを入れるため、JSON 本体の最大はこの値。
export const MAX_ITEM_JSON_BYTES = 65_532;

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function exactKeys(value: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}
function validDate(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(`${value}T00:00:00.000Z`);
  return Number.isFinite(date.getTime()) && date.toISOString().slice(0, 10) === value;
}
function checkField(value: unknown): CustomField {
  if (!record(value) || !exactKeys(value, ['type', 'label', 'value']) ||
      (value.type !== 'text' && value.type !== 'hidden' && value.type !== 'date') ||
      typeof value.label !== 'string' || value.label.trim().length === 0 ||
      typeof value.value !== 'string') throw new TypeError('invalid custom field');
  if (value.type === 'date' && !validDate(value.value)) throw new TypeError('invalid date');
  return { type: value.type, label: value.label, value: value.value };
}

export function validateItem(value: unknown): ClientItem {
  if (!record(value) || typeof value.title !== 'string' || value.title.trim().length === 0) throw new TypeError('invalid item');
  let checked: ClientItem;
  if (value.type === 'login') {
    if (!exactKeys(value, ['type', 'title', 'username', 'password', 'urls', 'notes', 'customFields']) ||
        typeof value.username !== 'string' || typeof value.password !== 'string' || typeof value.notes !== 'string' ||
        !Array.isArray(value.urls) || !value.urls.every((url: unknown) => {
          if (typeof url !== 'string') return false;
          try { originForSavedUrl(url); return true; } catch { return false; }
        }) ||
        !Array.isArray(value.customFields) || value.customFields.length > MAX_CUSTOM_FIELDS) throw new TypeError('invalid login');
    checked = { type: 'login', title: value.title, username: value.username, password: value.password,
      urls: [...value.urls] as string[], notes: value.notes, customFields: value.customFields.map(checkField) };
  } else if (value.type === 'note') {
    if (!exactKeys(value, ['type', 'title', 'body']) || typeof value.body !== 'string') throw new TypeError('invalid note');
    checked = { type: 'note', title: value.title, body: value.body };
  } else throw new TypeError('invalid item type');
  if (new TextEncoder().encode(JSON.stringify(checked)).length > MAX_ITEM_JSON_BYTES) throw new RangeError('item too large');
  return checked;
}
