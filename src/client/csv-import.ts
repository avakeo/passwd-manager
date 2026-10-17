import { originForSavedUrl } from './autofill-policy.ts';
import { validateItem, type LoginItem } from './item-data.ts';

export type CsvFormat = 'chrome' | 'proton' | '1password';
export type CsvIssue = { row: number; reason: string };
export type CsvPreview = { items: { row: number; item: LoginItem; duplicate: boolean }[]; errors: CsvIssue[]; warnings: CsvIssue[] };

type ParsedRow = { row: number; cells: string[] };

// RFC 4180 形式の最低限の状態機械。壊れた行は物理行末まで飛ばして次へ進む。
function parseCsv(source: string, lineOffset = 0): { rows: ParsedRow[]; errors: CsvIssue[] } {
  const rows: ParsedRow[] = [];
  const errors: CsvIssue[] = [];
  const csv = source.replace(/^\uFEFF/, '');
  let row = 1 + lineOffset, start = row, cells: string[] = [], cell = '', state: 'start' | 'plain' | 'quoted' | 'after' = 'start';
  let recoveryOffset: number | undefined;
  let i = 0;
  const finish = () => {
    cells.push(cell);
    if (cells.some((v) => v !== '')) rows.push({ row: start, cells });
    cells = []; cell = ''; state = 'start'; start = row; recoveryOffset = undefined;
  };
  while (i < csv.length) {
    const ch = csv[i]!;
    const newline = ch === '\r' || ch === '\n';
    const step = ch === '\r' && csv[i + 1] === '\n' ? 2 : 1;
    if (state === 'quoted') {
      if (ch === '"') {
        if (csv[i + 1] === '"') { cell += '"'; i += 2; continue; }
        state = 'after'; i++; continue;
      }
      if (newline) { if (recoveryOffset === undefined) recoveryOffset = i + step; cell += '\n'; row++; i += step; continue; }
      cell += ch; i++; continue;
    }
    if (newline) { row++; finish(); i += step; continue; }
    if (ch === ',') { cells.push(cell); cell = ''; state = 'start'; i++; continue; }
    if (state === 'start' && ch === '"') { state = 'quoted'; i++; continue; }
    if (state === 'after' || ch === '"') {
      errors.push({ row: start, reason: 'invalid CSV quoting' });
      while (i < csv.length && csv[i] !== '\r' && csv[i] !== '\n') i++;
      cells = []; cell = ''; state = 'start';
      continue;
    }
    state = 'plain'; cell += ch; i++;
  }
  if (state === 'quoted') {
    errors.push({ row: start, reason: 'unclosed quoted field' });
    if (recoveryOffset !== undefined) {
      const recovered = parseCsv(csv.slice(recoveryOffset), start);
      rows.push(...recovered.rows); errors.push(...recovered.errors);
    }
  }
  else if (cells.length || cell.length || state === 'after') finish();
  return { rows, errors };
}

function columns(format: CsvFormat, header: string[]): { title: number; url: number; username: number; password: number; notes: number } {
  const h = header.map((v) => v.trim().toLowerCase());
  const find = (...names: string[]) => h.findIndex((v) => names.includes(v));
  const result = {
    title: find(...(format === '1password' ? ['title'] : ['name'])),
    url: find(...(format === '1password' ? ['website', 'url'] : ['url'])),
    username: find('username', 'email'), password: find('password'),
    notes: find(...(format === '1password' ? ['notes'] : ['note', 'notes'])),
  };
  if (result.title < 0 && format === 'chrome') result.title = find('title');
  if (result.url < 0 || result.username < 0 || result.password < 0 || result.title < 0) {
    throw new TypeError('required CSV header missing');
  }
  if (new Set(h).size !== h.length) throw new TypeError('duplicate CSV header');
  return result;
}

function duplicateKey(item: LoginItem): string {
  return JSON.stringify([item.title.trim().toLowerCase(), item.username.trim().toLowerCase(), [...item.urls].sort()]);
}

export function importCsvPreview(csv: string, format: CsvFormat, existing: readonly LoginItem[] = []): CsvPreview {
  if (!['chrome', 'proton', '1password'].includes(format)) throw new TypeError('unsupported CSV format');
  const parsed = parseCsv(csv);
  const header = parsed.rows.shift();
  if (!header) throw new TypeError('CSV header missing');
  const map = columns(format, header.cells);
  const seen = new Set(existing.map(duplicateKey));
  const items: CsvPreview['items'] = [];
  const warnings: CsvIssue[] = [];
  const supported = new Set(Object.values(map));
  for (const entry of parsed.rows) {
    if (entry.cells.length !== header.cells.length) {
      parsed.errors.push({ row: entry.row, reason: 'column count mismatch' }); continue;
    }
    try {
      const value = (index: number) => index < 0 ? '' : entry.cells[index] ?? '';
      const url = value(map.url).trim();
      const item: LoginItem = {
        type: 'login', title: value(map.title), username: value(map.username),
        password: value(map.password), urls: url ? [url] : [],
        notes: value(map.notes), customFields: [],
      };
      validateItem(item);
      const key = duplicateKey(item);
      items.push({ row: entry.row, item, duplicate: seen.has(key) });
      seen.add(key);
      if (entry.cells.some((cell, index) => !supported.has(index) && cell.length > 0)) {
        warnings.push({ row: entry.row, reason: 'unsupported columns have values' });
      }
    } catch (error) {
      parsed.errors.push({ row: entry.row, reason: error instanceof RangeError ? 'item too large' : 'invalid item' });
    }
  }
  parsed.errors.sort((a, b) => a.row - b.row);
  return { items, errors: parsed.errors, warnings };
}


