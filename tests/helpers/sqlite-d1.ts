// テスト用：node:sqlite を D1 と同じ形（prepare、bind、first、all、run、batch）で包む。
// 実際の D1 では確かめていない（README に記載）。

import { DatabaseSync } from 'node:sqlite';
import { readFileSync, readdirSync } from 'node:fs';
import type { D1Database, D1PreparedStatement, D1Result } from '../../src/api/d1.ts';

type Value = null | number | string;

class SqliteStatement implements D1PreparedStatement {
  readonly #db: DatabaseSync;
  readonly #sql: string;
  readonly #params: Value[];

  constructor(db: DatabaseSync, sql: string, params: Value[] = []) {
    this.#db = db;
    this.#sql = sql;
    this.#params = params;
  }

  bind(...values: unknown[]): D1PreparedStatement {
    for (const v of values) {
      if (v !== null && typeof v !== 'number' && typeof v !== 'string') throw new TypeError(`bind できない値: ${typeof v}`);
    }
    return new SqliteStatement(this.#db, this.#sql, values as Value[]);
  }

  async first<T>(): Promise<T | null> {
    return (this.#db.prepare(this.#sql).get(...this.#params) as T | undefined) ?? null;
  }

  async all<T>(): Promise<D1Result<T>> {
    const results = this.#db.prepare(this.#sql).all(...this.#params) as T[];
    return { results, success: true, meta: { changes: 0 } };
  }

  async run<T>(): Promise<D1Result<T>> {
    return this.runSync<T>();
  }

  runSync<T>(): D1Result<T> {
    const r = this.#db.prepare(this.#sql).run(...this.#params);
    return { results: [], success: true, meta: { changes: Number(r.changes) } };
  }
}

export class SqliteD1 implements D1Database {
  readonly db: DatabaseSync;

  constructor() {
    this.db = new DatabaseSync(':memory:');
    // migrations/ のファイルを番号の順にすべて流す（本番の wrangler d1 migrations apply と同じ順）
    const dir = new URL('../../migrations/', import.meta.url);
    for (const file of readdirSync(dir).filter((f) => f.endsWith('.sql')).sort()) {
      this.db.exec(readFileSync(new URL(file, dir), 'utf8'));
    }
  }

  prepare(sql: string): D1PreparedStatement {
    return new SqliteStatement(this.db, sql);
  }

  // テストで「同時に来た2つのリクエストが、どちらも確認を済ませてからバッチに入る」順を作るための待ち合わせ
  beforeBatch: (() => Promise<void>) | null = null;

  // D1 の batch と同じく、1つのトランザクションで実行し、途中で失敗すれば全体を巻き戻す
  async batch<T>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> {
    if (this.beforeBatch) await this.beforeBatch();
    this.db.exec('BEGIN');
    try {
      const results = statements.map((s) => (s as SqliteStatement).runSync<T>());
      this.db.exec('COMMIT');
      return results;
    } catch (e) {
      this.db.exec('ROLLBACK');
      throw e;
    }
  }
}
