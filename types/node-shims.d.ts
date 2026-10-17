// @types/node を依存に入れないため、テストとスクリプトで使う Node 標準モジュールの型だけを最小限に宣言する。

declare module 'node:test' {
  type TestFn = () => void | Promise<void>;
  export function test(name: string, fn: TestFn): Promise<void>;
  export function describe(name: string, fn: () => void): Promise<void>;
  export function after(fn: () => void | Promise<void>): void;
  export function beforeEach(fn: () => void | Promise<void>): void;
  // 時刻を固定する（TOTP のテスト）。Date だけを置き換える
  export const mock: {
    timers: {
      enable(options: { apis: 'Date'[]; now?: number }): void;
      setTime(milliseconds: number): void;
      reset(): void;
    };
  };
}

declare module 'node:assert/strict' {
  interface Assert {
    (value: unknown, message?: string): asserts value;
    ok(value: unknown, message?: string): asserts value;
    equal<T>(actual: unknown, expected: T, message?: string): asserts actual is T;
    notEqual(actual: unknown, expected: unknown, message?: string): void;
    deepEqual<T>(actual: unknown, expected: T, message?: string): asserts actual is T;
    notDeepEqual(actual: unknown, expected: unknown, message?: string): void;
    match(value: string, pattern: RegExp, message?: string): void;
    throws(fn: () => unknown, expected?: unknown, message?: string): void;
    rejects(
      promiseOrFn: Promise<unknown> | (() => Promise<unknown>),
      expected?: unknown,
      message?: string,
    ): Promise<void>;
    doesNotReject(promiseOrFn: Promise<unknown> | (() => Promise<unknown>), message?: string): Promise<void>;
    fail(message?: string): never;
    AssertionError: new (options: { message?: string }) => Error;
  }
  const assert: Assert;
  export default assert;
}

declare module 'node:sqlite' {
  type SQLValue = null | number | bigint | string | Uint8Array;
  interface RunResult {
    changes: number | bigint;
    lastInsertRowid: number | bigint;
  }
  export class StatementSync {
    run(...params: SQLValue[]): RunResult;
    get(...params: SQLValue[]): Record<string, SQLValue> | undefined;
    all(...params: SQLValue[]): Record<string, SQLValue>[];
  }
  export class DatabaseSync {
    constructor(location: string);
    exec(sql: string): void;
    prepare(sql: string): StatementSync;
    close(): void;
  }
}

declare module 'node:fs' {
  export function readFileSync(path: string | URL, encoding: 'utf8'): string;
  export function writeFileSync(path: string | URL, data: string): void;
  export function existsSync(path: string | URL): boolean;
  export function mkdirSync(path: string | URL, options?: { recursive?: boolean }): void;
  export function readdirSync(path: string | URL, options?: { recursive: true }): string[];
}

// 管理者署名の既知解テストで、src を使わずに署名を確かめるためだけに使う
declare module 'node:crypto' {
  interface KeyObject {
    readonly type: string;
  }
  export function createPublicKey(input: { key: JsonWebKey; format: 'jwk' }): KeyObject;
  interface Verify {
    update(data: Uint8Array): Verify;
    verify(options: { key: KeyObject; dsaEncoding: 'der' | 'ieee-p1363' }, signature: Uint8Array): boolean;
  }
  export function createVerify(algorithm: string): Verify;
  // TOTP のテストで、src を使わずにコードを計算するためだけに使う
  interface Hmac {
    update(data: Uint8Array): Hmac;
    digest(): Uint8Array;
  }
  export function createHmac(algorithm: 'sha1' | 'sha256', key: Uint8Array): Hmac;
}

// 手動確認のスクリプト（scripts/discord-login-check.ts）で、認可コードを受け取るためだけに使う
declare module 'node:http' {
  interface IncomingMessage {
    url?: string;
  }
  interface ServerResponse {
    writeHead(status: number, headers?: Record<string, string>): ServerResponse;
    end(body?: string): void;
  }
  interface Server {
    listen(port: number, host: string, callback?: () => void): Server;
    close(): void;
  }
  export function createServer(handler: (req: IncomingMessage, res: ServerResponse) => void): Server;
}

// 手動確認のスクリプトで、TOTP のコードを1行だけ読むために使う
declare module 'node:readline/promises' {
  interface Interface {
    question(query: string): Promise<string>;
    close(): void;
  }
  export function createInterface(options: { input: unknown; output: unknown }): Interface;
}

declare const process: {
  argv: string[];
  exitCode: number | undefined;
  env: Record<string, string | undefined>;
  stdin: unknown;
  stdout: unknown;
};
