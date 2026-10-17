// API との通信。アクセストークンが切れていたら（401）、リフレッシュトークンで1回だけ更新して送り直す。
// 更新できなければ（401・403）、手元のセッションを消して「ログアウトの状態」にする。
// 送るのは決めた API の接続先だけ。トークンはこのファイルと storage.ts の外に出さない。

import type { SessionStore } from './storage.ts';

export class ApiError extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

export type ApiResult = { status: number; body: Record<string, unknown> };

type Fetch = (input: string, init: RequestInit) => Promise<Response>;

export class ApiClient {
  readonly #origin: string;
  readonly #fetch: Fetch;
  readonly #sessions: SessionStore;

  constructor(origin: string, fetchFn: Fetch, sessions: SessionStore) {
    this.#origin = origin;
    this.#fetch = fetchFn;
    this.#sessions = sessions;
  }

  // ログインの前（Bearer なし）
  async publicCall(method: string, path: string, body?: unknown): Promise<ApiResult> {
    return this.#send(method, path, body, undefined);
  }

  async call(method: string, path: string, body?: unknown): Promise<ApiResult> {
    const session = await this.#sessions.get();
    if (!session) throw new ApiError('NOT_LOGGED_IN');
    const first = await this.#send(method, path, body, session.accessToken);
    if (first.status !== 401) return first;
    if (!(await this.#refresh())) throw new ApiError('NOT_LOGGED_IN');
    const again = await this.#sessions.get();
    const second = await this.#send(method, path, body, again!.accessToken);
    if (second.status === 401) {
      await this.#sessions.clear();
      throw new ApiError('NOT_LOGGED_IN');
    }
    return second;
  }

  async #refresh(): Promise<boolean> {
    const session = await this.#sessions.get();
    if (!session) return false;
    const res = await this.#send('POST', '/v1/auth/refresh', { refresh_token: session.refreshToken }, undefined);
    if (res.status !== 200 || typeof res.body.access_token !== 'string' || typeof res.body.refresh_token !== 'string') {
      // 期限切れ、無効化、使い回しの検知、ロールを外された（A-04・A-12）
      await this.#sessions.clear();
      return false;
    }
    await this.#sessions.set({ ...session, accessToken: res.body.access_token, refreshToken: res.body.refresh_token });
    return true;
  }

  async #send(method: string, path: string, body: unknown, token: string | undefined): Promise<ApiResult> {
    const headers: Record<string, string> = {};
    if (token !== undefined) headers.Authorization = `Bearer ${token}`;
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    let res: Response;
    try {
      res = await this.#fetch(`${this.#origin}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    } catch {
      throw new ApiError('NETWORK');
    }
    let parsed: Record<string, unknown> = {};
    if ((res.headers.get('Content-Type') ?? '').includes('json')) {
      try {
        const v = (await res.json()) as unknown;
        if (typeof v === 'object' && v !== null) parsed = v as Record<string, unknown>;
      } catch {
        parsed = {};
      }
    }
    return { status: res.status, body: parsed };
  }
}
