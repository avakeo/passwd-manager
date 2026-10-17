// API との通信。アクセストークンが切れていたら（401）、リフレッシュトークンで更新して1回だけ送り直す。
// 更新は同時に1つだけにし、ほかの呼び出しはその結果を待つ（同じリフレッシュトークンで2回更新すると、
// サーバーが使い回しとみなしてセッションごと無効にするため：Codex #1、A-12）。
// 更新できなければ（401・403）、手元のセッションを消して「ログアウトの状態」にする。
// 更新の途中でログアウトや別の人のログインがあれば、遅れて終わった更新は書き戻さない（SessionStore の番号）。
// 送るのは決めた API の接続先だけ。トークンはこのファイルと storage.ts の外に出さない。

import type { SessionRecord, SessionStore } from './storage.ts';

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
  #refreshing: Promise<boolean> | null = null;

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
    if (!(await this.#refreshFrom(session.accessToken))) throw new ApiError('NOT_LOGGED_IN');
    const again = await this.#sessions.get();
    if (!again) throw new ApiError('NOT_LOGGED_IN');
    const second = await this.#send(method, path, body, again.accessToken);
    if (second.status === 401) {
      await this.#sessions.clear();
      throw new ApiError('NOT_LOGGED_IN');
    }
    return second;
  }

  // usedAccessToken で 401 になった呼び出しが呼ぶ。すでにほかの呼び出しが更新していれば、そのまま送り直してよい
  async #refreshFrom(usedAccessToken: string): Promise<boolean> {
    const current = await this.#sessions.get();
    if (!current) return false;
    if (current.accessToken !== usedAccessToken) return true;
    // 読んでから待つまでの間に await を挟まないので、同時に来た呼び出しは同じ更新を待つ
    this.#refreshing ??= this.#refresh(current).finally(() => {
      this.#refreshing = null;
    });
    return this.#refreshing;
  }

  async #refresh(session: SessionRecord): Promise<boolean> {
    const epoch = this.#sessions.epoch();
    const res = await this.#send('POST', '/v1/auth/refresh', { refresh_token: session.refreshToken }, undefined);
    if (res.status !== 200 || typeof res.body.access_token !== 'string' || typeof res.body.refresh_token !== 'string') {
      // 期限切れ、無効化、使い回しの検知、ロールを外された（A-04・A-12）。その間に別のログインがあれば消さない
      if (this.#sessions.epoch() === epoch) await this.#sessions.clear();
      return false;
    }
    return this.#sessions.setIfUnchanged(epoch, { ...session, accessToken: res.body.access_token, refreshToken: res.body.refresh_token });
  }

  // ログアウト：手元のセッションは呼ぶ側が先に消す。サーバーのセッションも無効にするため、アクセストークンが切れていれば、
  // 手元に書かずに更新してから送る（その間に更新が終わっていれば、同じリフレッシュトークンの使い回しで、サーバーがセッションごと無効にする）
  async logout(session: SessionRecord): Promise<void> {
    const first = await this.#send('POST', '/v1/auth/logout', undefined, session.accessToken);
    if (first.status !== 401) return;
    const res = await this.#send('POST', '/v1/auth/refresh', { refresh_token: session.refreshToken }, undefined);
    if (res.status === 200 && typeof res.body.access_token === 'string') await this.#send('POST', '/v1/auth/logout', undefined, res.body.access_token);
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
