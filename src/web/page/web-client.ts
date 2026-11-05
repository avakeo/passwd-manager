// Web ページのログインと API の呼び出し（2026-11-01 追記、判断待ち10）。仕様書「Webページの配信」。画面（app.ts）から切り離してテストする。
//   - ログイン：state と PKCE（S256）を作り、Discord へ移る間だけ sessionStorage に置く。戻ったら1回だけ取り出して消し、state を照合する（A-01）
//   - TOTP を確かめた後のアクセストークンは、このオブジェクト（ページのメモリ）だけに置く
//   - リフレッシュトークンと、画面に出す自分の ID と役割だけは sessionStorage にも置き、再読み込みしたらそれで同じセッションに
//     戻る（2026-11-05 追記、W-08）。タブを閉じれば消える。更新したら置き換え、更新に失敗したら消す。役割は表示にだけ使い、
//     見られる範囲はサーバーが決める
//   - 呼べるのは、決めた GET の入口だけ（Web 用のトークンは読み取り専用。Z-07）。アクセストークンが切れたら1回だけ更新する

import { LoginError, createLoginRequest, parseLoginRedirect } from '../../client/discord-login.ts';

export type WebConfig = { apiOrigin: string; discordClientId: string; webOrigin: string };
type KeyValue = { getItem(key: string): string | null; setItem(key: string, value: string): void; removeItem(key: string): void };
type Json = Record<string, unknown>;

const PENDING_KEY = 'teampw/v1/web-login';
export const SESSION_KEY = 'teampw/v1/web-session';
const DEVICE_LABEL = 'Web ページ';
const ALLOWED_PATHS = new Set(['/v1/me', '/v1/me/sessions', '/v1/members', '/v1/audit-logs']);

export type WebErrorCode = 'NO_PENDING' | 'STATE_MISMATCH' | 'ACCESS_DENIED' | 'MALFORMED' | 'FORBIDDEN' | 'BAD_CODE' | 'EXPIRED' | 'NOT_ALLOWED' | 'SERVER';

export class WebError extends Error {
  readonly code: WebErrorCode;

  constructor(code: WebErrorCode) {
    super(code);
    this.name = 'WebError';
    this.code = code;
  }
}

function callbackUri(config: WebConfig): string {
  return `${config.webOrigin}/callback`;
}

async function post(fetchFn: typeof fetch, config: WebConfig, path: string, body: Json): Promise<Response> {
  return fetchFn(`${config.apiOrigin}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
}

// ログインを始める。Discord の認可画面の URL を返す（画面は location.assign で移る）
export async function startLogin(config: WebConfig, storage: KeyValue): Promise<string> {
  const req = await createLoginRequest({ clientId: config.discordClientId, redirectUri: callbackUri(config) });
  storage.setItem(PENDING_KEY, JSON.stringify({ state: req.state, codeVerifier: req.codeVerifier, redirectUri: req.redirectUri }));
  return req.url;
}

// Discord から戻った。置いた値を1回だけ取り出して消し、state を照合してから API に渡す。TOTP の一時トークンを返す
export async function finishLogin(href: string, config: WebConfig, storage: KeyValue, fetchFn: typeof fetch): Promise<{ challengeToken: string }> {
  const raw = storage.getItem(PENDING_KEY);
  storage.removeItem(PENDING_KEY);
  if (raw === null) throw new WebError('NO_PENDING');
  let pending: { state: string; codeVerifier: string; redirectUri: string };
  try {
    const v = JSON.parse(raw) as Json;
    if (typeof v.state !== 'string' || typeof v.codeVerifier !== 'string' || v.redirectUri !== callbackUri(config)) throw new Error();
    pending = { state: v.state, codeVerifier: v.codeVerifier, redirectUri: v.redirectUri };
  } catch {
    throw new WebError('NO_PENDING');
  }
  let code: string;
  try {
    code = parseLoginRedirect(href, pending);
  } catch (e) {
    if (e instanceof LoginError) throw new WebError(e.code);
    throw e;
  }
  const res = await post(fetchFn, config, '/v1/auth/discord', { code, code_verifier: pending.codeVerifier, redirect_uri: pending.redirectUri, device_label: DEVICE_LABEL });
  // 403：チームのロールがない、削除された、TOTP を登録していない（登録は拡張機能で行う。W-07）
  if (res.status === 403) throw new WebError('FORBIDDEN');
  if (!res.ok) throw new WebError('SERVER');
  const body = (await res.json()) as Json;
  if (body.status !== 'totp_required' || typeof body.challenge_token !== 'string') throw new WebError('FORBIDDEN');
  return { challengeToken: body.challenge_token };
}

export type WebMember = { id: string; role: string };

export class WebSession {
  #config: WebConfig;
  #fetch: typeof fetch;
  #storage: KeyValue;
  #access: string;
  #refresh: string;
  readonly member: WebMember;

  private constructor(config: WebConfig, fetchFn: typeof fetch, storage: KeyValue, tokens: { access: string; refresh: string }, member: WebMember) {
    this.#config = config;
    this.#fetch = fetchFn;
    this.#storage = storage;
    this.#access = tokens.access;
    this.#refresh = tokens.refresh;
    this.member = member;
    this.#save();
  }

  // TOTP のコードを確かめて、セッションを受け取る
  static async verifyTotp(config: WebConfig, fetchFn: typeof fetch, storage: KeyValue, challengeToken: string, code: string): Promise<WebSession> {
    const res = await post(fetchFn, config, '/v1/auth/totp', { challenge_token: challengeToken, code });
    if (res.status === 401 || res.status === 400) throw new WebError('BAD_CODE');
    if (res.status === 403) throw new WebError('FORBIDDEN');
    if (!res.ok) throw new WebError('SERVER');
    const body = (await res.json()) as Json;
    const m = body.member as Json | undefined;
    if (typeof body.access_token !== 'string' || typeof body.refresh_token !== 'string' || !m || typeof m.id !== 'string') throw new WebError('SERVER');
    return new WebSession(config, fetchFn, storage, { access: body.access_token, refresh: body.refresh_token }, { id: m.id, role: String(m.role) });
  }

  // 再読み込みの後：置いたリフレッシュトークンで更新する。戻れなければ置いた値を消して null
  static async resume(config: WebConfig, fetchFn: typeof fetch, storage: KeyValue): Promise<WebSession | null> {
    let refresh: string;
    let member: WebMember;
    try {
      const v = JSON.parse(storage.getItem(SESSION_KEY) ?? 'null') as Json | null;
      const m = v?.member as Json | undefined;
      if (v === null || typeof v.refresh !== 'string' || !m || typeof m.id !== 'string' || typeof m.role !== 'string') throw new Error();
      refresh = v.refresh;
      member = { id: m.id, role: m.role };
    } catch {
      storage.removeItem(SESSION_KEY);
      return null;
    }
    let tokens: { access: string; refresh: string };
    try {
      tokens = await renew(fetchFn, config, refresh);
    } catch {
      storage.removeItem(SESSION_KEY);
      return null;
    }
    return new WebSession(config, fetchFn, storage, tokens, member);
  }

  // このタブのログインを消す。サーバーのセッションは残る（ログアウトは書き込みなので、Web 用のトークンでは呼べない）
  forget(): void {
    this.#storage.removeItem(SESSION_KEY);
  }

  // 決めた GET の入口だけを呼ぶ。401 なら1回だけ更新して呼び直す
  async get(path: string): Promise<Json> {
    if (!ALLOWED_PATHS.has(path)) throw new WebError('NOT_ALLOWED');
    let res = await this.#call(path);
    if (res.status === 401) {
      await this.#renew();
      res = await this.#call(path);
    }
    if (res.status === 401) throw new WebError('EXPIRED');
    if (res.status === 403) throw new WebError('FORBIDDEN');
    if (!res.ok) throw new WebError('SERVER');
    return (await res.json()) as Json;
  }

  #call(path: string): Promise<Response> {
    return this.#fetch(`${this.#config.apiOrigin}${path}`, { method: 'GET', headers: { Authorization: `Bearer ${this.#access}` } });
  }

  #save(): void {
    this.#storage.setItem(SESSION_KEY, JSON.stringify({ refresh: this.#refresh, member: this.member }));
  }

  async #renew(): Promise<void> {
    let tokens: { access: string; refresh: string };
    try {
      tokens = await renew(this.#fetch, this.#config, this.#refresh);
    } catch (e) {
      this.forget();
      throw e;
    }
    this.#access = tokens.access;
    this.#refresh = tokens.refresh;
    this.#save();
  }
}

async function renew(fetchFn: typeof fetch, config: WebConfig, refresh: string): Promise<{ access: string; refresh: string }> {
  const res = await post(fetchFn, config, '/v1/auth/refresh', { refresh_token: refresh });
  if (!res.ok) throw new WebError('EXPIRED');
  const body = (await res.json()) as Json;
  if (typeof body.access_token !== 'string' || typeof body.refresh_token !== 'string') throw new WebError('EXPIRED');
  return { access: body.access_token, refresh: body.refresh_token };
}
