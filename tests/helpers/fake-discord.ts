// テスト用の偽の Discord。globalThis.fetch を置き換えて、本物の Discord を呼ばずに、本番と同じコードの道筋を通す。
// 本物の振る舞いのうち、こちらの守りに関わる所（クライアントシークレット、redirect_uri、認可コードの1回だけの使用、
// PKCE の S256、Bot のトークン、サーバーにいない人の 404）を再現する。
// discord.com/api/v10 以外への通信はテストを失敗させる（うっかり本物のネットワークに出ないように）。

import { toBase64Url } from '../../src/crypto/bytes.ts';

export const DISCORD_API = 'https://discord.com/api/v10';

export type FakeRequest = { url: string; method: string; headers: Record<string, string>; body: string };

type Code = { userId: string; redirectUri: string; codeChallenge: string; used: boolean };

function random(prefix: string): string {
  return `${prefix}_${toBase64Url(crypto.getRandomValues(new Uint8Array(18)))}`;
}

async function s256(verifier: string): Promise<string> {
  return toBase64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

export class FakeDiscord {
  readonly requests: FakeRequest[] = [];
  readonly issuedAccessTokens: string[] = [];
  readonly unexpected: string[] = [];
  readonly #config: { clientId: string; clientSecret: string; botToken: string; guildId: string };
  readonly #users = new Map<string, { username: string; globalName: string | null }>();
  readonly #roles = new Map<string, string[]>(); // サーバーにいる人のロール。いない人は入れない
  readonly #codes = new Map<string, Code>();
  readonly #tokens = new Map<string, string>(); // アクセストークン → ユーザー ID
  failNext: 'token' | 'user' | 'member' | null = null; // 次の1回を 500 にする（Discord の障害）

  constructor(config: { clientId: string; clientSecret: string; botToken: string; guildId: string }) {
    this.#config = config;
  }

  addUser(userId: string, opts: { roles: string[] | null; username?: string; globalName?: string | null }): void {
    this.#users.set(userId, { username: opts.username ?? `user${userId.slice(-4)}`, globalName: opts.globalName ?? null });
    this.setRoles(userId, opts.roles);
  }

  // null はサーバーにいない人
  setRoles(userId: string, roles: string[] | null): void {
    if (roles === null) this.#roles.delete(userId);
    else this.#roles.set(userId, [...roles]);
  }

  // 利用者が Discord の画面で許可したことの代わり。本物は redirect_uri に code と state を付けて戻す。
  issueCode(opts: { userId: string; redirectUri: string; codeChallenge: string }): string {
    const code = random('code');
    this.#codes.set(code, { ...opts, used: false });
    return code;
  }

  install(): () => void {
    const original = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      const headers: Record<string, string> = {};
      request.headers.forEach((v, k) => (headers[k] = v));
      const body = await request.text();
      this.requests.push({ url: request.url, method: request.method, headers, body });
      if (!request.url.startsWith(`${DISCORD_API}/`)) {
        this.unexpected.push(request.url);
        throw new Error(`偽の Discord：想定外の通信 ${request.url}`);
      }
      return this.#handle(request.method, new URL(request.url), headers, body);
    }) as typeof fetch;
    return () => {
      globalThis.fetch = original;
    };
  }

  async #handle(method: string, url: URL, headers: Record<string, string>, body: string): Promise<Response> {
    const path = url.pathname.replace('/api/v10', '');
    if (method === 'POST' && path === '/oauth2/token') {
      if (this.failNext === 'token') return ((this.failNext = null), json(500, { message: 'internal' }));
      if (!(headers['content-type'] ?? '').startsWith('application/x-www-form-urlencoded')) return json(400, { error: 'invalid_request' });
      const form = new URLSearchParams(body);
      if (form.get('client_id') !== this.#config.clientId || form.get('client_secret') !== this.#config.clientSecret) {
        return json(401, { error: 'invalid_client' });
      }
      if (form.get('grant_type') !== 'authorization_code') return json(400, { error: 'unsupported_grant_type' });
      const code = this.#codes.get(form.get('code') ?? '');
      if (!code || code.used || code.redirectUri !== form.get('redirect_uri')) return json(400, { error: 'invalid_grant' });
      code.used = true; // 失敗しても使用済みにする（本物も同じコードは2度使えない）
      if ((await s256(form.get('code_verifier') ?? '')) !== code.codeChallenge) return json(400, { error: 'invalid_grant' });
      const accessToken = random('discord_access');
      this.#tokens.set(accessToken, code.userId);
      this.issuedAccessTokens.push(accessToken);
      return json(200, { access_token: accessToken, token_type: 'Bearer', expires_in: 604800, refresh_token: random('discord_refresh'), scope: 'identify' });
    }
    if (method === 'GET' && path === '/users/@me') {
      if (this.failNext === 'user') return ((this.failNext = null), json(500, { message: 'internal' }));
      const m = /^Bearer (.+)$/.exec(headers['authorization'] ?? '');
      const userId = m ? this.#tokens.get(m[1]!) : undefined;
      const user = userId ? this.#users.get(userId) : undefined;
      if (!userId || !user) return json(401, { message: '401: Unauthorized', code: 0 });
      return json(200, { id: userId, username: user.username, global_name: user.globalName });
    }
    const member = /^\/guilds\/(\d+)\/members\/(\d+)$/.exec(path);
    if (method === 'GET' && member) {
      if (this.failNext === 'member') return ((this.failNext = null), json(500, { message: 'internal' }));
      if (headers['authorization'] !== `Bot ${this.#config.botToken}`) return json(401, { message: '401: Unauthorized', code: 0 });
      if (member[1] !== this.#config.guildId) return json(403, { message: 'Missing Access', code: 50001 });
      const roles = this.#roles.get(member[2]!);
      if (!roles) return json(404, { message: 'Unknown Member', code: 10007 });
      return json(200, { user: { id: member[2] }, roles });
    }
    return json(404, { message: '404: Not Found', code: 0 });
  }
}
