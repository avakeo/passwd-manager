// Discord ログインの開始と戻り（拡張機能が使う。依存ゼロ、WebCrypto だけ）。
// 仕様書「ログイン（Chrome拡張機能）」：state と PKCE（S256）は拡張機能が作り、戻ってきた URL の state を照合する（A-01）。
// サーバーは state を持たない。認可コードと PKCE の検証値を POST /v1/auth/discord に渡す。

import { toBase64Url } from '../crypto/bytes.ts';
import { randomBytes } from '../crypto/random.ts';

export const DISCORD_AUTHORIZE_URL = 'https://discord.com/oauth2/authorize';

export type LoginErrorCode = 'STATE_MISMATCH' | 'ACCESS_DENIED' | 'MALFORMED';

const MESSAGES: Record<LoginErrorCode, string> = {
  STATE_MISMATCH: 'ログインの確認に失敗しました。もう一度ログインしてください',
  ACCESS_DENIED: 'Discord でログインが許可されませんでした',
  MALFORMED: 'ログインの戻り先が正しくありません',
};

export class LoginError extends Error {
  readonly code: LoginErrorCode;

  constructor(code: LoginErrorCode) {
    super(MESSAGES[code]);
    this.name = 'LoginError';
    this.code = code;
  }
}

export type LoginRequest = {
  url: string; // Discord の認可画面（identity API の launchWebAuthFlow に渡す）
  state: string;
  codeVerifier: string; // POST /v1/auth/discord に渡す。保存はメモリだけ
  redirectUri: string;
};

// state と code_verifier は、それぞれ乱数32バイト（base64url で43文字）
export async function createLoginRequest(opts: { clientId: string; redirectUri: string }): Promise<LoginRequest> {
  const state = toBase64Url(randomBytes(32));
  const codeVerifier = toBase64Url(randomBytes(32));
  const challenge = toBase64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier))));
  const url = new URL(DISCORD_AUTHORIZE_URL);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', opts.clientId);
  url.searchParams.set('scope', 'identify');
  url.searchParams.set('redirect_uri', opts.redirectUri);
  url.searchParams.set('state', state);
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('prompt', 'consent');
  return { url: url.toString(), state, codeVerifier, redirectUri: opts.redirectUri };
}

// 戻ってきた URL から認可コードを取り出す。戻り先が違う、state が違う・ない・2つある、なら拒否する。
export function parseLoginRedirect(redirectedTo: string, req: { state: string; redirectUri: string }): string {
  let url: URL;
  try {
    url = new URL(redirectedTo);
  } catch {
    throw new LoginError('MALFORMED');
  }
  if (url.origin + url.pathname !== new URL(req.redirectUri).origin + new URL(req.redirectUri).pathname) throw new LoginError('MALFORMED');
  const states = url.searchParams.getAll('state');
  if (states.length !== 1 || states[0] !== req.state || req.state.length === 0) throw new LoginError('STATE_MISMATCH');
  if (url.searchParams.has('error')) throw new LoginError('ACCESS_DENIED');
  const codes = url.searchParams.getAll('code');
  if (codes.length !== 1 || codes[0] === '') throw new LoginError('MALFORMED');
  return codes[0]!;
}
