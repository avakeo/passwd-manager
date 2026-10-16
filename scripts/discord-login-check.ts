// 本物の Discord で、拡張機能なしにログインを手で確かめる道具（マイルストーン1）。テストの実行には使わない。
//   1. `npx wrangler dev` で API を手元で動かす（http://localhost:8787）
//   2. 次を実行し、表示された URL をブラウザで開いて Discord で許可する
//        DISCORD_CLIENT_ID=<Client ID> node --experimental-strip-types --no-warnings scripts/discord-login-check.ts
//   3. http://localhost:8788/callback に戻ってきた認可コードを、このスクリプトが API に渡し、結果を表示する
// トークンそのものは表示しない（応答の status、メンバーの役割と状態、GET /v1/me の結果だけを出す）。
// Discord のアプリの Redirects と、wrangler の DISCORD_REDIRECT_URIS に http://localhost:8788/callback を足しておく。

import { createServer } from 'node:http';
import { createInterface } from 'node:readline/promises';
import { createLoginRequest, parseLoginRedirect } from '../src/client/discord-login.ts';

const clientId = process.env.DISCORD_CLIENT_ID;
const apiBase = process.env.API_BASE ?? 'http://localhost:8787';
const redirectUri = 'http://localhost:8788/callback';
if (!clientId) {
  console.error('DISCORD_CLIENT_ID を環境変数で渡してください');
  process.exitCode = 1;
} else {
  const req = await createLoginRequest({ clientId, redirectUri });
  console.log('次の URL をブラウザで開いて、Discord で許可してください：');
  console.log(req.url);

  const code = await new Promise<string>((resolve, reject) => {
    const server = createServer((r, res) => {
      try {
        const got = parseLoginRedirect(`http://localhost:8788${r.url ?? ''}`, req);
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('受け取りました。この画面は閉じてかまいません。');
        server.close();
        resolve(got);
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('ログインの戻りが正しくありません（state の不一致など）');
        server.close();
        reject(e);
      }
    });
    server.listen(8788, '127.0.0.1');
  });

  const post = (path: string, body: unknown, token?: string) =>
    fetch(`${apiBase}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(body),
    });

  let res = await post('/v1/auth/discord', { code, code_verifier: req.codeVerifier, redirect_uri: redirectUri, device_label: '手動確認' });
  let body = (await res.json()) as { status?: string; access_token?: string; challenge_token?: string; member?: unknown; title?: string };
  console.log(`POST /v1/auth/discord → ${res.status}`, { status: body.status, member: body.member, title: body.title });

  if (body.status === 'totp_required') {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    const totp = (await rl.question('認証アプリの6桁のコード：')).trim();
    rl.close();
    res = await post('/v1/auth/totp', { challenge_token: body.challenge_token, code: totp });
    body = (await res.json()) as typeof body;
    console.log(`POST /v1/auth/totp → ${res.status}`, { status: body.status, member: body.member, title: body.title });
  }

  if (body.access_token) {
    const me = await fetch(`${apiBase}/v1/me`, { headers: { Authorization: `Bearer ${body.access_token}` } });
    const meBody = (await me.json()) as { id?: string; role?: string; title?: string };
    console.log(`GET /v1/me → ${me.status}`, { id: meBody.id, role: meBody.role, title: meBody.title });
    await post('/v1/auth/logout', {}, body.access_token);
    console.log('ログアウトしました（確認用のセッションを残さない）');
  }
}
