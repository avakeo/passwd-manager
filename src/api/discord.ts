// Discord との通信（Workers の中だけで行う）。仕様書「認証・認可フロー」。
//   1. 認可コードとトークンを交換する（クライアントシークレットと PKCE の検証値を送る）
//   2. Discord のアクセストークンで /users/@me を引き、ユーザー ID を得る
//   3. Bot のトークンで /guilds/{サーバー}/members/{ユーザー} を引き、ロールを確かめる
// Discord のアクセストークンは、この関数の中だけで使い、保存も応答もしない（A-14）。ログも出さない。
// テストでは globalThis.fetch を偽の Discord に置き換える。本番とテストで同じコードを通す。

import { HttpProblem } from './problem.ts';

export const DISCORD_API = 'https://discord.com/api/v10';

export type DiscordConfig = {
  DISCORD_CLIENT_ID: string;
  DISCORD_CLIENT_SECRET: string;
  DISCORD_BOT_TOKEN: string;
  DISCORD_GUILD_ID: string;
  DISCORD_ROLE_ID: string;
};

export type DiscordUser = { id: string; displayName: string };

async function call(url: string, init: RequestInit): Promise<Response> {
  try {
    return await fetch(url, init);
  } catch {
    throw new HttpProblem(502);
  }
}

// 認可コードを交換して、ログインした人の Discord ユーザー ID と表示名を返す。
// Discord が拒否した（PKCE の検証値の違い、使用済みのコード、redirect_uri の違い）なら 400（A-02）。
export async function exchangeCodeForUser(
  config: DiscordConfig,
  args: { code: string; codeVerifier: string; redirectUri: string },
): Promise<DiscordUser> {
  const token = await call(`${DISCORD_API}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: config.DISCORD_CLIENT_ID,
      client_secret: config.DISCORD_CLIENT_SECRET,
      grant_type: 'authorization_code',
      code: args.code,
      redirect_uri: args.redirectUri,
      code_verifier: args.codeVerifier,
    }).toString(),
  });
  if (token.status === 400 || token.status === 401) throw new HttpProblem(400);
  if (!token.ok) throw new HttpProblem(502);
  const { access_token: accessToken } = (await token.json()) as { access_token?: unknown };
  if (typeof accessToken !== 'string' || accessToken === '') throw new HttpProblem(502);

  const me = await call(`${DISCORD_API}/users/@me`, { headers: { Authorization: `Bearer ${accessToken}` } });
  if (!me.ok) throw new HttpProblem(502);
  const user = (await me.json()) as { id?: unknown; username?: unknown; global_name?: unknown };
  if (typeof user.id !== 'string' || !/^\d{1,20}$/.test(user.id)) throw new HttpProblem(502);
  const name = typeof user.global_name === 'string' && user.global_name !== '' ? user.global_name : typeof user.username === 'string' ? user.username : user.id;
  return { id: user.id, displayName: [...name].slice(0, 64).join('') };
}

// Bot の権限で、チームのサーバーで決めたロールを持っているかを確かめる。サーバーにいなければ false。
export async function hasTeamRole(config: DiscordConfig, discordUserId: string): Promise<boolean> {
  if (!/^\d{1,20}$/.test(discordUserId)) return false;
  const res = await call(`${DISCORD_API}/guilds/${config.DISCORD_GUILD_ID}/members/${discordUserId}`, {
    headers: { Authorization: `Bot ${config.DISCORD_BOT_TOKEN}` },
  });
  if (res.status === 404) return false;
  if (!res.ok) throw new HttpProblem(502);
  const member = (await res.json()) as { roles?: unknown };
  return Array.isArray(member.roles) && member.roles.includes(config.DISCORD_ROLE_ID);
}
