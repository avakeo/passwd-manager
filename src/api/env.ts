// Workers の設定（バインディング）と、Hono の文脈の型。
// 秘密の値（クライアントシークレット、Bot のトークン、TOTP の暗号化の鍵）は Workers のシークレットに置く。D1 には置かない。

import type { Principal } from './auth.ts';
import type { D1Database } from './d1.ts';
import type { DiscordConfig } from './discord.ts';

export type Bindings = DiscordConfig & {
  DB: D1Database;
  DISCORD_REDIRECT_URIS: string; // 受け付ける redirect_uri をカンマで区切ったもの（A-13）
  TOTP_ENCRYPTION_KEY: string; // base64url の32バイト（シークレット）
  // Web ページのオリジン（2026-11-01 追記）。CORS で許可するのはこれ1つだけ。redirect_uri がこのオリジンなら Web 用のセッションにする。
  // 実際のドメインはリポジトリに書かず、wrangler.toml の vars に置く。なければ CORS はどこも許可しない
  WEB_ORIGIN?: string;
};

export type Env = { Bindings: Bindings; Variables: { principal: Principal } };
