// Web ページを配る Worker（2026-11-01 追記、判断待ち10）。仕様書「Webページの配信」。
// 中身は静的アセット（dist/web）。Worker は、すべての応答にセキュリティのヘッダーを付け（W-03）、http なら https へ転送する（W-04）。
// API のオリジンは、CSP の connect-src に入れる。リポジトリには書かず、wrangler.web.toml の vars に置く。
// ログは出さない（W-05）。

type Assets = { fetch(request: Request): Promise<Response> };
export type WebEnv = { ASSETS: Assets; API_ORIGIN: string };

// https のオリジンだけ（パス、ワイルドカード、空白を含まない）。おかしければ null
function checkedOrigin(value: unknown): string | null {
  if (typeof value !== 'string' || /[\s*'";]/.test(value)) return null;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.origin === value ? value : null;
  } catch {
    return null;
  }
}

export function securityHeaders(apiOrigin: string): Record<string, string> {
  return {
    'Content-Security-Policy': [
      "default-src 'none'",
      "script-src 'self'",
      "style-src 'self'",
      `connect-src ${apiOrigin}`,
      "img-src 'self'",
      "base-uri 'none'",
      "form-action 'none'",
      "frame-ancestors 'none'",
    ].join('; '),
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    // Discord から戻った URL には認可コードが付くので、ほかへ送らない
    'Referrer-Policy': 'no-referrer',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  };
}

export default {
  async fetch(request: Request, env: WebEnv): Promise<Response> {
    const url = new URL(request.url);
    if (url.protocol === 'http:') {
      url.protocol = 'https:';
      return Response.redirect(url.toString(), 301);
    }
    const apiOrigin = checkedOrigin(env.API_ORIGIN);
    // 設定がおかしいときに、CSP を緩めたページを返さない
    if (apiOrigin === null) return new Response('設定が正しくありません', { status: 500, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
    const res = await env.ASSETS.fetch(request);
    const out = new Response(res.body, res);
    for (const [name, value] of Object.entries(securityHeaders(apiOrigin))) out.headers.set(name, value);
    return out;
  },
};
