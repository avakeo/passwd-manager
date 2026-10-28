// エラー応答は RFC 9457（Problem Details）。内部の詳細（SQL のエラー文、スタック）は含めない。

const TITLES: Record<number, string> = {
  400: 'リクエストの形式が正しくありません',
  401: 'ログインが必要です',
  403: '権限がありません',
  404: '対象が見つかりません',
  409: '競合しました。最新の状態を取得してやり直してください',
  413: 'サイズが大きすぎます',
  429: '試行の回数が多すぎます。しばらく待ってからやり直してください',
  500: 'サーバーでエラーが起きました',
  502: 'Discord との通信に失敗しました',
};

export type ProblemStatus = 400 | 401 | 403 | 404 | 409 | 413 | 429 | 500 | 502;

// extra は RFC 9457 の拡張の項目（残りの試行回数など）。内部の詳細は入れない
export function problem(status: ProblemStatus, extra: Record<string, number> = {}): Response {
  return new Response(JSON.stringify({ type: 'about:blank', title: TITLES[status], status, ...extra }), {
    status,
    headers: { 'Content-Type': 'application/problem+json' },
  });
}

export class HttpProblem extends Error {
  readonly status: ProblemStatus;
  readonly extra: Record<string, number>;

  constructor(status: ProblemStatus, extra: Record<string, number> = {}) {
    super(TITLES[status]);
    this.status = status;
    this.extra = extra;
  }
}
