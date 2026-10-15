// エラー応答は RFC 9457（Problem Details）。内部の詳細（SQL のエラー文、スタック）は含めない。

const TITLES: Record<number, string> = {
  400: 'リクエストの形式が正しくありません',
  401: 'ログインが必要です',
  403: '権限がありません',
  404: '対象が見つかりません',
  409: '競合しました。最新の状態を取得してやり直してください',
  413: 'サイズが大きすぎます',
  500: 'サーバーでエラーが起きました',
};

export type ProblemStatus = 400 | 401 | 403 | 404 | 409 | 413 | 500;

export function problem(status: ProblemStatus): Response {
  return new Response(JSON.stringify({ type: 'about:blank', title: TITLES[status], status }), {
    status,
    headers: { 'Content-Type': 'application/problem+json' },
  });
}

export class HttpProblem extends Error {
  readonly status: ProblemStatus;

  constructor(status: ProblemStatus) {
    super(TITLES[status]);
    this.status = status;
  }
}
