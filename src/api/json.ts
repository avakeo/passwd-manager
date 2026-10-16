// リクエストの本文（JSON）を読む。想定外の項目も拒否する（I-02）。

import { HttpProblem } from './problem.ts';

async function readObject(req: Request): Promise<Record<string, unknown>> {
  let body: unknown;
  try {
    body = JSON.parse(await req.text());
  } catch {
    throw new HttpProblem(400);
  }
  if (typeof body !== 'object' || body === null || Array.isArray(body)) throw new HttpProblem(400);
  return body as Record<string, unknown>;
}

function sameKeys(body: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(body).sort().join(',') === [...keys].sort().join(',');
}

export async function readJson(req: Request, keys: string[]): Promise<Record<string, unknown>> {
  const body = await readObject(req);
  if (!sameKeys(body, keys)) throw new HttpProblem(400);
  return body;
}

// 項目の組が複数ありうるとき（TOTP のコードか回復コードか）。どれか1つと一致しなければ 400
export async function readJsonOneOf(req: Request, keySets: string[][]): Promise<Record<string, unknown>> {
  const body = await readObject(req);
  if (!keySets.some((keys) => sameKeys(body, keys))) throw new HttpProblem(400);
  return body;
}
