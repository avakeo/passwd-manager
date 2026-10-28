// この端末を覚える（2026-10-29 追記。仕様書「この端末を覚える」、A-16〜A-19）。
//   - ログインの直後に、4桁のパスコードを決めて覚える。端末のトークンは storage.local（ディスク）に、接続先ごとに1つ置く
//   - ブラウザを閉じた後（storage.session のログインのトークンが消えた後）は、端末のトークンとパスコードで同じセッションに戻る
//   - パスコードの間違いはサーバーが数え、3回で端末のトークンを無効にする（手元で数えるだけでは、ディスクを読める人に飛ばされる）
//   - パスコードそのものは送らず、置かない。送るのは接続先とメンバー ID を混ぜた SHA-256（pin_proof）
//   - 戻った状態はロックされている。鍵を開くにはマスターパスワード（またはロック解除を保つ設定）が要る

import { toBase64Url } from '../../crypto/bytes.ts';
import { Fail, type Context, type Handler } from './context.ts';

type DeviceRecord = { memberId: string; token: string; expiresAt: number };

export function createDevice(ctx: Context) {
  const { chrome, apiOrigin, sessions, api, readySession, expect } = ctx;
  const key = `teampw/v1/device|${apiOrigin}`;

  async function proof(memberId: string, pin: string): Promise<string> {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`v1|device-pin|${apiOrigin}|${memberId}|${pin}`));
    return toBase64Url(new Uint8Array(digest));
  }

  // 期限の切れたもの、形の違うものは消して undefined
  async function read(): Promise<DeviceRecord | undefined> {
    const v = (await chrome.storage.local.get(key))[key] as Partial<DeviceRecord> | undefined;
    if (v === undefined) return undefined;
    if (typeof v.memberId !== 'string' || typeof v.token !== 'string' || typeof v.expiresAt !== 'number' || v.expiresAt <= Date.now()) {
      await forget();
      return undefined;
    }
    return { memberId: v.memberId, token: v.token, expiresAt: v.expiresAt };
  }

  async function forget(): Promise<void> {
    await chrome.storage.local.remove(key);
  }

  async function available(): Promise<boolean> {
    return (await read()) !== undefined;
  }

  const handlers = {
    // TOTP を確かめてから5分を過ぎていたら、サーバーが 403 を返す。認証アプリのコードで再確認してからやり直す
    async rememberDevice(m) {
      const s = await readySession();
      const body = expect(await api.call('POST', '/v1/me/devices', { pin_proof: await proof(s.memberId, String(m.pin)) }), 201, { 403: 'STEP_UP_REQUIRED' });
      await chrome.storage.local.set({ [key]: { memberId: s.memberId, token: String(body.device_token), expiresAt: Number(body.expires_at) } satisfies DeviceRecord });
      return { ok: true };
    },

    async resumeDevice(m) {
      const rec = await read();
      if (!rec) throw new Fail('NO_DEVICE');
      const res = await api.publicCall('POST', '/v1/auth/resume', { device_token: rec.token, pin_proof: await proof(rec.memberId, String(m.pin)) });
      if (res.status === 401) return { ok: false, error: 'BAD_PASSCODE', attemptsLeft: Number(res.body.attempts_left) };
      if (res.status === 403) {
        // 3回間違えた、ログアウトした、期限が切れた、ロールを外された。ログインからやり直す
        await forget();
        throw new Fail('DEVICE_FORGOTTEN');
      }
      const body = expect(res, 200);
      const member = body.member as { id: string; role: 'admin' | 'member' };
      if (member.id !== rec.memberId) throw new Fail('MEMBER_MISMATCH');
      // 替わった端末のトークンを先に書く（ログインのトークンを書いた後に止まっても、次に戻れるように）
      await chrome.storage.local.set({ [key]: { ...rec, token: String(body.device_token) } satisfies DeviceRecord });
      await sessions.set({ accessToken: String(body.access_token), refreshToken: String(body.refresh_token), memberId: member.id, role: member.role, totpSetupRequired: false });
      return { ok: true };
    },

    async forgetDevice() {
      await forget();
      return { ok: true };
    },
  } satisfies Record<string, Handler>;

  return { handlers, available, forget };
}
