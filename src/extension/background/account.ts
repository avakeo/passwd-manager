// 状態の問い合わせ、ログイン（Discord と TOTP）、ログアウト、ロック、セッションの一覧と無効化（フェーズ1・2a）。
//   - トークンは chrome.storage.session（storage.ts）。応答には入れない
//   - ロックとログアウトは、ログインの途中の一時トークンも消す（DeepSeek #5）

import { createLoginRequest, parseLoginRedirect } from '../../client/discord-login.ts';
import { ApiError } from './api-client.ts';
import { groupBase32 } from './api-shapes.ts';
import { Fail, QUICK_UNLOCK_MAX_FAILURES, type Context, type Handler } from './context.ts';
import type { createPasscode } from './passcode.ts';
import type { createSessionUnlock } from './session-unlock.ts';
import type { createDevice } from './device.ts';

export function createAccount(
  ctx: Context,
  passcode: Pick<ReturnType<typeof createPasscode>, 'quickKey' | 'parseQuick'>,
  session: Pick<ReturnType<typeof createSessionUnlock>, 'enabled'>,
  device: Pick<ReturnType<typeof createDevice>, 'available' | 'forget'>,
) {
  const { deps, chrome, sessions, api, state, lock, readySession, expect, getMe } = ctx;
  const { quickKey, parseQuick } = passcode;

  const handlers = {
    async status() {
      const s = await sessions.get();
      const quick = s ? parseQuick((await chrome.storage.session.get(quickKey(s.memberId)))[quickKey(s.memberId)]) : null;
      const base = {
        ok: true as const,
        locked: state.unlockedBy === null,
        unlockedBy: state.unlockedBy,
        vault: state.unlockedBy === null ? 'locked' : state.vaultState,
        loginInProgress: state.challenge !== null,
        quickUnlockAvailable: quick !== null && quick.failures < QUICK_UNLOCK_MAX_FAILURES,
        cacheFull: state.cacheFull,
      };
      if (!s) return { ...base, loggedIn: false, deviceResumeAvailable: await device.available() };
      if (s.totpSetupRequired) return { ...base, loggedIn: true, totpSetupRequired: true, member: { id: s.memberId, role: s.role } };
      let me;
      try {
        me = await getMe();
      } catch (e) {
        if (e instanceof ApiError && e.code === 'NOT_LOGGED_IN') return { ...base, loggedIn: false };
        if (e instanceof Fail && e.code === 'ADMIN_NOT_READY') return { ...base, loggedIn: true, totpSetupRequired: false, member: { id: s.memberId, role: s.role }, hasKey: null };
        throw e;
      }
      return {
        ...base,
        loggedIn: true,
        totpSetupRequired: false,
        member: { id: me.id, role: me.role },
        hasKey: me.key !== null,
        vault: me.key === null ? 'no-key' : base.vault,
        recoveryCodesRemaining: me.recoveryCodesRemaining,
        keepUnlocked: await session.enabled(me.id),
        deviceRemembered: await device.available(),
      };
    },

    async login(m) {
      await lock();
      // 新しくログインするなら、前に覚えた端末のトークンは使わない（覚えるなら、ログインの後にもう一度）
      await device.forget();
      const req = await createLoginRequest({ clientId: deps.discordClientId, redirectUri: chrome.identity.getRedirectURL() });
      let redirected: string | undefined;
      try {
        redirected = await chrome.identity.launchWebAuthFlow({ url: req.url, interactive: true });
      } catch {
        throw new Fail('LOGIN_CANCELLED');
      }
      let code: string;
      try {
        code = parseLoginRedirect(redirected ?? '', req);
      } catch {
        throw new Fail('LOGIN_FAILED');
      }
      const body = expect(
        await api.publicCall('POST', '/v1/auth/discord', { code, code_verifier: req.codeVerifier, redirect_uri: req.redirectUri, device_label: m.deviceLabel }),
        200,
        { 400: 'LOGIN_FAILED', 403: 'NOT_ALLOWED', 502: 'SERVER' },
      );
      const member = body.member as { id: string; role: 'admin' | 'member' };
      if (body.status === 'totp_required') {
        await sessions.clear();
        state.challenge = { token: String(body.challenge_token) };
        return { ok: true, status: 'totp_required' };
      }
      await sessions.set({
        accessToken: String(body.access_token),
        refreshToken: String(body.refresh_token),
        memberId: member.id,
        role: member.role,
        totpSetupRequired: body.status === 'totp_setup_required',
      });
      return { ok: true, status: body.status };
    },

    async loginTotp(m) {
      if (!state.challenge) throw new Fail('NO_LOGIN_IN_PROGRESS');
      const payload = 'code' in m ? { challenge_token: state.challenge.token, code: m.code } : { challenge_token: state.challenge.token, recovery_code: m.recoveryCode };
      const body = expect(await api.publicCall('POST', '/v1/auth/totp', payload), 200, { 401: 'BAD_CODE', 403: 'NOT_ALLOWED' });
      state.challenge = null;
      const member = body.member as { id: string; role: 'admin' | 'member' };
      await sessions.set({ accessToken: String(body.access_token), refreshToken: String(body.refresh_token), memberId: member.id, role: member.role, totpSetupRequired: false });
      return { ok: true, status: 'ok', recoveryCodesRemaining: Number(body.recovery_codes_remaining ?? 0) };
    },

    async logout() {
      // 先に手元を消す（更新の途中でも、遅れて終わった更新は書き戻さない）
      const s = await sessions.get();
      await sessions.clear();
      await device.forget(); // サーバーでも、ログアウトでセッションと一緒に無効になる
      await lock();
      if (s) {
        try {
          await api.logout(s);
        } catch {
          // 通信できなくても、手元のセッションは消してある
        }
      }
      return { ok: true };
    },

    async totpSetupStart(m) {
      const s = await sessions.get();
      if (!s) throw new Fail('NOT_LOGGED_IN');
      const payload = 'code' in m ? { code: m.code } : 'recoveryCode' in m ? { recovery_code: m.recoveryCode } : undefined;
      const body = expect(await api.call('POST', '/v1/me/totp', payload), 200, { 400: 'CODE_REQUIRED', 403: 'BAD_CODE' });
      return { ok: true, secret: groupBase32(String(body.secret)), otpauthUri: String(body.otpauth_uri) };
    },

    async totpSetupConfirm(m) {
      const s = await sessions.get();
      if (!s) throw new Fail('NOT_LOGGED_IN');
      const body = expect(await api.call('POST', '/v1/me/totp/confirm', { code: m.code }), 200, { 403: 'BAD_CODE', 409: 'NO_SETUP_IN_PROGRESS' });
      await sessions.set({ ...s, totpSetupRequired: false });
      return { ok: true, recoveryCodes: body.recovery_codes };
    },

    async stepUp(m) {
      await readySession();
      expect(await api.call('POST', '/v1/auth/totp', { code: m.code }), 204, { 403: 'BAD_CODE' });
      return { ok: true };
    },

    async lock() {
      await lock();
      return { ok: true };
    },

    async opened() {
      return { ok: true };
    },

    async listSessions() {
      await readySession();
      const body = expect(await api.call('GET', '/v1/me/sessions'), 200);
      const list = Array.isArray(body.sessions) ? (body.sessions as Record<string, unknown>[]) : [];
      return {
        ok: true,
        sessions: list.map((s) => ({
          id: String(s.id),
          deviceLabel: typeof s.device_label === 'string' ? s.device_label : '',
          scope: String(s.scope),
          createdAt: Number(s.created_at),
          lastUsedAt: s.last_used_at === null ? null : Number(s.last_used_at),
          current: s.current === true,
        })),
      };
    },

    async revokeSession(m) {
      await readySession();
      expect(await api.call('DELETE', `/v1/me/sessions/${String(m.sessionId)}`), 204, { 403: 'STEP_UP_REQUIRED', 404: 'NOT_FOUND' });
      return { ok: true };
    },
  } satisfies Record<string, Handler>;

  return { handlers };
}
