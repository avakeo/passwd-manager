// 拡張機能の Service Worker の中身（chrome の API は引数で受け取る。テストは偽物を渡す）。
// 仕様書「拡張機能と自動入力の方針 > ロックと鍵の置き場所」。
//   - 秘密鍵・署名用秘密鍵・Vault 鍵は、createBackground ごとの状態（context.ts。メモリ）だけに、取り出し不可で置く。画面には渡さない
//   - トークンは chrome.storage.session（storage.ts）。応答には入れない
//   - 放置のロックは15分。Service Worker が起きたとき（onStartup）と、メッセージを受け取るたびに、処理の前に確かめる
//   - メッセージは messages.ts の検査を通ったものだけを処理する（E-08）
//   - アイテム（2b）：保存の前と復号の後に validateItem を通す。storage.local には暗号文だけをキャッシュし、平文の一覧はメモリだけ
//   - クイックロック解除（2b）：Vault 鍵だけを、パスコード由来の鍵で包んで storage.session に置く。戻った状態は秘密鍵を持たない

import type { MessageSender } from './chrome-like.ts';
import { PASSIVE_TYPES, acceptedSender, parseMessage, type Message } from './messages.ts';
import { ApiError } from './api-client.ts';
import { createItemSync } from './item-sync.ts';
import { createPasscode } from './passcode.ts';
import { createVault } from './vault.ts';
import { Fail, LAST_ACTIVITY_KEY, QUICK_UNLOCK_MAX_FAILURES, createContext, type BackgroundDeps, type Handler, type Reply } from './context.ts';
import { groupBase32 } from './api-shapes.ts';
import { createLoginRequest, parseLoginRedirect } from '../../client/discord-login.ts';
import { CryptoError } from '../../crypto/errors.ts';

export { IDLE_LOCK_MS, QUICK_UNLOCK_MAX_FAILURES, UNLOCK_KEY_PREFIX } from './context.ts';
export type { BackgroundDeps, VaultState } from './context.ts';

export type Background = {
  handleMessage(message: unknown, sender: MessageSender): Promise<Reply>;
  onStartup(): Promise<void>;
  // テスト用：メモリに鍵が残っているか（メッセージからは呼べない。中身は返さない）
  memoryState(): { unlocked: boolean; vaultKey: boolean };
};

export function createBackground(deps: BackgroundDeps): Background {
  const ctx = createContext(deps);
  const { chrome, sessions, api, state, lock, checkIdle, readySession, expect, getMe } = ctx;

  const vault = createVault(ctx);
  const passcode = createPasscode(ctx);
  const { quickKey, parseQuick } = passcode;
  const items = createItemSync(ctx, vault.openVault);

  const handlers: Record<Message['type'], Handler> = {
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
      if (!s) return { ...base, loggedIn: false };
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
      };
    },

    async login(m) {
      await lock();
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

    ...vault.handlers,
    ...passcode.handlers,
    ...items.handlers,
  };

  return {
    memoryState() {
      return { unlocked: state.unlocked !== null, vaultKey: state.vaultKey !== null };
    },

    async onStartup() {
      await checkIdle();
    },

    async handleMessage(raw, sender) {
      if (!acceptedSender(chrome.runtime, sender)) return { ok: false, error: 'BAD_REQUEST' };
      const message = parseMessage(raw);
      if (message === null) return { ok: false, error: 'BAD_REQUEST' };
      // 放置のロックは、どの指示も処理する前に確かめる。時刻を新しくするのは利用者の操作から来たものだけ（DeepSeek #4）
      await checkIdle();
      if (!PASSIVE_TYPES.has(message.type)) await chrome.storage.session.set({ [LAST_ACTIVITY_KEY]: Date.now() });
      try {
        return await handlers[message.type](message);
      } catch (e) {
        if (e instanceof Fail || e instanceof ApiError) return { ok: false, error: e.code };
        if (e instanceof CryptoError) return { ok: false, error: 'CRYPTO' };
        return { ok: false, error: 'INTERNAL' };
      }
    },
  };
}
