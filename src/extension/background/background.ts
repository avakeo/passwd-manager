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
import { chromePinStore } from './storage.ts';
import { createItemSync } from './item-sync.ts';
import { Fail, LAST_ACTIVITY_KEY, QUICK_UNLOCK_MAX_FAILURES, UNLOCK_KEY_PREFIX, createContext, type BackgroundDeps, type Handler, type Reply, type Unlocked, type VaultState } from './context.ts';
import { grantFromApi, groupBase32, keyBody, keyRecordFromMe } from './api-shapes.ts';
import { createLoginRequest, parseLoginRedirect } from '../../client/discord-login.ts';
import { toBase64Url, wipe } from '../../crypto/bytes.ts';
import { CryptoError } from '../../crypto/errors.ts';
import { createGrant, openGrant, openGrantForQuickUnlock } from '../../crypto/grant.ts';
import { openQuickUnlock, sealQuickUnlock, type QuickUnlockRecord } from '../../crypto/quick-unlock.ts';
import { createAdminKey, createMemberKey, unlockAdminKey, unlockMemberKey, type AdminKeyRecord, type MemberKeyRecord } from '../../crypto/member-key.ts';
import { pinPublicKey } from '../../crypto/public-key.ts';
import { assertSignerPinned, pinSigner, type SignerPin } from '../../crypto/signer.ts';
import { generateVaultKeyRaw, importVaultKeyAndWipe } from '../../crypto/vault-key.ts';

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
  const { chrome, apiOrigin, sessions, api, state, lock, checkIdle, stillCurrent, readySession, trustFor, expect, getMe } = ctx;

  // 自分宛てのグラントを、固定した管理者の鍵で確かめてから開く。開けない理由は状態として返す
  async function openVault(): Promise<VaultState> {
    const u = state.unlocked!;
    const trust = trustFor(u.memberId);
    if (u.role === 'admin' && u.signPublicKey) {
      const own: SignerPin = { memberId: u.memberId, keyId: u.keyId, publicKey: u.signPublicKey };
      if ((await trust.signerPins.get()) !== undefined) {
        try {
          await assertSignerPinned(trust, own);
        } catch {
          return 'grant-rejected';
        }
      }
    }
    const res = await api.call('GET', '/v1/vault');
    if (res.status === 403) return 'awaiting-approval'; // 承認待ち
    const body = expect(res, 200);
    if (body.grant === null || typeof body.grant !== 'object') return u.role === 'admin' ? 'needs-init' : 'awaiting-approval';
    try {
      state.vaultKey = await openGrant(
        { memberId: u.memberId, keyId: u.keyId, publicKey: u.publicKey, privateKey: u.privateKey },
        trust,
        grantFromApi(body.grant as Record<string, unknown>),
        Number(body.current_vault_key_version),
      );
      state.vaultVersion = Number(body.current_vault_key_version);
      return 'ready';
    } catch (e) {
      if (e instanceof CryptoError && e.code === 'SIGNER_NOT_PINNED') return u.role === 'admin' ? 'needs-generation-init' : 'awaiting-approval';
      return 'grant-rejected';
    }
  }

  async function afterUnlock(next: Unlocked, epoch: number): Promise<Reply> {
    if (!(await stillCurrent(epoch))) throw new Fail('LOCKED');
    state.unlocked = next;
    state.vaultKey = null;
    let opened: VaultState;
    try {
      opened = await openVault();
    } catch (e) {
      // 開けなかった（通信できない、ログアウトされた）なら、鍵を残さない
      const interrupted = epoch !== state.lockEpoch;
      await lock();
      throw interrupted ? new Fail('LOCKED') : e;
    }
    if (!(await stillCurrent(epoch))) {
      await lock();
      throw new Fail('LOCKED');
    }
    state.vaultState = opened;
    state.unlockedBy = 'password';
    return { ok: true, vault: state.vaultState };
  }

  // ---- クイックロック解除（2b、仕様書 A-5） ----

  function quickKey(memberId: string): string {
    return `${UNLOCK_KEY_PREFIX}${apiOrigin}|${memberId}`;
  }


  function parseQuick(v: unknown): (QuickUnlockRecord & { failures: number }) | null {
    const r = v as Partial<QuickUnlockRecord & { failures: number }> | undefined;
    if (!r || typeof r.salt !== 'string' || typeof r.wrapped !== 'string' || typeof r.iterations !== 'number' || typeof r.vaultKeyVersion !== 'number' || typeof r.failures !== 'number') return null;
    return { salt: r.salt, wrapped: r.wrapped, iterations: r.iterations, vaultKeyVersion: r.vaultKeyVersion, failures: r.failures };
  }

  // 順番に1つずつ行う（読む → 比べる → 書く の間に、別の試行が割り込まない）
  function serialized<T>(fn: () => Promise<T>): Promise<T> {
    const run = state.quickChain.then(fn);
    state.quickChain = run.catch(() => undefined);
    return run;
  }

  // 試す前に、失敗の回数を1つ増やして書く。すでに5回なら保存を消して null
  function reserveAttempt(memberId: string): Promise<(QuickUnlockRecord & { failures: number }) | null> {
    return serialized(async () => {
      const key = quickKey(memberId);
      const rec = parseQuick((await chrome.storage.session.get(key))[key]);
      if (!rec) return null;
      if (rec.failures >= QUICK_UNLOCK_MAX_FAILURES) {
        await chrome.storage.session.remove(key);
        return null;
      }
      const next = { ...rec, failures: rec.failures + 1 };
      await chrome.storage.session.set({ [key]: next });
      return next;
    });
  }

  const items = createItemSync(ctx, openVault);

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

    async createKey(m) {
      if (state.unlockedBy === 'passcode') throw new Fail('PASSWORD_REQUIRED'); // E-17
      const epoch = state.lockEpoch;
      await readySession();
      const me = await getMe();
      if (me.key !== null && m.replace !== true) throw new Fail('KEY_EXISTS');
      const password = String(m.masterPassword);
      const put = (record: MemberKeyRecord | AdminKeyRecord) =>
        api.call('PUT', '/v1/me/keys', keyBody(record)).then((res) => expect(res, 204, { 400: 'BAD_REQUEST', 403: 'STEP_UP_REQUIRED', 409: 'CONFLICT' }));
      if (me.role === 'admin') {
        const created = await createAdminKey(password);
        await put(created.record);
        const r = created.record;
        return afterUnlock({ memberId: me.id, role: me.role, keyId: r.keyId, publicKey: r.publicKey, privateKey: created.privateKey, signPublicKey: r.signPublicKey, signPrivateKey: created.signPrivateKey }, epoch);
      }
      const created = await createMemberKey(password);
      await put(created.record);
      return afterUnlock({ memberId: me.id, role: me.role, keyId: created.record.keyId, publicKey: created.record.publicKey, privateKey: created.privateKey }, epoch);
    },

    async unlock(m) {
      const epoch = state.lockEpoch;
      await readySession();
      const me = await getMe();
      if (me.key === null) throw new Fail('NO_KEY');
      const record = keyRecordFromMe(me.key);
      try {
        if ('signPublicKey' in record) {
          const keys = await unlockAdminKey(String(m.masterPassword), record);
          return await afterUnlock({ memberId: me.id, role: me.role, keyId: record.keyId, publicKey: record.publicKey, privateKey: keys.privateKey, signPublicKey: record.signPublicKey, signPrivateKey: keys.signPrivateKey }, epoch);
        }
        const privateKey = await unlockMemberKey(String(m.masterPassword), record);
        return await afterUnlock({ memberId: me.id, role: me.role, keyId: record.keyId, publicKey: record.publicKey, privateKey }, epoch);
      } catch (e) {
        if (e instanceof CryptoError) throw new Fail(e.code === 'DECRYPT_FAILED' ? 'BAD_PASSWORD' : 'KEY_REJECTED');
        throw e;
      }
    },

    async lock() {
      await lock();
      return { ok: true };
    },

    async opened() {
      return { ok: true };
    },

    // 最初の Vault（仕様書「初期化（管理者）」）：Vault 鍵（世代1）を作り、自分宛てに包んで署名し、送る。
    // 自分の署名鍵を固定し、最後に見た世代を1にしてから作る（暗号コアは、固定と世代がそろうまでグラントを作らない）
    async initVault() {
      await readySession();
      if (state.unlockedBy === 'passcode') throw new Fail('PASSWORD_REQUIRED'); // E-17
      if (state.unlocked === null) throw new Fail('LOCKED');
      const u = state.unlocked;
      if (u.role !== 'admin' || !u.signPublicKey || !u.signPrivateKey) throw new Fail('NOT_ADMIN');
      if (state.vaultState !== 'needs-init') throw new Fail('VAULT_EXISTS');
      const epoch = state.lockEpoch;
      const trust = trustFor(u.memberId);
      const own: SignerPin = { memberId: u.memberId, keyId: u.keyId, publicKey: u.signPublicKey };
      if ((await trust.signerPins.get()) === undefined) await pinSigner(trust, own, 1);
      else await assertSignerPinned(trust, own);
      const pins = chromePinStore(chrome.storage.local, apiOrigin, u.memberId);
      await pinPublicKey(pins, u.memberId, { keyId: u.keyId, publicKey: u.publicKey });
      const raw = generateVaultKeyRaw();
      try {
        const grant = await createGrant({
          pins,
          signer: { memberId: u.memberId, keyId: u.keyId, privateKey: u.signPrivateKey, trust },
          memberId: u.memberId,
          recipient: { keyId: u.keyId, publicKey: u.publicKey },
          vaultKeyVersion: 1,
          vaultKeyRaw: raw,
        });
        expect(
          await api.call('POST', '/v1/vault/init', {
            vault_key_version: grant.vaultKeyVersion,
            recipient_key_id: grant.recipientKeyId,
            ephemeral_public_key: toBase64Url(grant.ephemeralPublicKey),
            wrapped_key: toBase64Url(grant.wrappedKey),
            signer_key_id: grant.signerKeyId,
            signature: toBase64Url(grant.signature),
            format_version: grant.formatVersion,
          }),
          201,
          { 403: 'STEP_UP_REQUIRED', 409: 'CONFLICT' },
        );
        const key = await importVaultKeyAndWipe(raw);
        if (!(await stillCurrent(epoch))) throw new Fail('LOCKED'); // 送っている間にロックされた
        state.vaultKey = key;
        state.vaultVersion = 1;
        state.vaultState = 'ready';
        return { ok: true, vault: state.vaultState };
      } finally {
        wipe(raw);
      }
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

    // パスコードの設定：マスターパスワードで解除した後だけ。グラントを取り出し可として開き直し、包んだらすぐ消す
    async setupQuickUnlock(m) {
      await readySession();
      if (state.unlockedBy === 'passcode') throw new Fail('PASSWORD_REQUIRED'); // E-17
      if (state.unlocked === null) throw new Fail('LOCKED');
      if (state.vaultState !== 'ready') throw new Fail('VAULT_NOT_READY');
      const u = state.unlocked;
      const epoch = state.lockEpoch;
      const body = expect(await api.call('GET', '/v1/vault'), 200);
      if (body.grant === null || typeof body.grant !== 'object') throw new Fail('VAULT_NOT_READY');
      const current = Number(body.current_vault_key_version);
      const raw = await openGrantForQuickUnlock(
        { memberId: u.memberId, keyId: u.keyId, publicKey: u.publicKey, privateKey: u.privateKey },
        trustFor(u.memberId),
        grantFromApi(body.grant as Record<string, unknown>),
        current,
      );
      let record: QuickUnlockRecord;
      try {
        record = await sealQuickUnlock(String(m.passcode), raw, { apiOrigin, memberId: u.memberId, vaultKeyVersion: current });
      } finally {
        wipe(raw);
      }
      if (!(await stillCurrent(epoch))) throw new Fail('LOCKED');
      await serialized(() => chrome.storage.session.set({ [quickKey(u.memberId)]: { ...record, failures: 0 } }));
      return { ok: true };
    },

    // パスコードで戻る（E-14）。試す前に回数を増やして書き、5回目の失敗で保存を消す（E-15）
    async quickUnlock(m) {
      const s = await sessions.get();
      if (!s) throw new Fail('NOT_LOGGED_IN');
      const epoch = state.lockEpoch;
      const rec = await reserveAttempt(s.memberId);
      if (rec === null) throw new Fail('NO_QUICK_UNLOCK');
      let key: CryptoKey;
      try {
        key = await openQuickUnlock(String(m.passcode), rec, { apiOrigin, memberId: s.memberId });
      } catch (e) {
        if (!(e instanceof CryptoError) || e.code !== 'DECRYPT_FAILED') throw e;
        if (rec.failures >= QUICK_UNLOCK_MAX_FAILURES) {
          await serialized(() => chrome.storage.session.remove(quickKey(s.memberId)));
          throw new Fail('QUICK_UNLOCK_CLEARED');
        }
        throw new Fail('BAD_PASSCODE');
      }
      if (!(await stillCurrent(epoch))) throw new Fail('LOCKED');
      await serialized(async () => {
        const k = quickKey(s.memberId);
        const now = parseQuick((await chrome.storage.session.get(k))[k]);
        if (now) await chrome.storage.session.set({ [k]: { ...now, failures: 0 } });
      });
      state.unlocked = null; // 秘密鍵は戻さない
      state.vaultKey = key;
      state.vaultVersion = rec.vaultKeyVersion;
      state.vaultState = 'ready';
      state.unlockedBy = 'passcode';
      return { ok: true, vault: state.vaultState };
    },

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
