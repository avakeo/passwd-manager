// 拡張機能の Service Worker の中身（chrome の API は引数で受け取る。テストは偽物を渡す）。
// 仕様書「拡張機能と自動入力の方針 > ロックと鍵の置き場所」。
//   - 秘密鍵・署名用秘密鍵・Vault 鍵は、この中の変数（メモリ）だけに、取り出し不可で置く。画面には渡さない
//   - トークンは chrome.storage.session（storage.ts）。応答には入れない
//   - 放置のロックは15分。Service Worker が起きたとき（onStartup）と、メッセージを受け取るたびに、処理の前に確かめる
//   - メッセージは messages.ts の検査を通ったものだけを処理する（E-08）

import type { ChromeLike, MessageSender } from './chrome-like.ts';
import { acceptedSender, parseMessage, type Message } from './messages.ts';
import { ApiClient, ApiError, type ApiResult } from './api-client.ts';
import { SessionStore, chromePinStore, chromeTrustStorage, type SessionRecord } from './storage.ts';
import { createLoginRequest, parseLoginRedirect } from '../../client/discord-login.ts';
import { fromBase64Url, toBase64Url, wipe, type Bytes } from '../../crypto/bytes.ts';
import { CryptoError } from '../../crypto/errors.ts';
import { createGrant, openGrant, type Grant } from '../../crypto/grant.ts';
import type { KdfParams } from '../../crypto/kdf.ts';
import { createAdminKey, createMemberKey, unlockAdminKey, unlockMemberKey, type AdminKeyRecord, type MemberKeyRecord } from '../../crypto/member-key.ts';
import { pinPublicKey } from '../../crypto/public-key.ts';
import { assertSignerPinned, openTrust, pinSigner, type GrantTrust, type SignerPin } from '../../crypto/signer.ts';
import { generateVaultKeyRaw, importVaultKeyAndWipe } from '../../crypto/vault-key.ts';

export const IDLE_LOCK_MS = 15 * 60 * 1000;
const LAST_ACTIVITY_KEY = 'teampw/v1/last-activity';
// ロックで消す、ロック解除のための保存（2b のクイックロック解除が使う）
export const UNLOCK_KEY_PREFIX = 'teampw/v1/unlock|';

export type VaultState = 'locked' | 'no-key' | 'ready' | 'needs-init' | 'awaiting-approval' | 'needs-generation-init' | 'grant-rejected';

export type Background = {
  handleMessage(message: unknown, sender: MessageSender): Promise<Reply>;
  onStartup(): Promise<void>;
  // テスト用：メモリに鍵が残っているか（メッセージからは呼べない。中身は返さない）
  memoryState(): { unlocked: boolean; vaultKey: boolean };
};

type Reply = { ok: true } & Record<string, unknown> | { ok: false; error: string };

export type BackgroundDeps = {
  chrome: ChromeLike;
  apiOrigin: string;
  discordClientId: string;
  fetch: (input: string, init: RequestInit) => Promise<Response>;
};

// ロック解除した鍵（取り出し不可）。秘密鍵は、マスターパスワードで解除したときだけ持つ
type Unlocked = {
  memberId: string;
  role: 'admin' | 'member';
  keyId: string;
  publicKey: Bytes;
  privateKey: CryptoKey;
  signPublicKey?: Bytes;
  signPrivateKey?: CryptoKey;
};

type MeKey = Record<string, string | number | null>;

class Fail extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

function groupBase32(s: string): string {
  return s.replace(/(.{4})(?=.)/g, '$1 ');
}

function keyRecordFromMe(key: MeKey): MemberKeyRecord | AdminKeyRecord {
  const params = JSON.parse(String(key.kdf_params)) as { iterations: number; normalization: KdfParams['normalization'] };
  const base: MemberKeyRecord = {
    keyId: String(key.id),
    publicKey: fromBase64Url(String(key.ecdh_public_key)),
    encryptedPrivateKey: fromBase64Url(String(key.encrypted_private_key)),
    kdf: { algorithm: String(key.kdf_algorithm) as KdfParams['algorithm'], iterations: params.iterations, normalization: params.normalization, salt: fromBase64Url(String(key.kdf_salt)) },
  };
  if (typeof key.ecdsa_public_key !== 'string' || typeof key.encrypted_sign_private_key !== 'string') return base;
  return { ...base, signPublicKey: fromBase64Url(key.ecdsa_public_key), encryptedSignPrivateKey: fromBase64Url(key.encrypted_sign_private_key) };
}

function keyBody(record: MemberKeyRecord | AdminKeyRecord): Record<string, unknown> {
  const body: Record<string, unknown> = {
    id: record.keyId,
    ecdh_public_key: toBase64Url(record.publicKey),
    encrypted_private_key: toBase64Url(record.encryptedPrivateKey),
    kdf_algorithm: record.kdf.algorithm,
    kdf_params: JSON.stringify({ iterations: record.kdf.iterations, normalization: record.kdf.normalization }),
    kdf_salt: toBase64Url(record.kdf.salt),
    format_version: 1,
  };
  if ('signPublicKey' in record) {
    body.ecdsa_public_key = toBase64Url(record.signPublicKey);
    body.encrypted_sign_private_key = toBase64Url(record.encryptedSignPrivateKey);
  }
  return body;
}

function grantFromApi(g: Record<string, unknown>): Grant {
  return {
    vaultKeyVersion: Number(g.vault_key_version),
    recipientKeyId: String(g.recipient_key_id),
    ephemeralPublicKey: fromBase64Url(String(g.ephemeral_public_key)),
    wrappedKey: fromBase64Url(String(g.wrapped_key)),
    signerKeyId: String(g.signer_key_id),
    signature: fromBase64Url(String(g.signature)),
    formatVersion: Number(g.format_version),
  };
}

export function createBackground(deps: BackgroundDeps): Background {
  const { chrome, apiOrigin } = deps;
  const sessions = new SessionStore(chrome.storage.session);
  const api = new ApiClient(apiOrigin, deps.fetch, sessions);
  const trustStorage = chromeTrustStorage(chrome.storage.local);

  // メモリだけに置くもの
  let unlocked: Unlocked | null = null;
  let vaultKey: CryptoKey | null = null;
  let vaultState: VaultState = 'locked';
  let challenge: { token: string } | null = null; // ログインの途中の一時トークン（TOTP のコードを送るまで）
  // ロックとログアウトのたびに進める番号。時間のかかる処理（鍵の導出、通信）は、終わった時点で番号が変わっていたら、
  // 鍵を捨てて何もしない（Codex #3）
  let lockEpoch = 0;

  async function lock(): Promise<void> {
    lockEpoch += 1;
    unlocked = null;
    vaultKey = null;
    vaultState = 'locked';
    const all = await chrome.storage.session.get(null);
    const keys = Object.keys(all).filter((k) => k.startsWith(UNLOCK_KEY_PREFIX));
    if (keys.length > 0) await chrome.storage.session.remove(keys);
  }

  async function checkIdle(): Promise<void> {
    const last = (await chrome.storage.session.get(LAST_ACTIVITY_KEY))[LAST_ACTIVITY_KEY];
    if (typeof last === 'number' && Date.now() - last > IDLE_LOCK_MS) await lock();
  }

  // 処理を始めたときから、ロックもログアウトも放置の時間切れもないか。終わった時点で確かめる
  async function stillCurrent(epoch: number): Promise<boolean> {
    await checkIdle();
    return epoch === lockEpoch;
  }

  async function readySession(): Promise<SessionRecord> {
    const s = await sessions.get();
    if (!s) throw new Fail('NOT_LOGGED_IN');
    if (s.totpSetupRequired) throw new Fail('TOTP_SETUP_REQUIRED');
    return s;
  }

  function trustFor(memberId: string): GrantTrust {
    return openTrust(trustStorage, { apiOrigin, memberId });
  }

  function expect(res: ApiResult, ok: number, errors: Record<number, string> = {}): Record<string, unknown> {
    if (res.status === ok) return res.body;
    throw new Fail(errors[res.status] ?? (res.status === 429 ? 'RATE_LIMITED' : res.status >= 500 ? 'SERVER' : 'SERVER'));
  }

  // GET /v1/me の id は、ログインの応答で受け取ったメンバー ID と同じでなければならない。違えば止める
  // （食い違った id で鍵を作ったり、別のメンバーの組に固定と世代を書いたりしない：Codex #4）
  async function getMe(): Promise<{ id: string; role: 'admin' | 'member'; key: MeKey | null; recoveryCodesRemaining: number }> {
    const session = await sessions.get();
    const body = expect(await api.call('GET', '/v1/me'), 200, { 409: 'ADMIN_NOT_READY', 403: 'FORBIDDEN' });
    if (!session || body.id !== session.memberId) throw new Fail('MEMBER_MISMATCH');
    return {
      id: String(body.id),
      role: body.role === 'admin' ? 'admin' : 'member',
      key: (body.key as MeKey | null) ?? null,
      recoveryCodesRemaining: Number(body.recovery_codes_remaining ?? 0),
    };
  }

  // 自分宛てのグラントを、固定した管理者の鍵で確かめてから開く。開けない理由は状態として返す
  async function openVault(): Promise<VaultState> {
    const u = unlocked!;
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
      vaultKey = await openGrant(
        { memberId: u.memberId, keyId: u.keyId, publicKey: u.publicKey, privateKey: u.privateKey },
        trust,
        grantFromApi(body.grant as Record<string, unknown>),
        Number(body.current_vault_key_version),
      );
      return 'ready';
    } catch (e) {
      if (e instanceof CryptoError && e.code === 'SIGNER_NOT_PINNED') return u.role === 'admin' ? 'needs-generation-init' : 'awaiting-approval';
      return 'grant-rejected';
    }
  }

  async function afterUnlock(next: Unlocked, epoch: number): Promise<Reply> {
    if (!(await stillCurrent(epoch))) throw new Fail('LOCKED');
    unlocked = next;
    vaultKey = null;
    let state: VaultState;
    try {
      state = await openVault();
    } catch (e) {
      // 開けなかった（通信できない、ログアウトされた）なら、鍵を残さない
      const interrupted = epoch !== lockEpoch;
      await lock();
      throw interrupted ? new Fail('LOCKED') : e;
    }
    if (!(await stillCurrent(epoch))) {
      await lock();
      throw new Fail('LOCKED');
    }
    vaultState = state;
    return { ok: true, vault: vaultState };
  }

  const handlers: Record<Message['type'], (m: Message) => Promise<Reply>> = {
    async status() {
      const s = await sessions.get();
      const base = { ok: true as const, locked: unlocked === null, vault: unlocked === null ? 'locked' : vaultState, loginInProgress: challenge !== null };
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
      challenge = null;
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
        challenge = { token: String(body.challenge_token) };
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
      if (!challenge) throw new Fail('NO_LOGIN_IN_PROGRESS');
      const payload = 'code' in m ? { challenge_token: challenge.token, code: m.code } : { challenge_token: challenge.token, recovery_code: m.recoveryCode };
      const body = expect(await api.publicCall('POST', '/v1/auth/totp', payload), 200, { 401: 'BAD_CODE', 403: 'NOT_ALLOWED' });
      challenge = null;
      const member = body.member as { id: string; role: 'admin' | 'member' };
      await sessions.set({ accessToken: String(body.access_token), refreshToken: String(body.refresh_token), memberId: member.id, role: member.role, totpSetupRequired: false });
      return { ok: true, status: 'ok', recoveryCodesRemaining: Number(body.recovery_codes_remaining ?? 0) };
    },

    async logout() {
      // 先に手元を消す（更新の途中でも、遅れて終わった更新は書き戻さない）
      const s = await sessions.get();
      await sessions.clear();
      challenge = null;
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
      const epoch = lockEpoch;
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
      const epoch = lockEpoch;
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

    // 最初の Vault（仕様書「初期化（管理者）」）：Vault 鍵（世代1）を作り、自分宛てに包んで署名し、送る。
    // 自分の署名鍵を固定し、最後に見た世代を1にしてから作る（暗号コアは、固定と世代がそろうまでグラントを作らない）
    async initVault() {
      await readySession();
      if (unlocked === null) throw new Fail('LOCKED');
      const u = unlocked;
      if (u.role !== 'admin' || !u.signPublicKey || !u.signPrivateKey) throw new Fail('NOT_ADMIN');
      if (vaultState !== 'needs-init') throw new Fail('VAULT_EXISTS');
      const epoch = lockEpoch;
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
        vaultKey = key;
        vaultState = 'ready';
        return { ok: true, vault: vaultState };
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
  };

  return {
    memoryState() {
      return { unlocked: unlocked !== null, vaultKey: vaultKey !== null };
    },

    async onStartup() {
      await checkIdle();
    },

    async handleMessage(raw, sender) {
      if (!acceptedSender(chrome.runtime, sender)) return { ok: false, error: 'BAD_REQUEST' };
      const message = parseMessage(raw);
      if (message === null) return { ok: false, error: 'BAD_REQUEST' };
      // 放置のロックは、どの指示も処理する前に確かめる
      await checkIdle();
      await chrome.storage.session.set({ [LAST_ACTIVITY_KEY]: Date.now() });
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
