// 拡張機能の Service Worker の中身（chrome の API は引数で受け取る。テストは偽物を渡す）。
// 仕様書「拡張機能と自動入力の方針 > ロックと鍵の置き場所」。
//   - 秘密鍵・署名用秘密鍵・Vault 鍵は、この中の変数（メモリ）だけに、取り出し不可で置く。画面には渡さない
//   - トークンは chrome.storage.session（storage.ts）。応答には入れない
//   - 放置のロックは15分。Service Worker が起きたとき（onStartup）と、メッセージを受け取るたびに、処理の前に確かめる
//   - メッセージは messages.ts の検査を通ったものだけを処理する（E-08）
//   - アイテム（2b）：保存の前と復号の後に validateItem を通す。storage.local には暗号文だけをキャッシュし、平文の一覧はメモリだけ
//   - クイックロック解除（2b）：Vault 鍵だけを、パスコード由来の鍵で包んで storage.session に置く。戻った状態は秘密鍵を持たない

import type { ChromeLike, MessageSender } from './chrome-like.ts';
import { PASSIVE_TYPES, acceptedSender, parseMessage, type Message } from './messages.ts';
import { ApiClient, ApiError, type ApiResult } from './api-client.ts';
import { SessionStore, chromePinStore, chromeTrustStorage, type SessionRecord } from './storage.ts';
import { createLoginRequest, parseLoginRedirect } from '../../client/discord-login.ts';
import { fromBase64Url, toBase64Url, wipe, type Bytes } from '../../crypto/bytes.ts';
import { CryptoError } from '../../crypto/errors.ts';
import { createGrant, openGrant, openGrantForQuickUnlock, type Grant } from '../../crypto/grant.ts';
import { decryptItem, encryptItem, type ItemContent } from '../../crypto/item.ts';
import { openQuickUnlock, sealQuickUnlock, type QuickUnlockRecord } from '../../crypto/quick-unlock.ts';
import { newId } from '../../crypto/random.ts';
import { validateItem, type ClientItem } from '../../client/item-data.ts';
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

type Reply = ({ ok: true } & Record<string, unknown>) | ({ ok: false; error: string } & Record<string, unknown>);

export const QUICK_UNLOCK_MAX_FAILURES = 5;

// 一覧に出す分だけ（パスワード、メモ、カスタム項目は入れない）
type Summary = { id: string; type: 'login' | 'note' | null; title: string; username?: string; urls?: string[]; unreadable: boolean; revision: number };
type CacheEntry = { revision: number; vaultKeyVersion: number; ciphertext: string };
type CacheRecord = { cursor: number; lastVaultRevision: number; items: Record<string, CacheEntry> };

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
  // どの方法で解除したか。パスコードで戻った状態は Vault 鍵だけで、秘密鍵（unlocked）は持たない（E-17）
  let unlockedBy: 'password' | 'passcode' | null = null;
  let vaultVersion: number | null = null; // 開いた Vault 鍵の世代
  // 同期の状態（メモリ）。暗号文は storage.local にもキャッシュする。平文の一覧（summary）はメモリだけ
  const index = new Map<string, CacheEntry & { summary: Summary }>();
  let cacheLoadedFor: string | null = null;
  let cursor = 0;
  let lastVaultRevision = 0;
  let cacheFull = false;
  // クイックロック解除の「試す前に回数を増やして書く」を、1つずつ順に行う（同時に送られても5回を超えない）
  let quickChain: Promise<unknown> = Promise.resolve();

  async function lock(): Promise<void> {
    lockEpoch += 1;
    challenge = null; // ログインの途中の一時トークンも消す（DeepSeek #5）
    unlocked = null;
    vaultKey = null;
    vaultState = 'locked';
    unlockedBy = null;
    vaultVersion = null;
    index.clear();
    cacheLoadedFor = null;
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

  // 待たずに確かめる版。確かめてから書くまでの間に await を挟まない所で使う（2b Codex #2）
  function alive(epoch: number): void {
    if (epoch !== lockEpoch) throw new Fail('LOCKED');
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
      vaultVersion = Number(body.current_vault_key_version);
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
    unlockedBy = 'password';
    return { ok: true, vault: vaultState };
  }

  // ---- アイテムと同期（2b） ----

  function syncKey(memberId: string): string {
    return `teampw/v1/sync|${apiOrigin}|${memberId}`;
  }

  function quickKey(memberId: string): string {
    return `${UNLOCK_KEY_PREFIX}${apiOrigin}|${memberId}`;
  }

  async function vaultMember(): Promise<string> {
    if (vaultKey === null || vaultVersion === null) throw new Fail('LOCKED');
    const s = await readySession();
    return s.memberId;
  }

  // 1件の暗号文を開いて、一覧に出す分だけを作る。開けない・形が合わないものは「読めないアイテム」
  async function summarize(id: string, e: CacheEntry): Promise<Summary> {
    const unreadable: Summary = { id, type: null, title: '', unreadable: true, revision: e.revision };
    const item = await openEntry(id, e).catch(() => null);
    if (item === null) return unreadable;
    return item.type === 'login'
      ? { id, type: 'login', title: item.title, username: item.username, urls: [...item.urls], unreadable: false, revision: e.revision }
      : { id, type: 'note', title: item.title, unreadable: false, revision: e.revision };
  }

  async function openEntry(id: string, e: CacheEntry): Promise<ClientItem> {
    if (vaultKey === null || e.vaultKeyVersion !== vaultVersion) throw new Fail('UNREADABLE');
    const content = await decryptItem(vaultKey, { itemId: id, vaultKeyVersion: e.vaultKeyVersion }, fromBase64Url(e.ciphertext));
    return validateItem(content); // 復号した後も、形を確かめる（I-02）
  }

  // 復号している間にロックされたら、一覧（平文）を書き戻さない（2b Codex #2）
  async function loadCache(memberId: string): Promise<void> {
    if (cacheLoadedFor === memberId) return;
    const epoch = lockEpoch;
    const saved = (await chrome.storage.local.get(syncKey(memberId)))[syncKey(memberId)] as CacheRecord | undefined;
    const loaded = new Map<string, CacheEntry & { summary: Summary }>();
    for (const [id, e] of Object.entries(saved?.items ?? {})) loaded.set(id, { ...e, summary: await summarize(id, e) });
    alive(epoch);
    index.clear();
    for (const [id, e] of loaded) index.set(id, e);
    cursor = typeof saved?.cursor === 'number' ? saved.cursor : 0;
    lastVaultRevision = typeof saved?.lastVaultRevision === 'number' ? saved.lastVaultRevision : 0;
    cacheLoadedFor = memberId;
  }

  // 暗号文だけを書く。容量を超えたら、キャッシュをやめてメモリだけで続ける（判断待ち 2b-4）
  async function saveCache(memberId: string): Promise<void> {
    const items: Record<string, CacheEntry> = {};
    for (const [id, e] of index) items[id] = { revision: e.revision, vaultKeyVersion: e.vaultKeyVersion, ciphertext: e.ciphertext };
    try {
      await chrome.storage.local.set({ [syncKey(memberId)]: { cursor, lastVaultRevision, items } satisfies CacheRecord });
      cacheFull = false;
    } catch {
      cacheFull = true;
      // 暗号文を置けなくても、最後に見た Vault リビジョンは残す（S-09）。カーソルは0にして、起動し直したら全件を取り直す
      await chrome.storage.local.set({ [syncKey(memberId)]: { cursor: 0, lastVaultRevision, items: {} } satisfies CacheRecord }).catch(() => undefined);
    }
  }

  // 復号の後、ロックされていないことと、手元にもっと新しい版がないことを確かめてから置く。
  // 重なった同期の遅れた応答で、新しい版を古い版に戻さない（2b Codex #3、DeepSeek #2）
  async function putEntry(id: string, e: CacheEntry, epoch: number): Promise<void> {
    const summary = await summarize(id, e);
    alive(epoch);
    const now = index.get(id);
    if (now && now.revision > e.revision) return;
    index.set(id, { ...e, summary });
  }

  // 差分同期（10.3）。巻き戻し（S-09）なら何も書き換えずに止める。削除は暗号文ごと消す（S-02・S-10）
  async function sync(): Promise<number> {
    const memberId = await vaultMember();
    const epoch = lockEpoch;
    await loadCache(memberId);
    const body = expect(await api.call('GET', `/v1/items?after=${cursor}`), 200);
    if (!(await stillCurrent(epoch))) throw new Fail('LOCKED');
    const revision = Number(body.vault_revision);
    if (!Number.isSafeInteger(revision) || revision < lastVaultRevision) throw new Fail('ROLLBACK_DETECTED');
    const items = Array.isArray(body.items) ? (body.items as Record<string, unknown>[]) : [];
    // 新しい世代（ローテーションの後）のアイテムが来た
    if (items.some((i) => i.deleted !== true && Number(i.vault_key_version) > vaultVersion!)) {
      if (unlockedBy !== 'password') {
        // パスコードで戻った状態は秘密鍵を持たないので、新しい世代のグラントを開けない。マスターパスワードを求める（E-17）
        await lock();
        throw new Fail('PASSWORD_REQUIRED');
      }
      // 開き直している間にロックされたら、openVault が書き戻した鍵を残さない（afterUnlock と同じ確かめ方：Codex #3）
      let opened: VaultState;
      try {
        opened = await openVault();
      } catch (e) {
        if (epoch === lockEpoch) throw e;
        await lock();
        throw new Fail('LOCKED');
      }
      if (!(await stillCurrent(epoch))) {
        await lock();
        throw new Fail('LOCKED');
      }
      vaultState = opened;
      if (vaultState !== 'ready') {
        // 開けなかった（grant-rejected など）なら、前の世代の鍵と一覧も捨てる。状態は afterUnlock で開けなかったときと同じ
        vaultKey = null;
        vaultVersion = null;
        index.clear();
        cacheLoadedFor = null;
        throw new Fail('VAULT_NOT_READY');
      }
    }
    let maxSeq = 0;
    for (const i of items) {
      const id = String(i.id);
      if (i.deleted === true || typeof i.ciphertext !== 'string') {
        alive(epoch);
        const now = index.get(id);
        if (!now || now.revision <= Number(i.revision)) index.delete(id);
      } else await putEntry(id, { revision: Number(i.revision), vaultKeyVersion: Number(i.vault_key_version), ciphertext: i.ciphertext }, epoch);
      maxSeq = Math.max(maxSeq, Number(i.change_seq) || 0);
    }
    alive(epoch);
    // 重なった同期が先に進めていても、下げない（S-09。最後に見た値を下げる口は作らない）
    cursor = Math.max(cursor, maxSeq);
    lastVaultRevision = Math.max(lastVaultRevision, revision);
    await saveCache(memberId);
    return items.length;
  }

  // 409 のとき：同期してから、今の版を返す（自動で送り直さない：判断待ち 2b-5）
  // サーバーの今の鍵の世代が、開いている世代と違うか（作成と更新の 409 の原因を分ける：10.2）
  async function generationChanged(epoch: number): Promise<boolean> {
    const body = expect(await api.call('GET', '/v1/vault'), 200, { 403: 'FORBIDDEN' });
    if (!(await stillCurrent(epoch))) throw new Fail('LOCKED');
    return Number(body.current_vault_key_version) !== vaultVersion;
  }

  async function conflictReply(id: string): Promise<Reply> {
    await sync();
    const e = index.get(id);
    if (!e) return { ok: false, error: 'DELETED' };
    const current = await openEntry(id, e).catch(() => null);
    return { ok: false, error: 'CONFLICT', current, currentRevision: e.revision };
  }

  async function encryptFor(id: string, item: ClientItem): Promise<string> {
    return toBase64Url(await encryptItem(vaultKey!, { itemId: id, vaultKeyVersion: vaultVersion! }, item as unknown as ItemContent));
  }

  // ---- クイックロック解除（2b、仕様書 A-5） ----

  function parseQuick(v: unknown): (QuickUnlockRecord & { failures: number }) | null {
    const r = v as Partial<QuickUnlockRecord & { failures: number }> | undefined;
    if (!r || typeof r.salt !== 'string' || typeof r.wrapped !== 'string' || typeof r.iterations !== 'number' || typeof r.vaultKeyVersion !== 'number' || typeof r.failures !== 'number') return null;
    return { salt: r.salt, wrapped: r.wrapped, iterations: r.iterations, vaultKeyVersion: r.vaultKeyVersion, failures: r.failures };
  }

  // 順番に1つずつ行う（読む → 比べる → 書く の間に、別の試行が割り込まない）
  function serialized<T>(fn: () => Promise<T>): Promise<T> {
    const run = quickChain.then(fn);
    quickChain = run.catch(() => undefined);
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

  const handlers: Record<Message['type'], (m: Message) => Promise<Reply>> = {
    async status() {
      const s = await sessions.get();
      const quick = s ? parseQuick((await chrome.storage.session.get(quickKey(s.memberId)))[quickKey(s.memberId)]) : null;
      const base = {
        ok: true as const,
        locked: unlockedBy === null,
        unlockedBy,
        vault: unlockedBy === null ? 'locked' : vaultState,
        loginInProgress: challenge !== null,
        quickUnlockAvailable: quick !== null && quick.failures < QUICK_UNLOCK_MAX_FAILURES,
        cacheFull,
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
      if (unlockedBy === 'passcode') throw new Fail('PASSWORD_REQUIRED'); // E-17
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

    async opened() {
      return { ok: true };
    },

    // 最初の Vault（仕様書「初期化（管理者）」）：Vault 鍵（世代1）を作り、自分宛てに包んで署名し、送る。
    // 自分の署名鍵を固定し、最後に見た世代を1にしてから作る（暗号コアは、固定と世代がそろうまでグラントを作らない）
    async initVault() {
      await readySession();
      if (unlockedBy === 'passcode') throw new Fail('PASSWORD_REQUIRED'); // E-17
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
        vaultVersion = 1;
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

    // パスコードの設定：マスターパスワードで解除した後だけ。グラントを取り出し可として開き直し、包んだらすぐ消す
    async setupQuickUnlock(m) {
      await readySession();
      if (unlockedBy === 'passcode') throw new Fail('PASSWORD_REQUIRED'); // E-17
      if (unlocked === null) throw new Fail('LOCKED');
      if (vaultState !== 'ready') throw new Fail('VAULT_NOT_READY');
      const u = unlocked;
      const epoch = lockEpoch;
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
      const epoch = lockEpoch;
      const rec = await reserveAttempt(s.memberId);
      if (rec === null) throw new Fail('NO_QUICK_UNLOCK');
      // 端末が最後に見た世代より古い世代の保存では戻らない。ローテーションの後なので消して、マスターパスワードを求める（2b DeepSeek #5）
      const lastSeen = await trustFor(s.memberId).generations.get();
      if (lastSeen !== undefined && rec.vaultKeyVersion < lastSeen) {
        await serialized(() => chrome.storage.session.remove(quickKey(s.memberId)));
        throw new Fail('PASSWORD_REQUIRED');
      }
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
      // 回数を戻している間にロックされたかもしれない。鍵を置く直前にもう一度確かめる（2b Codex #1、DeepSeek #3）
      if (!(await stillCurrent(epoch))) throw new Fail('LOCKED');
      unlocked = null; // 秘密鍵は戻さない
      vaultKey = key;
      vaultVersion = rec.vaultKeyVersion;
      vaultState = 'ready';
      unlockedBy = 'passcode';
      return { ok: true, vault: vaultState };
    },

    async sync() {
      return { ok: true, received: await sync() };
    },

    async listItems() {
      const memberId = await vaultMember();
      await loadCache(memberId);
      const items = [...index.values()].map((e) => e.summary).sort((a, b) => a.title.localeCompare(b.title, 'ja') || a.id.localeCompare(b.id));
      return { ok: true, items };
    },

    // 1件を開いたときだけ、中身（パスワードを含む）を返す
    async getItem(m) {
      const epoch = lockEpoch;
      const memberId = await vaultMember();
      await loadCache(memberId);
      const e = index.get(String(m.id));
      if (!e) throw new Fail('NOT_FOUND');
      const item = await openEntry(String(m.id), e).catch(() => null);
      // 復号している間にロックされたら、平文を返さない（2b Codex #2、DeepSeek #4）
      if (!(await stillCurrent(epoch))) throw new Fail('LOCKED');
      if (item === null) throw new Fail('UNREADABLE');
      return { ok: true, item, revision: e.revision };
    },

    async saveItem(m) {
      const memberId = await vaultMember();
      await loadCache(memberId);
      const item = m.item as ClientItem; // messages.ts で validateItem を通した、確かめた値だけのオブジェクト
      if (typeof m.id !== 'string') {
        // 新しく作る。ID は Service Worker が作る（暗号化の前に AAD へ入れる）。ID が重なったら1回だけ作り直す（I-03）
        const epoch = lockEpoch;
        for (let attempt = 0; attempt < 2; attempt++) {
          const id = newId('item');
          const ciphertext = await encryptFor(id, item);
          const res = await api.call('POST', '/v1/items', { id, vault_key_version: vaultVersion, ciphertext });
          if (res.status === 201) {
            if (!(await stillCurrent(epoch))) throw new Fail('LOCKED');
            await putEntry(id, { revision: 1, vaultKeyVersion: vaultVersion!, ciphertext }, epoch);
            await saveCache(memberId);
            return { ok: true, id, revision: 1 };
          }
          if (res.status !== 409) expect(res, 201, { 413: 'TOO_LARGE', 400: 'BAD_REQUEST' });
          // 409 は原因で分ける（10.2）。鍵の世代が違うならローテーションの後なので、送り直さずにマスターパスワードを求める
          if (await generationChanged(epoch)) {
            await lock();
            throw new Fail('PASSWORD_REQUIRED');
          }
        }
        throw new Fail('CONFLICT');
      }
      const id = m.id;
      const epoch = lockEpoch;
      const ciphertext = await encryptFor(id, item);
      const res = await api.call('PUT', `/v1/items/${id}`, { revision: m.revision, vault_key_version: vaultVersion, ciphertext });
      if (res.status === 409) {
        // 作成と同じく原因で分ける（10.2）。鍵の世代の違いは、上書きを選んでも 409 が続くので、選択の画面に回さない
        if (await generationChanged(epoch)) {
          await lock();
          throw new Fail('PASSWORD_REQUIRED');
        }
        return conflictReply(id);
      }
      if (res.status === 404) {
        await sync();
        throw new Fail('NOT_FOUND');
      }
      const body = expect(res, 200, { 413: 'TOO_LARGE', 400: 'BAD_REQUEST' });
      if (!(await stillCurrent(epoch))) throw new Fail('LOCKED');
      await putEntry(id, { revision: Number(body.revision), vaultKeyVersion: vaultVersion!, ciphertext }, epoch);
      await saveCache(memberId);
      return { ok: true, id, revision: Number(body.revision) };
    },

    async deleteItem(m) {
      const memberId = await vaultMember();
      await loadCache(memberId);
      const id = String(m.id);
      const epoch = lockEpoch;
      const res = await api.call('DELETE', `/v1/items/${id}`, { revision: m.revision });
      if (res.status === 409) return conflictReply(id);
      if (res.status === 404) {
        await sync();
        throw new Fail('NOT_FOUND');
      }
      expect(res, 200);
      if (!(await stillCurrent(epoch))) throw new Fail('LOCKED');
      index.delete(id);
      await saveCache(memberId);
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
