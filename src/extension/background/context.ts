// Service Worker の中で、処理のまとまり（ファイル）をまたいで使う状態と共通の処理。
// 状態は createContext を呼ぶごとに作る（モジュールの最上位には置かない）。テストは1つのプロセスで端末を2つ作るため。
//   - 秘密鍵・署名用秘密鍵・Vault 鍵と、平文の一覧は、この状態（メモリ）だけに、取り出し不可で置く
//   - ロックとログアウトのたびに lockEpoch を進める。時間のかかる処理は、終わった時点で stillCurrent で確かめる（Codex #3）

import type { ChromeLike } from './chrome-like.ts';
import { ApiClient, type ApiResult } from './api-client.ts';
import { SessionStore, chromeTrustStorage, type SessionRecord } from './storage.ts';
import type { MeKey } from './api-shapes.ts';
import type { Bytes } from '../../crypto/bytes.ts';
import { openTrust, type GrantTrust, type TrustStorage } from '../../crypto/signer.ts';

export const IDLE_LOCK_MS = 15 * 60 * 1000;
export const LAST_ACTIVITY_KEY = 'teampw/v1/last-activity';
// ロックで消す、ロック解除のための保存（2b のクイックロック解除が使う）
export const UNLOCK_KEY_PREFIX = 'teampw/v1/unlock|';

export const QUICK_UNLOCK_MAX_FAILURES = 5;

export type VaultState = 'locked' | 'no-key' | 'ready' | 'needs-init' | 'awaiting-approval' | 'needs-generation-init' | 'grant-rejected';

export type Reply = ({ ok: true } & Record<string, unknown>) | ({ ok: false; error: string } & Record<string, unknown>);

export type BackgroundDeps = {
  chrome: ChromeLike;
  apiOrigin: string;
  discordClientId: string;
  fetch: (input: string, init: RequestInit) => Promise<Response>;
};

// ロック解除した鍵（取り出し不可）。秘密鍵は、マスターパスワードで解除したときだけ持つ
export type Unlocked = {
  memberId: string;
  role: 'admin' | 'member';
  keyId: string;
  publicKey: Bytes;
  privateKey: CryptoKey;
  signPublicKey?: Bytes;
  signPrivateKey?: CryptoKey;
};

// 一覧に出す分だけ（パスワード、メモ、カスタム項目は入れない）
export type Summary = { id: string; type: 'login' | 'note' | null; title: string; username?: string; urls?: string[]; unreadable: boolean; revision: number };
export type CacheEntry = { revision: number; vaultKeyVersion: number; ciphertext: string };
export type CacheRecord = { cursor: number; lastVaultRevision: number; items: Record<string, CacheEntry> };

export class Fail extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

// メモリだけに置くもの
export type BackgroundState = {
  unlocked: Unlocked | null;
  vaultKey: CryptoKey | null;
  vaultState: VaultState;
  challenge: { token: string } | null; // ログインの途中の一時トークン（TOTP のコードを送るまで）
  // ロックとログアウトのたびに進める番号。時間のかかる処理（鍵の導出、通信）は、終わった時点で番号が変わっていたら、
  // 鍵を捨てて何もしない（Codex #3）
  lockEpoch: number;
  // どの方法で解除したか。パスコードで戻った状態は Vault 鍵だけで、秘密鍵（unlocked）は持たない（E-17）
  unlockedBy: 'password' | 'passcode' | null;
  vaultVersion: number | null; // 開いた Vault 鍵の世代
  // 同期の状態（メモリ）。暗号文は storage.local にもキャッシュする。平文の一覧（summary）はメモリだけ
  readonly index: Map<string, CacheEntry & { summary: Summary }>;
  cacheLoadedFor: string | null;
  cursor: number;
  lastVaultRevision: number;
  cacheFull: boolean;
  // クイックロック解除の「試す前に回数を増やして書く」を、1つずつ順に行う（同時に送られても5回を超えない）
  quickChain: Promise<unknown>;
};

export type Context = {
  deps: BackgroundDeps;
  chrome: ChromeLike;
  apiOrigin: string;
  sessions: SessionStore;
  api: ApiClient;
  trustStorage: TrustStorage;
  state: BackgroundState;
  lock(): Promise<void>;
  checkIdle(): Promise<void>;
  stillCurrent(epoch: number): Promise<boolean>;
  readySession(): Promise<SessionRecord>;
  trustFor(memberId: string): GrantTrust;
  expect(res: ApiResult, ok: number, errors?: Record<number, string>): Record<string, unknown>;
  getMe(): Promise<{ id: string; role: 'admin' | 'member'; key: MeKey | null; recoveryCodesRemaining: number }>;
};

export function createContext(deps: BackgroundDeps): Context {
  const { chrome, apiOrigin } = deps;
  const sessions = new SessionStore(chrome.storage.session);
  const api = new ApiClient(apiOrigin, deps.fetch, sessions);
  const trustStorage = chromeTrustStorage(chrome.storage.local);

  const state: BackgroundState = {
    unlocked: null,
    vaultKey: null,
    vaultState: 'locked',
    challenge: null,
    lockEpoch: 0,
    unlockedBy: null,
    vaultVersion: null,
    index: new Map(),
    cacheLoadedFor: null,
    cursor: 0,
    lastVaultRevision: 0,
    cacheFull: false,
    quickChain: Promise.resolve(),
  };

  async function lock(): Promise<void> {
    state.lockEpoch += 1;
    state.challenge = null; // ログインの途中の一時トークンも消す（DeepSeek #5）
    state.unlocked = null;
    state.vaultKey = null;
    state.vaultState = 'locked';
    state.unlockedBy = null;
    state.vaultVersion = null;
    state.index.clear();
    state.cacheLoadedFor = null;
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
    return epoch === state.lockEpoch;
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

  return { deps, chrome, apiOrigin, sessions, api, trustStorage, state, lock, checkIdle, stillCurrent, readySession, trustFor, expect, getMe };
}
