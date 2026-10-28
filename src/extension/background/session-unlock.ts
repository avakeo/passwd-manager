// ロック解除を保つ（2026-10-29 追記。仕様書「ロックと鍵の置き場所」、E-19・E-20）。
//   - 利用者が選んだときだけ、Vault 鍵を storage.session に置く。storage.session はメモリだけで、ディスクに書かない。
//     読めるのは拡張機能自身のページと Service Worker だけ（アクセスの範囲は既定のまま。E-16）
//   - 秘密鍵と署名用秘密鍵は置かない。戻った状態は Vault 鍵だけを持つ（unlockedBy: 'session'。管理操作は E-17 と同じくマスターパスワード）
//   - 置き場所はクイックロック解除と同じ接頭辞（UNLOCK_KEY_PREFIX）なので、ロック・ログアウト・45分の放置（lock()）で消える。ブラウザを閉じても消える
//   - storage.local には「オンかオフか」だけを置く（接続先とメンバー ID の組ごと）。鍵は置かない

import { fromBase64Url, toBase64Url, wipe } from '../../crypto/bytes.ts';
import { openGrantForQuickUnlock } from '../../crypto/grant.ts';
import { VAULT_KEY_LENGTH, importVaultKeyAndWipe } from '../../crypto/vault-key.ts';
import { grantFromApi } from './api-shapes.ts';
import { Fail, UNLOCK_KEY_PREFIX, type Context, type Handler } from './context.ts';

type SessionRecord = { vaultKey: string; vaultKeyVersion: number };

export function createSessionUnlock(ctx: Context) {
  const { chrome, apiOrigin, sessions, api, state, stillCurrent, readySession, trustFor, expect } = ctx;

  function recordKey(memberId: string): string {
    return `${UNLOCK_KEY_PREFIX}session|${apiOrigin}|${memberId}`;
  }

  function prefKey(memberId: string): string {
    return `teampw/v1/keep-unlocked|${apiOrigin}|${memberId}`;
  }

  async function enabled(memberId: string): Promise<boolean> {
    return (await chrome.storage.local.get(prefKey(memberId)))[prefKey(memberId)] === true;
  }

  function parse(v: unknown): SessionRecord | null {
    const r = v as Partial<SessionRecord> | undefined;
    if (!r || typeof r.vaultKey !== 'string' || !Number.isSafeInteger(r.vaultKeyVersion) || Object.keys(r).length !== 2) return null;
    return { vaultKey: r.vaultKey, vaultKeyVersion: r.vaultKeyVersion! };
  }

  // マスターパスワードで解除した状態から、グラントを取り出し可として開き直し、生の Vault 鍵を置く（鍵のライフサイクルの表）
  async function seal(): Promise<void> {
    const u = state.unlocked;
    if (u === null || state.unlockedBy !== 'password' || state.vaultState !== 'ready') throw new Fail('PASSWORD_REQUIRED');
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
    let record: SessionRecord;
    try {
      record = { vaultKey: toBase64Url(raw), vaultKeyVersion: current };
    } finally {
      wipe(raw);
    }
    // 開き直している間にロックされたら置かない（lock() が消した後に書き戻さない）
    if (!(await stillCurrent(epoch))) throw new Fail('LOCKED');
    await chrome.storage.session.set({ [recordKey(u.memberId)]: record });
  }

  // マスターパスワードで解除した直後に呼ぶ。オンなら置き直す（ブラウザを閉じた後の、最初の解除）。失敗しても解除は続ける
  async function afterPasswordUnlock(): Promise<void> {
    const u = state.unlocked;
    if (u === null || state.vaultState !== 'ready' || !(await enabled(u.memberId))) return;
    await seal().catch(() => undefined);
  }

  // メッセージを処理する前に呼ぶ。ロックされていて、保存があれば、Vault 鍵だけを取り出し不可で読み込んで戻る
  async function resume(): Promise<void> {
    if (state.unlockedBy !== null) return;
    const s = await sessions.get();
    if (!s || s.totpSetupRequired) return;
    const key = recordKey(s.memberId);
    const stored = (await chrome.storage.session.get(key))[key];
    if (stored === undefined) return;
    const epoch = state.lockEpoch;
    const rec = parse(stored);
    const raw = rec ? fromBase64Url(rec.vaultKey) : null;
    // 形が違う、オフにした、端末が最後に見た世代より古い（ローテーションの後）なら、戻らずに消す
    const lastSeen = await trustFor(s.memberId).generations.get();
    if (!rec || !raw || raw.length !== VAULT_KEY_LENGTH || !(await enabled(s.memberId)) || (lastSeen !== undefined && rec.vaultKeyVersion < lastSeen)) {
      if (raw) wipe(raw);
      await chrome.storage.session.remove(key);
      return;
    }
    const vaultKey = await importVaultKeyAndWipe(raw);
    if (epoch !== state.lockEpoch || state.unlockedBy !== null) return;
    state.unlocked = null; // 秘密鍵は戻さない
    state.vaultKey = vaultKey;
    state.vaultVersion = rec.vaultKeyVersion;
    state.vaultState = 'ready';
    state.unlockedBy = 'session';
  }

  const handlers = {
    // オンにするのはマスターパスワードで解除した状態からだけ。オフにはいつでもできる
    async setKeepUnlocked(m) {
      const s = await readySession();
      if (m.enabled === true) {
        if (state.unlockedBy !== 'password') throw new Fail(state.unlockedBy === null ? 'LOCKED' : 'PASSWORD_REQUIRED');
        await chrome.storage.local.set({ [prefKey(s.memberId)]: true });
        await seal();
        return { ok: true, keepUnlocked: true };
      }
      await chrome.storage.local.remove(prefKey(s.memberId));
      await chrome.storage.session.remove(recordKey(s.memberId));
      return { ok: true, keepUnlocked: false };
    },
  } satisfies Record<string, Handler>;

  return { handlers, resume, afterPasswordUnlock, enabled };
}
