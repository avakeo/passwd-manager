// クイックロック解除（フェーズ2b、仕様書 A-5、docs/実装状況.md の10.5）。
//   - Vault 鍵だけを、パスコード由来の鍵で包んで storage.session に置く。秘密鍵は包まない
//   - 戻るときは、試す前に失敗の回数を1つ増やして書く。5回目の失敗で保存を消す（E-15）
//   - 戻った状態は Vault 鍵だけを持ち、秘密鍵を持たない（unlockedBy: 'passcode'。E-17）

import { wipe } from '../../crypto/bytes.ts';
import { CryptoError } from '../../crypto/errors.ts';
import { openGrantForQuickUnlock } from '../../crypto/grant.ts';
import { openQuickUnlock, sealQuickUnlock, type QuickUnlockRecord } from '../../crypto/quick-unlock.ts';
import { grantFromApi } from './api-shapes.ts';
import { Fail, QUICK_UNLOCK_MAX_FAILURES, UNLOCK_KEY_PREFIX, type Context, type Handler } from './context.ts';

export function createPasscode(ctx: Context) {
  const { chrome, apiOrigin, sessions, api, state, stillCurrent, readySession, trustFor, expect } = ctx;
  // 「試す前に回数を増やして書く」を、1つずつ順に行う（同時に送られても5回を超えない）。createPasscode を呼ぶごとに持つ
  let quickChain: Promise<unknown> = Promise.resolve();

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

  const handlers = {
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
  } satisfies Record<string, Handler>;

  return { handlers, quickKey, parseQuick };
}
