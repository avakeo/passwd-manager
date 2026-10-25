// アイテムと同期（フェーズ2b、docs/実装状況.md の10.2〜10.4）。
//   - 保存の前と復号の後に validateItem を通す
//   - storage.local には暗号文だけをキャッシュする（接続先とメンバー ID の組ごと）。平文の一覧（summary）は context.ts の状態（メモリ）だけ
//   - 差分同期は change_seq のカーソルで取る。巻き戻し（S-09）なら何も書き換えずに止める。削除は暗号文ごと消す（S-02・S-10）
//   - 409 は自動で送り直さない。同期してから今の版を返す（S-01）

import { fromBase64Url, toBase64Url } from '../../crypto/bytes.ts';
import { decryptItem, encryptItem, type ItemContent } from '../../crypto/item.ts';
import { newId } from '../../crypto/random.ts';
import { validateItem, type ClientItem } from '../../client/item-data.ts';
import { Fail, type CacheEntry, type CacheRecord, type Context, type Handler, type Reply, type Summary, type VaultState } from './context.ts';

export function createItemSync(ctx: Context, openVault: () => Promise<VaultState>) {
  const { chrome, apiOrigin, api, state, lock, stillCurrent, readySession, expect } = ctx;

  function syncKey(memberId: string): string {
    return `teampw/v1/sync|${apiOrigin}|${memberId}`;
  }

  async function vaultMember(): Promise<string> {
    if (state.vaultKey === null || state.vaultVersion === null) throw new Fail('LOCKED');
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
    if (state.vaultKey === null || e.vaultKeyVersion !== state.vaultVersion) throw new Fail('UNREADABLE');
    const content = await decryptItem(state.vaultKey, { itemId: id, vaultKeyVersion: e.vaultKeyVersion }, fromBase64Url(e.ciphertext));
    return validateItem(content); // 復号した後も、形を確かめる（I-02）
  }

  async function loadCache(memberId: string): Promise<void> {
    if (state.cacheLoadedFor === memberId) return;
    state.index.clear();
    const saved = (await chrome.storage.local.get(syncKey(memberId)))[syncKey(memberId)] as CacheRecord | undefined;
    state.cursor = typeof saved?.cursor === 'number' ? saved.cursor : 0;
    state.lastVaultRevision = typeof saved?.lastVaultRevision === 'number' ? saved.lastVaultRevision : 0;
    for (const [id, e] of Object.entries(saved?.items ?? {})) state.index.set(id, { ...e, summary: await summarize(id, e) });
    state.cacheLoadedFor = memberId;
  }

  // 暗号文だけを書く。容量を超えたら、キャッシュをやめてメモリだけで続ける（判断待ち 2b-4）
  async function saveCache(memberId: string): Promise<void> {
    const items: Record<string, CacheEntry> = {};
    for (const [id, e] of state.index) items[id] = { revision: e.revision, vaultKeyVersion: e.vaultKeyVersion, ciphertext: e.ciphertext };
    try {
      await chrome.storage.local.set({ [syncKey(memberId)]: { cursor: state.cursor, lastVaultRevision: state.lastVaultRevision, items } satisfies CacheRecord });
      state.cacheFull = false;
    } catch {
      state.cacheFull = true;
      // 暗号文を置けなくても、最後に見た Vault リビジョンは残す（S-09）。カーソルは0にして、起動し直したら全件を取り直す
      await chrome.storage.local.set({ [syncKey(memberId)]: { cursor: 0, lastVaultRevision: state.lastVaultRevision, items: {} } satisfies CacheRecord }).catch(() => undefined);
    }
  }

  async function putEntry(id: string, e: CacheEntry): Promise<void> {
    state.index.set(id, { ...e, summary: await summarize(id, e) });
  }

  // 差分同期（10.3）。巻き戻し（S-09）なら何も書き換えずに止める。削除は暗号文ごと消す（S-02・S-10）
  async function sync(): Promise<number> {
    const memberId = await vaultMember();
    const epoch = state.lockEpoch;
    await loadCache(memberId);
    const body = expect(await api.call('GET', `/v1/items?after=${state.cursor}`), 200);
    if (!(await stillCurrent(epoch))) throw new Fail('LOCKED');
    const revision = Number(body.vault_revision);
    if (!Number.isSafeInteger(revision) || revision < state.lastVaultRevision) throw new Fail('ROLLBACK_DETECTED');
    const items = Array.isArray(body.items) ? (body.items as Record<string, unknown>[]) : [];
    // 新しい世代（ローテーションの後）のアイテムが来た
    if (items.some((i) => i.deleted !== true && Number(i.vault_key_version) > state.vaultVersion!)) {
      if (state.unlockedBy !== 'password') {
        // パスコードで戻った状態は秘密鍵を持たないので、新しい世代のグラントを開けない。マスターパスワードを求める（E-17）
        await lock();
        throw new Fail('PASSWORD_REQUIRED');
      }
      // 開き直している間にロックされたら、openVault が書き戻した鍵を残さない（afterUnlock と同じ確かめ方：Codex #3）
      let opened: VaultState;
      try {
        opened = await openVault();
      } catch (e) {
        if (epoch === state.lockEpoch) throw e;
        await lock();
        throw new Fail('LOCKED');
      }
      if (!(await stillCurrent(epoch))) {
        await lock();
        throw new Fail('LOCKED');
      }
      state.vaultState = opened;
      if (state.vaultState !== 'ready') {
        // 開けなかった（grant-rejected など）なら、前の世代の鍵と一覧も捨てる。状態は afterUnlock で開けなかったときと同じ
        state.vaultKey = null;
        state.vaultVersion = null;
        state.index.clear();
        state.cacheLoadedFor = null;
        throw new Fail('VAULT_NOT_READY');
      }
    }
    let maxSeq = state.cursor;
    for (const i of items) {
      const id = String(i.id);
      if (i.deleted === true || typeof i.ciphertext !== 'string') state.index.delete(id);
      else await putEntry(id, { revision: Number(i.revision), vaultKeyVersion: Number(i.vault_key_version), ciphertext: i.ciphertext });
      maxSeq = Math.max(maxSeq, Number(i.change_seq) || 0);
    }
    state.cursor = maxSeq;
    state.lastVaultRevision = revision;
    await saveCache(memberId);
    return items.length;
  }

  // サーバーの今の鍵の世代が、開いている世代と違うか（作成の 409 の原因を分ける：10.2）
  async function generationChanged(epoch: number): Promise<boolean> {
    const body = expect(await api.call('GET', '/v1/vault'), 200, { 403: 'FORBIDDEN' });
    if (!(await stillCurrent(epoch))) throw new Fail('LOCKED');
    return Number(body.current_vault_key_version) !== state.vaultVersion;
  }

  // 409 のとき：同期してから、今の版を返す（自動で送り直さない：判断待ち 2b-5）
  async function conflictReply(id: string): Promise<Reply> {
    await sync();
    const e = state.index.get(id);
    if (!e) return { ok: false, error: 'DELETED' };
    const current = await openEntry(id, e).catch(() => null);
    return { ok: false, error: 'CONFLICT', current, currentRevision: e.revision };
  }

  async function encryptFor(id: string, item: ClientItem): Promise<string> {
    return toBase64Url(await encryptItem(state.vaultKey!, { itemId: id, vaultKeyVersion: state.vaultVersion! }, item as unknown as ItemContent));
  }

  const handlers = {
    async sync() {
      return { ok: true, received: await sync() };
    },

    async listItems() {
      const memberId = await vaultMember();
      await loadCache(memberId);
      const items = [...state.index.values()].map((e) => e.summary).sort((a, b) => a.title.localeCompare(b.title, 'ja') || a.id.localeCompare(b.id));
      return { ok: true, items };
    },

    // 1件を開いたときだけ、中身（パスワードを含む）を返す
    async getItem(m) {
      const memberId = await vaultMember();
      await loadCache(memberId);
      const e = state.index.get(String(m.id));
      if (!e) throw new Fail('NOT_FOUND');
      const item = await openEntry(String(m.id), e).catch(() => null);
      if (item === null) throw new Fail('UNREADABLE');
      return { ok: true, item, revision: e.revision };
    },

    async saveItem(m) {
      const memberId = await vaultMember();
      await loadCache(memberId);
      const item = m.item as ClientItem; // messages.ts で validateItem を通した、確かめた値だけのオブジェクト
      if (typeof m.id !== 'string') {
        // 新しく作る。ID は Service Worker が作る（暗号化の前に AAD へ入れる）。ID が重なったら1回だけ作り直す（I-03）
        const epoch = state.lockEpoch;
        for (let attempt = 0; attempt < 2; attempt++) {
          const id = newId('item');
          const ciphertext = await encryptFor(id, item);
          const res = await api.call('POST', '/v1/items', { id, vault_key_version: state.vaultVersion, ciphertext });
          if (res.status === 201) {
            await putEntry(id, { revision: 1, vaultKeyVersion: state.vaultVersion!, ciphertext });
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
      const ciphertext = await encryptFor(id, item);
      const res = await api.call('PUT', `/v1/items/${id}`, { revision: m.revision, vault_key_version: state.vaultVersion, ciphertext });
      if (res.status === 409) return conflictReply(id);
      if (res.status === 404) {
        await sync();
        throw new Fail('NOT_FOUND');
      }
      const body = expect(res, 200, { 413: 'TOO_LARGE', 400: 'BAD_REQUEST' });
      await putEntry(id, { revision: Number(body.revision), vaultKeyVersion: state.vaultVersion!, ciphertext });
      await saveCache(memberId);
      return { ok: true, id, revision: Number(body.revision) };
    },

    async deleteItem(m) {
      const memberId = await vaultMember();
      await loadCache(memberId);
      const id = String(m.id);
      const res = await api.call('DELETE', `/v1/items/${id}`, { revision: m.revision });
      if (res.status === 409) return conflictReply(id);
      if (res.status === 404) {
        await sync();
        throw new Fail('NOT_FOUND');
      }
      expect(res, 200);
      state.index.delete(id);
      await saveCache(memberId);
      return { ok: true };
    },
  } satisfies Record<string, Handler>;

  return { handlers };
}
