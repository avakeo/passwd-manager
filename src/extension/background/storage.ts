// 拡張機能の保存先。書き込むのは Service Worker だけ。
//   chrome.storage.local：署名鍵の固定と最後に見た世代（暗号コアの TrustStorage）、照合済みの公開鍵（PinStore）。平文と鍵は置かない
//   chrome.storage.session：自前のトークン、最後の操作の時刻。ブラウザを閉じると消え、既定の設定のまま信頼されたページだけが読める（E-16）
// キーは接続先とメンバー ID の組ごとに分ける（P-09）。

import type { StorageArea } from './chrome-like.ts';
import type { TrustStorage } from '../../crypto/signer.ts';
import type { PinnedKey, PinStore } from '../../crypto/public-key.ts';
import { fromBase64Url, toBase64Url } from '../../crypto/bytes.ts';

export function chromeTrustStorage(area: StorageArea): TrustStorage {
  return {
    async get(key) {
      const v = (await area.get(key))[key];
      return typeof v === 'string' ? v : undefined;
    },
    async set(key, value) {
      await area.set({ [key]: value });
    },
  };
}

// 管理者の端末の、照合済みの公開鍵（メンバー ID ごとに鍵 ID と公開鍵の組）
export function chromePinStore(area: StorageArea, apiOrigin: string, adminId: string): PinStore {
  const keyOf = (memberId: string) => `teampw/v1/pins|${apiOrigin}|${adminId}|${memberId}`;
  return {
    async get(memberId) {
      const v = (await area.get(keyOf(memberId)))[keyOf(memberId)];
      if (typeof v !== 'string') return undefined;
      try {
        const p = JSON.parse(v) as { keyId?: unknown; publicKey?: unknown };
        if (typeof p.keyId !== 'string' || typeof p.publicKey !== 'string') return undefined;
        return { keyId: p.keyId, publicKey: fromBase64Url(p.publicKey) };
      } catch {
        return undefined;
      }
    },
    async set(memberId: string, key: PinnedKey) {
      await area.set({ [keyOf(memberId)]: JSON.stringify({ keyId: key.keyId, publicKey: toBase64Url(key.publicKey) }) });
    },
  };
}

export type SessionRecord = {
  accessToken: string;
  refreshToken: string;
  memberId: string;
  role: 'admin' | 'member';
  totpSetupRequired: boolean;
};

const SESSION_KEY = 'teampw/v1/session';

export class SessionStore {
  readonly #area: StorageArea;

  constructor(area: StorageArea) {
    this.#area = area;
  }

  async get(): Promise<SessionRecord | undefined> {
    const v = (await this.#area.get(SESSION_KEY))[SESSION_KEY] as Partial<SessionRecord> | undefined;
    if (!v || typeof v.accessToken !== 'string' || typeof v.refreshToken !== 'string' || typeof v.memberId !== 'string') return undefined;
    return { accessToken: v.accessToken, refreshToken: v.refreshToken, memberId: v.memberId, role: v.role === 'admin' ? 'admin' : 'member', totpSetupRequired: v.totpSetupRequired === true };
  }

  async set(record: SessionRecord): Promise<void> {
    await this.#area.set({ [SESSION_KEY]: { ...record } });
  }

  async clear(): Promise<void> {
    await this.#area.remove(SESSION_KEY);
  }
}
