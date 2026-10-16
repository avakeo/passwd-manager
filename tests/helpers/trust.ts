// テスト用：端末の信頼の状態（管理者の署名鍵の固定と、最後に見た世代）を、メモリ上の保存先で作る。

import { MemoryTrustStorage, openTrust, type GrantTrust, type TrustStorage } from '../../src/crypto/signer.ts';

export const API_ORIGIN = 'https://pw-api.example.com'; // 仮の表記

export function newTrust(memberId = 'member_test', storage: TrustStorage = new MemoryTrustStorage()): GrantTrust {
  return openTrust(storage, { apiOrigin: API_ORIGIN, memberId });
}
