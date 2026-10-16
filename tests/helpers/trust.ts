// テスト用：端末の信頼の状態（管理者の署名鍵の固定と、最後に見た世代）を、メモリ上の保存先で作る。

import type { Grant } from '../../src/crypto/grant.ts';
import { MemoryTrustStorage, openTrust, type GrantTrust, type TrustStorage } from '../../src/crypto/signer.ts';

export const API_ORIGIN = 'https://pw-api.example.com'; // 仮の表記

// サーバーが /v1/vault で、グラントと一緒に「今の世代」としてグラントの世代を返した、という引数の組。
// openGrant(own, trust, ...served(grant)) のように使う。
export function served(grant: Grant, currentVaultKeyVersion = grant.vaultKeyVersion): [Grant, number] {
  return [grant, currentVaultKeyVersion];
}

export function newTrust(memberId = 'member_test', storage: TrustStorage = new MemoryTrustStorage()): GrantTrust {
  return openTrust(storage, { apiOrigin: API_ORIGIN, memberId });
}
