// ロック解除と鍵の状態（フェーズ2a）。仕様書「鍵とメンバーのライフサイクル」「初期化（管理者）」。
//   - 自分宛てのグラントは、固定した管理者の署名鍵で確かめてから開く。開けない理由は状態（VaultState）として返す
//   - 時間のかかる処理（鍵の導出、通信）の後は stillCurrent で確かめ、ロックやログアウトがあれば鍵を残さない（Codex #3）
//   - パスコードで戻った状態では、鍵の作り直しと最初の Vault にマスターパスワードを求める（E-17）

import { toBase64Url, wipe } from '../../crypto/bytes.ts';
import { CryptoError } from '../../crypto/errors.ts';
import { createGrant, openGrant } from '../../crypto/grant.ts';
import { createAdminKey, createMemberKey, unlockAdminKey, unlockMemberKey, type AdminKeyRecord, type MemberKeyRecord } from '../../crypto/member-key.ts';
import { pinPublicKey } from '../../crypto/public-key.ts';
import { assertSignerPinned, pinSigner, type SignerPin } from '../../crypto/signer.ts';
import { generateVaultKeyRaw, importVaultKeyAndWipe } from '../../crypto/vault-key.ts';
import { grantFromApi, keyBody, keyRecordFromMe } from './api-shapes.ts';
import { chromePinStore } from './storage.ts';
import { Fail, type Context, type Handler, type Reply, type Unlocked, type VaultState } from './context.ts';

export function createVault(ctx: Context) {
  const { chrome, apiOrigin, api, state, lock, stillCurrent, readySession, trustFor, expect, getMe } = ctx;

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

  const handlers = {
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
  } satisfies Record<string, Handler>;

  return { handlers, openVault };
}
