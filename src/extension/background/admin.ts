// 承認の双方向の照合、承認、削除、監査ログ（フェーズ4a。docs/実装状況.md の12.2・12.3、仕様書「メンバーの参加と承認」）。
//   - 照合は人が見比べる。画面に出したフィンガープリント（全桁）と鍵 ID と世代を、「一致」のメッセージに入れて送り返してもらい、
//     サーバーから取り直した値と同じときだけ固定する（見せてから押すまでの間に、サーバーが差し替えても固定しない）
//   - メンバー：管理者の署名用公開鍵を固定し、その世代で最後に見た世代を初期化する（pinSigner。P-04・P-07）
//   - 管理者：メンバーの鍵 ID と公開鍵の組を固定する（pinPublicKey）。承認では、固定値と照合してからグラントを作る（createGrant。P-01）
//   - 管理操作（承認、削除）は、マスターパスワードで解除した状態でだけ行う（E-17）。5分以内の TOTP の確認はサーバーが求める（A-10）

import { fromBase64Url, toBase64Url, wipe } from '../../crypto/bytes.ts';
import { CryptoError } from '../../crypto/errors.ts';
import { createGrant, openGrantForAdmin, type Grant } from '../../crypto/grant.ts';
import { fingerprint, pinPublicKey } from '../../crypto/public-key.ts';
import { pinSigner } from '../../crypto/signer.ts';
import { grantFromApi } from './api-shapes.ts';
import { chromePinStore } from './storage.ts';
import { Fail, type Context, type Handler, type VaultState } from './context.ts';

type ApiMember = { id: string; display_name: string; role: string; status: string; key: { id: string; ecdh_public_key: string } | null };

function grantBody(g: Grant) {
  return {
    vault_key_version: g.vaultKeyVersion,
    recipient_key_id: g.recipientKeyId,
    ephemeral_public_key: toBase64Url(g.ephemeralPublicKey),
    wrapped_key: toBase64Url(g.wrappedKey),
    signer_key_id: g.signerKeyId,
    signature: toBase64Url(g.signature),
    format_version: g.formatVersion,
  };
}

export function createAdmin(ctx: Context, openVault: () => Promise<VaultState>) {
  const { chrome, apiOrigin, api, state, lock, stillCurrent, readySession, trustFor, expect, getMe } = ctx;

  async function fetchMembers(): Promise<{ members: ApiMember[]; current: number }> {
    const body = expect(await api.call('GET', '/v1/members'), 200, { 403: 'FORBIDDEN' });
    return { members: Array.isArray(body.members) ? (body.members as ApiMember[]) : [], current: Number(body.current_vault_key_version) };
  }

  // サーバーが返す管理者の組（メンバーにだけ返る）。有効な管理者の署名鍵がちょうど1つでなければ 409
  async function fetchSigner() {
    const body = expect(await api.call('GET', '/v1/me'), 200, { 409: 'ADMIN_NOT_READY', 403: 'FORBIDDEN' });
    const s = body.admin_signer as { member_id?: unknown; key_id?: unknown; ecdsa_public_key?: unknown } | undefined;
    if (!s || typeof s.member_id !== 'string' || typeof s.key_id !== 'string' || typeof s.ecdsa_public_key !== 'string') throw new Fail('NOT_MEMBER');
    const publicKey = fromBase64Url(s.ecdsa_public_key);
    return { memberId: s.member_id, keyId: s.key_id, publicKey, fingerprint: await fingerprint(publicKey), vaultKeyVersion: Number(body.current_vault_key_version) };
  }

  // ロールはサーバーの今の値で見る（セッションに控えたロールは、ログインしたときのもの）
  async function asAdmin(): Promise<{ memberId: string }> {
    await readySession();
    const me = await getMe();
    if (me.role !== 'admin') throw new Fail('NOT_ADMIN');
    return { memberId: me.id };
  }

  // 管理操作の前：マスターパスワードで解除し、署名用秘密鍵を持っていること（E-17）
  function unlockedAdmin() {
    if (state.unlockedBy === null) throw new Fail('LOCKED');
    if (state.unlockedBy !== 'password' || state.unlocked === null) throw new Fail('PASSWORD_REQUIRED');
    const u = state.unlocked;
    if (!u.signPrivateKey) throw new Fail('NOT_ADMIN');
    return { ...u, signPrivateKey: u.signPrivateKey };
  }

  // 照合や承認の後に、グラントを開き直す（承認待ちから使えるようになる）
  async function reopen(): Promise<VaultState> {
    if (state.unlockedBy === null) throw new Fail('LOCKED');
    if (state.unlocked === null) throw new Fail('PASSWORD_REQUIRED');
    const epoch = state.lockEpoch;
    let opened: VaultState;
    try {
      opened = await openVault();
    } catch (e) {
      if (epoch !== state.lockEpoch) throw new Fail('LOCKED');
      throw e;
    }
    if (!(await stillCurrent(epoch))) {
      await lock();
      throw new Fail('LOCKED');
    }
    state.vaultState = opened;
    return opened;
  }

  const handlers = {
    // メンバーの照合の画面に出す値。固定はしない
    async adminSigner() {
      const s = await readySession();
      const signer = await fetchSigner();
      const pinned = await trustFor(s.memberId).signerPins.get();
      const me = await getMe();
      const own = typeof me.key?.ecdh_public_key === 'string' ? await fingerprint(fromBase64Url(me.key.ecdh_public_key)) : null;
      return {
        ok: true,
        ownFingerprint: own, // 管理者が承認の画面で見比べる、自分の公開鍵
        memberId: signer.memberId,
        keyId: signer.keyId,
        fingerprint: signer.fingerprint,
        vaultKeyVersion: signer.vaultKeyVersion,
        pinned: pinned !== undefined && pinned.keyId === signer.keyId && pinned.memberId === signer.memberId,
      };
    },

    // メンバーが「一致」を押した。見せた値とサーバーの今の値が同じときだけ固定し、世代を初期化する
    async confirmAdminSigner(m) {
      const s = await readySession();
      const signer = await fetchSigner();
      if (signer.keyId !== m.keyId || signer.fingerprint !== m.fingerprint || signer.vaultKeyVersion !== m.vaultKeyVersion) throw new Fail('SIGNER_CHANGED');
      await pinSigner(trustFor(s.memberId), { memberId: signer.memberId, keyId: signer.keyId, publicKey: signer.publicKey }, signer.vaultKeyVersion);
      const vault = state.unlocked !== null ? await reopen() : state.vaultState;
      return { ok: true, vault };
    },

    async reopenVault() {
      await readySession();
      return { ok: true, vault: await reopen() };
    },

    // 一覧。フィンガープリントは全桁（DeepSeek #13）。pinned は、この端末が固定した組と同じか（管理者の端末だけで意味がある）
    async listMembers() {
      const s = await readySession();
      const { members, current } = await fetchMembers();
      const pins = chromePinStore(chrome.storage.local, apiOrigin, s.memberId);
      const out = [];
      for (const x of members) {
        const publicKey = x.key ? fromBase64Url(x.key.ecdh_public_key) : null;
        const pin = await pins.get(x.id);
        const pinned = publicKey !== null && pin !== undefined && pin.keyId === x.key!.id && toBase64Url(pin.publicKey) === x.key!.ecdh_public_key;
        out.push({
          id: x.id,
          displayName: x.display_name,
          role: x.role,
          status: x.status,
          keyId: x.key?.id ?? null,
          fingerprint: publicKey ? await fingerprint(publicKey).catch(() => null) : null,
          pinned,
          self: x.id === s.memberId,
        });
      }
      // 管理者なら、メンバーが照合の画面で見比べる自分の署名用公開鍵
      const me = await getMe();
      const sign = typeof me.key?.ecdsa_public_key === 'string' ? await fingerprint(fromBase64Url(me.key.ecdsa_public_key)) : null;
      return { ok: true, members: out, signFingerprint: sign, currentVaultKeyVersion: current, lastSeenGeneration: (await trustFor(s.memberId).generations.get()) ?? null };
    },

    // 管理者が「一致」を押した。見せた鍵 ID とフィンガープリントが、サーバーの今の値と同じときだけ固定する
    async pinMember(m) {
      const s = await asAdmin();
      const { members } = await fetchMembers();
      const row = members.find((x) => x.id === m.memberId);
      if (!row?.key || row.key.id !== m.keyId) throw new Fail('KEY_CHANGED');
      const publicKey = fromBase64Url(row.key.ecdh_public_key);
      if ((await fingerprint(publicKey)) !== m.fingerprint) throw new Fail('KEY_CHANGED');
      await pinPublicKey(chromePinStore(chrome.storage.local, apiOrigin, s.memberId), row.id, { keyId: row.key.id, publicKey });
      return { ok: true };
    },

    // 承認：自分宛てのグラントを取り出し可として開き直し、固定値と照合してから相手宛てのグラントを作り、承認と一緒に送る
    async approveMember(m) {
      const s = await asAdmin();
      const u = unlockedAdmin();
      const memberId = String(m.memberId);
      const pins = chromePinStore(chrome.storage.local, apiOrigin, s.memberId);
      if ((await pins.get(memberId)) === undefined) throw new Fail('NOT_PINNED');
      const epoch = state.lockEpoch;
      const { members } = await fetchMembers();
      const row = members.find((x) => x.id === memberId);
      if (!row) throw new Fail('NOT_FOUND');
      if (!row.key) throw new Fail('NO_KEY');
      const vault = expect(await api.call('GET', '/v1/vault'), 200);
      if (vault.grant === null || typeof vault.grant !== 'object') throw new Fail('VAULT_NOT_READY');
      const current = Number(vault.current_vault_key_version);
      const trust = trustFor(u.memberId);
      const raw = await openGrantForAdmin({ memberId: u.memberId, keyId: u.keyId, publicKey: u.publicKey, privateKey: u.privateKey }, trust, grantFromApi(vault.grant as Record<string, unknown>), current);
      let grant: Grant;
      try {
        grant = await createGrant({
          pins,
          signer: { memberId: u.memberId, keyId: u.keyId, privateKey: u.signPrivateKey, trust },
          memberId,
          recipient: { keyId: row.key.id, publicKey: fromBase64Url(row.key.ecdh_public_key) },
          vaultKeyVersion: current,
          vaultKeyRaw: raw,
        });
      } catch (e) {
        // サーバーの鍵が固定と違う（P-01）。グラントを作らずに止める
        if (e instanceof CryptoError && e.code === 'PUBLIC_KEY_MISMATCH') throw new Fail('KEY_MISMATCH');
        if (e instanceof CryptoError && e.code === 'PUBLIC_KEY_NOT_PINNED') throw new Fail('NOT_PINNED');
        throw e;
      } finally {
        wipe(raw);
      }
      if (!(await stillCurrent(epoch))) throw new Fail('LOCKED');
      expect(await api.call('POST', `/v1/members/${memberId}/approve`, grantBody(grant)), 200, { 403: 'STEP_UP_REQUIRED', 404: 'NOT_FOUND', 409: 'CONFLICT' });
      return { ok: true };
    },

    // 削除。相手の端末に残った Vault 鍵は回収できないので、画面でローテーションを促す（判断待ち8）
    async removeMember(m) {
      const s = await asAdmin();
      unlockedAdmin();
      if (m.memberId === s.memberId) throw new Fail('CANNOT_REMOVE_SELF');
      expect(await api.call('DELETE', `/v1/members/${String(m.memberId)}`), 204, { 403: 'STEP_UP_REQUIRED', 404: 'NOT_FOUND', 409: 'CANNOT_REMOVE_SELF' });
      return { ok: true, rotationRecommended: true };
    },

    async auditLogs() {
      await asAdmin();
      const body = expect(await api.call('GET', '/v1/audit-logs'), 200, { 403: 'STEP_UP_REQUIRED' });
      const logs = Array.isArray(body.logs) ? (body.logs as Record<string, unknown>[]) : [];
      return {
        ok: true,
        logs: logs.map((l) => ({ actor: String(l.actor_member_id ?? ''), action: String(l.action), targetType: String(l.target_type ?? ''), targetId: String(l.target_id ?? ''), createdAt: Number(l.created_at) })),
      };
    },
  } satisfies Record<string, Handler>;

  return { handlers };
}
