// ログインの開始（拡張機能が使うクライアント側の関数）。state と PKCE を作り、戻ってきた URL の state を照合する。
// 仕様書「ログイン（Chrome拡張機能）」：state は拡張機能が作って照合する（サーバーは state を持たない）。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createLoginRequest, LoginError, parseLoginRedirect } from '../../src/client/discord-login.ts';
import { toBase64Url } from '../../src/crypto/bytes.ts';

const REDIRECT = 'https://abcdefghijklmnopabcdefghijklmnop.chromiumapp.org/';
const CLIENT_ID = '100000000000000001';

function isLoginError(code: string) {
  return (e: unknown) => e instanceof LoginError && e.code === code;
}

test('ログインの開始：認可 URL に state、S256 の PKCE、identify だけのスコープ、redirect_uri が入る', async () => {
  const req = await createLoginRequest({ clientId: CLIENT_ID, redirectUri: REDIRECT });
  const url = new URL(req.url);
  assert.equal(url.origin + url.pathname, 'https://discord.com/oauth2/authorize');
  assert.equal(url.searchParams.get('response_type'), 'code');
  assert.equal(url.searchParams.get('client_id'), CLIENT_ID);
  assert.equal(url.searchParams.get('scope'), 'identify');
  assert.equal(url.searchParams.get('redirect_uri'), REDIRECT);
  assert.equal(url.searchParams.get('state'), req.state);
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  // code_challenge は code_verifier の SHA-256 を base64url にしたもの（RFC 7636）
  const expected = toBase64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(req.codeVerifier))));
  assert.equal(url.searchParams.get('code_challenge'), expected);
  // state と verifier は乱数（32バイト以上）で、毎回変わる
  assert.match(req.state, /^[A-Za-z0-9_-]{43,}$/);
  assert.match(req.codeVerifier, /^[A-Za-z0-9_-]{43,128}$/);
  const again = await createLoginRequest({ clientId: CLIENT_ID, redirectUri: REDIRECT });
  assert.notEqual(again.state, req.state);
  assert.notEqual(again.codeVerifier, req.codeVerifier);
});

test('A-01 戻ってきた URL の state が、開始したときの state と違えば拒否する', async () => {
  const req = await createLoginRequest({ clientId: CLIENT_ID, redirectUri: REDIRECT });
  const other = await createLoginRequest({ clientId: CLIENT_ID, redirectUri: REDIRECT });
  const cases = [
    `${REDIRECT}?code=abc&state=${other.state}`, // 別のログインの state（すり替え）
    `${REDIRECT}?code=abc`, // state がない
    `${REDIRECT}?code=abc&state=`, // 空
    `${REDIRECT}?code=abc&state=${req.state}x`, // 1文字違う
    `${REDIRECT}?code=abc&state=${req.state}&state=${other.state}`, // 2つある
  ];
  for (const url of cases) assert.throws(() => parseLoginRedirect(url, req), isLoginError('STATE_MISMATCH'), url);
  // 一致すれば認可コードを返す
  assert.equal(parseLoginRedirect(`${REDIRECT}?code=abc&state=${req.state}`, req), 'abc');
});

test('A-01 戻り先が開始したときの redirect_uri と違う、コードがない、利用者が拒否した場合も拒否する', async () => {
  const req = await createLoginRequest({ clientId: CLIENT_ID, redirectUri: REDIRECT });
  assert.throws(() => parseLoginRedirect(`https://evil.example.com/?code=abc&state=${req.state}`, req), isLoginError('MALFORMED'));
  assert.throws(() => parseLoginRedirect(`${REDIRECT}other?code=abc&state=${req.state}`, req), isLoginError('MALFORMED'));
  assert.throws(() => parseLoginRedirect(`${REDIRECT}?state=${req.state}`, req), isLoginError('MALFORMED'));
  assert.throws(() => parseLoginRedirect(`${REDIRECT}?error=access_denied&state=${req.state}`, req), isLoginError('ACCESS_DENIED'));
  assert.throws(() => parseLoginRedirect('not a url', req), isLoginError('MALFORMED'));
});
