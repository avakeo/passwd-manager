// 画面の共通部品。描画は textContent と createElement だけで行い、HTML として解釈する書き方は使わない
// （サーバーや CSV から来た文字列、端末名に <img onerror=…> などが入っていても、文字として出る。DeepSeek #2）。

type Reply = { ok: boolean; error?: string } & Record<string, unknown>;

type Props = { text?: string; className?: string; type?: string; placeholder?: string; value?: string; autocomplete?: string; disabled?: boolean };

export function el<K extends keyof HTMLElementTagNameMap>(tag: K, props: Props = {}, ...children: (Node | string)[]): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (props.text !== undefined) node.textContent = props.text;
  if (props.className !== undefined) node.className = props.className;
  const input = node as unknown as HTMLInputElement;
  if (props.type !== undefined) input.type = props.type;
  if (props.placeholder !== undefined) input.placeholder = props.placeholder;
  if (props.value !== undefined) input.value = props.value;
  if (props.autocomplete !== undefined) input.autocomplete = props.autocomplete as AutoFill;
  if (props.disabled !== undefined) input.disabled = props.disabled;
  for (const c of children) node.append(typeof c === 'string' ? document.createTextNode(c) : c);
  return node;
}

// ロックされていると分かったときに呼ぶ（全画面ページが、ロック解除だけの画面に描き直すのに使う）
let lockedHandler: (() => void) | null = null;

export function onLocked(handler: () => void): void {
  lockedHandler = handler;
}

export async function send(message: Record<string, unknown>): Promise<Reply> {
  const runtime = (globalThis as unknown as { chrome: { runtime: { sendMessage(m: unknown): Promise<Reply> } } }).chrome.runtime;
  const reply = await runtime.sendMessage(message);
  if (reply?.error === 'LOCKED' && lockedHandler) queueMicrotask(lockedHandler);
  return reply;
}

export function pageUrl(path: string): string {
  return (globalThis as unknown as { chrome: { runtime: { getURL(p: string): string } } }).chrome.runtime.getURL(path);
}

const ERRORS: Record<string, string> = {
  BAD_REQUEST: '入力の形が正しくありません',
  NOT_LOGGED_IN: 'ログインしてください',
  TOTP_SETUP_REQUIRED: '先に認証アプリ（TOTP）を登録してください',
  LOCKED: 'ロックされています。マスターパスワードで解除してください',
  BAD_PASSWORD: 'マスターパスワードが違います',
  BAD_CODE: 'コードが違います',
  CODE_REQUIRED: '今の認証アプリのコードか、回復コードを入れてください',
  RATE_LIMITED: '失敗が続いたので、しばらく待ってください',
  STEP_UP_REQUIRED: '先に認証アプリのコードで再確認してください',
  KEY_EXISTS: '鍵はもう作ってあります',
  CONFLICT: 'ほかの操作とぶつかりました。状態を読み直してください',
  NOT_ADMIN: '管理者だけができる操作です',
  NOT_ALLOWED: 'このアカウントは使えません（ロールがないか、削除済み）',
  LOGIN_CANCELLED: 'ログインを中止しました',
  LOGIN_FAILED: 'ログインに失敗しました',
  NETWORK: 'サーバーにつながりません',
  ADMIN_NOT_READY: '管理者の準備がまだです',
  PASSWORD_REQUIRED: 'この操作にはマスターパスワードが要ります。ロックしてから、マスターパスワードで解除してください',
  BAD_PASSCODE: 'パスコードが違います',
  QUICK_UNLOCK_CLEARED: '5回間違えたので、パスコードを消しました。マスターパスワードで解除してください',
  NO_QUICK_UNLOCK: 'パスコードは使えません。マスターパスワードで解除してください',
  ROLLBACK_DETECTED: 'サーバーが古い状態を返しました。同期を止めています',
  UNREADABLE: 'このアイテムは読めません',
  TOO_LARGE: 'アイテムが大きすぎます',
  VAULT_NOT_READY: 'まだ Vault を開けていません',
  MEMBER_MISMATCH: 'サーバーの応答が、ログインした人と食い違っています',
};

export function errorText(code: string | undefined): string {
  return ERRORS[code ?? ''] ?? `エラー（${code ?? '不明'}）`;
}

// 回復コードの残りが少ないときの知らせ（3以下で勧め、0なら強く勧める）
export function recoveryNotice(remaining: unknown): string | null {
  if (typeof remaining !== 'number') return null;
  if (remaining === 0) return '回復コードが残っていません。すぐに認証アプリ（TOTP）を作り直してください';
  if (remaining <= 3) return `回復コードの残りが ${remaining} 個です。認証アプリ（TOTP）の作り直しをおすすめします`;
  return null;
}
