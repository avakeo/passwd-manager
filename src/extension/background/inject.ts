// ページに注入する関数（chrome.scripting.executeScript の func）。注入するときは関数の本文だけが送られるので、
// この外の変数や import を使わない。どちらも、ページからのメッセージを受けない（E-08）。

// 確認のスクリプト：今のページのオリジンを返す。文書 ID は executeScript の戻り値に入る
export function probePage(): { origin: string } {
  return { origin: location.origin };
}

// 入力のスクリプト：1件分のユーザー名とパスワードだけを受け取る（E-09）。
//   - 入れる直前に、ページのオリジンが照合したものと同じか確かめる。違えば何もしない（E-13）
//   - 見えている欄だけに入れる（E-06）。2段階のログインで、パスワードの欄が見えていなければユーザー名だけ入れる
//   - 入れた欄の数だけを返す。値は返さない
export function fillLogin(expectedOrigin: string, username: string, password: string): { filled: number; reason?: 'origin' | 'no-field' } {
  if (location.origin !== expectedOrigin) return { filled: 0, reason: 'origin' };

  function visible(el: HTMLInputElement): boolean {
    if (el.disabled || el.readOnly) return false;
    if (typeof el.checkVisibility === 'function' && !el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })) return false;
    const style = getComputedStyle(el);
    if (style.display === 'none' || style.visibility !== 'visible' || Number(style.opacity) === 0) return false;
    const rect = el.getBoundingClientRect();
    if (rect.width < 4 || rect.height < 4) return false;
    // 画面の外（左や上へ大きくずらした欄）は見えていない。下へのスクロールで見える欄は入れてよい
    if (rect.right + scrollX <= 0 || rect.bottom + scrollY <= 0 || rect.left >= document.documentElement.scrollWidth) return false;
    return true;
  }

  function set(el: HTMLInputElement, value: string): void {
    // フレームワークの画面でも値の変化が伝わるよう、元の setter で入れてからイベントを送る
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
    if (setter) setter.call(el, value);
    else el.value = value;
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  }

  const inputs = [...document.querySelectorAll('input')].filter(visible);
  const passwordField = inputs.find((el) => el.type === 'password');
  const userLike = (el: HTMLInputElement) =>
    el.autocomplete === 'username' || el.type === 'email' || ((el.type === 'text' || el.type === 'tel') && /user|mail|login|account|id/i.test(`${el.name} ${el.id}`));
  let usernameField: HTMLInputElement | undefined;
  if (passwordField) {
    // パスワードの欄より前にある、ユーザー名らしい欄（なければ、すぐ前の文字の欄）
    const before = inputs.slice(0, inputs.indexOf(passwordField)).filter((el) => el.type !== 'password' && el.type !== 'hidden');
    usernameField = before.filter(userLike).pop() ?? before.filter((el) => el.type === 'text' || el.type === 'email').pop();
  } else {
    usernameField = inputs.find(userLike);
  }

  let filled = 0;
  if (usernameField && username !== '') {
    set(usernameField, username);
    filled += 1;
  }
  if (passwordField && password !== '') {
    set(passwordField, password);
    filled += 1;
  }
  return filled === 0 ? { filled, reason: 'no-field' } : { filled };
}
