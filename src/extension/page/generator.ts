// パスワードの自動作成のパネル（仕様書「パスワード生成」）。文字数はスライダー、文字種と紛らわしい文字の除外はトグル。
// 作った値は、このページのメモリと入力欄にだけ置く。「使う」を押したときだけ、パスワードの欄に入れる。

import { generatePassword, passwordAlphabetSize, passwordEntropyBits, type PasswordOptions } from '../../client/password.ts';
import { el } from '../shared/ui.ts';

const MIN_LENGTH = 8;
const MAX_LENGTH = 64;
const DEFAULT_LENGTH = 20;

function toggle(label: string, checked: boolean, onChange: () => void): { node: HTMLElement; on: () => boolean } {
  const box = el('input', { type: 'checkbox' });
  box.checked = checked;
  box.style.width = 'auto';
  box.addEventListener('change', onChange);
  return { node: el('label', { className: 'row' }, box, el('span', { text: label })), on: () => box.checked };
}

export function generatorPanel(onUse: (password: string) => void, onClose: () => void): HTMLElement {
  const slider = el('input', { type: 'range' });
  slider.min = String(MIN_LENGTH);
  slider.max = String(MAX_LENGTH);
  slider.value = String(DEFAULT_LENGTH);
  const lengthText = el('span', { className: 'muted' });
  const preview = el('p', { className: 'secret' });
  const strength = el('p', { className: 'muted' });
  let current = '';

  const lower = toggle('英小文字（a-z）', true, () => regenerate());
  const upper = toggle('英大文字（A-Z）', true, () => regenerate());
  const digits = toggle('数字（0-9）', true, () => regenerate());
  const symbols = toggle('記号（!@#$ など）', true, () => regenerate());
  const ambiguous = toggle('紛らわしい文字（0 O 1 l I）を除く', false, () => regenerate());

  const use = el('button', { text: '使う', type: 'button' });
  const again = el('button', { text: '作り直す', className: 'secondary', type: 'button' });
  const close = el('button', { text: '閉じる', className: 'secondary', type: 'button' });

  function options(): PasswordOptions {
    return { length: Number(slider.value), lower: lower.on(), upper: upper.on(), digits: digits.on(), symbols: symbols.on(), excludeAmbiguous: ambiguous.on() };
  }

  function regenerate(): void {
    const o = options();
    lengthText.textContent = `${o.length} 文字`;
    try {
      current = generatePassword(o);
      preview.textContent = current;
      preview.className = 'secret';
      strength.textContent = `強度：約 ${Math.floor(passwordEntropyBits(o.length!, passwordAlphabetSize(o)))} ビット`;
      use.disabled = false;
    } catch {
      // 文字種がすべて切られている、などで作れない
      current = '';
      preview.textContent = '文字種を1つ以上選んでください。';
      preview.className = 'error';
      strength.textContent = '';
      use.disabled = true;
    }
  }

  slider.addEventListener('input', () => regenerate());
  again.addEventListener('click', () => regenerate());
  use.addEventListener('click', () => {
    if (current !== '') onUse(current);
  });
  close.addEventListener('click', () => onClose());
  regenerate();

  return el(
    'div',
    { className: 'generator' },
    preview,
    strength,
    el('label', { className: 'field' }, el('span', { text: '文字数 ', className: 'muted' }), lengthText, slider),
    lower.node,
    upper.node,
    digits.node,
    symbols.node,
    ambiguous.node,
    el('div', { className: 'row' }, use, again, close),
  );
}
