import { randomBytes } from '../crypto/random.ts';

// 乱数は WebCrypto だけ。256 の剰余の偏りをなくすため、使えない値を捨てる。
export type PasswordOptions = {
  length?: number;
  lower?: boolean;
  upper?: boolean;
  digits?: boolean;
  symbols?: boolean;
  excludeAmbiguous?: boolean;
  alphabet?: string;
};

const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';
const SYMBOLS = '!@#$%^&*()-_=+[]{}:,.?';
const AMBIGUOUS = new Set('0O1lI');

export function passwordEntropyBits(length: number, alphabetSize: number): number {
  if (!Number.isSafeInteger(length) || length < 1 || !Number.isSafeInteger(alphabetSize) || alphabetSize < 2) {
    throw new RangeError('length and alphabet size must be valid');
  }
  return length * Math.log2(alphabetSize);
}

export function generatePassword(options: PasswordOptions = {}): string {
  const length = options.length ?? 20;
  if (!Number.isSafeInteger(length) || length < 1 || length > 65_532) throw new RangeError('invalid password length');
  if (options.alphabet !== undefined && [options.lower, options.upper, options.digits, options.symbols].some((v) => v !== undefined)) {
    throw new RangeError('alphabet and character classes cannot be combined');
  }
  let classes = options.alphabet !== undefined ? [options.alphabet] : [
    options.lower !== false ? LOWER : '',
    options.upper !== false ? UPPER : '',
    options.digits !== false ? DIGITS : '',
    options.symbols !== false ? SYMBOLS : '',
  ];
  classes = classes.filter((group) => group.length > 0);
  if (options.excludeAmbiguous) classes = classes.map((group) => [...group].filter((c) => !AMBIGUOUS.has(c)).join(''));
  if (classes.some((group) => group.length === 0) || length < classes.length) throw new RangeError('password cannot contain every enabled character class');
  const alphabet = classes.join('');
  if (alphabet.length < 2 || alphabet.length > 256 || new Set(alphabet).size !== alphabet.length || [...alphabet].some((c) => c.length !== 1)) {
    throw new RangeError('alphabet must contain 2 to 256 distinct ASCII characters');
  }
  const limit = Math.floor(256 / alphabet.length) * alphabet.length;
  for (;;) {
    const result: string[] = [];
    while (result.length < length) {
      const random = randomBytes(Math.min(4096, length - result.length + 32));
      for (const value of random) {
        if (value < limit) result.push(alphabet[value % alphabet.length]!);
        if (result.length === length) break;
      }
    }
    const password = result.join('');
    if (classes.every((group) => [...group].some((ch) => password.includes(ch)))) return password;
  }
}

