// 暗号コアのエラー。
// DECRYPT_FAILED は、パスワードの誤り、改ざん、AAD の不一致、パディングの不正を区別せず1つにまとめる（C-07）。
// 理由を返し分けると、攻撃者がどこを変えれば通るかの手がかりになるため。

export type CryptoErrorCode =
  | 'DECRYPT_FAILED'
  | 'UNSUPPORTED_FORMAT'
  | 'MALFORMED'
  | 'INVALID_INPUT'
  | 'KDF_PARAMS_REJECTED'
  | 'ITEM_TOO_LARGE'
  | 'INVALID_PUBLIC_KEY'
  | 'PUBLIC_KEY_NOT_PINNED'
  | 'PUBLIC_KEY_MISMATCH';

const MESSAGES: Record<CryptoErrorCode, string> = {
  DECRYPT_FAILED: '復号に失敗しました',
  UNSUPPORTED_FORMAT: '対応していない形式です',
  MALFORMED: 'データの形が正しくありません',
  INVALID_INPUT: '入力が正しくありません',
  KDF_PARAMS_REJECTED: '鍵導出のパラメータが下限を満たしていません',
  ITEM_TOO_LARGE: 'アイテムが大きすぎます',
  INVALID_PUBLIC_KEY: '公開鍵が正しくありません',
  PUBLIC_KEY_NOT_PINNED: '公開鍵が固定されていません。照合して承認してください',
  PUBLIC_KEY_MISMATCH: '公開鍵が固定した値と一致しません。処理を中止しました',
};

export class CryptoError extends Error {
  readonly code: CryptoErrorCode;

  constructor(code: CryptoErrorCode) {
    // 元の例外（cause）は付けない。メッセージは code ごとに固定。
    super(MESSAGES[code]);
    this.name = 'CryptoError';
    this.code = code;
  }
}

export function decryptFailed(): CryptoError {
  return new CryptoError('DECRYPT_FAILED');
}
