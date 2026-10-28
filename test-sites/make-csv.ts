// CSV インポートを手で確かめるための、架空のログインの CSV（Chrome の形式）を作る。
// メールアドレスは example.com（例のために予約されたドメイン）、パスワードは毎回 WebCrypto の乱数で作る使い捨ての値。
//
//   node --experimental-strip-types test-sites/make-csv.ts <workers.dev のサブドメイン> > test-sites/sample.local.csv
//
// *.local.csv は .gitignore に入っている（自分のサブドメインが入るので、コミットしない）。
// 取り込んだ後は、ファイルを消す。

const subdomain = process.argv[2] ?? 'example';
if (!/^[a-z0-9-]{1,63}$/.test(subdomain)) throw new Error('サブドメインは英小文字・数字・ハイフンだけ');

const site = (name: 'a' | 'b') => `https://teampw-site-${name}.${subdomain}.workers.dev/`;

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_!@#%$';
if (ALPHABET.length !== 64) throw new Error('ALPHABET は64文字');
function password(length = 20): string {
  // 256 は64で割り切れるので、b % 64 に偏りはない
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return [...bytes].map((b) => ALPHABET[b % 64]).join('');
}

function cell(value: string): string {
  return /[",\r\n]/.test(value) ? `"${value.replaceAll('"', '""')}"` : value;
}

// [name, url, username, password, note, totp]。totp は Chrome の形式にない列で、取り込まない（値がある行は警告）
const rows: string[][] = [
  ['テスト site-a', site('a'), 'a-tester@example.com', password(), 'site-a のふつうのログイン（/simple、/hidden、/two-step で使う）', ''],
  ['テスト site-a（2人目）', site('a'), 'a-second@example.com', password(), '同じサイトに2つのアカウント。ポップアップに2件出る', ''],
  ['テスト site-b', site('b'), 'b-tester@example.com', password(), 'site-b のログイン。site-a のページでは出ない（E-04）', ''],
  ['メモに記号', site('b'), 'b-memo@example.com', password(), 'カンマ, "引用符" と\n改行を含むメモ（M-01）', ''],
  ['TOTP の列に値', site('a'), 'a-totp@example.com', password(), '取り込まない列に値があるので警告が出る', 'JBSWY3DPEHPK3PXP'],
  ['http のサイト', `http://teampw-site-a.${subdomain}.workers.dev/`, 'a-http@example.com', password(), 'https でないので読めなかった行になる', ''],
  ['テスト site-a', site('a'), 'a-tester@example.com', password(), '最初の行と重なる（パスワードは違う）。初めはチェックが外れている', ''],
];

const lines = [['name', 'url', 'username', 'password', 'note', 'totp'], ...rows].map((r) => r.map(cell).join(','));
process.stdout.write(lines.join('\n') + '\n');
