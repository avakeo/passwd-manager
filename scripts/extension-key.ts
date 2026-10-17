// 拡張機能 ID を固定する鍵を作る（依存なし、node:crypto だけ）。
//   node --experimental-strip-types scripts/extension-key.ts <リポジトリの外の .pem のパス>
// 秘密鍵（.pem）は指定したパスにだけ書き、画面には出さない。リポジトリの中のパスと、既にあるファイルには書かない。
// 表示するのは manifest の key（公開鍵、秘密ではない）と、そこから決まる拡張機能 ID。
// ID の決め方は Chrome と同じ：公開鍵（SubjectPublicKeyInfo の DER）の SHA-256 の先頭16バイトを16進にし、0〜f を a〜p に置き換える。

import { createHash, generateKeyPairSync } from 'node:crypto';
import { existsSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export function extensionIdFromPublicKey(spkiDer: Uint8Array): string {
  const hex = createHash('sha256').update(spkiDer).digest('hex').slice(0, 32);
  return [...hex].map((c) => String.fromCharCode('a'.charCodeAt(0) + parseInt(c, 16))).join('');
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1]) {
  const out = process.argv[2];
  const repo = fileURLToPath(new URL('../', import.meta.url)).replace(/\\/g, '/').toLowerCase();
  const target = (out ?? '').replace(/\\/g, '/');
  if (!out || !target.endsWith('.pem')) {
    process.stderr.write('使い方：node --experimental-strip-types scripts/extension-key.ts <リポジトリの外の .pem のパス>\n');
    process.exitCode = 1;
  } else if (target.toLowerCase().startsWith(repo) || !/^([A-Za-z]:\/|\/)/.test(target)) {
    process.stderr.write('秘密鍵は、リポジトリの外の絶対パスに置く\n');
    process.exitCode = 1;
  } else if (existsSync(out)) {
    process.stderr.write('そのパスにはもうファイルがある。上書きしない\n');
    process.exitCode = 1;
  } else {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    writeFileSync(out, privateKey);
    process.stdout.write(`秘密鍵を書いた（画面には出さない）：${out}\n`);
    process.stdout.write(`manifestKey（extension.config.local.json に書く）：${Buffer.from(publicKey).toString('base64')}\n`);
    process.stdout.write(`拡張機能 ID：${extensionIdFromPublicKey(publicKey)}\n`);
  }
}
