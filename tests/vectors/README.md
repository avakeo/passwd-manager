# 外部のテストベクタ

| ファイル | 使うテスト | 出典 | ライセンス | SHA-256 |
|---|---|---|---|---|
| wycheproof/ecdh_secp256r1_ecpoint_test.json | C-12 | https://github.com/C2SP/wycheproof/blob/e0df04e0c033f2d25c5051dd06230336c7822358/testvectors_v1/ecdh_secp256r1_ecpoint_test.json | Apache License 2.0（wycheproof/LICENSE に全文） | 648f16d077caf2400d02331ca51f44744c72c799830c8d0595d0b18b6dd9f886 |
| wycheproof/ecdsa_secp256r1_sha256_p1363_test.json | C-22 | https://github.com/C2SP/wycheproof/blob/e0df04e0c033f2d25c5051dd06230336c7822358/testvectors_v1/ecdsa_secp256r1_sha256_p1363_test.json | Apache License 2.0（wycheproof/LICENSE に全文） | 229dec841a9a5477cee5cf4790446c75b47dd18c1e63bc7fe51538077af6d299 |
| hpke/hpke-base-p256-sha256-aes256gcm.json | C-15 | https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json から、Base モード（mode 0）、KEM 0x0010・KDF 0x0001・AEAD 0x0002 の1件だけを抜き出したもの | 下記 | このファイル：8986462ab769b6c3fc805a7043f707229ccea1e58fd2d410ed1a59e43ade3106。元の test-vectors.json：61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6 |

## HPKE のテストベクタのライセンス

ライセンス表記は確認できなかった。出典のリポジトリにはライセンスファイルがなく、CONTRIBUTING.md には、中身が IETF の Contribution として BCP 78、79 と IETF Trust Legal Provisions に従うことが書かれている。IETF 文書由来のコード部品の扱いに準じると解釈して引用した。権利者から求めがあれば削除する。

引用したのは、C-15 に必要な1件（Base モード、KEM 0x0010・KDF 0x0001・AEAD 0x0002）だけで、値は変えていない。出典から作り直して照合するには、次のコマンドを使う（テストの実行には不要）。

```
npm run vectors:fetch
```

コミットを固定した URL から取得し、元の JSON の SHA-256 が上の値と一致しなければ止まる。
