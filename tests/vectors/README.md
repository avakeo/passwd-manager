# 外部のテストベクタ

| ファイル | 使うテスト | 出典 | ライセンス | SHA-256 |
|---|---|---|---|---|
| wycheproof/ecdh_secp256r1_ecpoint_test.json | C-12 | https://github.com/C2SP/wycheproof/blob/e0df04e0c033f2d25c5051dd06230336c7822358/testvectors_v1/ecdh_secp256r1_ecpoint_test.json | Apache License 2.0（wycheproof/LICENSE に全文） | 648f16d077caf2400d02331ca51f44744c72c799830c8d0595d0b18b6dd9f886 |
| .cache/hpke-base-p256-sha256-aes256gcm.json（コミットしない） | C-15 | https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json の mode 0、KEM 0x0010・KDF 0x0001・AEAD 0x0002 | 下記のとおり未確認 | 元の test-vectors.json：61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6 |
| .cache/hpke-base-p256-sha256-aes128gcm.json（コミットしない） | C-15 | 同じ JSON の mode 0、KEM 0x0010・KDF 0x0001・AEAD 0x0001（RFC 9180 付録 A.3 と同じ組） | 同上 | 同上 |

## HPKE のベクタをコミットしない理由

CFRG のリポジトリには、ライセンスファイルがない。CONTRIBUTING.md に「IETF の Contribution として BCP 78、79 と IETF Trust Legal Provisions に従う。コードの部分は Simplified BSD」とあるだけで、テストベクタの JSON が「コードの部分」に当たるかを確認できなかった。そのため、決定事項（ライセンスが確認できないものは置かない）に従い、リポジトリには置かない。

C-15 を動かす前に、次のコマンドで取得する。コミットを固定した URL から取り、SHA-256 が一致しなければ止まる。

```
npm run vectors:fetch
```
