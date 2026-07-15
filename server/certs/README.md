# 証明書フォルダ

このフォルダに TLS 証明書と秘密鍵を置きます。

- `<名前>.crt` — 証明書(PEM 形式)
- `<名前>.key` — 秘密鍵(PEM 形式)

`config.json` の `"cert_name"` に `<名前>` を設定すると、
サーバーがこのフォルダから `<名前>.crt` / `<名前>.key` を読み込んで HTTPS で起動します。

例: `certs/myserver.crt` と `certs/myserver.key` を置いた場合

```json
{ "cert_dir": "certs", "cert_name": "myserver" }
```

自己署名証明書は次のコマンドで作成できます:

```sh
./scripts/gen-cert.sh myserver <サーバーのホスト名またはIP>
```

Let's Encrypt などで取得した証明書を使う場合は、
`fullchain.pem` を `<名前>.crt`、`privkey.pem` を `<名前>.key` としてコピーしてください。

**注意**: `.key` ファイルは秘密鍵です。絶対に Git にコミットしないでください
(このリポジトリの .gitignore で除外済みです)。
