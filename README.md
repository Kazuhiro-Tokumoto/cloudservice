クラウドサービスです
まぁ、身内だけなんでログイン権限渡すのは私からです

---

# クラウドサービス

身内向けのファイル保管・共有サービス。

- **server/** — Go 製サーバー(Debian 向け、HTTPS)
- **client/** — TypeScript + Vite 製 Web クライアント

## 機能

- ログイン: ユーザー名とパスワードをブラウザ内で SHA-256 ハッシュ化し、
  その値を秘密鍵(認証キー)としてサーバーに送信。生パスワードは通信に乗らない。
  サーバー側は認証キーを更に bcrypt でハッシュ化して保存する。
- ファイルの読み出し・書き込み・アップロード・ダウンロード・削除・フォルダ作成
- ファイル共有(2 種類)
  - 特定ユーザーへの共有(相手のログイン後の画面に表示される)
  - 共有リンク(URL を知っていれば誰でもダウンロード可、有効期限も設定可)
- 通信は HTTPS(TLS)。証明書は `server/certs/` フォルダに置き、名前を指定するだけ。
- ユーザー登録は管理者が `userctl` コマンドで行う(勝手に登録できない)

## サーバーのセットアップ(Debian)

### 1. ビルド

Go 1.24 以上が必要(`apt install golang` または https://go.dev/dl/ から)。

```sh
cd server
go build -o cloudserver ./cmd/cloudserver
go build -o userctl ./cmd/userctl
```

### 2. 証明書を置く

`certs/` フォルダに `<名前>.crt` と `<名前>.key` を置く。
自己署名証明書なら:

```sh
./scripts/gen-cert.sh myserver <サーバーのホスト名またはIP>
```

Let's Encrypt 等の証明書を使う場合は `fullchain.pem` → `<名前>.crt`、
`privkey.pem` → `<名前>.key` としてコピーする。

### 3. 設定ファイル

```sh
cp config.example.json config.json
```

```json
{
  "addr": ":8443",
  "cert_dir": "certs",
  "cert_name": "myserver",
  "data_dir": "data",
  "web_dir": "web",
  "session_hours": 24,
  "max_upload_mb": 1024
}
```

`cert_name` に証明書の名前(拡張子なし)を入れると HTTPS で起動する。

### 4. ユーザーを作る(管理者のみ)

```sh
./userctl -data data add <ユーザー名> <パスワード>   # 追加
./userctl -data data passwd <ユーザー名> <新パスワード> # パスワード変更
./userctl -data data del <ユーザー名>                 # 削除
./userctl -data data list                             # 一覧
```

### 5. Web クライアントを配置して起動

```sh
# クライアントをビルド(Node.js 20+ が必要。別マシンでビルドしてコピーでも OK)
cd ../client
npm install
npm run build
cp -r dist ../server/web

cd ../server
./cloudserver -config config.json
```

ブラウザで `https://<サーバー>:8443/` を開くとログイン画面が表示される。

### systemd で常駐させる場合

`server/deploy/cloudservice.service` にユニットファイルと手順コメントがある。

```sh
sudo cp deploy/cloudservice.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cloudservice
```

## クライアント開発

```sh
cd client
npm install
npm run dev   # http://localhost:5173 (API は localhost:8443 へプロキシ)
```

HTTPS のサーバーに向ける場合は `API_TARGET=https://localhost:8443 npm run dev`。

## API 概要

| メソッド | パス | 説明 |
| --- | --- | --- |
| POST | `/api/login` | ログイン(`{username, auth_key}` → トークン) |
| GET | `/api/files?path=` | ファイル一覧 |
| GET | `/api/files/download?path=` | ファイル読み出し |
| PUT | `/api/files/upload?path=` | ファイル書き込み(本文 = 内容) |
| DELETE | `/api/files?path=` | 削除 |
| POST | `/api/files/mkdir` | フォルダ作成 |
| GET | `/api/shares` | 共有一覧(自分の共有 + 自分宛) |
| POST | `/api/shares` | 共有作成(`target_user` 省略でリンク共有) |
| DELETE | `/api/shares/{id}` | 共有解除 |
| GET | `/api/shared/download?id=` | 自分宛共有のダウンロード |
| GET | `/s/{token}` | 共有リンクのダウンロード(認証不要) |

`/api/*` は `Authorization: Bearer <トークン>` が必要。

## セキュリティ設計

- パスワード → `SHA-256("ユーザー名:パスワード")` = 認証キー(クライアント側で計算)
- サーバーは `bcrypt(認証キー)` のみ保存。データファイルが漏れてもパスワードは復元困難
- セッショントークンは HMAC-SHA256 署名付き・有効期限あり
- 各ユーザーは自分のホームディレクトリ配下のみアクセス可(パストラバーサル対策済み)
- 秘密鍵・ユーザーデータ(`certs/*.key`, `data/`)は .gitignore でコミット対象外
