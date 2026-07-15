クラウドサービスです
まぁ、身内だけなんでログイン権限渡すのは私からです

---

# クラウドサービス

身内向けのファイル保管・共有サービス。

- **server/** — Go 製サーバー(Debian 向け、HTTPS)
- **client/** — TypeScript + Vite 製 Web クライアント

## 機能

- **エンドツーエンド暗号化**: ファイルはブラウザ内で暗号化されてからアップロードされ、
  サーバー(管理者を含む)は中身を一切読めない。
- ログイン: パスワードから PBKDF2 で「認証キー(サーバーへ送信)」と
  「包み鍵(ブラウザ内のみ)」を導出。生パスワードは通信に乗らず、
  サーバーは認証キーの bcrypt ハッシュのみ保存する。
- ファイルの読み出し・書き込み・アップロード・ダウンロード・削除・フォルダ作成、
  テキストファイルはブラウザ上でそのまま編集できる
- ファイル共有(2 種類、どちらも E2E 暗号化のまま)
  - 特定ユーザーへの共有: ファイル鍵を相手の公開鍵で包み直す(相手だけが復号可能)
  - 共有リンク: 復号鍵を URL の `#` 以降に載せる(フラグメントはサーバーに
    送信されないため、リンクを知っている人だけが復号できる)
- パスワード変更は Web 画面から(マスター鍵は変わらないので既存ファイルはそのまま)
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
./userctl -data data passwd <ユーザー名> <新パスワード> # パスワードリセット(注意あり)
./userctl -data data del <ユーザー名>                 # 削除
./userctl -data data list                             # 一覧
```

**注意**: `userctl passwd` は緊急用のリセットです。E2E 暗号化のため、
この方法でリセットすると既存の暗号化ファイルは復号できなくなります
(次回ログイン時に鍵の作り直しを促されます)。
ファイルを残したままパスワードを変えるには Web 画面の「パスワード変更」を
使ってください(鍵を包み直すだけなのでファイルはそのまま読めます)。
同じ理由で、**ユーザーがパスワードを忘れるとそのユーザーのファイルは誰にも復元できません**。

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
| GET | `/api/keys` | 自分の鍵バンドル取得 |
| PUT | `/api/keys` | 鍵バンドル登録(`?force=1` で作り直し) |
| GET | `/api/keys/user/{name}` | 指定ユーザーの公開鍵取得 |
| POST | `/api/password` | パスワード変更(認証キー + 鍵バンドルを更新) |
| GET | `/api/shares` | 共有一覧(自分の共有 + 自分宛) |
| POST | `/api/shares` | 共有作成(`target_user` 省略でリンク共有) |
| DELETE | `/api/shares/{id}` | 共有解除 |
| GET | `/api/shared/download?id=` | 自分宛共有のダウンロード(暗号化ブロブ) |
| GET | `/api/public/share/{token}` | リンク共有のブロブ取得(認証不要) |
| GET | `/s/{token}#k=<鍵>` | 共有リンクの閲覧ページ(ブラウザ内で復号) |

`/api/*` は `Authorization: Bearer <トークン>` が必要(login と public/share を除く)。

## セキュリティ設計(エンドツーエンド暗号化)

```
パスワード ──PBKDF2-SHA256(31万回)──▶ [認証キー 32B | 包み鍵 32B]
                                        │            │
                              サーバーへ送信      ブラウザ内のみ
                              (bcrypt で保存)        │
                                                     ▼
                          ┌── 包み鍵で暗号化してサーバー保管 ──┐
                          │  マスター鍵(ランダム 32B)          │
                          │  ECDH P-256 秘密鍵                  │
                          └─────────────────────────────────────┘
ファイル: ランダムなファイル鍵で AES-256-GCM 暗号化。
          ファイル鍵はマスター鍵で包んでファイル先頭に埋め込む。
共有(ユーザー): ファイル鍵を相手の公開鍵で包み直す(ECDH + HKDF + AES-GCM)
共有(リンク):   ファイル鍵を URL のフラグメント(#k=)に載せる
```

- サーバーが保存するのは暗号文・bcrypt ハッシュ・暗号化済み鍵バンドルのみ。
  サーバーが漏洩/押収されてもファイルの中身とパスワードは守られる
- セッショントークンは HMAC-SHA256 署名付き・有効期限あり
- 各ユーザーは自分のホームディレクトリ配下のみアクセス可(パストラバーサル対策済み)
- 秘密鍵・ユーザーデータ(`certs/*.key`, `data/`)は .gitignore でコミット対象外

### 制限事項(割り切り)

- **パスワードを忘れるとファイルは復元不可能**(E2E 暗号化の宿命)
- ファイル名・フォルダ構成・サイズ・更新日時はサーバーから見える(中身のみ暗号化)
- 共有リンクの復号鍵は URL に含まれるため、リンクの取り扱い注意。
  リンクは作成時の URL 全体を渡すこと(サーバーに鍵が無いので再表示できない)
- Web 画面(サーバーが配るクライアント)を信頼する前提。
  サーバー運営者が悪意を持って改ざんしたクライアントを配れば鍵は盗める
  (身内運用ではサーバー管理者 = 信頼できる人なので実用上問題ない)
