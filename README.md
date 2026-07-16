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
- **内部メール**: ユーザー名を宛先にしたメール(件名・本文とも E2E 暗号化、返信対応)
- **保存容量は 1 人 10GB**(`quota_mb` で変更可)。Google と同様に
  ファイルとメールの合計で計算され、画面に使用量バーが表示される
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

**Let's Encrypt を使う場合(mail.shudo-physics.com、sudo で起動する構成)**:
config.example.json は Let's Encrypt の証明書を直接参照する設定になっている。
`privkey.pem` は root しか読めないため、サーバーは sudo で起動する。

```json
{
  "cert_file": "/etc/letsencrypt/live/mail.shudo-physics.com/fullchain.pem",
  "key_file": "/etc/letsencrypt/live/mail.shudo-physics.com/privkey.pem"
}
```

```sh
sudo ./cloudserver -config config.json
```

**証明書の更新は自動で反映される。** サーバーは 1 時間ごと
(`cert_check_minutes` で変更可)に証明書ファイルを確認して再読み込みするため、
certbot が更新しても再起動は不要。期限切れが近い/切れている場合は
ログと `userctl status` で警告が出る。

(root で動かしたくない場合は `deploy/letsencrypt-deploy-hook.sh` で
証明書を `certs/` にコピーして一般ユーザーで動かす方式も使える)

### 3. 設定ファイル

```sh
cp config.example.json config.json
```

```json
{
  "addr": ":443",
  "cert_dir": "certs",
  "cert_name": "mail",
  "data_dir": "data",
  "web_dir": "web",
  "session_hours": 168,
  "max_upload_mb": 1024,
  "quota_mb": 10240
}
```

`cert_name` に証明書の名前(拡張子なし)を入れると HTTPS で起動する。
`addr: ":443"`(HTTPS 標準ポート)で待ち受けるので、DNS で mail.shudo-physics.com を
このサーバーの IP に向け、ファイアウォールで TCP 443 を開けておくこと。
ブラウザからは **`https://mail.shudo-physics.com/`** とポート番号なしでアクセスできる
(Web クライアントも同じサーバーが配信するので、これ 1 つで完結)。
443 は特権ポートのため、sudo(root)での起動が必要
(sudo 運用なら Let's Encrypt の直接参照と合わせてそのまま動く)。

### 4. 管理コンソール(管理者のみ)

`userctl` を引数なしで起動すると対話型の管理コンソール(CUI)になる:

```
$ sudo ./userctl -data data
クラウドサービス 管理コンソール
help でコマンド一覧、exit で終了します。
cloud[稼働中]> add taro pass1234
ユーザー taro を追加しました
cloud[稼働中]> list
ユーザー名            使用容量      鍵登録     作成日
taro                 0 B          未ログイン  2026-07-15
cloud[稼働中]> exit
```

プロンプトの `[稼働中]` / `[停止中]` はサーバーの状態。
**サーバーを止める必要はない** — 稼働中は data ディレクトリ内の管理ソケット
(`admin.sock`、起動ユーザーのみアクセス可)経由で実行され即座に反映される。
停止中はファイルを直接更新する(次回起動時に反映)。
sudo でサーバーを動かしている場合は userctl も sudo で実行すること。

#### コマンド一覧

| コマンド | 説明 |
| --- | --- |
| `add <ユーザー名> <パスワード>` | ユーザーを追加する(英数字・`-`・`_` で 1〜32 文字、パスワード 8 文字以上) |
| `passwd <ユーザー名> <新パスワード>` | パスワードをリセットする(**注意**: E2E 暗号化のため対象ユーザーの既存データは読めなくなる。データを残すなら Web 画面の「パスワード変更」を使う) |
| `del <ユーザー名>` | ユーザーを削除する(ファイルはディスクに残る) |
| `list` | ユーザー一覧を表示する(使用容量・鍵登録状況・作成日つき) |
| `status` | サーバー状態を表示する(稼働時間・証明書の有効期限と残り日数・ユーザー数・容量上限) |
| `help` | コマンド一覧を表示する |
| `exit` | コンソールを終了する |

スクリプトから使う場合は引数に直接コマンドを書けば 1 回だけ実行して終了する:

```sh
sudo ./userctl -data data add taro pass1234
sudo ./userctl -data data status
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

ブラウザで `https://<サーバー>/`(mail.shudo-physics.com なら
`https://mail.shudo-physics.com/`)を開くとログイン画面が表示される。

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
| GET | `/api/quota` | 使用容量と上限(ファイル + メール) |
| POST | `/api/mail` | メール送信(暗号化済み件名・本文 + 包んだ鍵×2) |
| GET | `/api/mail?folder=inbox\|sent` | メール一覧(本文なし) |
| GET | `/api/mail/{id}` | メール 1 通(本文込み) |
| DELETE | `/api/mail/{id}` | メール削除 |

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
メール:          1 通ごとのメール鍵で件名・本文を暗号化。
                 メール鍵は宛先の公開鍵(受信箱用)と自分の公開鍵(送信済み用)で包む
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
