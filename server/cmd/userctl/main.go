// userctl は管理者用のユーザー管理 CLI。
// 身内向けサービスのため、ユーザー登録はサーバー管理者がこのコマンドで行う。
//
// 使い方:
//
//	userctl -data data add <ユーザー名> <パスワード>     ユーザー追加
//	userctl -data data passwd <ユーザー名> <新パスワード> パスワード変更
//	userctl -data data del <ユーザー名>                  ユーザー削除
//	userctl -data data list                              ユーザー一覧
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/auth"
	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/store"
)

func usage() {
	fmt.Fprintln(os.Stderr, `使い方:
  userctl [-data <dataディレクトリ>] add <ユーザー名> <パスワード>
  userctl [-data <dataディレクトリ>] passwd <ユーザー名> <新パスワード>
  userctl [-data <dataディレクトリ>] del <ユーザー名>
  userctl [-data <dataディレクトリ>] list`)
	os.Exit(2)
}

func main() {
	dataDir := flag.String("data", "data", "data ディレクトリのパス(config.json の data_dir と同じ場所)")
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		usage()
	}

	st, err := store.Open(*dataDir)
	if err != nil {
		fatal("ストアを開けません: %v", err)
	}

	switch args[0] {
	case "add":
		if len(args) != 3 {
			usage()
		}
		username, password := args[1], args[2]
		if !store.ValidUsername(username) {
			fatal("ユーザー名は英数字・ハイフン・アンダースコア 1〜32 文字にしてください")
		}
		if len(password) < 8 {
			fatal("パスワードは 8 文字以上にしてください")
		}
		hash, err := auth.HashAuthKey(auth.DeriveAuthKey(username, password))
		if err != nil {
			fatal("ハッシュ化に失敗: %v", err)
		}
		if err := st.AddUser(store.User{Username: username, AuthKeyHash: hash, CreatedAt: time.Now()}); err != nil {
			fatal("%v", err)
		}
		fmt.Printf("ユーザー %s を追加しました\n", username)

	case "passwd":
		if len(args) != 3 {
			usage()
		}
		username, password := args[1], args[2]
		if len(password) < 8 {
			fatal("パスワードは 8 文字以上にしてください")
		}
		hash, err := auth.HashAuthKey(auth.DeriveAuthKey(username, password))
		if err != nil {
			fatal("ハッシュ化に失敗: %v", err)
		}
		if err := st.SetAuthKeyHash(username, hash); err != nil {
			fatal("%v", err)
		}
		fmt.Printf("ユーザー %s のパスワードを変更しました\n", username)
		fmt.Println("注意: ファイルはエンドツーエンド暗号化されているため、この方法でリセットすると")
		fmt.Println("既存の暗号化ファイルは復号できなくなります(次回ログイン時に鍵の作り直しが必要)。")
		fmt.Println("ファイルを残したままパスワードを変えるには、Web 画面の「パスワード変更」を使ってください。")

	case "del":
		if len(args) != 2 {
			usage()
		}
		if err := st.DeleteUser(args[1]); err != nil {
			fatal("%v", err)
		}
		fmt.Printf("ユーザー %s を削除しました(ファイルは残ります)\n", args[1])

	case "list":
		names := st.ListUsers()
		sort.Strings(names)
		for _, n := range names {
			fmt.Println(n)
		}

	default:
		usage()
	}
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}
