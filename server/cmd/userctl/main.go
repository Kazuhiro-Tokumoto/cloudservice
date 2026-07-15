// userctl は管理者用の管理 CLI。
// 身内向けサービスのため、ユーザー登録はサーバー管理者がこのコマンドで行う。
//
// サーバーが稼働中なら data ディレクトリ内の管理ソケット (admin.sock) 経由で
// 実行され、サーバーを止めずに即座に反映される。
// サーバーが停止中ならファイルを直接更新する(次回起動時に反映)。
//
// 使い方:
//
//	userctl [-data <dataディレクトリ>] add <ユーザー名> <パスワード>     ユーザー追加
//	userctl [-data <dataディレクトリ>] passwd <ユーザー名> <新パスワード> パスワードリセット
//	userctl [-data <dataディレクトリ>] del <ユーザー名>                  ユーザー削除
//	userctl [-data <dataディレクトリ>] list                              ユーザー一覧(使用容量つき)
//	userctl [-data <dataディレクトリ>] status                            サーバー状態
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/auth"
	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/files"
	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/mail"
	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/store"
)

func usage() {
	fmt.Fprintln(os.Stderr, `使い方:
  userctl [-data <dataディレクトリ>] add <ユーザー名> <パスワード>      ユーザー追加
  userctl [-data <dataディレクトリ>] passwd <ユーザー名> <新パスワード>  パスワードリセット(注意: 対象ユーザーの暗号化データは読めなくなる)
  userctl [-data <dataディレクトリ>] del <ユーザー名>                   ユーザー削除(ファイルは残る)
  userctl [-data <dataディレクトリ>] list                               ユーザー一覧(使用容量つき)
  userctl [-data <dataディレクトリ>] status                             サーバー状態(稼働時間・証明書期限など)

サーバー稼働中は管理ソケット経由で即時反映、停止中はファイルを直接更新します。`)
	os.Exit(2)
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func fmtBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KB", "MB", "GB", "TB"}
	v := float64(n) / 1024
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

func validate(username, password string) {
	if !store.ValidUsername(username) {
		fatal("ユーザー名は英数字・ハイフン・アンダースコア 1〜32 文字にしてください")
	}
	if len(password) < 8 {
		fatal("パスワードは 8 文字以上にしてください")
	}
}

func passwdWarning() {
	fmt.Println("注意: ファイルはエンドツーエンド暗号化されているため、この方法でリセットすると")
	fmt.Println("既存の暗号化ファイル・メールは復号できなくなります(次回ログイン時に鍵の作り直しが必要)。")
	fmt.Println("データを残したままパスワードを変えるには、Web 画面の「パスワード変更」を使ってください。")
}

func main() {
	dataDir := flag.String("data", "data", "data ディレクトリのパス(config.json の data_dir と同じ場所)")
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		usage()
	}

	if c := adminClient(filepath.Join(*dataDir, "admin.sock")); c != nil {
		runRemote(c, args)
		return
	}
	runLocal(*dataDir, args)
}

// --- 稼働中サーバーへの接続(管理ソケット経由) ---

func adminClient(sock string) *http.Client {
	if _, err := os.Stat(sock); err != nil {
		return nil
	}
	c := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}
	// 生きているか確認(サーバー異常終了でソケットファイルだけ残っている場合がある)
	res, err := c.Get("http://cloudservice/admin/status")
	if err != nil {
		return nil
	}
	res.Body.Close()
	return c
}

func adminCall(c *http.Client, method, path string, body any) map[string]json.RawMessage {
	var reqBody io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reqBody = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, "http://cloudservice"+path, reqBody)
	res, err := c.Do(req)
	if err != nil {
		fatal("サーバーとの通信に失敗: %v", err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			fatal("%s", e.Error)
		}
		fatal("サーバーエラー: HTTP %d", res.StatusCode)
	}
	var out map[string]json.RawMessage
	json.Unmarshal(data, &out)
	// 配列レスポンス用に生データも入れておく
	if out == nil {
		out = map[string]json.RawMessage{}
	}
	out["_raw"] = data
	return out
}

func runRemote(c *http.Client, args []string) {
	fmt.Println("(稼働中のサーバーに接続しました: 即時反映されます)")
	switch args[0] {
	case "add":
		if len(args) != 3 {
			usage()
		}
		validate(args[1], args[2])
		adminCall(c, "POST", "/admin/users", map[string]string{"username": args[1], "password": args[2]})
		fmt.Printf("ユーザー %s を追加しました\n", args[1])

	case "passwd":
		if len(args) != 3 {
			usage()
		}
		validate(args[1], args[2])
		adminCall(c, "POST", "/admin/passwd", map[string]string{"username": args[1], "password": args[2]})
		fmt.Printf("ユーザー %s のパスワードをリセットしました\n", args[1])
		passwdWarning()

	case "del":
		if len(args) != 2 {
			usage()
		}
		adminCall(c, "DELETE", "/admin/users/"+args[1], nil)
		fmt.Printf("ユーザー %s を削除しました(ファイルは残ります)\n", args[1])

	case "list":
		res := adminCall(c, "GET", "/admin/users", nil)
		var users []struct {
			Username  string    `json:"username"`
			CreatedAt time.Time `json:"created_at"`
			HasKeys   bool      `json:"has_keys"`
			UsedBytes int64     `json:"used_bytes"`
		}
		json.Unmarshal(res["_raw"], &users)
		if len(users) == 0 {
			fmt.Println("ユーザーはいません")
			return
		}
		fmt.Printf("%-20s %-12s %-10s %s\n", "ユーザー名", "使用容量", "鍵登録", "作成日")
		for _, u := range users {
			keys := "未ログイン"
			if u.HasKeys {
				keys = "済み"
			}
			fmt.Printf("%-20s %-12s %-10s %s\n",
				u.Username, fmtBytes(u.UsedBytes), keys, u.CreatedAt.Format("2006-01-02"))
		}

	case "status":
		res := adminCall(c, "GET", "/admin/status", nil)
		var st struct {
			Addr          string    `json:"addr"`
			HTTPS         bool      `json:"https"`
			UptimeSeconds int64     `json:"uptime_seconds"`
			CertNotAfter  time.Time `json:"cert_not_after"`
			UserCount     int       `json:"user_count"`
			QuotaBytes    int64     `json:"quota_bytes"`
		}
		json.Unmarshal(res["_raw"], &st)
		up := time.Duration(st.UptimeSeconds) * time.Second
		fmt.Printf("サーバー:     稼働中 (%s, 起動から %s)\n", st.Addr, up.Round(time.Second))
		if st.HTTPS {
			remain := time.Until(st.CertNotAfter)
			mark := ""
			switch {
			case remain < 0:
				mark = " ★期限切れ! certbot renew 等で更新してください"
			case remain < 7*24*time.Hour:
				mark = " ★まもなく期限切れ"
			}
			fmt.Printf("証明書:       %s まで有効 (残り %d 日)%s\n",
				st.CertNotAfter.Format("2006-01-02 15:04"), int(remain.Hours()/24), mark)
		} else {
			fmt.Println("証明書:       未設定 (平文 HTTP で稼働中)")
		}
		fmt.Printf("ユーザー数:   %d\n", st.UserCount)
		fmt.Printf("容量上限:     %s / ユーザー\n", fmtBytes(st.QuotaBytes))

	default:
		usage()
	}
}

// --- サーバー停止中: ファイルを直接更新 ---

func runLocal(dataDir string, args []string) {
	fmt.Println("(サーバー停止中: ファイルを直接更新します。次回起動時に反映)")
	st, err := store.Open(dataDir)
	if err != nil {
		fatal("ストアを開けません: %v", err)
	}

	switch args[0] {
	case "add":
		if len(args) != 3 {
			usage()
		}
		validate(args[1], args[2])
		hash, err := auth.HashAuthKey(auth.DeriveAuthKey(args[1], args[2]))
		if err != nil {
			fatal("ハッシュ化に失敗: %v", err)
		}
		if err := st.AddUser(store.User{Username: args[1], AuthKeyHash: hash, CreatedAt: time.Now()}); err != nil {
			fatal("%v", err)
		}
		fmt.Printf("ユーザー %s を追加しました\n", args[1])

	case "passwd":
		if len(args) != 3 {
			usage()
		}
		validate(args[1], args[2])
		hash, err := auth.HashAuthKey(auth.DeriveAuthKey(args[1], args[2]))
		if err != nil {
			fatal("ハッシュ化に失敗: %v", err)
		}
		if err := st.SetAuthKeyHash(args[1], hash); err != nil {
			fatal("%v", err)
		}
		fmt.Printf("ユーザー %s のパスワードをリセットしました\n", args[1])
		passwdWarning()

	case "del":
		if len(args) != 2 {
			usage()
		}
		if err := st.DeleteUser(args[1]); err != nil {
			fatal("%v", err)
		}
		fmt.Printf("ユーザー %s を削除しました(ファイルは残ります)\n", args[1])

	case "list":
		root, _ := files.NewRoot(dataDir)
		mailStore, _ := mail.NewStore(dataDir)
		users := st.Users()
		sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
		if len(users) == 0 {
			fmt.Println("ユーザーはいません")
			return
		}
		fmt.Printf("%-20s %-12s %-10s %s\n", "ユーザー名", "使用容量", "鍵登録", "作成日")
		for _, u := range users {
			var used int64
			if root != nil {
				fu, _ := root.Usage(u.Username)
				used = fu
			}
			if mailStore != nil {
				used += mailStore.Usage(u.Username)
			}
			keys := "未ログイン"
			if len(u.KeyBundle) > 0 {
				keys = "済み"
			}
			fmt.Printf("%-20s %-12s %-10s %s\n",
				u.Username, fmtBytes(used), keys, u.CreatedAt.Format("2006-01-02"))
		}

	case "status":
		fmt.Println("サーバー:     停止中(管理ソケットに接続できません)")
		fmt.Printf("ユーザー数:   %d\n", len(st.ListUsers()))

	default:
		usage()
	}
}
