// userctl は管理者用の管理 CLI。
//
// 引数なしで起動すると対話型の管理コンソール(CUI)になり、
// プロンプトにコマンドを打ち込んで操作する。
// 引数を付ければ 1 コマンドだけ実行して終了する(スクリプト用)。
//
//	sudo ./userctl                  # 対話型コンソール
//	sudo ./userctl add taro pass123 # 1 コマンド実行
//
// サーバーが稼働中なら data ディレクトリ内の管理ソケット (admin.sock) 経由で
// 実行され、サーバーを止めずに即座に反映される。
// サーバーが停止中ならファイルを直接更新する(次回起動時に反映)。
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/auth"
	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/files"
	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/mail"
	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/store"
)

const helpText = `コマンド一覧:
  add <ユーザー名> <パスワード>       ユーザーを追加する
  passwd <ユーザー名> <新パスワード>   パスワードをリセットする(注意: 対象ユーザーの暗号化データは読めなくなる)
  del <ユーザー名>                    ユーザーを削除する(ファイルは残る)
  list                                ユーザー一覧(使用容量・鍵登録状況・作成日)
  status                              サーバー状態(稼働時間・証明書の有効期限など)
  help                                このヘルプを表示する
  exit                                コンソールを終了する
`

func main() {
	dataDir := flag.String("data", "data", "data ディレクトリのパス(config.json の data_dir と同じ場所)")
	flag.Parse()
	args := flag.Args()

	// 引数なし → 対話型コンソール
	if len(args) == 0 {
		runShell(*dataDir)
		return
	}
	// 引数あり → 1 コマンド実行(スクリプト用)
	if args[0] == "help" {
		fmt.Print(helpText)
		return
	}
	if err := dispatch(*dataDir, args, true); err != nil {
		fmt.Fprintln(os.Stderr, "エラー: "+err.Error())
		os.Exit(1)
	}
}

// --- 対話型コンソール ---

func runShell(dataDir string) {
	fmt.Println("クラウドサービス 管理コンソール")
	fmt.Println("help でコマンド一覧、exit で終了します。")
	in := bufio.NewScanner(os.Stdin)
	for {
		// プロンプトにサーバーの稼働状態を表示する
		mode := "停止中"
		if c := adminClient(filepath.Join(dataDir, "admin.sock")); c != nil {
			mode = "稼働中"
		}
		fmt.Printf("cloud[%s]> ", mode)
		if !in.Scan() {
			fmt.Println()
			return
		}
		fields := strings.Fields(in.Text())
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "exit", "quit":
			return
		case "help", "?":
			fmt.Print(helpText)
			continue
		}
		if err := dispatch(dataDir, fields, false); err != nil {
			fmt.Println("エラー: " + err.Error())
		}
	}
}

// dispatch はコマンドを実行する。サーバー稼働中は管理ソケット経由、停止中はファイル直接。
// announce が true のとき、どちらのモードで実行したかを表示する(1 コマンド実行用)。
func dispatch(dataDir string, args []string, announce bool) error {
	if c := adminClient(filepath.Join(dataDir, "admin.sock")); c != nil {
		if announce {
			fmt.Println("(稼働中のサーバーに接続しました: 即時反映されます)")
		}
		return runRemote(c, args)
	}
	if announce {
		fmt.Println("(サーバー停止中: ファイルを直接更新します。次回起動時に反映)")
	}
	return runLocal(dataDir, args)
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

func validate(username, password string) error {
	if !store.ValidUsername(username) {
		return errors.New("ユーザー名は英数字・ハイフン・アンダースコア 1〜32 文字にしてください")
	}
	if len(password) < 8 {
		return errors.New("パスワードは 8 文字以上にしてください")
	}
	return nil
}

func passwdWarning() {
	fmt.Println("注意: ファイルはエンドツーエンド暗号化されているため、この方法でリセットすると")
	fmt.Println("既存の暗号化ファイル・メールは復号できなくなります(次回ログイン時に鍵の作り直しが必要)。")
	fmt.Println("データを残したままパスワードを変えるには、Web 画面の「パスワード変更」を使ってください。")
}

func printUserTable(rows [][4]string) {
	fmt.Printf("%-20s %-12s %-10s %s\n", "ユーザー名", "使用容量", "鍵登録", "作成日")
	for _, r := range rows {
		fmt.Printf("%-20s %-12s %-10s %s\n", r[0], r[1], r[2], r[3])
	}
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

func adminCall(c *http.Client, method, path string, body any) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://cloudservice"+path, reqBody)
	if err != nil {
		return nil, err
	}
	res, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("サーバーとの通信に失敗: %w", err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return nil, errors.New(e.Error)
		}
		return nil, fmt.Errorf("サーバーエラー: HTTP %d", res.StatusCode)
	}
	return data, nil
}

func runRemote(c *http.Client, args []string) error {
	switch args[0] {
	case "add":
		if len(args) != 3 {
			return errors.New("使い方: add <ユーザー名> <パスワード>")
		}
		if err := validate(args[1], args[2]); err != nil {
			return err
		}
		if _, err := adminCall(c, "POST", "/admin/users",
			map[string]string{"username": args[1], "password": args[2]}); err != nil {
			return err
		}
		fmt.Printf("ユーザー %s を追加しました\n", args[1])

	case "passwd":
		if len(args) != 3 {
			return errors.New("使い方: passwd <ユーザー名> <新パスワード>")
		}
		if err := validate(args[1], args[2]); err != nil {
			return err
		}
		if _, err := adminCall(c, "POST", "/admin/passwd",
			map[string]string{"username": args[1], "password": args[2]}); err != nil {
			return err
		}
		fmt.Printf("ユーザー %s のパスワードをリセットしました\n", args[1])
		passwdWarning()

	case "del":
		if len(args) != 2 {
			return errors.New("使い方: del <ユーザー名>")
		}
		if _, err := adminCall(c, "DELETE", "/admin/users/"+args[1], nil); err != nil {
			return err
		}
		fmt.Printf("ユーザー %s を削除しました(ファイルは残ります)\n", args[1])

	case "list":
		data, err := adminCall(c, "GET", "/admin/users", nil)
		if err != nil {
			return err
		}
		var users []struct {
			Username  string    `json:"username"`
			CreatedAt time.Time `json:"created_at"`
			HasKeys   bool      `json:"has_keys"`
			UsedBytes int64     `json:"used_bytes"`
		}
		json.Unmarshal(data, &users)
		if len(users) == 0 {
			fmt.Println("ユーザーはいません")
			return nil
		}
		rows := make([][4]string, 0, len(users))
		for _, u := range users {
			keys := "未ログイン"
			if u.HasKeys {
				keys = "済み"
			}
			rows = append(rows, [4]string{
				u.Username, fmtBytes(u.UsedBytes), keys, u.CreatedAt.Format("2006-01-02"),
			})
		}
		printUserTable(rows)

	case "status":
		data, err := adminCall(c, "GET", "/admin/status", nil)
		if err != nil {
			return err
		}
		var st struct {
			Addr          string    `json:"addr"`
			HTTPS         bool      `json:"https"`
			UptimeSeconds int64     `json:"uptime_seconds"`
			CertNotAfter  time.Time `json:"cert_not_after"`
			UserCount     int       `json:"user_count"`
			QuotaBytes    int64     `json:"quota_bytes"`
		}
		json.Unmarshal(data, &st)
		up := time.Duration(st.UptimeSeconds) * time.Second
		fmt.Printf("サーバー:     稼働中 (%s, 起動から %s)\n", st.Addr, up.Round(time.Second))
		if st.HTTPS {
			remain := time.Until(st.CertNotAfter)
			mark := ""
			switch {
			case remain < 0:
				mark = " [警告] 期限切れ! certbot renew 等で更新してください"
			case remain < 7*24*time.Hour:
				mark = " [警告] まもなく期限切れ"
			}
			fmt.Printf("証明書:       %s まで有効 (残り %d 日)%s\n",
				st.CertNotAfter.Format("2006-01-02 15:04"), int(remain.Hours()/24), mark)
		} else {
			fmt.Println("証明書:       未設定 (平文 HTTP で稼働中)")
		}
		fmt.Printf("ユーザー数:   %d\n", st.UserCount)
		fmt.Printf("容量上限:     %s / ユーザー\n", fmtBytes(st.QuotaBytes))

	default:
		return fmt.Errorf("不明なコマンド %q です(help で一覧を表示)", args[0])
	}
	return nil
}

// --- サーバー停止中: ファイルを直接更新 ---

func runLocal(dataDir string, args []string) error {
	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("ストアを開けません: %w", err)
	}

	switch args[0] {
	case "add":
		if len(args) != 3 {
			return errors.New("使い方: add <ユーザー名> <パスワード>")
		}
		if err := validate(args[1], args[2]); err != nil {
			return err
		}
		hash, err := auth.HashAuthKey(auth.DeriveAuthKey(args[1], args[2]))
		if err != nil {
			return err
		}
		if err := st.AddUser(store.User{Username: args[1], AuthKeyHash: hash, CreatedAt: time.Now()}); err != nil {
			return err
		}
		fmt.Printf("ユーザー %s を追加しました\n", args[1])

	case "passwd":
		if len(args) != 3 {
			return errors.New("使い方: passwd <ユーザー名> <新パスワード>")
		}
		if err := validate(args[1], args[2]); err != nil {
			return err
		}
		hash, err := auth.HashAuthKey(auth.DeriveAuthKey(args[1], args[2]))
		if err != nil {
			return err
		}
		if err := st.SetAuthKeyHash(args[1], hash); err != nil {
			return err
		}
		fmt.Printf("ユーザー %s のパスワードをリセットしました\n", args[1])
		passwdWarning()

	case "del":
		if len(args) != 2 {
			return errors.New("使い方: del <ユーザー名>")
		}
		if err := st.DeleteUser(args[1]); err != nil {
			return err
		}
		fmt.Printf("ユーザー %s を削除しました(ファイルは残ります)\n", args[1])

	case "list":
		root, _ := files.NewRoot(dataDir)
		mailStore, _ := mail.NewStore(dataDir)
		users := st.Users()
		sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
		if len(users) == 0 {
			fmt.Println("ユーザーはいません")
			return nil
		}
		rows := make([][4]string, 0, len(users))
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
			rows = append(rows, [4]string{
				u.Username, fmtBytes(used), keys, u.CreatedAt.Format("2006-01-02"),
			})
		}
		printUserTable(rows)

	case "status":
		fmt.Println("サーバー:     停止中(管理ソケットに接続できません)")
		fmt.Printf("ユーザー数:   %d\n", len(st.ListUsers()))

	default:
		return fmt.Errorf("不明なコマンド %q です(help で一覧を表示)", args[0])
	}
	return nil
}
