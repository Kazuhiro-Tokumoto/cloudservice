// cloudserver はクラウドサービスのサーバー本体。
//
// 使い方:
//
//	cloudserver -config config.json
//
// 証明書は config の cert_dir フォルダに <cert_name>.crt / <cert_name>.key を置くか、
// cert_file / key_file で直接パスを指定すると HTTPS で起動する。
// 証明書は cert_check_minutes(既定 60 分)ごとに再読み込みされるため、
// certbot が更新しても再起動は不要。
//
// 起動中は data ディレクトリ内の admin.sock で管理 API を待ち受け、
// userctl からサーバーを止めずにユーザー管理ができる。
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/api"
	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/auth"
	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/certwatch"
	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/config"
	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/files"
	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/mail"
	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/push"
	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/store"
)

func main() {
	configPath := flag.String("config", "config.json", "設定ファイルのパス")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("設定の読み込みに失敗: %v", err)
	}

	st, err := store.Open(cfg.DataDir)
	if err != nil {
		log.Fatalf("ストアの初期化に失敗: %v", err)
	}
	root, err := files.NewRoot(cfg.DataDir)
	if err != nil {
		log.Fatalf("ファイルルートの初期化に失敗: %v", err)
	}
	mailStore, err := mail.NewStore(cfg.DataDir)
	if err != nil {
		log.Fatalf("メールストアの初期化に失敗: %v", err)
	}
	signer, err := auth.LoadOrCreateSigner(cfg.DataDir)
	if err != nil {
		log.Fatalf("セッション鍵の初期化に失敗: %v", err)
	}
	pushStore, err := push.Open(cfg.DataDir)
	if err != nil {
		log.Printf("プッシュ通知の初期化に失敗(通知なしで続行): %v", err)
		pushStore = nil
	}

	srv := &api.Server{
		Store:      st,
		Files:      root,
		Mail:       mailStore,
		Push:       pushStore,
		Signer:     signer,
		SessionTTL: time.Duration(cfg.SessionHours) * time.Hour,
		MaxUpload:  cfg.MaxUploadMB * 1024 * 1024,
		Quota:      cfg.QuotaMB * 1024 * 1024,
		WebDir:     cfg.WebDir,
	}

	// 証明書の読み込みと定期再読み込み
	var reloader *certwatch.Reloader
	if certFile, keyFile, ok := cfg.CertFiles(); ok {
		reloader, err = certwatch.New(certFile, keyFile)
		if err != nil {
			log.Fatalf("%v\n"+
				"cert_dir/cert_name 方式なら証明書フォルダに <名前>.crt と <名前>.key を置いてください"+
				"(自己署名は scripts/gen-cert.sh で作成可)。\n"+
				"cert_file/key_file 方式ならパスと読み取り権限を確認してください"+
				"(Let's Encrypt の privkey.pem は root しか読めないため sudo で起動すること)。", err)
		}
		go reloader.Watch(time.Duration(cfg.CertCheckMinutes) * time.Minute)
	}

	// 管理ソケット(userctl 用)。サーバー起動ユーザーのみアクセス可。
	start := time.Now()
	statusFn := func() map[string]any {
		m := map[string]any{
			"addr":           cfg.Addr,
			"https":          reloader != nil,
			"uptime_seconds": int64(time.Since(start).Seconds()),
		}
		if reloader != nil {
			m["cert_not_after"] = reloader.NotAfter()
		}
		return m
	}
	sockPath := filepath.Join(cfg.DataDir, "admin.sock")
	os.Remove(sockPath)
	adminLn, err := net.Listen("unix", sockPath)
	if err != nil {
		log.Fatalf("管理ソケットの作成に失敗: %v", err)
	}
	if err := os.Chmod(sockPath, 0o600); err != nil {
		log.Fatalf("管理ソケットの権限設定に失敗: %v", err)
	}
	go func() {
		if err := http.Serve(adminLn, srv.AdminHandler(statusFn)); err != nil {
			log.Printf("管理ソケットが停止しました: %v", err)
		}
	}()
	log.Printf("管理ソケット: %s (userctl が自動で使用します)", sockPath)

	httpServer := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	if reloader != nil {
		httpServer.TLSConfig = &tls.Config{GetCertificate: reloader.GetCertificate}
		log.Printf("HTTPS サーバーを %s で起動します (証明書の有効期限: %s / %d 分ごとに再読み込み)",
			cfg.Addr, reloader.NotAfter().Format("2006-01-02 15:04"), cfg.CertCheckMinutes)
		err = httpServer.ListenAndServeTLS("", "")
	} else {
		fmt.Fprintln(os.Stderr, "警告: 証明書が未設定のため平文 HTTP で起動します。本番環境では必ず証明書を設定してください。")
		log.Printf("HTTP サーバーを %s で起動します", cfg.Addr)
		err = httpServer.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("サーバーの起動に失敗: %v", err)
	}
}
