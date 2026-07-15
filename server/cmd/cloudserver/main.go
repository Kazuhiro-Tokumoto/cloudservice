// cloudserver はクラウドサービスのサーバー本体。
//
// 使い方:
//
//	cloudserver -config config.json
//
// 証明書は config の cert_dir フォルダに <cert_name>.crt / <cert_name>.key を
// 置いて cert_name を指定すると HTTPS で起動する。
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/api"
	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/auth"
	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/config"
	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/files"
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
	signer, err := auth.LoadOrCreateSigner(cfg.DataDir)
	if err != nil {
		log.Fatalf("セッション鍵の初期化に失敗: %v", err)
	}

	srv := &api.Server{
		Store:      st,
		Files:      root,
		Signer:     signer,
		SessionTTL: time.Duration(cfg.SessionHours) * time.Hour,
		MaxUpload:  cfg.MaxUploadMB * 1024 * 1024,
		WebDir:     cfg.WebDir,
	}

	httpServer := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	if certFile, keyFile, ok := cfg.CertFiles(); ok {
		for _, f := range []string{certFile, keyFile} {
			if _, err := os.Stat(f); err != nil {
				log.Fatalf("証明書ファイルが見つかりません: %s\n"+
					"証明書フォルダ %q に %s.crt と %s.key を置いてください。\n"+
					"自己署名証明書は scripts/gen-cert.sh で作成できます。",
					f, cfg.CertDir, cfg.CertName, cfg.CertName)
			}
		}
		log.Printf("HTTPS サーバーを %s で起動します (証明書: %s)", cfg.Addr, certFile)
		err = httpServer.ListenAndServeTLS(certFile, keyFile)
	} else {
		fmt.Fprintln(os.Stderr, "警告: cert_name が未設定のため平文 HTTP で起動します。本番環境では必ず証明書を設定してください。")
		log.Printf("HTTP サーバーを %s で起動します", cfg.Addr)
		err = httpServer.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("サーバーの起動に失敗: %v", err)
	}
}
