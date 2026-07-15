// Package config はサーバー設定の読み込みを行う。
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config はサーバーの設定。config.json から読み込む。
type Config struct {
	// Addr は待ち受けアドレス (例 ":8443")
	Addr string `json:"addr"`
	// CertDir は証明書フォルダのパス
	CertDir string `json:"cert_dir"`
	// CertName を指定すると CertDir/<CertName>.crt と CertDir/<CertName>.key を使って HTTPS で起動する。
	// 空の場合は平文 HTTP で起動する(開発用。本番では必ず証明書を指定すること)。
	CertName string `json:"cert_name"`
	// DataDir はユーザーデータ(ファイル・ユーザー情報)の保存先
	DataDir string `json:"data_dir"`
	// WebDir はビルド済みクライアント(client/dist)のパス。空なら静的配信しない。
	WebDir string `json:"web_dir"`
	// SessionHours はログイントークンの有効時間(時間)。0 なら 24。
	SessionHours int `json:"session_hours"`
	// MaxUploadMB は 1 ファイルの最大アップロードサイズ(MB)。0 なら 1024。
	MaxUploadMB int64 `json:"max_upload_mb"`
}

// Default はデフォルト設定を返す。
func Default() Config {
	return Config{
		Addr:         ":8443",
		CertDir:      "certs",
		CertName:     "",
		DataDir:      "data",
		WebDir:       "web",
		SessionHours: 24,
		MaxUploadMB:  1024,
	}
}

// Load は path の JSON を読み込む。ファイルが無ければデフォルトを返す。
func Load(path string) (Config, error) {
	cfg := Default()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("config %s の解析に失敗: %w", path, err)
	}
	if cfg.SessionHours <= 0 {
		cfg.SessionHours = 24
	}
	if cfg.MaxUploadMB <= 0 {
		cfg.MaxUploadMB = 1024
	}
	return cfg, nil
}

// CertFiles は証明書と秘密鍵のパスを返す。CertName が空なら ok=false。
func (c Config) CertFiles() (certFile, keyFile string, ok bool) {
	if c.CertName == "" {
		return "", "", false
	}
	certFile = filepath.Join(c.CertDir, c.CertName+".crt")
	keyFile = filepath.Join(c.CertDir, c.CertName+".key")
	return certFile, keyFile, true
}
