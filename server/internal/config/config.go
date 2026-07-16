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
	// CertFile / KeyFile を両方指定すると CertDir/CertName より優先して
	// そのパスの証明書を直接読み込む(Let's Encrypt の live ディレクトリ指定などに)。
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	// DataDir はユーザーデータ(ファイル・ユーザー情報)の保存先
	DataDir string `json:"data_dir"`
	// WebDir はビルド済みクライアント(client/dist)のパス。空なら静的配信しない。
	WebDir string `json:"web_dir"`
	// SessionHours はログイントークンの有効時間(時間)。0 なら 168 (7日)。
	// 期限が切れると再ログイン(パスワード入力)が必要になる。
	SessionHours int `json:"session_hours"`
	// MaxUploadMB は 1 ファイルの最大アップロードサイズ(MB)。0 なら 1024。
	MaxUploadMB int64 `json:"max_upload_mb"`
	// QuotaMB は 1 ユーザーが使える合計容量(MB)。ファイルとメールの両方を含む。
	// 0 なら 10240 (10GB)。
	QuotaMB int64 `json:"quota_mb"`
	// CertCheckMinutes は証明書ファイルを再読み込みする間隔(分)。0 なら 60。
	// certbot が証明書を更新すると、次の確認時に再起動なしで反映される。
	CertCheckMinutes int `json:"cert_check_minutes"`
}

// Default はデフォルト設定を返す。
func Default() Config {
	return Config{
		Addr:         ":40000",
		CertDir:      "certs",
		CertName:     "",
		DataDir:      "data",
		WebDir:       "web",
		SessionHours: 168, // 7 日

		MaxUploadMB:  1024,
		QuotaMB:      10240, // 10GB
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
		cfg.SessionHours = 168 // 7 日
	}
	if cfg.MaxUploadMB <= 0 {
		cfg.MaxUploadMB = 1024
	}
	if cfg.QuotaMB <= 0 {
		cfg.QuotaMB = 10240
	}
	if cfg.CertCheckMinutes <= 0 {
		cfg.CertCheckMinutes = 60
	}
	return cfg, nil
}

// CertFiles は証明書と秘密鍵のパスを返す。未設定なら ok=false(HTTP 起動)。
func (c Config) CertFiles() (certFile, keyFile string, ok bool) {
	if c.CertFile != "" && c.KeyFile != "" {
		return c.CertFile, c.KeyFile, true
	}
	if c.CertName == "" {
		return "", "", false
	}
	certFile = filepath.Join(c.CertDir, c.CertName+".crt")
	keyFile = filepath.Join(c.CertDir, c.CertName+".key")
	return certFile, keyFile, true
}
