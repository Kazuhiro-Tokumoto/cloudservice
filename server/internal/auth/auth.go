// Package auth は認証キーの導出とセッショントークンの発行・検証を行う。
//
// 認証・暗号化方式 (v2):
//   - クライアントはパスワードから PBKDF2-SHA256 で 64 バイトを導出し、
//     前半 32 バイトを「認証キー」としてサーバーに送信、
//     後半 32 バイトを「包み鍵」としてブラウザ内に留める(サーバーは知り得ない)。
//   - 包み鍵はユーザーのマスター鍵・秘密鍵の暗号化にのみ使われ、
//     ファイル本体はエンドツーエンド暗号化されるためサーバーでは読めない。
//   - サーバーは認証キーの bcrypt ハッシュのみを保存する。
//   - ログイン成功後は HMAC-SHA256 署名付きトークンを発行し、
//     ファイルの読み書きなど全 API はこのトークンで認可する。
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

// PBKDF2Iterations はクライアント(Web Crypto)と一致させること。
const PBKDF2Iterations = 310000

// DeriveAuthKey はユーザー名とパスワードから認証キー(hex 64 文字)を導出する。
// クライアント側 crypto.ts の deriveKeys と同じ計算:
// PBKDF2-SHA256(password, "cloudservice/v2:"+username, 310000 回, 64 バイト) の前半 32 バイト。
// 後半 32 バイト(包み鍵)はクライアント専用のため、サーバー側では導出しない。
func DeriveAuthKey(username, password string) string {
	salt := []byte("cloudservice/v2:" + username)
	bits := pbkdf2.Key([]byte(password), salt, PBKDF2Iterations, 64, sha256.New)
	return hex.EncodeToString(bits[:32])
}

// HashAuthKey は保存用に認証キーを bcrypt でハッシュ化する。
func HashAuthKey(authKey string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(authKey), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// VerifyAuthKey は認証キーが保存済みハッシュと一致するか検証する。
func VerifyAuthKey(storedHash, authKey string) bool {
	return bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(authKey)) == nil
}

// TokenSigner はセッショントークンの署名・検証を行う。
type TokenSigner struct {
	secret []byte
}

// LoadOrCreateSigner は dataDir/session.key からサーバー秘密鍵を読み込む。
// 無ければ乱数 32 バイトを生成して保存する(サーバー再起動後もトークンが有効)。
func LoadOrCreateSigner(dataDir string) (*TokenSigner, error) {
	path := filepath.Join(dataDir, "session.key")
	b, err := os.ReadFile(path)
	if err == nil && len(b) >= 32 {
		return &TokenSigner{secret: b}, nil
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, secret, 0o600); err != nil {
		return nil, err
	}
	return &TokenSigner{secret: secret}, nil
}

// Issue は username 用のトークンを発行する。形式: base64(username|expiresUnix|hmac)
func (s *TokenSigner) Issue(username string, ttl time.Duration) (token string, expires time.Time) {
	expires = time.Now().Add(ttl)
	payload := username + "|" + strconv.FormatInt(expires.Unix(), 10)
	mac := s.sign(payload)
	return base64.RawURLEncoding.EncodeToString([]byte(payload + "|" + mac)), expires
}

// Verify はトークンを検証し、有効ならユーザー名を返す。
func (s *TokenSigner) Verify(token string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", errors.New("不正なトークン形式")
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 {
		return "", errors.New("不正なトークン形式")
	}
	username, expStr, mac := parts[0], parts[1], parts[2]
	expected := s.sign(username + "|" + expStr)
	if !hmac.Equal([]byte(mac), []byte(expected)) {
		return "", errors.New("トークンの署名が不正")
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", errors.New("トークンの有効期限切れ")
	}
	return username, nil
}

func (s *TokenSigner) sign(payload string) string {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte(payload))
	return hex.EncodeToString(m.Sum(nil))
}

// NewShareToken は共有リンク用のランダムトークンを生成する。
func NewShareToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("乱数生成に失敗: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
