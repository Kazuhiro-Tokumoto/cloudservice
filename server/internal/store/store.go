// Package store はユーザー情報と共有情報を JSON ファイルで永続化する。
package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// User は登録ユーザー。パスワードそのものは保存せず、
// 認証キー(PBKDF2 派生値の前半)の bcrypt ハッシュのみを持つ。
type User struct {
	Username    string    `json:"username"`
	AuthKeyHash string    `json:"auth_key_hash"`
	CreatedAt   time.Time `json:"created_at"`
	// KeyBundle はクライアントが管理する鍵の入れ物(公開鍵 + 暗号化済み秘密鍵/マスター鍵)。
	// サーバーにとっては不透明な JSON で、public_key 以外は復号できない。
	KeyBundle json.RawMessage `json:"key_bundle,omitempty"`
}

// Share は共有エントリ。TargetUser が空なら誰でも開けるリンク共有。
type Share struct {
	ID         string    `json:"id"`          // 共有リンクのトークンを兼ねる
	Owner      string    `json:"owner"`       // 共有元ユーザー
	Path       string    `json:"path"`        // 共有元ユーザーのホームからの相対パス
	TargetUser string    `json:"target_user"` // 共有先ユーザー(空 = リンク共有)
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"` // ゼロ値 = 無期限
	// WrappedKey は共有先ユーザーの公開鍵で包んだファイル鍵(ユーザー共有のみ)。
	// リンク共有ではファイル鍵は URL のフラグメントに入り、サーバーには保存されない。
	WrappedKey string `json:"wrapped_key,omitempty"`
}

// Expired は共有が期限切れかどうかを返す。
func (s Share) Expired() bool {
	return !s.ExpiresAt.IsZero() && time.Now().After(s.ExpiresAt)
}

var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,32}$`)

// ValidUsername はユーザー名として使える文字列か検証する(ディレクトリ名にも使うため)。
func ValidUsername(name string) bool { return usernameRe.MatchString(name) }

// Store は data ディレクトリ配下の users.json / shares.json を管理する。
type Store struct {
	mu      sync.Mutex
	dataDir string
	users   map[string]User
	shares  map[string]Share
}

type persisted struct {
	Users  []User  `json:"users"`
	Shares []Share `json:"shares"`
}

// Open は dataDir から読み込んだ Store を返す。ファイルが無ければ空で開始する。
func Open(dataDir string) (*Store, error) {
	s := &Store{dataDir: dataDir, users: map[string]User{}, shares: map[string]Share{}}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	if err := s.loadFile("users.json", func(b []byte) error {
		var us []User
		if err := json.Unmarshal(b, &us); err != nil {
			return err
		}
		for _, u := range us {
			s.users[u.Username] = u
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if err := s.loadFile("shares.json", func(b []byte) error {
		var sh []Share
		if err := json.Unmarshal(b, &sh); err != nil {
			return err
		}
		for _, x := range sh {
			s.shares[x.ID] = x
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) loadFile(name string, fn func([]byte) error) error {
	b, err := os.ReadFile(filepath.Join(s.dataDir, name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return fn(b)
}

func (s *Store) saveLocked(name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(s.dataDir, name)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Store) saveUsersLocked() error {
	us := make([]User, 0, len(s.users))
	for _, u := range s.users {
		us = append(us, u)
	}
	return s.saveLocked("users.json", us)
}

func (s *Store) saveSharesLocked() error {
	sh := make([]Share, 0, len(s.shares))
	for _, x := range s.shares {
		sh = append(sh, x)
	}
	return s.saveLocked("shares.json", sh)
}

// ErrUserExists / ErrNotFound はストア操作のエラー。
var (
	ErrUserExists = errors.New("そのユーザー名は既に存在します")
	ErrNotFound   = errors.New("見つかりません")
)

// AddUser はユーザーを追加する。
func (s *Store) AddUser(u User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[u.Username]; ok {
		return ErrUserExists
	}
	s.users[u.Username] = u
	return s.saveUsersLocked()
}

// SetAuthKeyHash は既存ユーザーの認証キーを更新する(パスワード変更用)。
func (s *Store) SetAuthKeyHash(username, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	if !ok {
		return ErrNotFound
	}
	u.AuthKeyHash = hash
	s.users[username] = u
	return s.saveUsersLocked()
}

// ErrKeyBundleExists は上書きが許可されていないのに鍵バンドルが既にある場合のエラー。
var ErrKeyBundleExists = errors.New("鍵バンドルは既に登録されています")

// SetKeyBundle はユーザーの鍵バンドルを保存する。
// overwrite が false で既に登録済みの場合は ErrKeyBundleExists を返す。
func (s *Store) SetKeyBundle(username string, bundle json.RawMessage, overwrite bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	if !ok {
		return ErrNotFound
	}
	if len(u.KeyBundle) > 0 && !overwrite {
		return ErrKeyBundleExists
	}
	u.KeyBundle = bundle
	s.users[username] = u
	return s.saveUsersLocked()
}

// SetAuthAndKeyBundle はパスワード変更時に認証キーと鍵バンドルをまとめて更新する。
func (s *Store) SetAuthAndKeyBundle(username, hash string, bundle json.RawMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	if !ok {
		return ErrNotFound
	}
	u.AuthKeyHash = hash
	u.KeyBundle = bundle
	s.users[username] = u
	return s.saveUsersLocked()
}

// DeleteUser はユーザーを削除する。
func (s *Store) DeleteUser(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[username]; !ok {
		return ErrNotFound
	}
	delete(s.users, username)
	return s.saveUsersLocked()
}

// GetUser はユーザーを取得する。
func (s *Store) GetUser(username string) (User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	return u, ok
}

// Users は全ユーザーの情報を返す(管理用)。
func (s *Store) Users() []User {
	s.mu.Lock()
	defer s.mu.Unlock()
	us := make([]User, 0, len(s.users))
	for _, u := range s.users {
		us = append(us, u)
	}
	return us
}

// ListUsers は全ユーザー名を返す。
func (s *Store) ListUsers() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make([]string, 0, len(s.users))
	for n := range s.users {
		names = append(names, n)
	}
	return names
}

// AddShare は共有を追加する。
func (s *Store) AddShare(sh Share) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shares[sh.ID] = sh
	return s.saveSharesLocked()
}

// GetShare は共有を取得する(期限切れは false)。
func (s *Store) GetShare(id string) (Share, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sh, ok := s.shares[id]
	if !ok || sh.Expired() {
		return Share{}, false
	}
	return sh, true
}

// DeleteShare は共有を削除する。共有した本人(owner)に加えて、
// 共有された側(target_user)も自分宛の共有を削除(拒否)できる。
func (s *Store) DeleteShare(id, requester string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sh, ok := s.shares[id]
	if !ok || (sh.Owner != requester && sh.TargetUser != requester) {
		return ErrNotFound
	}
	delete(s.shares, id)
	return s.saveSharesLocked()
}

// UpdateSharePaths はファイル名変更に共有レコードのパスを追従させる。
// from と一致する共有、および from/ 配下(フォルダ名変更)の共有を to に書き換える。
func (s *Store) UpdateSharePaths(owner, from, to string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for id, sh := range s.shares {
		if sh.Owner != owner {
			continue
		}
		switch {
		case sh.Path == from:
			sh.Path = to
		case strings.HasPrefix(sh.Path, from+"/"):
			sh.Path = to + sh.Path[len(from):]
		default:
			continue
		}
		s.shares[id] = sh
		changed = true
	}
	if !changed {
		return nil
	}
	return s.saveSharesLocked()
}

// SharesByOwner は owner が作成した共有一覧を返す。
func (s *Store) SharesByOwner(owner string) []Share {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Share
	for _, sh := range s.shares {
		if sh.Owner == owner && !sh.Expired() {
			out = append(out, sh)
		}
	}
	return out
}

// SharesForUser は user 宛に共有されたエントリ一覧を返す。
func (s *Store) SharesForUser(user string) []Share {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Share
	for _, sh := range s.shares {
		if sh.TargetUser == user && !sh.Expired() {
			out = append(out, sh)
		}
	}
	return out
}
