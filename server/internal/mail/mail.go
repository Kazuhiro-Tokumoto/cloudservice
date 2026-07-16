// Package mail はユーザー間の内部メールを保存する。
// 件名・本文はクライアント側で暗号化されており(ファイルと同じ E2E 方式)、
// サーバーは暗号文と宛先などのメタ情報しか持たない。
// メールは受信者の受信箱コピーと送信者の送信済みコピーとして 2 通保存され、
// それぞれ各ユーザーの保存容量(クォータ)に算入される。
package mail

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

// Attachment はメールの添付ファイル。内容はメール鍵で暗号化されている。
type Attachment struct {
	Name string `json:"name"`
	Size int64  `json:"size"` // 復号後のサイズ(表示用)
	// Data はメール鍵で AES-GCM 暗号化した内容 (base64)。一覧では省略される。
	Data string `json:"data,omitempty"`
}

// Message は 1 通のメール(のあるユーザーから見たコピー)。
type Message struct {
	ID        string    `json:"id"`
	Folder    string    `json:"folder"` // "inbox" | "sent"
	From      string    `json:"from"`
	To        string    `json:"to"`
	CreatedAt time.Time `json:"created_at"`
	// EncSubject / EncBody はメール鍵で AES-GCM 暗号化された件名と本文。
	EncSubject string `json:"enc_subject"`
	EncBody    string `json:"enc_body,omitempty"`
	// Attachments は添付ファイル(内容もメール鍵で暗号化済み)。
	Attachments []Attachment `json:"attachments,omitempty"`
	// WrappedKey はこのコピーの持ち主の公開鍵で包んだメール鍵。
	WrappedKey string `json:"wrapped_key"`
	// Size はディスク上のサイズ(一覧表示用に List が設定する)。
	Size int64 `json:"size,omitempty"`
}

var idRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ErrNotFound はメールが存在しない場合のエラー。
var ErrNotFound = errors.New("メールが見つかりません")

// Store は data/mail/<ユーザー名>/<ID>.json としてメールを保存する。
type Store struct {
	mu  sync.Mutex
	dir string
}

// NewStore はメール保存ルートを作成する。
func NewStore(dataDir string) (*Store, error) {
	dir := filepath.Join(dataDir, "mail")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

func (s *Store) path(owner, id string) (string, error) {
	if !idRe.MatchString(id) {
		return "", ErrNotFound
	}
	return filepath.Join(s.dir, owner, id+".json"), nil
}

// Save は owner のメールボックスにメッセージを保存する。
func (s *Store) Save(owner string, m Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.path(owner, m.ID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o600)
}

// List は owner の folder("inbox" か "sent")のメール一覧を新しい順で返す。
// 本文(EncBody)は含めない。
func (s *Store) List(owner, folder string) ([]Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(filepath.Join(s.dir, owner))
	if err != nil {
		if os.IsNotExist(err) {
			return []Message{}, nil
		}
		return nil, err
	}
	out := []Message{}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.dir, owner, e.Name()))
		if err != nil {
			continue
		}
		var m Message
		if json.Unmarshal(b, &m) != nil || m.Folder != folder {
			continue
		}
		m.EncBody = ""
		// 添付は名前とサイズだけ残して中身は落とす(一覧を軽くするため)
		for i := range m.Attachments {
			m.Attachments[i].Data = ""
		}
		m.Size = int64(len(b))
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// Get は owner のメール 1 通を本文込みで返す。
func (s *Store) Get(owner, id string) (Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.path(owner, id)
	if err != nil {
		return Message{}, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return Message{}, ErrNotFound
	}
	var m Message
	if err := json.Unmarshal(b, &m); err != nil {
		return Message{}, err
	}
	return m, nil
}

// Delete は owner のメール 1 通を削除する。
func (s *Store) Delete(owner, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.path(owner, id)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil {
		return ErrNotFound
	}
	return nil
}

// Usage は owner のメールボックスの合計サイズ(バイト)を返す。
func (s *Store) Usage(owner string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(filepath.Join(s.dir, owner))
	if err != nil {
		return 0
	}
	var total int64
	for _, e := range entries {
		if info, err := e.Info(); err == nil && !e.IsDir() {
			total += info.Size()
		}
	}
	return total
}
