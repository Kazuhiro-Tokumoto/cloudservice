// Package push は Web Push 通知の購読管理と送信を行う。
// E2E 暗号化のため通知にメールや共有の中身は載せず、
// 「誰から届いたか」程度の定型文のみを送る。
package push

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	webpush "github.com/SherClockHolmes/webpush-go"
)

type persisted struct {
	VAPIDPublic  string                            `json:"vapid_public"`
	VAPIDPrivate string                            `json:"vapid_private"`
	Subs         map[string][]webpush.Subscription `json:"subs"`
}

// Store は購読情報と VAPID 鍵を data/push.json で永続化する。
type Store struct {
	mu   sync.Mutex
	path string
	data persisted
}

// Open は購読ストアを開く。VAPID 鍵が無ければ生成して保存する。
func Open(dataDir string) (*Store, error) {
	s := &Store{path: filepath.Join(dataDir, "push.json")}
	if b, err := os.ReadFile(s.path); err == nil {
		json.Unmarshal(b, &s.data)
	}
	if s.data.Subs == nil {
		s.data.Subs = map[string][]webpush.Subscription{}
	}
	if s.data.VAPIDPublic == "" {
		priv, pub, err := webpush.GenerateVAPIDKeys()
		if err != nil {
			return nil, err
		}
		s.data.VAPIDPrivate, s.data.VAPIDPublic = priv, pub
		if err := s.saveLocked(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) saveLocked() error {
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// PublicKey はクライアントが購読時に使う VAPID 公開鍵を返す。
func (s *Store) PublicKey() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.VAPIDPublic
}

// Subscribe はユーザーの購読を追加する(同じ endpoint は置き換え)。
func (s *Store) Subscribe(username string, sub webpush.Subscription) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	subs := s.data.Subs[username]
	out := subs[:0]
	for _, x := range subs {
		if x.Endpoint != sub.Endpoint {
			out = append(out, x)
		}
	}
	s.data.Subs[username] = append(out, sub)
	return s.saveLocked()
}

// Unsubscribe は endpoint の購読を解除する。
func (s *Store) Unsubscribe(username, endpoint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	subs := s.data.Subs[username]
	out := subs[:0]
	for _, x := range subs {
		if x.Endpoint != endpoint {
			out = append(out, x)
		}
	}
	s.data.Subs[username] = out
	return s.saveLocked()
}

// Notify はユーザーの全購読先に通知を送る(非同期・失敗しても本処理には影響しない)。
func (s *Store) Notify(username, title, body string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	subs := append([]webpush.Subscription(nil), s.data.Subs[username]...)
	pub, priv := s.data.VAPIDPublic, s.data.VAPIDPrivate
	s.mu.Unlock()
	if len(subs) == 0 {
		return
	}
	payload, _ := json.Marshal(map[string]string{"title": title, "body": body})
	go func() {
		for _, sub := range subs {
			resp, err := webpush.SendNotification(payload, &sub, &webpush.Options{
				Subscriber:      "mailto:admin@shudo-physics.com",
				VAPIDPublicKey:  pub,
				VAPIDPrivateKey: priv,
				TTL:             3600,
			})
			if err != nil {
				log.Printf("プッシュ通知の送信に失敗 (%s): %v", username, err)
				continue
			}
			resp.Body.Close()
			// 失効した購読は掃除する
			if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
				s.Unsubscribe(username, sub.Endpoint)
			}
		}
	}()
}
