// Package certwatch は TLS 証明書の定期的な再読み込みを行う。
// certbot などが証明書を更新しても、サーバーを再起動せずに
// 新しい証明書が自動で使われるようになる。
package certwatch

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"sync"
	"time"
)

// Reloader は証明書を保持し、定期的にファイルから再読み込みする。
type Reloader struct {
	certFile, keyFile string

	mu   sync.RWMutex
	cert *tls.Certificate
}

// New は証明書を読み込んで Reloader を返す。読み込めなければエラー。
func New(certFile, keyFile string) (*Reloader, error) {
	r := &Reloader{certFile: certFile, keyFile: keyFile}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Reloader) load() error {
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("証明書の読み込みに失敗 (%s): %w", r.certFile, err)
	}
	// 有効期限の確認用に leaf を解析しておく
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("証明書の解析に失敗: %w", err)
	}
	cert.Leaf = leaf
	r.mu.Lock()
	r.cert = &cert
	r.mu.Unlock()
	return nil
}

// GetCertificate は tls.Config.GetCertificate に渡すコールバック。
func (r *Reloader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert, nil
}

// NotAfter は現在使用中の証明書の有効期限を返す。
func (r *Reloader) NotAfter() time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert.Leaf.NotAfter
}

// Watch は interval ごとに証明書ファイルを再読み込みし続ける(goroutine で呼ぶ)。
// 期限が切れていたり近い場合はログで警告する。
func (r *Reloader) Watch(interval time.Duration) {
	for {
		time.Sleep(interval)
		old := r.NotAfter()
		if err := r.load(); err != nil {
			log.Printf("証明書の再読み込みに失敗(現在の証明書を使い続けます): %v", err)
		} else if na := r.NotAfter(); !na.Equal(old) {
			log.Printf("証明書を再読み込みしました。新しい有効期限: %s", na.Format("2006-01-02 15:04"))
		}
		switch remain := time.Until(r.NotAfter()); {
		case remain < 0:
			log.Printf("警告: 証明書の有効期限が切れています(%s)。certbot renew 等で更新してください",
				r.NotAfter().Format("2006-01-02"))
		case remain < 7*24*time.Hour:
			log.Printf("警告: 証明書の有効期限が近づいています(残り %d 日)", int(remain.Hours()/24))
		}
	}
}
