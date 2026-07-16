// Package api は HTTP API のルーティングとハンドラーを提供する。
package api

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/auth"
	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/files"
	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/mail"
	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/push"
	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/store"
)

// Server は API サーバー本体。
type Server struct {
	Store      *store.Store
	Files      *files.Root
	Mail       *mail.Store
	Push       *push.Store // nil なら通知なしで動く
	Signer     *auth.TokenSigner
	SessionTTL time.Duration
	MaxUpload  int64  // バイト
	Quota      int64  // 1 ユーザーの合計容量(バイト)。ファイル + メール
	WebDir     string // ビルド済みクライアントの配信ディレクトリ(空なら配信しない)
}

// usage はユーザーの現在の使用容量(ファイル + メール)を返す。
func (s *Server) usage(username string) int64 {
	fu, _ := s.Files.Usage(username)
	return fu + s.Mail.Usage(username)
}

// Handler はルーティング済みの http.Handler を返す。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// 認証不要
	mux.HandleFunc("POST /api/login", s.handleLogin)
	// リンク共有の暗号化ブロブ取得。復号は Web クライアント(/s/... ページ)がブラウザ内で行う。
	mux.HandleFunc("GET /api/public/share/{token}", s.handlePublicShare)

	// 認証必須
	mux.Handle("GET /api/me", s.authed(s.handleMe))
	mux.Handle("GET /api/files", s.authed(s.handleList))
	mux.Handle("GET /api/files/download", s.authed(s.handleDownload))
	mux.Handle("PUT /api/files/upload", s.authed(s.handleUpload))
	mux.Handle("DELETE /api/files", s.authed(s.handleDelete))
	mux.Handle("POST /api/files/mkdir", s.authed(s.handleMkdir))
	mux.Handle("POST /api/files/rename", s.authed(s.handleRename))
	mux.Handle("GET /api/users", s.authed(s.handleUsers))
	mux.Handle("GET /api/keys", s.authed(s.handleGetKeys))
	mux.Handle("PUT /api/keys", s.authed(s.handlePutKeys))
	mux.Handle("GET /api/keys/user/{name}", s.authed(s.handleUserPublicKey))
	mux.Handle("POST /api/password", s.authed(s.handleChangePassword))
	mux.Handle("GET /api/shares", s.authed(s.handleShares))
	mux.Handle("POST /api/shares", s.authed(s.handleCreateShare))
	mux.Handle("DELETE /api/shares/{id}", s.authed(s.handleDeleteShare))
	mux.Handle("GET /api/shared/download", s.authed(s.handleSharedDownload))
	mux.Handle("GET /api/quota", s.authed(s.handleQuota))
	mux.Handle("GET /api/push/vapid", s.authed(s.handleVapidKey))
	mux.Handle("POST /api/push/subscribe", s.authed(s.handlePushSubscribe))
	mux.Handle("POST /api/push/unsubscribe", s.authed(s.handlePushUnsubscribe))
	mux.Handle("POST /api/mail", s.authed(s.handleSendMail))
	mux.Handle("GET /api/mail", s.authed(s.handleListMail))
	mux.Handle("GET /api/mail/{id}", s.authed(s.handleGetMail))
	mux.Handle("DELETE /api/mail/{id}", s.authed(s.handleDeleteMail))

	// 静的配信(Web クライアント)
	if s.WebDir != "" {
		if _, err := os.Stat(s.WebDir); err == nil {
			mux.Handle("GET /", spaHandler(s.WebDir))
		} else {
			log.Printf("web_dir %q が見つからないため静的配信は無効です", s.WebDir)
		}
	}
	return securityHeaders(mux)
}

// spaHandler は存在しないパスへのアクセスに index.html を返す(SPA 用)。
func spaHandler(dir string) http.Handler {
	fs := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := path.Clean(r.URL.Path)
		if p != "/" {
			if _, err := os.Stat(path.Join(dir, p)); err != nil {
				http.ServeFile(w, r, path.Join(dir, "index.html"))
				return
			}
		}
		fs.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

type ctxKey int

const userKey ctxKey = 0

// authed は Bearer トークンを検証し、ユーザー名を確定させるミドルウェア。
func (s *Server) authed(fn func(http.ResponseWriter, *http.Request, string)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := ""
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			token = strings.TrimPrefix(h, "Bearer ")
		} else {
			token = r.URL.Query().Get("token") // ダウンロードリンク用
		}
		username, err := s.Signer.Verify(token)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "認証が必要です: "+err.Error())
			return
		}
		if _, ok := s.Store.GetUser(username); !ok {
			writeErr(w, http.StatusUnauthorized, "ユーザーが存在しません")
			return
		}
		fn(w, r, username)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func fileError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, files.ErrBadPath):
		writeErr(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, files.ErrExists):
		writeErr(w, http.StatusConflict, err.Error())
	case os.IsNotExist(err):
		writeErr(w, http.StatusNotFound, "ファイルが見つかりません")
	default:
		writeErr(w, http.StatusInternalServerError, err.Error())
	}
}

// --- 認証 ---

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		AuthKey  string `json:"auth_key"` // SHA-256("username:password") hex
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "リクエストの解析に失敗")
		return
	}
	u, ok := s.Store.GetUser(req.Username)
	if !ok || !auth.VerifyAuthKey(u.AuthKeyHash, req.AuthKey) {
		// ユーザー有無を悟らせないため同一メッセージ
		writeErr(w, http.StatusUnauthorized, "ユーザー名または認証キーが違います")
		return
	}
	if err := s.Files.EnsureHome(u.Username); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	token, exp := s.Signer.Issue(u.Username, s.SessionTTL)
	writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"username":   u.Username,
		"expires_at": exp,
	})
}

func (s *Server) handleMe(w http.ResponseWriter, _ *http.Request, username string) {
	writeJSON(w, http.StatusOK, map[string]string{"username": username})
}

func (s *Server) handleUsers(w http.ResponseWriter, _ *http.Request, _ string) {
	writeJSON(w, http.StatusOK, s.Store.ListUsers())
}

// --- 鍵管理(サーバーは鍵バンドルを不透明データとして保管するだけで中身は復号できない) ---

const maxKeyBundleSize = 16 * 1024

func (s *Server) handleGetKeys(w http.ResponseWriter, _ *http.Request, username string) {
	u, ok := s.Store.GetUser(username)
	if !ok || len(u.KeyBundle) == 0 {
		writeErr(w, http.StatusNotFound, "鍵バンドルが未登録です")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(u.KeyBundle)
}

func (s *Server) handlePutKeys(w http.ResponseWriter, r *http.Request, username string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxKeyBundleSize))
	if err != nil || !json.Valid(body) {
		writeErr(w, http.StatusBadRequest, "鍵バンドルの形式が不正です")
		return
	}
	overwrite := r.URL.Query().Get("force") == "1"
	if err := s.Store.SetKeyBundle(username, body, overwrite); err != nil {
		if errors.Is(err, store.ErrKeyBundleExists) {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

func (s *Server) handleUserPublicKey(w http.ResponseWriter, r *http.Request, _ string) {
	name := r.PathValue("name")
	u, ok := s.Store.GetUser(name)
	if !ok || len(u.KeyBundle) == 0 {
		writeErr(w, http.StatusNotFound, "そのユーザーはまだ鍵を登録していません(一度もログインしていない可能性があります)")
		return
	}
	var bundle struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(u.KeyBundle, &bundle); err != nil || bundle.PublicKey == "" {
		writeErr(w, http.StatusNotFound, "公開鍵が見つかりません")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"username":   name,
		"public_key": bundle.PublicKey,
	})
}

// handleChangePassword は認証キーと鍵バンドルをまとめて更新する。
// 鍵の再包み(マスター鍵を新しい包み鍵で暗号化し直す)はクライアント側で行われるため、
// マスター鍵は変わらず既存ファイルはそのまま読める。
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, username string) {
	var req struct {
		NewAuthKey string          `json:"new_auth_key"`
		KeyBundle  json.RawMessage `json:"key_bundle"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxKeyBundleSize+4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "リクエストの解析に失敗")
		return
	}
	if len(req.NewAuthKey) != 64 || len(req.KeyBundle) == 0 {
		writeErr(w, http.StatusBadRequest, "新しい認証キーと鍵バンドルが必要です")
		return
	}
	hash, err := auth.HashAuthKey(req.NewAuthKey)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.Store.SetAuthAndKeyBundle(username, hash, req.KeyBundle); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "changed"})
}

// --- ファイル操作 ---

func (s *Server) handleList(w http.ResponseWriter, r *http.Request, username string) {
	entries, err := s.Files.List(username, r.URL.Query().Get("path"))
	if err != nil {
		fileError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

// serveFile はファイル(中身は暗号化済みブロブ)をそのまま送出する。
// limit > 0 なら先頭 limit バイトだけを返す(暗号化ヘッダーのみ読みたい場合用)。
func serveFile(w http.ResponseWriter, r *http.Request, f *os.File, name string, size, limit int64) {
	defer f.Close()
	if limit > 0 && limit < size {
		size = limit
	}
	ctype := mime.TypeByExtension(path.Ext(name))
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	if r.Method != http.MethodHead {
		io.CopyN(w, f, size)
	}
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request, username string) {
	rel := r.URL.Query().Get("path")
	f, info, err := s.Files.Open(username, rel)
	if err != nil {
		fileError(w, err)
		return
	}
	limit, _ := strconv.ParseInt(r.URL.Query().Get("limit"), 10, 64)
	serveFile(w, r, f, info.Name(), info.Size(), limit)
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request, username string) {
	rel := r.URL.Query().Get("path")

	// クォータ確認。同名ファイルの上書きは旧サイズ分を差し引いて計算する。
	remaining := s.Quota - s.usage(username)
	if info, err := s.Files.Stat(username, rel); err == nil && !info.IsDir() {
		remaining += info.Size()
	}
	if remaining <= 0 {
		writeErr(w, http.StatusRequestEntityTooLarge, "保存容量を使い切っています。不要なファイルやメールを削除してください")
		return
	}
	limit := s.MaxUpload
	quotaLimited := remaining < limit
	if quotaLimited {
		limit = remaining
	}

	body := http.MaxBytesReader(w, r.Body, limit)
	n, err := s.Files.Write(username, rel, body)
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			if quotaLimited {
				writeErr(w, http.StatusRequestEntityTooLarge, "保存容量が不足しています。不要なファイルやメールを削除してください")
			} else {
				writeErr(w, http.StatusRequestEntityTooLarge, "ファイルサイズが上限を超えています")
			}
			return
		}
		fileError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"path": rel, "size": n})
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request, username string) {
	if err := s.Files.Delete(username, r.URL.Query().Get("path")); err != nil {
		fileError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleMkdir(w http.ResponseWriter, r *http.Request, username string) {
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "リクエストの解析に失敗")
		return
	}
	if err := s.Files.Mkdir(username, req.Path); err != nil {
		fileError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "created"})
}

func (s *Server) handleRename(w http.ResponseWriter, r *http.Request, username string) {
	var req struct {
		From string `json:"from"`
		To   string `json:"to"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "リクエストの解析に失敗")
		return
	}
	if err := s.Files.Rename(username, req.From, req.To); err != nil {
		fileError(w, err)
		return
	}
	// 共有レコードのパスも新しい名前に追従させる(共有が切れないように)
	from, _ := files.Clean(req.From)
	to, _ := files.Clean(req.To)
	if err := s.Store.UpdateSharePaths(username, from, to); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "renamed"})
}

// --- 共有 ---

func (s *Server) handleShares(w http.ResponseWriter, _ *http.Request, username string) {
	mine := s.Store.SharesByOwner(username)
	received := s.Store.SharesForUser(username)
	if mine == nil {
		mine = []store.Share{}
	}
	if received == nil {
		received = []store.Share{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"mine": mine, "received": received})
}

func (s *Server) handleCreateShare(w http.ResponseWriter, r *http.Request, username string) {
	var req struct {
		Path        string `json:"path"`
		TargetUser  string `json:"target_user"`  // 空ならリンク共有
		ExpiresDays int    `json:"expires_days"` // 0 = 無期限
		WrappedKey  string `json:"wrapped_key"`  // 共有先の公開鍵で包んだファイル鍵
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "リクエストの解析に失敗")
		return
	}
	rel, err := files.Clean(req.Path)
	if err != nil || rel == "" {
		writeErr(w, http.StatusBadRequest, "共有するファイルのパスが不正です")
		return
	}
	info, err := s.Files.Stat(username, rel)
	if err != nil {
		fileError(w, err)
		return
	}
	if info.IsDir() {
		writeErr(w, http.StatusBadRequest, "現在共有できるのはファイルのみです")
		return
	}
	if req.TargetUser != "" {
		if _, ok := s.Store.GetUser(req.TargetUser); !ok {
			writeErr(w, http.StatusBadRequest, "共有先ユーザーが存在しません")
			return
		}
		if req.TargetUser == username {
			writeErr(w, http.StatusBadRequest, "自分自身には共有できません")
			return
		}
		// E2E 暗号化のため、共有先が復号できるよう包み直したファイル鍵が必須
		if req.WrappedKey == "" {
			writeErr(w, http.StatusBadRequest, "wrapped_key(共有先の公開鍵で包んだファイル鍵)が必要です")
			return
		}
	}
	id, err := auth.NewShareToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	sh := store.Share{
		ID:         id,
		Owner:      username,
		Path:       rel,
		TargetUser: req.TargetUser,
		WrappedKey: req.WrappedKey,
		CreatedAt:  time.Now(),
	}
	if req.ExpiresDays > 0 {
		sh.ExpiresAt = time.Now().AddDate(0, 0, req.ExpiresDays)
	}
	if err := s.Store.AddShare(sh); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if sh.TargetUser != "" {
		// プッシュ通知(ファイル名は載せない)
		s.Push.Notify(sh.TargetUser, "ファイル共有", username+" さんがファイルを共有しました")
	}
	resp := map[string]any{"share": sh}
	if sh.TargetUser == "" {
		resp["url"] = "/s/" + sh.ID
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleDeleteShare(w http.ResponseWriter, r *http.Request, username string) {
	if err := s.Store.DeleteShare(r.PathValue("id"), username); err != nil {
		writeErr(w, http.StatusNotFound, "共有が見つかりません")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleSharedDownload は自分宛に共有されたファイル(暗号化ブロブ)をダウンロードする。
// 復号は共有レコードの wrapped_key を使ってクライアント側で行う。
func (s *Server) handleSharedDownload(w http.ResponseWriter, r *http.Request, username string) {
	sh, ok := s.Store.GetShare(r.URL.Query().Get("id"))
	if !ok || sh.TargetUser != username {
		writeErr(w, http.StatusNotFound, "共有が見つかりません")
		return
	}
	f, info, err := s.Files.Open(sh.Owner, sh.Path)
	if err != nil {
		fileError(w, err)
		return
	}
	serveFile(w, r, f, info.Name(), info.Size(), 0)
}

// --- クォータ ---

func (s *Server) handleQuota(w http.ResponseWriter, _ *http.Request, username string) {
	writeJSON(w, http.StatusOK, map[string]int64{
		"used":  s.usage(username),
		"limit": s.Quota,
	})
}

// --- プッシュ通知 ---

func (s *Server) handleVapidKey(w http.ResponseWriter, _ *http.Request, _ string) {
	if s.Push == nil {
		writeErr(w, http.StatusServiceUnavailable, "プッシュ通知は無効です")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"public_key": s.Push.PublicKey()})
}

func (s *Server) handlePushSubscribe(w http.ResponseWriter, r *http.Request, username string) {
	if s.Push == nil {
		writeErr(w, http.StatusServiceUnavailable, "プッシュ通知は無効です")
		return
	}
	var sub webpush.Subscription
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&sub); err != nil || sub.Endpoint == "" {
		writeErr(w, http.StatusBadRequest, "購読情報の形式が不正です")
		return
	}
	if err := s.Push.Subscribe(username, sub); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "subscribed"})
}

func (s *Server) handlePushUnsubscribe(w http.ResponseWriter, r *http.Request, username string) {
	if s.Push == nil {
		writeErr(w, http.StatusServiceUnavailable, "プッシュ通知は無効です")
		return
	}
	var req struct {
		Endpoint string `json:"endpoint"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "リクエストの解析に失敗")
		return
	}
	if err := s.Push.Unsubscribe(username, req.Endpoint); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "unsubscribed"})
}

// --- メール(件名・本文・添付とも E2E 暗号化。サーバーは暗号文と宛先しか知らない) ---

// 添付を含むため上限は大きめ(base64 + 暗号化のオーバーヘッド込み)
const maxMailSize = 64 * 1024 * 1024

func (s *Server) handleSendMail(w http.ResponseWriter, r *http.Request, username string) {
	var req struct {
		To         string `json:"to"`
		EncSubject string `json:"enc_subject"`
		EncBody    string `json:"enc_body"`
		// メール鍵を宛先の公開鍵で包んだもの / 自分の公開鍵で包んだもの(送信済み用)
		WrappedKeyTo   string            `json:"wrapped_key_to"`
		WrappedKeySelf string            `json:"wrapped_key_self"`
		Attachments    []mail.Attachment `json:"attachments"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxMailSize)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "リクエストの解析に失敗(添付が大きすぎる可能性があります)")
		return
	}
	if req.To == "" || req.EncSubject == "" || req.EncBody == "" ||
		req.WrappedKeyTo == "" || req.WrappedKeySelf == "" {
		writeErr(w, http.StatusBadRequest, "宛先・件名・本文・包んだ鍵がすべて必要です")
		return
	}
	if req.To == username {
		writeErr(w, http.StatusBadRequest, "自分自身には送れません")
		return
	}
	if _, ok := s.Store.GetUser(req.To); !ok {
		writeErr(w, http.StatusBadRequest, "宛先ユーザーが存在しません")
		return
	}
	for _, a := range req.Attachments {
		if a.Name == "" || a.Data == "" {
			writeErr(w, http.StatusBadRequest, "添付ファイルの形式が不正です")
			return
		}
	}

	// メールも保存容量(10GB)に含める。受信者・送信者の両方を確認する。
	size := int64(len(req.EncSubject) + len(req.EncBody) + len(req.WrappedKeyTo))
	for _, a := range req.Attachments {
		size += int64(len(a.Data))
	}
	if s.usage(req.To)+size > s.Quota {
		writeErr(w, http.StatusRequestEntityTooLarge, "宛先ユーザーの保存容量が不足しています")
		return
	}
	if s.usage(username)+size > s.Quota {
		writeErr(w, http.StatusRequestEntityTooLarge, "保存容量が不足しています。不要なファイルやメールを削除してください")
		return
	}

	id, err := auth.NewShareToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	now := time.Now()
	base := mail.Message{
		ID:          id,
		From:        username,
		To:          req.To,
		CreatedAt:   now,
		EncSubject:  req.EncSubject,
		EncBody:     req.EncBody,
		Attachments: req.Attachments,
	}
	inbox := base
	inbox.Folder = "inbox"
	inbox.WrappedKey = req.WrappedKeyTo
	sent := base
	sent.Folder = "sent"
	sent.WrappedKey = req.WrappedKeySelf
	if err := s.Mail.Save(req.To, inbox); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.Mail.Save(username, sent); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// プッシュ通知(中身は載せない)
	s.Push.Notify(req.To, "新着メール", username+" さんからメールが届きました")
	writeJSON(w, http.StatusOK, map[string]string{"id": id})
}

func (s *Server) handleListMail(w http.ResponseWriter, r *http.Request, username string) {
	folder := r.URL.Query().Get("folder")
	if folder != "sent" {
		folder = "inbox"
	}
	msgs, err := s.Mail.List(username, folder)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, msgs)
}

func (s *Server) handleGetMail(w http.ResponseWriter, r *http.Request, username string) {
	m, err := s.Mail.Get(username, r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) handleDeleteMail(w http.ResponseWriter, r *http.Request, username string) {
	if err := s.Mail.Delete(username, r.PathValue("id")); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handlePublicShare はリンク共有の暗号化ブロブを返す(認証不要)。
// ファイル鍵は共有 URL のフラグメント(#k=...)にありサーバーへは送られないため、
// サーバー(とこのエンドポイント単体)では復号できない。
func (s *Server) handlePublicShare(w http.ResponseWriter, r *http.Request) {
	sh, ok := s.Store.GetShare(r.PathValue("token"))
	if !ok || sh.TargetUser != "" {
		writeErr(w, http.StatusNotFound, "共有が見つかりません")
		return
	}
	f, info, err := s.Files.Open(sh.Owner, sh.Path)
	if err != nil {
		fileError(w, err)
		return
	}
	serveFile(w, r, f, info.Name(), info.Size(), 0)
}
