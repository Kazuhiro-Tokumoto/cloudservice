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

	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/auth"
	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/files"
	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/store"
)

// Server は API サーバー本体。
type Server struct {
	Store      *store.Store
	Files      *files.Root
	Signer     *auth.TokenSigner
	SessionTTL time.Duration
	MaxUpload  int64  // バイト
	WebDir     string // ビルド済みクライアントの配信ディレクトリ(空なら配信しない)
}

// Handler はルーティング済みの http.Handler を返す。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// 認証不要
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("GET /s/{token}", s.handlePublicShare)

	// 認証必須
	mux.Handle("GET /api/me", s.authed(s.handleMe))
	mux.Handle("GET /api/files", s.authed(s.handleList))
	mux.Handle("GET /api/files/download", s.authed(s.handleDownload))
	mux.Handle("PUT /api/files/upload", s.authed(s.handleUpload))
	mux.Handle("DELETE /api/files", s.authed(s.handleDelete))
	mux.Handle("POST /api/files/mkdir", s.authed(s.handleMkdir))
	mux.Handle("GET /api/users", s.authed(s.handleUsers))
	mux.Handle("GET /api/shares", s.authed(s.handleShares))
	mux.Handle("POST /api/shares", s.authed(s.handleCreateShare))
	mux.Handle("DELETE /api/shares/{id}", s.authed(s.handleDeleteShare))
	mux.Handle("GET /api/shared/download", s.authed(s.handleSharedDownload))

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

// --- ファイル操作 ---

func (s *Server) handleList(w http.ResponseWriter, r *http.Request, username string) {
	entries, err := s.Files.List(username, r.URL.Query().Get("path"))
	if err != nil {
		fileError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

func serveFile(w http.ResponseWriter, r *http.Request, f *os.File, name string, size int64) {
	defer f.Close()
	ctype := mime.TypeByExtension(path.Ext(name))
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	if r.Method != http.MethodHead {
		io.Copy(w, f)
	}
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request, username string) {
	rel := r.URL.Query().Get("path")
	f, info, err := s.Files.Open(username, rel)
	if err != nil {
		fileError(w, err)
		return
	}
	serveFile(w, r, f, info.Name(), info.Size())
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request, username string) {
	rel := r.URL.Query().Get("path")
	body := http.MaxBytesReader(w, r.Body, s.MaxUpload)
	n, err := s.Files.Write(username, rel, body)
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeErr(w, http.StatusRequestEntityTooLarge, "ファイルサイズが上限を超えています")
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
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
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
		CreatedAt:  time.Now(),
	}
	if req.ExpiresDays > 0 {
		sh.ExpiresAt = time.Now().AddDate(0, 0, req.ExpiresDays)
	}
	if err := s.Store.AddShare(sh); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
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

// handleSharedDownload は自分宛に共有されたファイルをダウンロードする。
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
	serveFile(w, r, f, info.Name(), info.Size())
}

// handlePublicShare はリンク共有(認証不要)のダウンロード。
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
	serveFile(w, r, f, info.Name(), info.Size())
}
