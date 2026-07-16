package api

// 管理 API。data ディレクトリ内の Unix ドメインソケット (admin.sock) でのみ待ち受け、
// サーバーを止めずに userctl からユーザー管理などを行うために使う。
// ソケットのパーミッションはサーバー起動ユーザー(sudo 運用なら root)のみアクセス可。

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/auth"
	"github.com/kazuhiro-tokumoto/cloudservice/server/internal/store"
)

// AdminUser は管理 API が返すユーザー情報。
type AdminUser struct {
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	HasKeys   bool      `json:"has_keys"` // 一度ログインして暗号鍵を登録済みか
	UsedBytes int64     `json:"used_bytes"`
}

// AdminHandler は管理ソケット用のハンドラーを返す。
// status はサーバー状態(稼働時間・証明書の期限など)を返すコールバック。
func (s *Server) AdminHandler(status func() map[string]any) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/status", func(w http.ResponseWriter, _ *http.Request) {
		m := status()
		m["user_count"] = len(s.Store.ListUsers())
		m["quota_bytes"] = s.Quota
		writeJSON(w, http.StatusOK, m)
	})
	mux.HandleFunc("GET /admin/users", s.adminListUsers)
	mux.HandleFunc("POST /admin/users", s.adminAddUser)
	mux.HandleFunc("POST /admin/passwd", s.adminPasswd)
	mux.HandleFunc("DELETE /admin/users/{name}", s.adminDeleteUser)
	return mux
}

func (s *Server) adminListUsers(w http.ResponseWriter, _ *http.Request) {
	users := s.Store.Users()
	out := make([]AdminUser, 0, len(users))
	for _, u := range users {
		out = append(out, AdminUser{
			Username:  u.Username,
			CreatedAt: u.CreatedAt,
			HasKeys:   len(u.KeyBundle) > 0,
			UsedBytes: s.usage(u.Username),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	writeJSON(w, http.StatusOK, out)
}

type adminUserReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func decodeAdminUserReq(r *http.Request) (adminUserReq, error) {
	var req adminUserReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		return req, errors.New("リクエストの解析に失敗")
	}
	if !store.ValidUsername(req.Username) {
		return req, errors.New("ユーザー名は英数字・ハイフン・アンダースコア 1〜32 文字にしてください")
	}
	if len(req.Password) < 8 {
		return req, errors.New("パスワードは 8 文字以上にしてください")
	}
	return req, nil
}

func (s *Server) adminAddUser(w http.ResponseWriter, r *http.Request) {
	req, err := decodeAdminUserReq(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := auth.HashAuthKey(auth.DeriveAuthKey(req.Username, req.Password))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	u := store.User{Username: req.Username, AuthKeyHash: hash, CreatedAt: time.Now()}
	if err := s.Store.AddUser(u); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "created"})
}

// adminPasswd は緊急リセット。鍵バンドルは古いパスワード由来のままになるため、
// 対象ユーザーの既存暗号化データは読めなくなる(次回ログインで鍵の作り直し)。
func (s *Server) adminPasswd(w http.ResponseWriter, r *http.Request) {
	req, err := decodeAdminUserReq(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := auth.HashAuthKey(auth.DeriveAuthKey(req.Username, req.Password))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.Store.SetAuthKeyHash(req.Username, hash); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "changed"})
}

func (s *Server) adminDeleteUser(w http.ResponseWriter, r *http.Request) {
	if err := s.Store.DeleteUser(r.PathValue("name")); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
