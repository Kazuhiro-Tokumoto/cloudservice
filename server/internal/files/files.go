// Package files はユーザーごとのホームディレクトリ配下のファイル操作を提供する。
// すべてのパスはホームからの相対パスとして解決し、ディレクトリトラバーサルを防ぐ。
package files

import (
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ErrBadPath は不正なパス(トラバーサル等)。
var ErrBadPath = errors.New("不正なパスです")

// Root はユーザーファイルの保存ルート(<dataDir>/files)。
type Root struct {
	dir string
}

// NewRoot は保存ルートを作成する。
func NewRoot(dataDir string) (*Root, error) {
	dir := filepath.Join(dataDir, "files")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Root{dir: dir}, nil
}

// Clean は相対パスを正規化して返す。ホーム外に出るパスはエラー。
func Clean(rel string) (string, error) {
	rel = strings.TrimPrefix(strings.ReplaceAll(rel, "\\", "/"), "/")
	p := path.Clean(rel)
	if p == "." {
		return "", nil
	}
	if p == ".." || strings.HasPrefix(p, "../") || strings.Contains(p, "\x00") {
		return "", ErrBadPath
	}
	return p, nil
}

// resolve はユーザー home 配下の絶対パスを返す。
func (r *Root) resolve(username, rel string) (string, error) {
	p, err := Clean(rel)
	if err != nil {
		return "", err
	}
	return filepath.Join(r.dir, username, filepath.FromSlash(p)), nil
}

// EnsureHome はユーザーのホームディレクトリを作成する。
func (r *Root) EnsureHome(username string) error {
	return os.MkdirAll(filepath.Join(r.dir, username), 0o700)
}

// Entry はファイル一覧の 1 件。
type Entry struct {
	Name    string    `json:"name"`
	Path    string    `json:"path"` // ホームからの相対パス
	IsDir   bool      `json:"is_dir"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
}

// List は rel ディレクトリの内容を返す(ディレクトリ先頭・名前順)。
func (r *Root) List(username, rel string) ([]Entry, error) {
	abs, err := r.resolve(username, rel)
	if err != nil {
		return nil, err
	}
	des, err := os.ReadDir(abs)
	if err != nil {
		return nil, err
	}
	relClean, _ := Clean(rel)
	entries := make([]Entry, 0, len(des))
	for _, de := range des {
		info, err := de.Info()
		if err != nil {
			continue
		}
		entries = append(entries, Entry{
			Name:    de.Name(),
			Path:    path.Join(relClean, de.Name()),
			IsDir:   de.IsDir(),
			Size:    info.Size(),
			ModTime: info.ModTime(),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir != entries[j].IsDir {
			return entries[i].IsDir
		}
		return entries[i].Name < entries[j].Name
	})
	return entries, nil
}

// Open は読み出し用にファイルを開く。
func (r *Root) Open(username, rel string) (*os.File, os.FileInfo, error) {
	abs, err := r.resolve(username, rel)
	if err != nil {
		return nil, nil, err
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if info.IsDir() {
		f.Close()
		return nil, nil, errors.New("ディレクトリはダウンロードできません")
	}
	return f, info, nil
}

// Write は body の内容を rel に書き込む(親ディレクトリは自動作成、一時ファイル経由)。
func (r *Root) Write(username, rel string, body io.Reader) (int64, error) {
	abs, err := r.resolve(username, rel)
	if err != nil {
		return 0, err
	}
	if rel == "" || strings.HasSuffix(rel, "/") {
		return 0, ErrBadPath
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return 0, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(abs), ".upload-*")
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(tmp, body)
	closeErr := tmp.Close()
	if err != nil || closeErr != nil {
		os.Remove(tmp.Name())
		if err == nil {
			err = closeErr
		}
		return 0, err
	}
	if err := os.Rename(tmp.Name(), abs); err != nil {
		os.Remove(tmp.Name())
		return 0, err
	}
	return n, nil
}

// Mkdir はディレクトリを作成する。
func (r *Root) Mkdir(username, rel string) error {
	abs, err := r.resolve(username, rel)
	if err != nil {
		return err
	}
	return os.MkdirAll(abs, 0o700)
}

// Delete はファイルまたはディレクトリ(再帰)を削除する。ホーム自体は削除不可。
func (r *Root) Delete(username, rel string) error {
	p, err := Clean(rel)
	if err != nil {
		return err
	}
	if p == "" {
		return ErrBadPath
	}
	abs, err := r.resolve(username, rel)
	if err != nil {
		return err
	}
	if _, err := os.Stat(abs); err != nil {
		return err
	}
	return os.RemoveAll(abs)
}

// Stat は rel の情報を返す。
func (r *Root) Stat(username, rel string) (os.FileInfo, error) {
	abs, err := r.resolve(username, rel)
	if err != nil {
		return nil, err
	}
	return os.Stat(abs)
}
