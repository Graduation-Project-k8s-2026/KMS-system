package storage

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

var ErrInvalidKey = errors.New("storage: invalid path or symlink")

type FileStorage struct {
	root  string
	lock  *os.File
	fault func(string) error
}

func NewFileStorage(root string) *FileStorage { return &FileStorage{root: root} }

// OpenFileStorage owns a nonblocking process lock until Close. Never unlink the lock.
func OpenFileStorage(root string) (*FileStorage, error) {
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	s := NewFileStorage(root)
	p, err := s.resolvePath(".lock")
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Open(p, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), p)
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("storage: already locked")
	}
	s.lock = f
	return s, nil
}
func (s *FileStorage) Close() error {
	if s.lock != nil {
		return s.lock.Close()
	}
	return nil
}
func (s *FileStorage) resolvePath(key string) (string, error) {
	if filepath.IsAbs(key) || strings.ContainsRune(key, 0) {
		return "", ErrInvalidKey
	}
	p := s.root
	if st, e := os.Lstat(p); e == nil && st.Mode()&os.ModeSymlink != 0 {
		return "", ErrInvalidKey
	}
	for _, part := range strings.Split(key, "/") {
		if part == ".." {
			return "", ErrInvalidKey
		}
		p = filepath.Join(p, part)
		if st, e := os.Lstat(p); e == nil && st.Mode()&os.ModeSymlink != 0 {
			return "", ErrInvalidKey
		}
	}
	return p, nil
}
func (s *FileStorage) Get(key string) ([]byte, error) {
	if _, err := s.resolvePath(key); err != nil {
		return nil, err
	}
	r, e := os.OpenRoot(s.root)
	if errors.Is(e, os.ErrNotExist) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	defer r.Close()
	b, e := r.ReadFile(key)
	if errors.Is(e, os.ErrNotExist) {
		return nil, nil
	}
	return b, e
}
func syncDir(p string) error {
	f, e := os.Open(p)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func (s *FileStorage) step(stage string) error {
	if s.fault != nil {
		return s.fault(stage)
	}
	return nil
}
func (s *FileStorage) Put(key string, value []byte) error {
	if _, e := s.resolvePath(key); e != nil {
		return e
	}
	if e := os.MkdirAll(s.root, 0700); e != nil {
		return e
	}
	r, e := os.OpenRoot(s.root)
	if e != nil {
		return e
	}
	defer r.Close()
	dir := filepath.Dir(key)
	if e = r.MkdirAll(dir, 0700); e != nil {
		return e
	}
	id := make([]byte, 16)
	if _, e = rand.Read(id); e != nil {
		return e
	}
	tmpName := filepath.Join(dir, ".pending-"+hex.EncodeToString(id))
	if e = s.step("create"); e != nil {
		return e
	}
	f, e := r.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer r.Remove(tmpName)
	if e = s.step("write"); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(value); e != nil {
		f.Close()
		return e
	}
	if e = s.step("sync"); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = s.step("rename"); e != nil {
		return e
	}
	if e = r.Rename(tmpName, key); e != nil {
		return e
	}
	if e = s.step("dir-sync"); e != nil {
		return e
	}
	// Persist both the entry and newly created parent directories.
	for {
		d, e := r.Open(dir)
		if e != nil {
			return e
		}
		e = d.Sync()
		d.Close()
		if e != nil {
			return e
		}
		if dir == "." {
			break
		}
		dir = filepath.Dir(dir)
	}
	return nil
}
func (s *FileStorage) Delete(key string) error {
	p, e := s.resolvePath(key)
	if e != nil {
		return e
	}
	r, e := os.OpenRoot(s.root)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	defer r.Close()
	e = r.Remove(key)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	return syncDir(filepath.Dir(p))
}
func (s *FileStorage) List(prefix string) ([]string, error) {
	p, e := s.resolvePath(prefix)
	if e != nil {
		return nil, e
	}
	entries, e := os.ReadDir(p)
	if errors.Is(e, os.ErrNotExist) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	var names []string
	for _, x := range entries {
		if strings.HasPrefix(x.Name(), ".") {
			continue
		}
		if x.Type()&os.ModeSymlink != 0 {
			return nil, ErrInvalidKey
		}
		names = append(names, x.Name())
	}
	return names, nil
}
