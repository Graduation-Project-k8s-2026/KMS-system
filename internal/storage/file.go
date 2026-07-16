package storage

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// ErrInvalidKey: key(또는 List의 prefix)에 ".." 경로 탈출 세그먼트가 있을 때 반환.
var ErrInvalidKey = errors.New("storage: key must not contain a \"..\" path segment")

// FileStorage는 루트 디렉토리 아래의 실제 파일로 데이터를 저장하는 StorageBackend
// 구현체다. key는 그 루트 기준 상대 파일 경로로 취급된다 (예: key "keys/app-secret"은
// "<root>/keys/app-secret" 파일이 된다).
type FileStorage struct {
	root string
}

// NewFileStorage는 root 디렉토리를 기준으로 하는 FileStorage를 만든다.
// root 자체가 아직 없어도 된다 — 실제로 쓸 때(Put) 필요한 하위 디렉토리를
// 자동으로 만든다.
func NewFileStorage(root string) *FileStorage {
	return &FileStorage{root: root}
}

// resolvePath는 key를 루트 디렉토리 기준의 실제 파일 경로로 바꾼다.
//
// key에 ".." 세그먼트가 있으면 거부한다 — 그렇지 않으면 예를 들어
// key = "../../etc/passwd" 같은 값이 그대로 filepath.Join에 들어가서 루트
// 디렉토리 바깥의 임의 파일을 읽거나 덮어쓸 수 있게 된다 (경로 탈출 취약점).
// 저장소 계층에 들어오는 key는 상위 계층(keys 등)이 내부적으로 붙이는 이름이라
// 보통은 안전하지만, 이 검증이 없으면 그 가정이 깨졌을 때 조용히 심각한
// 취약점이 된다.
func (s *FileStorage) resolvePath(key string) (string, error) {
	for _, part := range strings.Split(key, "/") {
		if part == ".." {
			return "", ErrInvalidKey
		}
	}
	return filepath.Join(s.root, key), nil
}

func (s *FileStorage) Get(key string) ([]byte, error) {
	path, err := s.resolvePath(key)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (s *FileStorage) Put(key string, value []byte) error {
	path, err := s.resolvePath(key)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, value, 0o600)
}

func (s *FileStorage) Delete(key string) error {
	path, err := s.resolvePath(key)
	if err != nil {
		return err
	}

	err = os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s *FileStorage) List(prefix string) ([]string, error) {
	dirPath, err := s.resolvePath(prefix)
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(dirPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names, nil
}
