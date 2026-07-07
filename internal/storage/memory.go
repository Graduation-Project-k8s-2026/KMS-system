package storage

import (
	"strings"
	"sync"
)

// MemoryStorage는 프로세스 메모리 안의 map에만 데이터를 보관하는 StorageBackend
// 구현체다. 테스트/개발용이며, 프로세스가 재시작되면 저장된 내용이 전부 사라진다.
type MemoryStorage struct {
	// mu는 data map을 여러 goroutine이 동시에 읽고/쓸 때 생기는 데이터 경합을
	// 막는다. Go의 map은 동시 접근에 안전하지 않다 — 한 goroutine이 쓰는 동안
	// 다른 goroutine이 읽거나 쓰면 프로그램이 그 자리에서 크래시할 수 있다.
	// HTTP 서버는 요청마다 별도 goroutine에서 핸들러를 실행하므로, 이 저장소는
	// 언제든 여러 요청이 동시에 접근할 수 있다고 가정해야 한다.
	mu   sync.Mutex
	data map[string][]byte
}

// NewMemoryStorage는 빈 MemoryStorage를 만든다.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{data: make(map[string][]byte)}
}

func (s *MemoryStorage) Get(key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	value, ok := s.data[key]
	if !ok {
		return nil, nil
	}
	return value, nil
}

func (s *MemoryStorage) Put(key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.data[key] = value
	return nil
}

func (s *MemoryStorage) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.data, key)
	return nil
}

func (s *MemoryStorage) List(prefix string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var names []string
	for key := range s.data {
		if strings.HasPrefix(key, prefix) {
			names = append(names, strings.TrimPrefix(key, prefix))
		}
	}
	return names, nil
}
