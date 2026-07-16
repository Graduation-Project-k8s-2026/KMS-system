package storage

import (
	"reflect"
	"sort"
	"testing"
)

// runStorageBackendTests는 StorageBackend 인터페이스를 만족하는 어떤 구현체든
// 지켜야 하는 동작을 검증한다. newBackend는 테스트마다 깨끗한 상태의 구현체를
// 하나 만들어 반환하는 함수다.
//
// Python의 unittest라면 보통 베이스 TestCase 클래스에 이 테스트들을 넣고
// MemoryStorageTest(BaseStorageTest), FileStorageTest(BaseStorageTest)처럼
// 상속으로 재사용하거나, pytest라면 fixture를 params로 매개변수화해서 같은
// 테스트 함수를 여러 백엔드에 대해 돌린다. Go에는 클래스 상속이 없어서, 대신
// "테스트 로직을 담은 평범한 함수"를 하나 만들고, 각 구현체용 Test 함수에서
// 그 함수를 호출하는 식으로 같은 효과를 낸다 — 상속 대신 함수 재사용이다.
func runStorageBackendTests(t *testing.T, newBackend func() StorageBackend) {
	t.Run("PutThenGetReturnsSameValue", func(t *testing.T) {
		s := newBackend()

		if err := s.Put("greeting", []byte("hello")); err != nil {
			t.Fatalf("Put failed: %v", err)
		}

		got, err := s.Get("greeting")
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}
		if string(got) != "hello" {
			t.Fatalf("Get = %q, want %q", got, "hello")
		}
	})

	t.Run("GetOnMissingKeyReturnsNilNil", func(t *testing.T) {
		s := newBackend()

		got, err := s.Get("does-not-exist")
		if err != nil {
			t.Fatalf("Get on missing key returned err = %v, want nil", err)
		}
		if got != nil {
			t.Fatalf("Get on missing key = %v, want nil", got)
		}
	})

	t.Run("DeleteRemovesValue", func(t *testing.T) {
		s := newBackend()

		if err := s.Put("temp", []byte("data")); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
		if err := s.Delete("temp"); err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		got, err := s.Get("temp")
		if err != nil {
			t.Fatalf("Get after Delete returned err = %v, want nil", err)
		}
		if got != nil {
			t.Fatalf("Get after Delete = %v, want nil", got)
		}
	})

	t.Run("ListReturnsNamesWithPrefixStripped", func(t *testing.T) {
		s := newBackend()

		for _, kv := range []struct{ key, value string }{
			{"keys/app-secret", "v1"},
			{"keys/db-secret", "v1"},
			{"other/thing", "v1"},
		} {
			if err := s.Put(kv.key, []byte(kv.value)); err != nil {
				t.Fatalf("Put(%q) failed: %v", kv.key, err)
			}
		}

		names, err := s.List("keys/")
		if err != nil {
			t.Fatalf("List failed: %v", err)
		}
		sort.Strings(names)

		want := []string{"app-secret", "db-secret"}
		if !reflect.DeepEqual(names, want) {
			t.Fatalf(`List("keys/") = %v, want %v`, names, want)
		}
	})
}

func TestMemoryStorage(t *testing.T) {
	runStorageBackendTests(t, func() StorageBackend {
		return NewMemoryStorage()
	})
}

func TestFileStorage(t *testing.T) {
	runStorageBackendTests(t, func() StorageBackend {
		// t.TempDir()는 테스트마다 새 임시 디렉토리를 만들고, 테스트가 끝나면
		// 자동으로 지워준다 — 실제 파일을 쓰는 테스트를 서로 간섭 없이 반복
		// 실행할 수 있게 해준다.
		return NewFileStorage(t.TempDir())
	})
}

func TestFileStorage_RejectsPathTraversal(t *testing.T) {
	fs := NewFileStorage(t.TempDir())

	if err := fs.Put("../escape", []byte("data")); err != ErrInvalidKey {
		t.Fatalf("Put with \"..\" key: err = %v, want ErrInvalidKey", err)
	}
	if _, err := fs.Get("../escape"); err != ErrInvalidKey {
		t.Fatalf("Get with \"..\" key: err = %v, want ErrInvalidKey", err)
	}
	if err := fs.Delete("../escape"); err != ErrInvalidKey {
		t.Fatalf("Delete with \"..\" key: err = %v, want ErrInvalidKey", err)
	}
	if _, err := fs.List("../"); err != ErrInvalidKey {
		t.Fatalf("List with \"..\" prefix: err = %v, want ErrInvalidKey", err)
	}
}
