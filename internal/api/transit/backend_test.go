package transit_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"

	apiadmin "github.com/Graduation-Project-k8s-2026/KMS-system/internal/api/admin"
	apitransit "github.com/Graduation-Project-k8s-2026/KMS-system/internal/api/transit"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
	transit "github.com/Graduation-Project-k8s-2026/KMS-system/internal/transit"
)

type failingKeys struct {
	storage.StorageBackend
	fail bool
}

func (s *failingKeys) Get(key string) ([]byte, error) {
	if s.fail {
		return nil, errors.New("storage offline")
	}
	return s.StorageBackend.Get(key)
}
func TestTransitDistinguishesBackendFromBadCiphertext(t *testing.T) {
	store := &failingKeys{StorageBackend: storage.NewMemoryStorage()}
	b := barrier.NewBarrier(store, seal.NewDevSeal("fixture"))
	if err := b.Unseal(); err != nil {
		t.Fatal(err)
	}
	km := keys.NewKeyManager(b)
	if _, err := km.CreateKey("demo", 0); err != nil {
		t.Fatal(err)
	}
	svc := transit.NewTransitService(km)
	cipher, err := svc.Encrypt("demo", []byte("public fixture"))
	if err != nil {
		t.Fatal(err)
	}
	router := apitransit.NewRouter(apitransit.Deps{Barrier: b, Transit: svc})
	request := func(value string, want int) {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"ciphertext": value})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/decrypt/demo", bytes.NewReader(body)))
		if w.Code != want {
			t.Fatalf("got %d want %d", w.Code, want)
		}
	}
	request(cipher, 200)
	admin := apiadmin.NewRouter(apiadmin.Deps{Barrier: b, Keys: km})
	duplicate := httptest.NewRecorder()
	admin.ServeHTTP(duplicate, httptest.NewRequest("POST", "/v1/keys/", bytes.NewBufferString(`{"name":"demo"}`)))
	if duplicate.Code != 409 {
		t.Fatal("duplicate key must return conflict")
	}
	request("invalid", 400)
	store.fail = true
	request(cipher, 503)
	store.fail = false
	request(cipher, 200)
}
