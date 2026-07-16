package barrier

import (
	"bytes"
	"testing"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
)

type testSecret struct {
	Value string `json:"value"`
}

func newTestBarrier() (*Barrier, *storage.MemoryStorage) {
	store := storage.NewMemoryStorage()
	sealer := seal.NewDevSeal("test-passphrase")
	return NewBarrier(store, sealer), store
}

func TestBarrier_SealedByDefault_BlocksAccess(t *testing.T) {
	b, _ := newTestBarrier()

	if !b.IsSealed() {
		t.Fatal("new Barrier should start sealed")
	}

	if err := b.PutJSON("k", testSecret{Value: "x"}); err != ErrSealed {
		t.Fatalf("PutJSON while sealed: err = %v, want ErrSealed", err)
	}
	if err := b.GetJSON("k", &testSecret{}); err != ErrSealed {
		t.Fatalf("GetJSON while sealed: err = %v, want ErrSealed", err)
	}
	if _, err := b.List(""); err != ErrSealed {
		t.Fatalf("List while sealed: err = %v, want ErrSealed", err)
	}
	if err := b.Delete("k"); err != ErrSealed {
		t.Fatalf("Delete while sealed: err = %v, want ErrSealed", err)
	}
}

func TestBarrier_PutJSONThenGetJSON_RoundTrip(t *testing.T) {
	b, _ := newTestBarrier()

	if err := b.Unseal(); err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	want := testSecret{Value: "top secret"}
	if err := b.PutJSON("mykey", want); err != nil {
		t.Fatalf("PutJSON failed: %v", err)
	}

	var got testSecret
	if err := b.GetJSON("mykey", &got); err != nil {
		t.Fatalf("GetJSON failed: %v", err)
	}
	if got != want {
		t.Fatalf("GetJSON = %+v, want %+v", got, want)
	}
}

func TestBarrier_StoredBytesAreCiphertext(t *testing.T) {
	b, store := newTestBarrier()

	if err := b.Unseal(); err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	secretValue := "this-must-not-appear-in-plaintext"
	if err := b.PutJSON("mykey", testSecret{Value: secretValue}); err != nil {
		t.Fatalf("PutJSON failed: %v", err)
	}

	raw, err := store.Get("mykey")
	if err != nil {
		t.Fatalf("store.Get failed: %v", err)
	}
	if raw == nil {
		t.Fatal("store.Get returned nil; expected stored ciphertext")
	}
	if bytes.Contains(raw, []byte(secretValue)) {
		t.Fatal("raw stored bytes contain the plaintext secret value; expected ciphertext only")
	}
}

func TestBarrier_Seal_ReSealsAndBlocksAccess(t *testing.T) {
	b, _ := newTestBarrier()

	if err := b.Unseal(); err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}
	if err := b.PutJSON("mykey", testSecret{Value: "x"}); err != nil {
		t.Fatalf("PutJSON failed: %v", err)
	}

	b.Seal()

	if !b.IsSealed() {
		t.Fatal("IsSealed() = false after Seal(); want true")
	}
	if err := b.GetJSON("mykey", &testSecret{}); err != ErrSealed {
		t.Fatalf("GetJSON after Seal(): err = %v, want ErrSealed", err)
	}
}

func TestBarrier_GetJSON_MissingKeyReturnsErrNotFound(t *testing.T) {
	b, _ := newTestBarrier()

	if err := b.Unseal(); err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	var dest testSecret
	if err := b.GetJSON("does-not-exist", &dest); err != ErrNotFound {
		t.Fatalf("GetJSON on missing key: err = %v, want ErrNotFound", err)
	}
}
