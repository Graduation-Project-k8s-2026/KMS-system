package transit

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
)

func newTestService(t *testing.T) (*TransitService, *keys.KeyManager) {
	t.Helper()

	store := storage.NewMemoryStorage()
	sealer := seal.NewDevSeal("test-passphrase")
	b := barrier.NewBarrier(store, sealer)
	if err := b.Unseal(); err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	km := keys.NewKeyManager(b)
	return NewTransitService(km), km
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	svc, km := newTestService(t)
	if _, err := km.CreateKey("app", 0); err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	plaintext := []byte("top secret data")

	ciphertext, err := svc.Encrypt("app", plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	got, err := svc.Decrypt("app", ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("Decrypt = %q, want %q", got, plaintext)
	}
}

func TestEncrypt_ResultHasVersionPrefix(t *testing.T) {
	svc, km := newTestService(t)
	if _, err := km.CreateKey("app", 0); err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	ciphertext, err := svc.Encrypt("app", []byte("data"))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if !strings.HasPrefix(ciphertext, "kms:v1:") {
		t.Fatalf("Encrypt result = %q, want prefix %q", ciphertext, "kms:v1:")
	}
}

func TestEncrypt_ProducesDifferentCiphertextEachTime(t *testing.T) {
	svc, km := newTestService(t)
	if _, err := km.CreateKey("app", 0); err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	plaintext := []byte("same plaintext")

	ct1, err := svc.Encrypt("app", plaintext)
	if err != nil {
		t.Fatalf("Encrypt (1st) failed: %v", err)
	}
	ct2, err := svc.Encrypt("app", plaintext)
	if err != nil {
		t.Fatalf("Encrypt (2nd) failed: %v", err)
	}

	if ct1 == ct2 {
		t.Fatal("two Encrypt calls on the same plaintext produced identical ciphertext (DEK reuse?)")
	}
}

func TestEncryptDecrypt_AfterRotation_OldAndNewVersionsBothWork(t *testing.T) {
	svc, km := newTestService(t)
	if _, err := km.CreateKey("app", 0); err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	v1Plaintext := []byte("encrypted before rotation")
	v1Ciphertext, err := svc.Encrypt("app", v1Plaintext)
	if err != nil {
		t.Fatalf("Encrypt (v1) failed: %v", err)
	}
	if !strings.HasPrefix(v1Ciphertext, "kms:v1:") {
		t.Fatalf("v1 ciphertext = %q, want prefix %q", v1Ciphertext, "kms:v1:")
	}

	if _, err := km.RotateKey("app"); err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	v2Plaintext := []byte("encrypted after rotation")
	v2Ciphertext, err := svc.Encrypt("app", v2Plaintext)
	if err != nil {
		t.Fatalf("Encrypt (v2) failed: %v", err)
	}
	if !strings.HasPrefix(v2Ciphertext, "kms:v2:") {
		t.Fatalf("v2 ciphertext = %q, want prefix %q", v2Ciphertext, "kms:v2:")
	}

	gotV1, err := svc.Decrypt("app", v1Ciphertext)
	if err != nil {
		t.Fatalf("Decrypt (v1, after rotation) failed: %v", err)
	}
	if !bytes.Equal(gotV1, v1Plaintext) {
		t.Fatalf("Decrypt (v1) = %q, want %q", gotV1, v1Plaintext)
	}

	gotV2, err := svc.Decrypt("app", v2Ciphertext)
	if err != nil {
		t.Fatalf("Decrypt (v2) failed: %v", err)
	}
	if !bytes.Equal(gotV2, v2Plaintext) {
		t.Fatalf("Decrypt (v2) = %q, want %q", gotV2, v2Plaintext)
	}
}

func TestDecrypt_RejectsVersionBelowMinDecryptionVersion(t *testing.T) {
	svc, km := newTestService(t)
	if _, err := km.CreateKey("app", 0); err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	v1Ciphertext, err := svc.Encrypt("app", []byte("old data"))
	if err != nil {
		t.Fatalf("Encrypt (v1) failed: %v", err)
	}

	if _, err := km.RotateKey("app"); err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	minV := 2
	if _, err := km.UpdateConfig("app", &minV, nil); err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}

	if _, err := svc.Decrypt("app", v1Ciphertext); err == nil {
		t.Fatal("Decrypt succeeded on a version below min_decryption_version; want error")
	}
}

// 다른 키 이름으로 Decrypt를 시도하면 실패해야 한다. app-a와 app-b는 서로 다른
// 무작위 KEK를 가지므로, 이 테스트는 "KEK 자체가 다름"과 "aad가 키 이름을
// 포함해 일치하지 않음" 두 방어선이 함께 작동해 거부하는 것을 확인한다.
func TestDecrypt_RejectsWrongKeyName(t *testing.T) {
	svc, km := newTestService(t)
	if _, err := km.CreateKey("app-a", 0); err != nil {
		t.Fatalf("CreateKey(app-a) failed: %v", err)
	}
	if _, err := km.CreateKey("app-b", 0); err != nil {
		t.Fatalf("CreateKey(app-b) failed: %v", err)
	}

	ciphertext, err := svc.Encrypt("app-a", []byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if _, err := svc.Decrypt("app-b", ciphertext); err == nil {
		t.Fatal("Decrypt succeeded using the wrong key name; want error")
	}
}

func TestDecrypt_RejectsCorruptedCiphertext(t *testing.T) {
	svc, km := newTestService(t)
	if _, err := km.CreateKey("app", 0); err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	if _, err := svc.Decrypt("app", "kms:v1:!!!"); err == nil {
		t.Fatal("Decrypt succeeded on a corrupted ciphertext; want error")
	}
}
