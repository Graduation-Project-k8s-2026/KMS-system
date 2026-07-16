package seal

import (
	"bytes"
	"os"
	"testing"

	kmscrypto "github.com/Graduation-Project-k8s-2026/KMS-system/internal/crypto"
)

// 같은 패스프레이즈로 Unseal하면 항상 같은 Root Key가 나와야 한다 (결정적).
func TestUnseal_Deterministic(t *testing.T) {
	s := NewDevSeal("correct-horse-battery-staple")

	key1, err := s.Unseal()
	if err != nil {
		t.Fatalf("Unseal (1st) failed: %v", err)
	}
	key2, err := s.Unseal()
	if err != nil {
		t.Fatalf("Unseal (2nd) failed: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Fatal("Unseal returned different keys for the same passphrase; expected deterministic output")
	}
}

// 반환된 Root Key는 정확히 crypto.KeyLen(32)바이트여야 한다 — 나머지 계층이
// 이 길이를 그대로 KEK/Root Key로 사용하기 때문이다.
func TestUnseal_KeyLength(t *testing.T) {
	s := NewDevSeal("some-passphrase")

	key, err := s.Unseal()
	if err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}
	if len(key) != kmscrypto.KeyLen {
		t.Fatalf("got root key length %d, want %d", len(key), kmscrypto.KeyLen)
	}
}

// 서로 다른 패스프레이즈는 서로 다른 Root Key를 만들어야 한다.
func TestUnseal_DifferentPassphrasesProduceDifferentKeys(t *testing.T) {
	keyA, err := NewDevSeal("passphrase-A").Unseal()
	if err != nil {
		t.Fatalf("Unseal (A) failed: %v", err)
	}
	keyB, err := NewDevSeal("passphrase-B").Unseal()
	if err != nil {
		t.Fatalf("Unseal (B) failed: %v", err)
	}

	if bytes.Equal(keyA, keyB) {
		t.Fatal("different passphrases produced the same root key")
	}
}

// 패스프레이즈가 전혀 설정되지 않았을 때: IsConfigured()는 false, Unseal은 에러.
func TestUnconfigured_IsConfiguredFalse_UnsealErrors(t *testing.T) {
	// 테스트 실행 환경에 KMS_MASTER_KEY가 우연히 설정되어 있을 수도 있으니,
	// 이 테스트 동안만 확실히 비워두고 끝나면 원래 값으로 복원한다.
	original, wasSet := os.LookupEnv(envMasterKey)
	os.Unsetenv(envMasterKey)
	t.Cleanup(func() {
		if wasSet {
			os.Setenv(envMasterKey, original)
		}
	})

	s := NewDevSeal("")

	if s.IsConfigured() {
		t.Fatal("IsConfigured() = true, want false when no passphrase is set")
	}
	if _, err := s.Unseal(); err != ErrPassphraseNotConfigured {
		t.Fatalf("Unseal() err = %v, want ErrPassphraseNotConfigured", err)
	}
}

// 생성자에 직접 넘기지 않고 환경변수 KMS_MASTER_KEY로 주입해도 동작해야 한다.
func TestNewDevSeal_ReadsPassphraseFromEnv(t *testing.T) {
	t.Setenv(envMasterKey, "env-provided-passphrase")

	s := NewDevSeal("")

	if !s.IsConfigured() {
		t.Fatal("IsConfigured() = false, want true when KMS_MASTER_KEY is set")
	}

	fromEnv, err := s.Unseal()
	if err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	// 같은 패스프레이즈를 직접 주입했을 때와 동일한 키가 나와야 한다 —
	// 환경변수 경로와 직접 주입 경로가 같은 로직을 타는지 확인.
	direct, err := NewDevSeal("env-provided-passphrase").Unseal()
	if err != nil {
		t.Fatalf("Unseal (direct) failed: %v", err)
	}
	if !bytes.Equal(fromEnv, direct) {
		t.Fatal("env-provided passphrase produced a different key than the same passphrase passed directly")
	}
}
