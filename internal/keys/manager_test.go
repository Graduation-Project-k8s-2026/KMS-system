package keys

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
)

func newTestManager(t *testing.T) *KeyManager {
	t.Helper()

	store := storage.NewMemoryStorage()
	sealer := seal.NewDevSeal("test-passphrase")
	b := barrier.NewBarrier(store, sealer)
	if err := b.Unseal(); err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}
	return NewKeyManager(b)
}

// backdateLastRotatedAt은 FindKeysDueForRotation 테스트를 위해, 저장된 KeyRing의
// LastRotatedAt을 barrier를 통해 직접 과거 시각으로 바꿔쓴다.
func backdateLastRotatedAt(t *testing.T, m *KeyManager, name string, when time.Time) {
	t.Helper()

	var ring KeyRing
	if err := m.barrier.GetJSON(storageKey(name), &ring); err != nil {
		t.Fatalf("GetJSON(%q) failed: %v", name, err)
	}
	ring.LastRotatedAt = when
	if err := m.barrier.PutJSON(storageKey(name), &ring); err != nil {
		t.Fatalf("PutJSON(%q) failed: %v", name, err)
	}
}

func TestCreateKey_ThenGetKeyMetaAndListKeys(t *testing.T) {
	m := newTestManager(t)

	created, err := m.CreateKey("app-secret", 0)
	if err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}
	if created.Name != "app-secret" || created.LatestVersion != 1 || created.MinDecryptionVersion != 1 {
		t.Fatalf("unexpected created meta: %+v", created)
	}

	got, err := m.GetKeyMeta("app-secret")
	if err != nil {
		t.Fatalf("GetKeyMeta failed: %v", err)
	}
	if got.Name != created.Name || got.LatestVersion != created.LatestVersion {
		t.Fatalf("GetKeyMeta = %+v, want %+v", got, created)
	}

	names, err := m.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(names) != 1 || names[0] != "app-secret" {
		t.Fatalf(`ListKeys = %v, want ["app-secret"]`, names)
	}
}

func TestGetKeyMeta_DoesNotExposeKeyMaterial(t *testing.T) {
	m := newTestManager(t)

	if _, err := m.CreateKey("app-secret", 0); err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	_, material, err := m.GetEncryptionKEK("app-secret")
	if err != nil {
		t.Fatalf("GetEncryptionKEK failed: %v", err)
	}

	meta, err := m.GetKeyMeta("app-secret")
	if err != nil {
		t.Fatalf("GetKeyMeta failed: %v", err)
	}

	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	if bytes.Contains(data, []byte("KeyMaterial")) {
		t.Fatalf(`KeyRingMeta JSON contains a "KeyMaterial" field: %s`, data)
	}
	if bytes.Contains(data, []byte(base64.StdEncoding.EncodeToString(material))) {
		t.Fatalf("KeyRingMeta JSON contains the raw KEK material: %s", data)
	}
}

func TestCreateKey_DuplicateNameReturnsKeyPolicyError(t *testing.T) {
	m := newTestManager(t)

	if _, err := m.CreateKey("dup", 0); err != nil {
		t.Fatalf("CreateKey (1st) failed: %v", err)
	}

	_, err := m.CreateKey("dup", 0)
	var policyErr *KeyPolicyError
	if !errors.As(err, &policyErr) {
		t.Fatalf("CreateKey (duplicate) err = %v, want *KeyPolicyError", err)
	}
}

func TestCreateKey_RejectsInvalidNames(t *testing.T) {
	m := newTestManager(t)

	invalidNames := []string{"bad name!", "", strings.Repeat("a", 65)}

	for _, name := range invalidNames {
		_, err := m.CreateKey(name, 0)
		var policyErr *KeyPolicyError
		if !errors.As(err, &policyErr) {
			t.Errorf("CreateKey(%q) err = %v, want *KeyPolicyError", name, err)
		}
	}
}

func TestRotateKey_IncrementsLatestVersion_KeepsOldVersions(t *testing.T) {
	m := newTestManager(t)

	created, err := m.CreateKey("k", 0)
	if err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}
	if created.LatestVersion != 1 {
		t.Fatalf("initial LatestVersion = %d, want 1", created.LatestVersion)
	}

	v1KEK, err := m.GetDecryptionKEK("k", 1)
	if err != nil {
		t.Fatalf("GetDecryptionKEK(1) failed: %v", err)
	}

	rotated, err := m.RotateKey("k")
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}
	if rotated.LatestVersion != 2 {
		t.Fatalf("LatestVersion after rotate = %d, want 2", rotated.LatestVersion)
	}
	if len(rotated.Versions) != 2 {
		t.Fatalf("len(Versions) after rotate = %d, want 2", len(rotated.Versions))
	}

	v1KEKAfter, err := m.GetDecryptionKEK("k", 1)
	if err != nil {
		t.Fatalf("GetDecryptionKEK(1) after rotate failed: %v", err)
	}
	if !bytes.Equal(v1KEK, v1KEKAfter) {
		t.Fatal("version 1 KEK material changed after rotation; expected it to remain untouched")
	}
}

func TestGetEncryptionKEK_AlwaysReturnsLatestVersion(t *testing.T) {
	m := newTestManager(t)

	if _, err := m.CreateKey("k", 0); err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}
	if _, err := m.RotateKey("k"); err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	version, kek, err := m.GetEncryptionKEK("k")
	if err != nil {
		t.Fatalf("GetEncryptionKEK failed: %v", err)
	}
	if version != 2 {
		t.Fatalf("GetEncryptionKEK version = %d, want 2", version)
	}

	v2KEK, err := m.GetDecryptionKEK("k", 2)
	if err != nil {
		t.Fatalf("GetDecryptionKEK(2) failed: %v", err)
	}
	if !bytes.Equal(kek, v2KEK) {
		t.Fatal("GetEncryptionKEK material does not match version 2's material")
	}
}

func TestGetDecryptionKEK_RejectsVersionBelowMinDecryptionVersion(t *testing.T) {
	m := newTestManager(t)

	if _, err := m.CreateKey("k", 0); err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}
	if _, err := m.RotateKey("k"); err != nil { // -> version 2
		t.Fatalf("RotateKey (1st) failed: %v", err)
	}
	if _, err := m.RotateKey("k"); err != nil { // -> version 3
		t.Fatalf("RotateKey (2nd) failed: %v", err)
	}

	minV := 2
	if _, err := m.UpdateConfig("k", &minV, nil); err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}

	_, err := m.GetDecryptionKEK("k", 1)
	var policyErr *KeyPolicyError
	if !errors.As(err, &policyErr) {
		t.Fatalf("GetDecryptionKEK(version=1) err = %v, want *KeyPolicyError", err)
	}

	if _, err := m.GetDecryptionKEK("k", 2); err != nil {
		t.Fatalf("GetDecryptionKEK(version=2) failed: %v", err)
	}
}

func TestFindKeysDueForRotation(t *testing.T) {
	m := newTestManager(t)

	if _, err := m.CreateKey("due-key", 3600); err != nil {
		t.Fatalf("CreateKey(due-key) failed: %v", err)
	}
	if _, err := m.CreateKey("not-due-key", 3600); err != nil {
		t.Fatalf("CreateKey(not-due-key) failed: %v", err)
	}
	if _, err := m.CreateKey("no-auto-rotate-key", 0); err != nil {
		t.Fatalf("CreateKey(no-auto-rotate-key) failed: %v", err)
	}

	// due-key만 마지막 회전 시각을 2시간 전으로 되돌려, 1시간(3600초) 주기를
	// 이미 넘긴 상태로 만든다. not-due-key는 방금 생성됐으니 아직 주기가 안 됐고,
	// no-auto-rotate-key는 AutoRotatePeriodSec=0이라 애초에 대상이 아니다.
	backdateLastRotatedAt(t, m, "due-key", time.Now().Add(-2*time.Hour))

	due, err := m.FindKeysDueForRotation(time.Now().UnixMilli())
	if err != nil {
		t.Fatalf("FindKeysDueForRotation failed: %v", err)
	}

	if len(due) != 1 || due[0] != "due-key" {
		t.Fatalf(`FindKeysDueForRotation = %v, want ["due-key"]`, due)
	}
}
