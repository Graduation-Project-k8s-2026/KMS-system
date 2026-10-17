package barrier

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	kmscrypto "github.com/Graduation-Project-k8s-2026/KMS-system/internal/crypto"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/shamir"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
)

// putV1Store: 운영 저장소와 같은 v1 기록(format_version 1, seal 필드 없음,
// 옛 aad 문자열)을 직접 만든다. 이 테스트가 v1 호환의 증거다 — aad 문자열을
// Initialization.aad()에서 가져오지 않고 여기에 따로 적어, aad()를 실수로
// 바꾸면 이 테스트가 깨지게 한다.
func putV1Store(t *testing.T, store storage.StorageBackend, root []byte, parts, threshold int) {
	t.Helper()
	const storeID = "00112233445566778899aabbccddeeff"
	aad := []byte(fmt.Sprintf("kms-init:1:%s:%d:%d", storeID, parts, threshold))
	ver, err := kmscrypto.Encrypt(root, []byte("kms-root-valid-v1"), aad)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{
		"format_version": 1, "store_id": storeID, "parts": parts, "threshold": threshold, "verification": ver,
	})
	if err := store.Put(initPath, raw); err != nil {
		t.Fatal(err)
	}
}

func unsealWithShares(t *testing.T, b *Barrier, s *seal.ShamirSeal, shares [][]byte) error {
	t.Helper()
	for _, sh := range shares {
		if _, err := s.SubmitShare(sh); err != nil {
			t.Fatal(err)
		}
	}
	return b.Unseal()
}

func TestV1Store_UnsealsAndReportsShamir(t *testing.T) {
	root := make([]byte, 32)
	root[0] = 1
	store := storage.NewMemoryStorage()
	putV1Store(t, store, root, 5, 3)
	shares, err := shamir.Split(root, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	s := seal.NewShamirSeal(3)
	b := NewBarrier(store, s)
	if err := b.CheckInitialization(5, 3); err != nil {
		t.Fatalf("v1 record rejected by CheckInitialization: %v", err)
	}
	if mode, err := b.SealMode(); err != nil || mode != SealShamir {
		t.Fatalf("SealMode = %q, %v; want shamir", mode, err)
	}
	if err := unsealWithShares(t, b, s, shares[:3]); err != nil {
		t.Fatalf("v1 store did not unseal with v2 code: %v", err)
	}
}

func TestV1Store_UpgradeToV2RewritesVerificationWithSameRoot(t *testing.T) {
	root := make([]byte, 32)
	root[0] = 2
	store := storage.NewMemoryStorage()
	putV1Store(t, store, root, 5, 3)
	shares, _ := shamir.Split(root, 5, 3)
	s := seal.NewShamirSeal(3)
	b := NewBarrier(store, s)
	if err := unsealWithShares(t, b, s, shares[:3]); err != nil {
		t.Fatal(err)
	}

	b.mu.Lock()
	cur, err := b.loadInit()
	if err == nil {
		_, err = b.rewriteInitLocked(cur, SealShamir)
	}
	b.mu.Unlock()
	if err != nil {
		t.Fatalf("upgrade failed: %v", err)
	}

	raw, _ := store.Get(initPath)
	var m Initialization
	if err := json.Unmarshal(raw, &m); err != nil || m.FormatVersion != 2 || m.Seal != SealShamir {
		t.Fatalf("record after upgrade = %s (%v)", raw, err)
	}
	// 같은 루트 키(같은 조각)로 새 프로세스가 다시 해제할 수 있어야 한다.
	s2 := seal.NewShamirSeal(3)
	b2 := NewBarrier(store, s2)
	if err := unsealWithShares(t, b2, s2, shares[2:5]); err != nil {
		t.Fatalf("unseal after v1->v2 upgrade failed: %v", err)
	}
}

func TestRewriteInit_RefusesForeignRootAndLeavesRecordUntouched(t *testing.T) {
	root := make([]byte, 32)
	store := storage.NewMemoryStorage()
	putV1Store(t, store, root, 5, 3)
	before, _ := store.Get(initPath)

	b := NewBarrier(store, seal.NewShamirSeal(3))
	foreign := make([]byte, 32)
	foreign[5] = 9
	b.rootKey = foreign // 일부러 틀린 키를 메모리에 둔다
	b.mu.Lock()
	cur, _ := b.loadInit()
	_, err := b.rewriteInitLocked(cur, SealShamir)
	b.mu.Unlock()
	if !errors.Is(err, ErrRootVerification) {
		t.Fatalf("err = %v, want ErrRootVerification", err)
	}
	after, _ := store.Get(initPath)
	if string(before) != string(after) {
		t.Fatal("record was modified despite verification failure")
	}
}

func TestNewInitializeWritesV2Shamir(t *testing.T) {
	store := storage.NewMemoryStorage()
	b := NewBarrier(store, seal.NewShamirSeal(3))
	if _, err := b.Initialize(5, 3); err != nil {
		t.Fatal(err)
	}
	raw, _ := store.Get(initPath)
	var m Initialization
	json.Unmarshal(raw, &m)
	if m.FormatVersion != 2 || m.Seal != SealShamir {
		t.Fatalf("new record = %s", raw)
	}
}

func TestV2Record_SealFieldTamperRejected(t *testing.T) {
	store := storage.NewMemoryStorage()
	s := seal.NewShamirSeal(3)
	b := NewBarrier(store, s)
	shares, err := b.Initialize(5, 3)
	if err != nil {
		t.Fatal(err)
	}
	// 디스크에서 seal 값을 tpm으로 바꿔치기 → aad 불일치로 검증 실패해야 한다.
	raw, _ := store.Get(initPath)
	var m map[string]any
	json.Unmarshal(raw, &m)
	m["seal"] = "tpm"
	raw, _ = json.Marshal(m)
	store.Put(initPath, raw)
	if err := unsealWithShares(t, b, s, shares[:3]); !errors.Is(err, ErrRootVerification) || !b.IsSealed() {
		t.Fatalf("tampered seal field accepted: %v", err)
	}
}

func TestUnknownFormatsAndBadSealRejected(t *testing.T) {
	for name, rec := range map[string]map[string]any{
		"v3":              {"format_version": 3, "store_id": "00112233445566778899aabbccddeeff", "parts": 5, "threshold": 3, "seal": "shamir"},
		"v2 unknown seal": {"format_version": 2, "store_id": "00112233445566778899aabbccddeeff", "parts": 5, "threshold": 3, "seal": "k8s"},
		"v2 missing seal": {"format_version": 2, "store_id": "00112233445566778899aabbccddeeff", "parts": 5, "threshold": 3},
		"v1 with seal":    {"format_version": 1, "store_id": "00112233445566778899aabbccddeeff", "parts": 5, "threshold": 3, "seal": "tpm"},
	} {
		store := storage.NewMemoryStorage()
		raw, _ := json.Marshal(rec)
		store.Put(initPath, raw)
		b := NewBarrier(store, seal.NewShamirSeal(3))
		if err := b.CheckInitialization(5, 3); !errors.Is(err, ErrRootVerification) {
			t.Errorf("%s: CheckInitialization err = %v", name, err)
		}
		if _, err := b.SealMode(); !errors.Is(err, ErrRootVerification) {
			t.Errorf("%s: SealMode err = %v", name, err)
		}
	}
}
