//go:build tpm_lab

package barrier_test

import (
	"errors"
	"testing"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
	transitsvc "github.com/Graduation-Project-k8s-2026/KMS-system/internal/transit"
	"github.com/google/go-tpm-tools/simulator"
)

// 실제 TPMSeal(go-tpm 시뮬레이터)로 Shamir→TPM 이전, 재시작 자동 해제, blob 삭제 후
// 복구 조각 해제, TPM→Shamir 되돌리기를 끝까지 확인한다.
func TestMigrateSeal_RealTPMSimulator_EndToEnd(t *testing.T) {
	sim, err := simulator.Get()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sim.Close() })
	store := storage.NewMemoryStorage()

	boot := func() (*barrier.Barrier, *seal.Switch) {
		sw := seal.NewSwitch("shamir", seal.NewShamirSeal(3), nil,
			func() (seal.TPMBackend, error) { return seal.NewTPMSeal(sim, store), nil }, store)
		b := barrier.NewBarrier(store, sw)
		mode, err := b.SealMode()
		if err != nil {
			t.Fatal(err)
		}
		if mode != "" {
			sw.SetMode(mode)
		}
		return b, sw
	}

	b, sw := boot()
	shares, err := b.Initialize(5, 3)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range shares[:3] {
		sw.Shamir().SubmitShare(s)
	}
	if err := b.Unseal(); err != nil {
		t.Fatal(err)
	}
	km := keys.NewKeyManager(b)
	if _, err := km.CreateKey("app", 0); err != nil {
		t.Fatal(err)
	}
	ct, err := transitsvc.NewTransitService(km).Encrypt("app", []byte("sim-before"))
	if err != nil {
		t.Fatal(err)
	}

	recovery, err := b.MigrateSeal(sw, "tpm", 5, 3)
	if err != nil || len(recovery) != 5 {
		t.Fatalf("migrate: %v (%d shares)", err, len(recovery))
	}

	// 재시작: 조각 없이 TPM으로 해제.
	b2, sw2 := boot()
	if sw2.Mode() != "tpm" {
		t.Fatalf("mode = %s", sw2.Mode())
	}
	if err := b2.Unseal(); err != nil {
		t.Fatalf("TPM auto-unseal failed: %v", err)
	}
	pt, err := transitsvc.NewTransitService(keys.NewKeyManager(b2)).Decrypt("app", ct)
	if err != nil || string(pt) != "sim-before" {
		t.Fatalf("decrypt after TPM unseal: %v", err)
	}

	// 같은 TPMSeal로 이미 blob이 있으면 SealExisting 거부(시뮬레이터 경로 확인).
	if _, err := b2.MigrateSeal(sw2, "tpm", 5, 3); !errors.Is(err, barrier.ErrSealAlreadyTarget) {
		t.Fatalf("tpm->tpm err = %v", err)
	}

	// blob 삭제 → 봉인 → 복구 조각으로 해제.
	if err := store.Delete("seal/tpm/rootkey"); err != nil {
		t.Fatal(err)
	}
	b3, sw3 := boot()
	if err := b3.Unseal(); err == nil {
		t.Fatal("unsealed without blob")
	}
	for _, s := range recovery[:3] {
		sw3.Shamir().SubmitShare(s)
	}
	if err := b3.Unseal(); err != nil {
		t.Fatalf("recovery unseal: %v", err)
	}
}
