package seal_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal/sealtest"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/shamir"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
)

func newSwitch(t *testing.T, mode string, dev *sealtest.Device, store storage.StorageBackend) *seal.Switch {
	t.Helper()
	open := func() (seal.TPMBackend, error) { return dev.Open(store) }
	return seal.NewSwitch(mode, seal.NewShamirSeal(3), nil, open, store)
}

func submit(t *testing.T, s *seal.Switch, shares [][]byte) {
	t.Helper()
	for _, sh := range shares {
		if _, err := s.Shamir().SubmitShare(sh); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSwitch_ShamirMode_NeedsShares(t *testing.T) {
	store := storage.NewMemoryStorage()
	s := newSwitch(t, "shamir", sealtest.NewDevice(), store)
	if s.Type() != "shamir" {
		t.Fatalf("Type = %q", s.Type())
	}
	if _, err := s.Unseal(); !errors.Is(err, seal.ErrNotEnoughShares) {
		t.Fatalf("err = %v, want ErrNotEnoughShares", err)
	}
	root := bytes.Repeat([]byte{3}, 32)
	shares, _ := shamir.Split(root, 5, 3)
	submit(t, s, shares[:3])
	got, err := s.Unseal()
	if err != nil || !bytes.Equal(got, root) {
		t.Fatalf("Unseal = %x, %v", got, err)
	}
}

func TestSwitch_TPMMode_AutoUnsealsWithoutShares(t *testing.T) {
	store := storage.NewMemoryStorage()
	dev := sealtest.NewDevice()
	root := bytes.Repeat([]byte{4}, 32)
	tpm, _ := dev.Open(store)
	if err := tpm.SealExisting(root); err != nil {
		t.Fatal(err)
	}
	s := newSwitch(t, "tpm", dev, store)
	got, err := s.Unseal()
	if err != nil || !bytes.Equal(got, root) {
		t.Fatalf("Unseal = %x, %v", got, err)
	}
}

func TestSwitch_TPMMode_DeviceMissing_FailsClosedThenRecoversWithShares(t *testing.T) {
	store := storage.NewMemoryStorage()
	dev := sealtest.NewDevice()
	root := bytes.Repeat([]byte{5}, 32)
	tpm, _ := dev.Open(store)
	tpm.SealExisting(root)
	dev.SetBroken(true)

	s := newSwitch(t, "tpm", dev, store)
	if _, err := s.Unseal(); !errors.Is(err, seal.ErrTPMUnavailable) {
		t.Fatalf("err = %v, want ErrTPMUnavailable", err)
	}
	// 복구 조각 3개 → Shamir 경로로 해제.
	shares, _ := shamir.Split(root, 5, 3)
	submit(t, s, shares[1:4])
	got, err := s.Unseal()
	if err != nil || !bytes.Equal(got, root) {
		t.Fatalf("recovery Unseal = %x, %v", got, err)
	}
	if s.Type() != "tpm" {
		t.Fatal("recovery must not change the recorded mode")
	}
}

func TestSwitch_TPMMode_LazyReopenAfterDeviceAppears(t *testing.T) {
	store := storage.NewMemoryStorage()
	dev := sealtest.NewDevice()
	root := bytes.Repeat([]byte{6}, 32)
	tpm, _ := dev.Open(store)
	tpm.SealExisting(root)
	dev.SetBroken(true)
	s := newSwitch(t, "tpm", dev, store)
	if _, err := s.Unseal(); err == nil {
		t.Fatal("expected failure while device is broken")
	}
	dev.SetBroken(false)
	if got, err := s.Unseal(); err != nil || !bytes.Equal(got, root) {
		t.Fatalf("retry Unseal = %x, %v", got, err)
	}
}

func TestSwitch_RemoveTPMBlobWorksWithoutDevice(t *testing.T) {
	store := storage.NewMemoryStorage()
	dev := sealtest.NewDevice()
	tpm, _ := dev.Open(store)
	tpm.SealExisting(bytes.Repeat([]byte{7}, 32))
	dev.SetBroken(true)
	s := newSwitch(t, "tpm", dev, store)
	if err := s.RemoveTPMBlob(); err != nil {
		t.Fatal(err)
	}
	dev.SetBroken(false)
	tpm2, _ := dev.Open(store)
	if tpm2.IsConfigured() {
		t.Fatal("blob still present")
	}
}

func TestSwitch_NoTPMConfigured(t *testing.T) {
	s := seal.NewSwitch("tpm", seal.NewShamirSeal(3), nil, nil, storage.NewMemoryStorage())
	if _, err := s.Unseal(); !errors.Is(err, seal.ErrTPMUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestSwitch_ProfileFollowsMode(t *testing.T) {
	s := seal.NewSwitch("shamir", seal.NewShamirSeal(3), nil, nil, storage.NewMemoryStorage())
	if p := s.Profile(); p.Type != "shamir" || p.HumanCount != 3 {
		t.Fatalf("profile = %+v", p)
	}
	s.SetMode("tpm")
	if p := s.Profile(); p.Type != "tpm" || !p.AutoUnsealCapable {
		t.Fatalf("profile = %+v", p)
	}
}
