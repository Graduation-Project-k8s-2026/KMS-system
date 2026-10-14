package barrier_test

import (
	"errors"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
	transitsvc "github.com/Graduation-Project-k8s-2026/KMS-system/internal/transit"
	"os"
	"sync"
	"sync/atomic"
	"testing"
)

func TestInitializationRestartWrongRootAndRestore(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStorage(dir)
	s := seal.NewShamirSeal(3)
	b := barrier.NewBarrier(store, s)
	shares, e := b.Initialize(5, 3)
	if e != nil {
		t.Fatal(e)
	}
	for _, x := range shares[:3] {
		if _, e = s.SubmitShare(x); e != nil {
			t.Fatal(e)
		}
	}
	if e = b.Unseal(); e != nil {
		t.Fatal(e)
	}
	if e = b.PutJSON("keys/example", map[string]string{"value": "public fixture"}); e != nil {
		t.Fatal(e)
	}
	b.Seal()
	// A new process object cannot reinitialize and cannot accept another root.
	s = seal.NewShamirSeal(3)
	b = barrier.NewBarrier(storage.NewFileStorage(dir), s)
	if _, e = b.Initialize(5, 3); !errors.Is(e, barrier.ErrInitialized) {
		t.Fatal("reinit accepted")
	}
	_, foreign, e := seal.InitShamir(5, 3)
	if e != nil {
		t.Fatal(e)
	}
	for _, x := range foreign[:3] {
		s.SubmitShare(x)
	}
	if e = b.Unseal(); !errors.Is(e, barrier.ErrRootVerification) || !b.IsSealed() {
		t.Fatal("foreign root accepted")
	}
	bad := append([]byte(nil), shares[0]...)
	bad[0] ^= 1
	s.SubmitShare(bad)
	s.SubmitShare(shares[1])
	s.SubmitShare(shares[2])
	if e = b.Unseal(); e == nil {
		t.Fatal("corrupt shares accepted")
	}
	s.SubmitShare(shares[0])
	duplicate := append([]byte(nil), shares[0]...)
	duplicate[1] ^= 1
	if _, e = s.SubmitShare(duplicate); !errors.Is(e, seal.ErrDuplicateShare) {
		t.Fatal("duplicate coordinate accepted")
	}
	s.SubmitShare(shares[1])
	s.SubmitShare(shares[2])
	if e = b.Unseal(); e != nil {
		t.Fatal(e)
	}
	var got map[string]string
	if e = b.GetJSON("keys/example", &got); e != nil || got["value"] != "public fixture" {
		t.Fatal("restart restore failed")
	}
	before := b.LastUnseal()
	if e = b.Unseal(); e != nil || !before.Equal(b.LastUnseal()) {
		t.Fatal("duplicate unseal changed event")
	}
	if e = b.CheckInitialization(5, 2); e == nil {
		t.Fatal("threshold change accepted")
	}
}
func TestConcurrentInitializationAndLegacyRefusal(t *testing.T) {
	store := storage.NewMemoryStorage()
	b := barrier.NewBarrier(store, seal.NewShamirSeal(3))
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := b.Initialize(5, 3); e == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatal("multiple successful initializations")
	}
	legacy := storage.NewMemoryStorage()
	legacy.Put("keys/old", []byte("existing"))
	b = barrier.NewBarrier(legacy, seal.NewShamirSeal(3))
	if _, e := b.Initialize(5, 3); !errors.Is(e, barrier.ErrInitialized) {
		t.Fatal("legacy overwritten")
	}
}

func TestBackupRestoreIntoSeparateDirectory(t *testing.T) {
	source := t.TempDir()
	s := seal.NewShamirSeal(2)
	b := barrier.NewBarrier(storage.NewFileStorage(source), s)
	shares, e := b.Initialize(3, 2)
	if e != nil {
		t.Fatal(e)
	}
	for _, x := range shares[:2] {
		s.SubmitShare(x)
	}
	if e = b.Unseal(); e != nil {
		t.Fatal(e)
	}
	km := keys.NewKeyManager(b)
	km.CreateKey("demo", 0)
	transit := transitsvc.NewTransitService(km)
	ct, e := transit.Encrypt("demo", []byte("public restore fixture"))
	if e != nil {
		t.Fatal(e)
	}
	km.RotateKey("demo")
	b.Seal()
	restored := t.TempDir()
	if e = os.CopyFS(restored, os.DirFS(source)); e != nil {
		t.Fatal(e)
	}
	s2 := seal.NewShamirSeal(2)
	b2 := barrier.NewBarrier(storage.NewFileStorage(restored), s2)
	for _, x := range shares[:2] {
		s2.SubmitShare(x)
	}
	if e = b2.Unseal(); e != nil {
		t.Fatal(e)
	}
	km2 := keys.NewKeyManager(b2)
	p, e := transitsvc.NewTransitService(km2).Decrypt("demo", ct)
	if e != nil || string(p) != "public restore fixture" {
		t.Fatal("separate-directory backup restore failed")
	}
	meta, e := km2.GetKeyMeta("demo")
	if e != nil || meta.LatestVersion != 2 {
		t.Fatal("historical key versions lost")
	}
}
