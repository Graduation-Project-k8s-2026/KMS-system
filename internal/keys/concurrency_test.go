package keys_test

import (
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
	"sync"
	"sync/atomic"
	"testing"
)

func TestConcurrentCreateRotateConfig(t *testing.T) {
	b := barrier.NewBarrier(storage.NewMemoryStorage(), seal.NewDevSeal("test fixture"))
	if e := b.Unseal(); e != nil {
		t.Fatal(e)
	}
	km := keys.NewKeyManager(b)
	var wg sync.WaitGroup
	var count atomic.Int32
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := km.CreateKey("test", 0); e == nil {
				count.Add(1)
			}
		}()
	}
	wg.Wait()
	if count.Load() != 1 {
		t.Fatal("duplicate create")
	}
	for i := 0; i < 40; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, e := km.RotateKey("test"); e != nil {
				t.Error(e)
			}
		}()
		go func() {
			defer wg.Done()
			period := 60
			if _, e := km.UpdateConfig("test", nil, &period); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	m, e := km.GetKeyMeta("test")
	if e != nil || m.LatestVersion != 41 || m.AutoRotatePeriodSec != 60 {
		t.Fatal("lost concurrent update")
	}
	km.Protect("test")
	v := 2
	if _, e = km.UpdateConfig("test", &v, nil); e == nil {
		t.Fatal("protected history removed")
	}
}
