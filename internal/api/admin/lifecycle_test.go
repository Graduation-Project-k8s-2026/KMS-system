package admin_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/api/admin"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/rotation"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/transit"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestManualUnsealStartsRotationAndSealStops(t *testing.T) {
	s := seal.NewShamirSeal(2)
	b := barrier.NewBarrier(storage.NewMemoryStorage(), s)
	shares, e := b.Initialize(3, 2)
	if e != nil {
		t.Fatal(e)
	}
	km := keys.NewKeyManager(b)
	var rotations atomic.Int32
	scheduler := rotation.NewRotationScheduler(km, rotation.WithTickInterval(10*time.Millisecond), rotation.WithOnRotate(func(string) { rotations.Add(1) }))
	defer scheduler.Stop()
	h := admin.NewRouter(admin.Deps{Barrier: b, Keys: km, Seal: s, ShamirParts: 3, ShamirThreshold: 2, OnUnseal: func() error { scheduler.Start(); return nil }, OnSeal: scheduler.Stop})
	post := func(path string, body any) int {
		raw, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", path, bytes.NewReader(raw)))
		return w.Code
	}
	for _, share := range shares[:2] {
		if post("/v1/sys/unseal", map[string]string{"share": base64.StdEncoding.EncodeToString(share)}) != 200 {
			t.Fatal("manual unseal failed")
		}
	}
	if _, e = km.CreateKey("demo", 1); e != nil {
		t.Fatal(e)
	}
	ts := transit.NewTransitService(km)
	ct, e := ts.Encrypt("demo", []byte("public fixture"))
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 10; i++ {
		if post("/v1/sys/unseal", nil) != 200 {
			t.Fatal("duplicate unseal")
		}
	}
	deadline := time.After(3 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for rotations.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("manual unseal never started scheduler")
		case <-ticker.C:
		}
	}
	if rotations.Load() != 1 {
		t.Fatal("multiple schedulers rotated simultaneously")
	}
	if _, e = ts.Decrypt("demo", ct); e != nil {
		t.Fatal("old ciphertext lost")
	}
	if post("/v1/sys/seal", nil) != 200 || !b.IsSealed() {
		t.Fatal("seal failed")
	}
	count := rotations.Load()
	time.Sleep(40 * time.Millisecond)
	if rotations.Load() != count {
		t.Fatal("scheduler continued after seal")
	}
	if post("/v1/sys/init", nil) != 409 {
		t.Fatal("reinit after seal allowed")
	}
}
