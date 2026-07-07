package rotation

import (
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
)

func newTestKeyManager(t *testing.T) *keys.KeyManager {
	t.Helper()

	store := storage.NewMemoryStorage()
	sealer := seal.NewDevSeal("test-passphrase")
	b := barrier.NewBarrier(store, sealer)
	if err := b.Unseal(); err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}
	return keys.NewKeyManager(b)
}

func TestTick_RotatesOnlyDueKeys(t *testing.T) {
	km := newTestKeyManager(t)

	if _, err := km.CreateKey("due-key", 1); err != nil { // 1초 주기
		t.Fatalf("CreateKey(due-key) failed: %v", err)
	}
	if _, err := km.CreateKey("not-due-key", 3600); err != nil { // 1시간 주기
		t.Fatalf("CreateKey(not-due-key) failed: %v", err)
	}
	if _, err := km.CreateKey("no-auto-key", 0); err != nil { // 자동회전 off
		t.Fatalf("CreateKey(no-auto-key) failed: %v", err)
	}

	s := NewRotationScheduler(km)
	// 생성 직후 시각 기준 2초 뒤로 "현재 시각"을 준다 — 1초 주기인 due-key만
	// 넘기고, 1시간 주기인 not-due-key는 아직 넘기지 못한다.
	futureMs := time.Now().Add(2 * time.Second).UnixMilli()

	rotated, err := s.tick(futureMs)
	if err != nil {
		t.Fatalf("tick failed: %v", err)
	}

	if len(rotated) != 1 || rotated[0] != "due-key" {
		t.Fatalf(`tick rotated = %v, want ["due-key"]`, rotated)
	}
}

func TestTick_IncrementsLatestVersion(t *testing.T) {
	km := newTestKeyManager(t)
	if _, err := km.CreateKey("due-key", 1); err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	s := NewRotationScheduler(km)
	futureMs := time.Now().Add(2 * time.Second).UnixMilli()

	if _, err := s.tick(futureMs); err != nil {
		t.Fatalf("tick failed: %v", err)
	}

	meta, err := km.GetKeyMeta("due-key")
	if err != nil {
		t.Fatalf("GetKeyMeta failed: %v", err)
	}
	if meta.LatestVersion != 2 {
		t.Fatalf("LatestVersion after tick = %d, want 2", meta.LatestVersion)
	}
}

func TestTick_CallsOnRotateCallback(t *testing.T) {
	km := newTestKeyManager(t)
	if _, err := km.CreateKey("due-key", 1); err != nil {
		t.Fatalf("CreateKey(due-key) failed: %v", err)
	}
	if _, err := km.CreateKey("no-auto-key", 0); err != nil {
		t.Fatalf("CreateKey(no-auto-key) failed: %v", err)
	}

	var mu sync.Mutex
	var rotatedNames []string
	s := NewRotationScheduler(km, WithOnRotate(func(name string) {
		mu.Lock()
		defer mu.Unlock()
		rotatedNames = append(rotatedNames, name)
	}))

	futureMs := time.Now().Add(2 * time.Second).UnixMilli()
	if _, err := s.tick(futureMs); err != nil {
		t.Fatalf("tick failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	sort.Strings(rotatedNames)
	if len(rotatedNames) != 1 || rotatedNames[0] != "due-key" {
		t.Fatalf(`onRotate calls = %v, want ["due-key"]`, rotatedNames)
	}
}

func TestStartStop_NoLeakOrPanic(t *testing.T) {
	km := newTestKeyManager(t)
	if _, err := km.CreateKey("due-key", 1); err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	s := NewRotationScheduler(km, WithTickInterval(10*time.Millisecond))
	s.Start()
	time.Sleep(50 * time.Millisecond)
	s.Stop()
	// 여기까지 패닉이나 데드락 없이 도달하면 goroutine이 정상적으로
	// 정리(정지 신호 수신 → 루프 탈출 → doneCh close)된 것이다.
}

func TestStop_CalledTwice_IsSafe(t *testing.T) {
	km := newTestKeyManager(t)

	s := NewRotationScheduler(km, WithTickInterval(10*time.Millisecond))
	s.Start()
	s.Stop()
	s.Stop() // 두 번째 호출도 패닉 없이 즉시 반환되어야 한다.
}
