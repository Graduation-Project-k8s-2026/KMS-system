package keys

import (
	"errors"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

func clocked(t *testing.T) (*KeyManager, *time.Time) {
	t.Helper()
	m := newTestManager(t)
	now := t0
	m.SetClock(func() time.Time { return now })
	return m, &now
}

func state(t *testing.T, m *KeyManager, name string) KeyRingMeta {
	t.Helper()
	meta, err := m.GetKeyMeta(name)
	if err != nil {
		t.Fatal(err)
	}
	return meta
}

func TestLifecycle_TransitionsAndAutomaticFields(t *testing.T) {
	m, _ := clocked(t)
	m.CreateKey("k", 0)
	if s := state(t, m, "k"); s.State != StateActive || s.DeletionDate != nil {
		t.Fatalf("new key = %+v", s)
	}
	if meta, err := m.DisableKey("k"); err != nil || meta.State != StateDisabled {
		t.Fatalf("disable: %+v %v", meta, err)
	}
	if _, err := m.DisableKey("k"); err != nil { // 멱등
		t.Fatalf("disable twice: %v", err)
	}
	if meta, err := m.EnableKey("k"); err != nil || meta.State != StateActive {
		t.Fatalf("enable: %+v %v", meta, err)
	}
	if _, err := m.EnableKey("k"); err != nil {
		t.Fatalf("enable twice: %v", err)
	}
	meta, err := m.ScheduleDeletion("k", 10)
	if err != nil || meta.State != StatePendingDeletion || meta.DeletionDate == nil || !meta.DeletionDate.Equal(t0.AddDate(0, 0, 10)) {
		t.Fatalf("schedule: %+v %v", meta, err)
	}
	// pending에서는 disable/enable/schedule이 모두 invalid_state
	for name, op := range map[string]func() error{
		"disable":  func() error { _, e := m.DisableKey("k"); return e },
		"enable":   func() error { _, e := m.EnableKey("k"); return e },
		"schedule": func() error { _, e := m.ScheduleDeletion("k", 10); return e },
	} {
		if err := op(); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("%s while pending: %v", name, err)
		}
	}
	// cancel → disabled (바로 active가 아님)
	meta, err = m.CancelDeletion("k")
	if err != nil || meta.State != StateDisabled || meta.DeletionDate != nil {
		t.Fatalf("cancel: %+v %v", meta, err)
	}
	if _, err := m.CancelDeletion("k"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("cancel when not pending: %v", err)
	}
	// disabled 에서도 삭제 예약 가능
	if _, err := m.ScheduleDeletion("k", 0); err != nil {
		t.Fatalf("schedule from disabled: %v", err)
	}
	if s := state(t, m, "k"); !s.DeletionDate.Equal(t0.AddDate(0, 0, 30)) {
		t.Fatalf("default pending days should be 30: %v", s.DeletionDate)
	}
	if _, err := m.DisableKey("missing"); !errors.Is(err, &KeyNotFoundError{}) {
		t.Fatalf("missing key: %v", err)
	}
}

func TestLifecycle_PendingDaysRange(t *testing.T) {
	m, _ := clocked(t)
	m.CreateKey("k", 0)
	for _, d := range []int{-1, 1, 6, 31, 365} {
		_, err := m.ScheduleDeletion("k", d)
		var pe *KeyPolicyError
		if !errors.As(err, &pe) {
			t.Fatalf("days %d: err = %v, want KeyPolicyError", d, err)
		}
		if s := state(t, m, "k"); s.State != StateActive {
			t.Fatalf("state changed by rejected request: %s", s.State)
		}
	}
	for _, d := range []int{7, 30} {
		m.CreateKey("k"+string(rune('a'+d%26)), 0)
	}
	if _, err := m.ScheduleDeletion("k", 7); err != nil {
		t.Fatalf("7 days: %v", err)
	}
}

func TestLifecycle_InactiveKeysRejectOperationsAndSkipRotation(t *testing.T) {
	m, now := clocked(t)
	m.CreateKey("auto", 60)
	m.CreateKey("manual", 0)
	if _, _, err := m.GetEncryptionKEK("auto"); err != nil {
		t.Fatal(err)
	}
	m.DisableKey("auto")
	if _, _, err := m.GetEncryptionKEK("auto"); !errors.Is(err, ErrKeyNotActive) {
		t.Fatalf("encrypt kek on disabled: %v", err)
	}
	if _, err := m.GetDecryptionKEK("auto", 1); !errors.Is(err, ErrKeyNotActive) {
		t.Fatalf("decrypt kek on disabled: %v", err)
	}
	if _, err := m.RotateKey("auto"); !errors.Is(err, ErrKeyNotActive) {
		t.Fatalf("rotate disabled: %v", err)
	}
	// 자동 회전 스케줄러는 비활성 키를 건너뛴다
	_ = now
	later := time.Now().Add(2 * time.Hour).UnixMilli() // LastRotatedAt은 실제 시각 기준이다
	due, err := m.FindKeysDueForRotation(later)
	if err != nil || len(due) != 0 {
		t.Fatalf("due = %v, %v (disabled auto-rotate key must be skipped)", due, err)
	}
	m.EnableKey("auto")
	due, _ = m.FindKeysDueForRotation(later)
	if len(due) != 1 || due[0] != "auto" {
		t.Fatalf("due after enable = %v", due)
	}
	m.ScheduleDeletion("auto", 7)
	if _, _, err := m.GetEncryptionKEK("auto"); !errors.Is(err, ErrKeyNotActive) {
		t.Fatalf("pending key encrypt: %v", err)
	}
	if _, err := m.UpdateConfig("auto", nil, new(int)); !errors.Is(err, ErrKeyNotActive) {
		t.Fatalf("config update on pending: %v", err)
	}
}

func TestLifecycle_PurgeAfterGracePeriodOnly(t *testing.T) {
	m, now := clocked(t)
	m.CreateKey("gone", 0)
	m.CreateKey("cancelled", 0)
	m.CreateKey("alive", 0)
	m.ScheduleDeletion("gone", 7)
	m.ScheduleDeletion("cancelled", 7)
	m.CancelDeletion("cancelled")

	var before, after []string
	b := func(n string) error { before = append(before, n); return nil }
	a := func(n string) { after = append(after, n) }

	*now = t0.AddDate(0, 0, 7).Add(-time.Second)
	if p, err := m.PurgeExpired(b, a); err != nil || len(p) != 0 {
		t.Fatalf("purged early: %v %v", p, err)
	}
	*now = t0.AddDate(0, 0, 7) // 정확히 만료 시각
	p, err := m.PurgeExpired(b, a)
	if err != nil || len(p) != 1 || p[0] != "gone" {
		t.Fatalf("purged = %v, %v", p, err)
	}
	if len(before) != 1 || before[0] != "gone" || len(after) != 1 || after[0] != "gone" {
		t.Fatalf("audit hooks before=%v after=%v", before, after)
	}
	if _, err := m.GetKeyMeta("gone"); !errors.Is(err, &KeyNotFoundError{}) {
		t.Fatalf("purged key still readable: %v", err)
	}
	for _, n := range []string{"cancelled", "alive"} {
		if _, err := m.GetKeyMeta(n); err != nil {
			t.Fatalf("%s must survive: %v", n, err)
		}
	}
	// 같은 이름으로 다시 만들 수 있다 (자료가 완전히 사라졌음)
	if _, err := m.CreateKey("gone", 0); err != nil {
		t.Fatalf("recreate: %v", err)
	}
}

func TestLifecycle_PurgeSkippedWhenAuditFails(t *testing.T) {
	m, now := clocked(t)
	m.CreateKey("k", 0)
	m.ScheduleDeletion("k", 7)
	*now = t0.AddDate(0, 0, 8)
	p, err := m.PurgeExpired(func(string) error { return errors.New("audit down") }, nil)
	if err != nil || len(p) != 0 {
		t.Fatalf("purged despite audit failure: %v %v", p, err)
	}
	if _, err := m.GetKeyMeta("k"); err != nil {
		t.Fatal("key deleted without audit record")
	}
	if p, _ := m.PurgeExpired(nil, nil); len(p) != 1 {
		t.Fatal("retry should purge")
	}
}

func TestLifecycle_SealedBarrierPurgesNothing(t *testing.T) {
	m, now := clocked(t)
	m.CreateKey("k", 0)
	m.ScheduleDeletion("k", 7)
	*now = t0.AddDate(0, 0, 8)
	m.barrier.Seal()
	if _, err := m.PurgeExpired(nil, nil); err == nil {
		t.Fatal("PurgeExpired must fail while sealed")
	}
	if err := m.barrier.Unseal(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetKeyMeta("k"); err != nil {
		t.Fatalf("key lost while sealed: %v", err)
	}
}

func TestLifecycle_ProtectedKeys(t *testing.T) {
	m, now := clocked(t)
	m.CreateKey("k8s-secrets", 0)
	m.Protect("k8s-secrets")
	if _, err := m.DisableKey("k8s-secrets"); !errors.Is(err, ErrKeyProtected) {
		t.Fatalf("disable protected: %v", err)
	}
	if _, err := m.ScheduleDeletion("k8s-secrets", 7); !errors.Is(err, ErrKeyProtected) {
		t.Fatalf("schedule protected: %v", err)
	}
	// 저장소가 외부에서 변조돼 disabled가 되더라도 보호 키는 계속 사용 가능해야 한다 (KMS v2 경로 보호).
	var ring KeyRing
	m.barrier.GetJSON(storageKey("k8s-secrets"), &ring)
	ring.State = StateDisabled
	ring.DeletionDate = &t0
	m.barrier.PutJSON(storageKey("k8s-secrets"), &ring)
	if _, _, err := m.GetEncryptionKEK("k8s-secrets"); err != nil {
		t.Fatalf("protected key must stay usable: %v", err)
	}
	*now = t0.AddDate(1, 0, 0)
	if p, _ := m.PurgeExpired(nil, nil); len(p) != 0 {
		t.Fatalf("protected key purged: %v", p)
	}
	// 보호되지 않은 같은 상태의 키는 막힌다
	m.CreateKey("other", 0)
	m.DisableKey("other")
	if _, _, err := m.GetEncryptionKEK("other"); !errors.Is(err, ErrKeyNotActive) {
		t.Fatalf("unprotected disabled key usable: %v", err)
	}
}

// 하위 호환: State/DeletionDate 필드가 없던 옛 형식의 키를 active로 읽고 정상 동작한다.
func TestLifecycle_LegacyFormatKeyReadsAsActive(t *testing.T) {
	m := newTestManager(t)
	legacy := map[string]any{ // 옛 KeyRing JSON (State 없음)
		"Name": "old", "Type": "aes256-gcm", "CreatedAt": t0, "LatestVersion": 1, "MinDecryptionVersion": 1,
		"AutoRotatePeriodSec": 0, "LastRotatedAt": t0,
		"Versions": []map[string]any{{"Version": 1, "KeyMaterial": make([]byte, 32), "CreatedAt": t0}},
	}
	if err := m.barrier.PutJSON(storageKey("old"), legacy); err != nil {
		t.Fatal(err)
	}
	if s := state(t, m, "old"); s.State != StateActive || s.DeletionDate != nil {
		t.Fatalf("legacy key meta = %+v", s)
	}
	if _, _, err := m.GetEncryptionKEK("old"); err != nil {
		t.Fatalf("legacy key unusable: %v", err)
	}
	if _, err := m.RotateKey("old"); err != nil {
		t.Fatalf("legacy key rotate: %v", err)
	}
	if _, err := m.DisableKey("old"); err != nil {
		t.Fatal(err)
	}
	if s := state(t, m, "old"); s.State != StateDisabled || s.LatestVersion != 2 {
		t.Fatalf("after disable = %+v", s)
	}
}
