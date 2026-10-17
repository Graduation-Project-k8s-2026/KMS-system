package audit

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/metrics"
)

func countLines(t *testing.T, dir string) (n int, raw string) {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	var sb strings.Builder
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		sb.Write(b)
		sc := bufio.NewScanner(strings.NewReader(string(b)))
		for sc.Scan() {
			n++
		}
	}
	return n, sb.String()
}

func TestTransitLog_CloseFlushesEverything(t *testing.T) {
	dir := t.TempDir()
	l, err := NewTransit(dir, 1024, time.Hour) // fsync 주기를 길게 해도 Close가 flush해야 한다
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 500; i++ {
		l.Record(TransitEvent{RequestID: "r", Subject: "system:serviceaccount:a:b", Action: "encrypt", Key: "k", Status: 200})
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if n, _ := countLines(t, dir); n != 500 {
		t.Fatalf("lines after Close = %d, want 500", n)
	}
	l.Record(TransitEvent{}) // 닫힌 뒤 Record는 패닉 없이 버린다
}

func TestTransitLog_FullBufferNeverBlocksAndCountsDrops(t *testing.T) {
	dir := t.TempDir()
	l := &TransitLog{dir: dir, ch: make(chan TransitEvent, 2), fsyncEvery: time.Hour, gate: make(chan struct{})}
	l.start()
	before := testutil.ToFloat64(metrics.AuditDroppedTotal)

	done := make(chan struct{})
	go func() {
		for i := 0; i < 10; i++ {
			l.Record(TransitEvent{Action: "decrypt", Key: "k", Status: 200})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Record blocked on a full buffer")
	}
	if got := testutil.ToFloat64(metrics.AuditDroppedTotal) - before; got != 8 {
		t.Fatalf("dropped = %v, want 8 (buffer 2, 10 events)", got)
	}
	close(l.gate)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if n, _ := countLines(t, dir); n != 2 {
		t.Fatalf("lines = %d, want the 2 buffered events", n)
	}
}

func TestTransitLog_PeriodicFsyncMakesRecordsVisibleWithoutClose(t *testing.T) {
	dir := t.TempDir()
	l, _ := NewTransit(dir, 16, 20*time.Millisecond)
	defer l.Close()
	l.Record(TransitEvent{Action: "rewrap", Key: "k", Status: 200})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if n, _ := countLines(t, dir); n == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("record not written within 2s without Close")
}

func TestReadTransitToday_RoundTripAndFields(t *testing.T) {
	dir := t.TempDir()
	l, _ := NewTransit(dir, 16, time.Second)
	l.Record(TransitEvent{RequestID: "abc", Subject: "system:serviceaccount:ns:sa", Action: "encrypt", Key: "ns.k", SARNamespace: "ns", Status: 403, LatencyMs: 1.5, Detail: "why"})
	l.Close()
	evs, err := ReadTransitToday(dir)
	if err != nil || len(evs) != 1 {
		t.Fatalf("events = %v, err = %v", evs, err)
	}
	e := evs[0]
	if e.UTC.IsZero() || e.RequestID != "abc" || e.Subject != "system:serviceaccount:ns:sa" || e.Action != "encrypt" ||
		e.Key != "ns.k" || e.SARNamespace != "ns" || e.Status != 403 || e.LatencyMs != 1.5 || e.Detail != "why" {
		t.Fatalf("event = %+v", e)
	}
	// 필드 목록은 고정이다: 본문/토큰/암호문 필드가 생기면 이 테스트가 알려 준다.
	b, _ := json.Marshal(e)
	var m map[string]any
	json.Unmarshal(b, &m)
	for k := range m {
		switch k {
		case "utc", "request_id", "subject", "action", "key", "sar_namespace", "status", "latency_ms", "detail":
		default:
			t.Fatalf("unexpected audit field %q", k)
		}
	}
}

func TestAdminAudit_KeyNameRecordedFromPathAndSetKey(t *testing.T) {
	dir := t.TempDir()
	l, _ := New(dir)
	h := l.Middleware(func(*http.Request) string { return "admin" }, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/keys" {
			SetKey(r, "created-key") // 생성은 경로에 이름이 없어 핸들러가 알린다
		}
		w.WriteHeader(200)
	}))
	for _, path := range []string{"/v1/keys", "/v1/keys/team-a.pay/rotate", "/v1/keys/old/disable", "/v1/keys/old/schedule-deletion"} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", path, strings.NewReader("private-body")))
	}
	events, err := ReadToday(dir)
	if err != nil || len(events) != 8 {
		t.Fatalf("events = %d, err = %v", len(events), err)
	}
	want := []struct{ action, key string }{
		{"POST /v1/keys", "created-key"}, {"POST /v1/keys", "team-a.pay"},
		{"POST /v1/keys/disable", "old"}, {"POST /v1/keys/schedule-deletion", "old"},
	}
	for i, w := range want {
		for _, e := range events[2*i : 2*i+2] {
			if !strings.HasPrefix(e.Action, w.action+" ") || e.Key != w.key {
				// "requested" 이벤트는 SetKey 전이라 생성 요청의 Key가 비어 있을 수 있다 — completed만 엄격히 본다.
				if strings.HasSuffix(e.Action, "completed") || w.key != "created-key" {
					t.Fatalf("event %d = %+v, want action %q key %q", i, e, w.action, w.key)
				}
			}
		}
	}
	raw, _ := os.ReadFile(filepath.Join(dir, time.Now().UTC().Format("2006-01-02")+".jsonl"))
	if strings.Contains(string(raw), "private-body") {
		t.Fatal("request body leaked into audit")
	}
}
